//! Скан проекта на уязвимые зависимости: lockfile'ы → пакеты → OSV → находки.

use super::discover;
use super::osv::{self, Http, OsvOptions};
use super::scripts::{self, InstallScript};
use super::typosquat;
use super::{Dep, Ecosystem, Package, Vuln, VulnFinding, best_fix, numeric_version, pep503};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// lockfile'ы больше — подозрительны; читать сотни МБ в память не будем.
const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LockfileReport {
    pub rel: String,
    pub label: &'static str,
    pub ecosystem: Ecosystem,
    pub packages: usize,
    /// Не разобран (битый, слишком большой, формат ещё не поддержан).
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DepsReport {
    pub root: PathBuf,
    pub lockfiles: Vec<LockfileReport>,
    /// Уникальные пакеты, по порядку.
    pub packages: Vec<Package>,
    /// По убыванию опасности, затем экосистема/имя/версия/id.
    pub findings: Vec<VulnFinding>,
    /// Не проверены: OSV недоступен и в кэше их нет.
    pub unchecked: Vec<Package>,
    pub from_cache: usize,
    pub fresh: usize,
    pub stale_cache_age: Option<u64>,
    pub osv_unavailable: bool,
    pub offline: bool,
    pub warnings: Vec<String>,
    /// Что запустит `npm install` (только package-lock v2/v3).
    pub install_scripts: Vec<InstallScript>,
    /// Имена, похожие на популярные (тайпсквоттинг, T4.4) — эвристика, не вердикт.
    pub typosquats: Vec<(Package, typosquat::Suspect)>,
}

impl DepsReport {
    /// Вредоносные пакеты (хоть одна находка `malicious`), по порядку находок.
    pub fn malicious_packages(&self) -> Vec<&Package> {
        let mut out: Vec<&Package> = Vec::new();
        for f in self.findings.iter().filter(|f| f.vuln.malicious) {
            if !out.contains(&&f.package) {
                out.push(&f.package);
            }
        }
        out
    }

    /// Пакеты, в которых есть хотя бы одна уязвимость.
    pub fn vulnerable_packages(&self) -> usize {
        // Находки отсортированы по опасности, а не по пакету — нужен именно set.
        self.findings
            .iter()
            .map(|f| &f.package)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// По пакету: (пакет, версия, закрывающая все исправимые дыры, сколько закрывает,
    /// сколько без исправления). Порядок — по самой опасной дыре пакета.
    pub fn upgrades(&self) -> Vec<Upgrade<'_>> {
        let mut out: Vec<Upgrade> = Vec::new();
        for f in &self.findings {
            let i = match out.iter().position(|u| u.package == &f.package) {
                Some(i) => i,
                None => {
                    out.push(Upgrade {
                        package: &f.package,
                        to: None,
                        fixes: 0,
                        unfixed: 0,
                    });
                    out.len() - 1
                }
            };
            let u = &mut out[i];
            match &f.fix {
                Some(v) => {
                    u.fixes += 1;
                    // Нужна версия не ниже каждого фикса — берём максимум.
                    let higher = match &u.to {
                        None => true,
                        Some(cur) => match (numeric_version(v), numeric_version(cur)) {
                            (Some(a), Some(b)) => a > b,
                            _ => false,
                        },
                    };
                    if higher {
                        u.to = Some(v.clone());
                    }
                }
                None => u.unfixed += 1,
            }
        }
        out
    }
}

pub struct Upgrade<'a> {
    pub package: &'a Package,
    pub to: Option<String>,
    pub fixes: usize,
    pub unfixed: usize,
}

pub fn scan(
    root: &Path,
    opts: &OsvOptions,
    http: &dyn Http,
    sleep: &(dyn Fn(u64) + Sync),
) -> Result<DepsReport, String> {
    let found = discover::find_lockfiles(root)?;

    let mut lockfiles = Vec::new();
    let mut install_scripts = Vec::new();
    // Ключ дедупа: в PyPI `Django` и `django` — один пакет.
    let mut uniq: BTreeMap<(Ecosystem, String, String), Package> = BTreeMap::new();
    for f in &found {
        let mut rep = LockfileReport {
            rel: f.rel.clone(),
            label: f.kind.label,
            ecosystem: f.kind.ecosystem,
            packages: 0,
            error: None,
        };
        let text = read_lockfile(&f.path);
        if let (Ok(t), "package-lock.json") = (&text, f.kind.label) {
            collect_scripts(f, t, &mut install_scripts);
        }
        match text.and_then(|t| (f.kind.parse)(&t)) {
            Ok(deps) => {
                for Dep { name, version } in deps {
                    let key_name = match f.kind.ecosystem {
                        Ecosystem::PyPI => pep503(&name),
                        _ => name.clone(),
                    };
                    let p = uniq
                        .entry((f.kind.ecosystem, key_name, version.clone()))
                        .or_insert_with(|| Package {
                            ecosystem: f.kind.ecosystem,
                            name,
                            version,
                            lockfiles: Vec::new(),
                        });
                    if !p.lockfiles.contains(&f.rel) {
                        p.lockfiles.push(f.rel.clone());
                    }
                }
                // Сколько пакетов в этом файле (включая общие с другими файлами).
                rep.packages = uniq
                    .values()
                    .filter(|p| p.lockfiles.contains(&f.rel))
                    .count();
            }
            Err(e) => rep.error = Some(crate::ui::sanitize_line(&e)),
        }
        lockfiles.push(rep);
    }
    let packages: Vec<Package> = uniq.into_values().collect();
    // Локально, без сети: сравнение с встроенными списками популярных имён.
    // Ревью Claude: похожее имя само по себе — слабый сигнал (на реальных проектах это
    // почти всегда настоящие пакеты: is-object/isobject, split/split2, sockjs/socks).
    // Показываем «перестановку букв» всегда, а остальное — только вместе со скриптом
    // установки: через него тайпсквот и запускает свой код. Два сигнала, а не один.
    let typosquats: Vec<(Package, typosquat::Suspect)> = packages
        .iter()
        .filter_map(|p| typosquat::check(p.ecosystem, &p.name).map(|s| (p.clone(), s)))
        .filter(|(p, s)| {
            s.reason == "two letters swapped"
                || install_scripts
                    .iter()
                    .any(|i: &InstallScript| i.name == p.name && i.version == p.version)
        })
        .collect();

    let res = if packages.is_empty() {
        osv::OsvResult::default()
    } else {
        osv::check(&packages, opts, http, sleep)
    };

    let mut findings = Vec::new();
    let mut unchecked = Vec::new();
    for (i, p) in packages.iter().enumerate() {
        match res.vulns.get(i).cloned().flatten() {
            Some(vulns) => {
                for vuln in merge_aliases(vulns) {
                    let fix = best_fix(&p.version, &vuln.fixed);
                    findings.push(VulnFinding {
                        package: p.clone(),
                        vuln,
                        fix,
                    });
                }
            }
            None => unchecked.push(p.clone()),
        }
    }
    findings.sort_by(|a, b| {
        b.vuln
            .severity
            .cmp(&a.vuln.severity)
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.vuln.id.cmp(&b.vuln.id))
    });

    Ok(DepsReport {
        root: root.to_path_buf(),
        lockfiles,
        packages,
        findings,
        unchecked,
        from_cache: res.from_cache,
        fresh: res.fresh,
        stale_cache_age: res.stale_cache_age,
        osv_unavailable: res.osv_unavailable,
        offline: opts.offline,
        warnings: res.warnings,
        install_scripts,
        typosquats,
    })
}

/// Пакеты со скриптами установки из одного package-lock (T2.5).
fn collect_scripts(f: &discover::Found, text: &str, out: &mut Vec<InstallScript>) {
    let Ok(flagged) = scripts::flagged_in_lock(text) else {
        return; // битый lockfile — об этом уже скажет парсер
    };
    let project = f.path.parent().unwrap_or(Path::new("."));
    for (path, name, version, dev) in flagged {
        let commands = scripts::read_commands(project, &path);
        let flags = scripts::flags(&commands);
        out.push(InstallScript {
            lockfile: f.rel.clone(),
            name: crate::ui::sanitize_line(&name),
            version: crate::ui::sanitize_line(&version),
            dev,
            commands,
            flags,
        });
    }
}

fn read_lockfile(path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_LOCKFILE_BYTES {
        return Err(format!(
            "larger than {} MB, skipped",
            MAX_LOCKFILE_BYTES / 1024 / 1024
        ));
    }
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(bytes).map_err(|_| "not UTF-8 text".to_string())?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(&text).to_string())
}

/// Одна дыра под разными id (`PYSEC-…` и `GHSA-…` с общим `CVE-…` в `aliases`) —
/// одна находка. Остальные id уходят в `aliases`, исправления объединяются,
/// опасность — максимальная из известных.
fn merge_aliases(vulns: Vec<Vuln>) -> Vec<Vuln> {
    let n = vulns.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut owner: HashMap<&str, usize> = HashMap::new();
    for (i, v) in vulns.iter().enumerate() {
        for key in std::iter::once(&v.id).chain(v.aliases.iter()) {
            match owner.get(key.as_str()) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    parent[a] = b;
                }
                None => {
                    owner.insert(key, i);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }
    let mut out: Vec<Vuln> = groups
        .into_values()
        .map(|members| {
            // Представитель: с деталями, самый опасный, с CVSS, по id.
            let best = *members
                .iter()
                .min_by(|&&a, &&b| {
                    let (x, y) = (&vulns[a], &vulns[b]);
                    let detailed = |v: &Vuln| v.summary != "(details unavailable)";
                    detailed(y)
                        .cmp(&detailed(x))
                        .then(y.severity.cmp(&x.severity))
                        .then(y.cvss.is_some().cmp(&x.cvss.is_some()))
                        .then(x.id.cmp(&y.id))
                })
                .expect("group is never empty");
            let mut v = vulns[best].clone();
            for &m in &members {
                let o = &vulns[m];
                for a in std::iter::once(&o.id).chain(o.aliases.iter()) {
                    if *a != v.id && !v.aliases.contains(a) {
                        v.aliases.push(a.clone());
                    }
                }
                for f in &o.fixed {
                    if !v.fixed.contains(f) {
                        v.fixed.push(f.clone());
                    }
                }
                if o.severity > v.severity && v.cvss.is_none() {
                    v.severity = o.severity;
                }
                // Хоть одна запись говорит «вредонос» — вся группа вредонос.
                v.malicious |= o.malicious;
            }
            // CVE — первыми: это то, что гуглят.
            v.aliases.sort_by(|a, b| {
                (!a.starts_with("CVE-"))
                    .cmp(&!b.starts_with("CVE-"))
                    .then(a.cmp(b))
            });
            v
        })
        .collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

/// Для тестов и `--offline` без сети: транспорт, который всегда «сеть недоступна».
pub struct NoNetwork;

impl Http for NoNetwork {
    fn request(&self, _url: &str, _body: Option<&str>) -> osv::Attempt {
        osv::Attempt::Fatal("network disabled".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Severity;

    fn v(id: &str, aliases: &[&str], sev: Severity, fixed: &[&str]) -> Vuln {
        Vuln {
            id: id.into(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            summary: format!("summary of {id}"),
            severity: sev,
            cvss: None,
            fixed: fixed.iter().map(|s| s.to_string()).collect(),
            malicious: false,
        }
    }

    #[test]
    fn counts_packages_not_runs_and_picks_one_upgrade_per_package() {
        let pkg = |n: &str| Package {
            ecosystem: Ecosystem::Npm,
            name: n.into(),
            version: "0.21.0".into(),
            lockfiles: vec!["package-lock.json".into()],
        };
        let f = |p: &Package, sev, fix: Option<&str>| VulnFinding {
            package: p.clone(),
            vuln: v("GHSA-x", &[], sev, &[]),
            fix: fix.map(str::to_string),
        };
        let (axios, lodash) = (pkg("axios"), pkg("lodash"));
        // Порядок как после сортировки по опасности: пакеты чередуются.
        let findings = vec![
            f(&axios, Severity::High, Some("0.21.2")),
            f(&lodash, Severity::High, Some("4.17.21")),
            f(&axios, Severity::Medium, Some("0.33.0")),
            f(&axios, Severity::Low, Some("0.30.0")),
            f(&lodash, Severity::Low, None),
        ];
        let r = DepsReport {
            root: PathBuf::from("."),
            lockfiles: Vec::new(),
            packages: vec![axios.clone(), lodash.clone()],
            findings,
            unchecked: Vec::new(),
            from_cache: 0,
            fresh: 2,
            stale_cache_age: None,
            osv_unavailable: false,
            offline: false,
            warnings: Vec::new(),
            install_scripts: Vec::new(),
            typosquats: Vec::new(),
        };
        assert_eq!(r.vulnerable_packages(), 2);
        let ups = r.upgrades();
        let up: Vec<(&str, Option<&str>, usize, usize)> = ups
            .iter()
            .map(|u| (u.package.name.as_str(), u.to.as_deref(), u.fixes, u.unfixed))
            .collect();
        assert_eq!(
            up,
            vec![
                ("axios", Some("0.33.0"), 3, 0),
                ("lodash", Some("4.17.21"), 1, 1)
            ]
        );
    }

    #[test]
    fn same_hole_under_two_ids_is_one_finding() {
        let merged = merge_aliases(vec![
            v(
                "PYSEC-2021-1",
                &["CVE-2021-1"],
                Severity::Unknown,
                &["3.2.1"],
            ),
            v(
                "GHSA-aaaa-bbbb-cccc",
                &["CVE-2021-1"],
                Severity::High,
                &["3.2.1", "3.1.9"],
            ),
            v("GHSA-zzzz-0000-0000", &[], Severity::Low, &[]),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].id, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(merged[0].aliases, vec!["CVE-2021-1", "PYSEC-2021-1"]);
        assert_eq!(merged[0].fixed, vec!["3.2.1", "3.1.9"]);
        assert_eq!(merged[1].id, "GHSA-zzzz-0000-0000");
    }

    #[test]
    fn scan_dedups_packages_across_lockfiles_and_reports_bad_ones() {
        let d = std::env::temp_dir().join(format!("jetscan-deps-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("web")).unwrap();
        let lock =
            r#"{"lockfileVersion":3,"packages":{"":{},"node_modules/ms":{"version":"2.1.3"}}}"#;
        fs::write(d.join("package-lock.json"), format!("\u{feff}{lock}")).unwrap();
        fs::write(d.join("web/package-lock.json"), lock).unwrap();
        fs::write(d.join("web/yarn.lock"), "# yarn").unwrap();
        fs::write(d.join("web/npm-shrinkwrap.json"), "{ broken").unwrap();
        let opts = OsvOptions {
            cache_dir: None,
            no_cache: false,
            offline: true,
        };
        let r = scan(&d, &opts, &NoNetwork, &|_| {}).unwrap();
        assert_eq!(r.packages.len(), 1);
        assert_eq!(
            r.packages[0].lockfiles,
            vec!["package-lock.json", "web/package-lock.json"]
        );
        let errs: Vec<(&str, bool)> = r
            .lockfiles
            .iter()
            .map(|l| (l.rel.as_str(), l.error.is_some()))
            .collect();
        assert_eq!(
            errs,
            vec![
                ("package-lock.json", false),
                ("web/npm-shrinkwrap.json", true),
                ("web/package-lock.json", false),
                ("web/yarn.lock", true),
            ]
        );
        // Без сети и без кэша — «не проверено», а не «чисто».
        assert_eq!(r.unchecked.len(), 1);
        assert!(r.findings.is_empty());
        let _ = fs::remove_dir_all(&d);
    }
}
