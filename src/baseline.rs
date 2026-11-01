//! Baseline для CI (T5.1): снимок уже известных находок. С `--baseline` отчёт и
//! `--exit-code` видят только новое — старый проект можно подключить к CI сразу,
//! а долг разбирать постепенно.
//!
//! - В файле только ключи: отпечатки секретов (как в отчётах и `.jetscanignore`),
//!   `экосистема:пакет:id` уязвимостей, имена пакетов, `id:путь:сообщение` workflow
//!   (без номера строки — сдвиг строк не делает находку новой). Ни одного секрета.
//! - Уязвимость привязана к пакету, не к версии: обновление, которое её не закрыло, —
//!   не «новая» находка. Скрипт установки — к версии: новая версия могла его поменять.
//! - Вредоносные пакеты baseline НЕ скрывает никогда.
//! - Детерминированно: ключи отсортированы.

use crate::deps::scan::DepsReport;
use crate::deps::{Package, VulnFinding};
use crate::hygiene::Issue;
use crate::json::{self, Json};
use crate::secrets::scan::ScanReport;
use std::collections::BTreeSet;
use std::path::Path;

const FORMAT: f64 = 1.0;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Baseline {
    secrets: BTreeSet<String>,
    vulns: BTreeSet<String>,
    scripts: BTreeSet<String>,
    names: BTreeSet<String>,
    workflows: BTreeSet<String>,
}

/// Сколько находок скрыто baseline'ом.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hidden {
    pub secrets: usize,
    pub vulns: usize,
    /// Скрипты установки, подозрительные имена, workflow.
    pub other: usize,
}

impl Hidden {
    pub fn total(&self) -> usize {
        self.secrets + self.vulns + self.other
    }

    pub fn add(&mut self, o: Hidden) {
        self.secrets += o.secrets;
        self.vulns += o.vulns;
        self.other += o.other;
    }
}

fn vuln_key(f: &VulnFinding) -> String {
    format!(
        "{}:{}:{}",
        f.package.ecosystem.osv_name(),
        f.package.name,
        f.vuln.id
    )
}

fn script_key(name: &str, version: &str) -> String {
    format!("npm:{name}@{version}")
}

fn name_key(p: &Package) -> String {
    format!("{}:{}", p.ecosystem.osv_name(), p.name)
}

fn workflow_key(i: &Issue) -> String {
    format!("{}:{}:{}", i.id, i.path, i.message)
}

impl Baseline {
    /// Снимок текущих находок (включая локальные в `.gitignore` — их тоже «знаем»).
    pub fn from_reports(
        secrets: Option<&ScanReport>,
        deps: Option<&DepsReport>,
        workflows: Option<&[Issue]>,
    ) -> Baseline {
        let mut b = Baseline::default();
        if let Some(s) = secrets {
            b.secrets
                .extend(s.all_findings().map(|f| f.fingerprint.clone()));
        }
        if let Some(d) = deps {
            b.vulns.extend(
                d.findings
                    .iter()
                    .filter(|f| !f.vuln.malicious)
                    .map(vuln_key),
            );
            b.scripts.extend(
                d.install_scripts
                    .iter()
                    .map(|s| script_key(&s.name, &s.version)),
            );
            b.names
                .extend(d.typosquats.iter().map(|(p, _)| name_key(p)));
        }
        if let Some(w) = workflows {
            b.workflows.extend(w.iter().map(workflow_key));
        }
        b
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
            && self.vulns.is_empty()
            && self.scripts.is_empty()
            && self.names.is_empty()
            && self.workflows.is_empty()
    }

    pub fn to_json(&self) -> String {
        let list = |set: &BTreeSet<String>| Json::Arr(set.iter().cloned().map(Json::Str).collect());
        let doc = Json::Obj(
            [
                ("jetscan_baseline", Json::Num(FORMAT)),
                ("secrets", list(&self.secrets)),
                ("vulnerabilities", list(&self.vulns)),
                ("install_scripts", list(&self.scripts)),
                ("suspicious_names", list(&self.names)),
                ("workflows", list(&self.workflows)),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        );
        json::stringify_pretty(&doc) + "\n"
    }

    pub fn parse(text: &str) -> Result<Baseline, String> {
        let doc = json::parse(text.trim_start_matches('\u{feff}'))
            .map_err(|e| format!("not a jetscan baseline (bad JSON: {e})"))?;
        if doc.get("jetscan_baseline").and_then(Json::as_f64) != Some(FORMAT) {
            return Err(
                "not a jetscan baseline (create one with --write-baseline <file>)".to_string(),
            );
        }
        let list = |key: &str| -> Result<BTreeSet<String>, String> {
            let Some(v) = doc.get(key) else {
                return Ok(BTreeSet::new());
            };
            let arr = v
                .as_array()
                .ok_or_else(|| format!("baseline: '{key}' must be a list"))?;
            arr.iter()
                .map(|x| {
                    x.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| format!("baseline: '{key}' must contain strings"))
                })
                .collect()
        };
        Ok(Baseline {
            secrets: list("secrets")?,
            vulns: list("vulnerabilities")?,
            scripts: list("install_scripts")?,
            names: list("suspicious_names")?,
            workflows: list("workflows")?,
        })
    }

    pub fn load(path: &Path) -> Result<Baseline, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read baseline {}: {e}", path.display()))?;
        Baseline::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn write(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.to_json())
            .map_err(|e| format!("cannot write baseline {}: {e}", path.display()))
    }

    /// Убирает из отчёта уже известные секреты.
    pub fn apply_secrets(&self, r: &mut ScanReport) -> Hidden {
        let before = r.total();
        r.findings
            .retain(|f| !self.secrets.contains(&f.fingerprint));
        r.history_findings
            .retain(|f| !self.secrets.contains(&f.fingerprint));
        Hidden {
            secrets: before - r.total(),
            ..Hidden::default()
        }
    }

    /// Убирает уже известные проблемы workflow.
    pub fn apply_workflows(&self, w: &mut Vec<Issue>) -> Hidden {
        let before = w.len();
        w.retain(|i| !self.workflows.contains(&workflow_key(i)));
        Hidden {
            other: before - w.len(),
            ..Hidden::default()
        }
    }

    /// Убирает уже известные уязвимости, скрипты и имена. Вредоносные — остаются.
    pub fn apply_deps(&self, r: &mut DepsReport) -> Hidden {
        let (f, s, n) = (
            r.findings.len(),
            r.install_scripts.len(),
            r.typosquats.len(),
        );
        r.findings
            .retain(|f| f.vuln.malicious || !self.vulns.contains(&vuln_key(f)));
        r.install_scripts
            .retain(|s| !self.scripts.contains(&script_key(&s.name, &s.version)));
        r.typosquats
            .retain(|(p, _)| !self.names.contains(&name_key(p)));
        Hidden {
            secrets: 0,
            vulns: f - r.findings.len(),
            other: (s - r.install_scripts.len()) + (n - r.typosquats.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::scan::LockfileReport;
    use crate::deps::scripts::InstallScript;
    use crate::deps::typosquat::Suspect;
    use crate::deps::{Ecosystem, Severity, Vuln};
    use crate::secrets::scan::HistoryOutcome;
    use crate::secrets::walk::WalkStats;
    use crate::secrets::{Confidence, Finding, Location, RuleInfo, Tracking};
    use std::path::PathBuf;

    fn secret(fp: &str) -> Finding {
        Finding {
            rule: RuleInfo {
                id: "t",
                name: "t",
                confidence: Confidence::High,
            },
            location: Location::File {
                path: PathBuf::from("a.env"),
            },
            line: 1,
            col: 1,
            masked: "x***".into(),
            fingerprint: fp.into(),
            tracking: Tracking::Tracked,
            verified: None,
        }
    }

    fn secrets(fps: &[&str]) -> ScanReport {
        ScanReport {
            root: PathBuf::from("repo"),
            findings: fps.iter().map(|f| secret(f)).collect(),
            history_findings: vec![],
            walk: WalkStats::default(),
            history: HistoryOutcome::Disabled,
            ignored: 0,
        }
    }

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            lockfiles: vec!["package-lock.json".into()],
        }
    }

    fn finding(p: Package, id: &str, malicious: bool) -> VulnFinding {
        VulnFinding {
            package: p,
            vuln: Vuln {
                id: id.into(),
                aliases: vec![],
                summary: String::new(),
                severity: Severity::High,
                cvss: None,
                fixed: vec![],
                malicious,
            },
            fix: None,
        }
    }

    fn deps(findings: Vec<VulnFinding>) -> DepsReport {
        DepsReport {
            root: PathBuf::from("repo"),
            lockfiles: vec![LockfileReport {
                rel: "package-lock.json".into(),
                label: "package-lock.json",
                ecosystem: Ecosystem::Npm,
                packages: 1,
                error: None,
            }],
            packages: vec![],
            findings,
            unchecked: vec![],
            from_cache: 0,
            fresh: 0,
            stale_cache_age: None,
            osv_unavailable: false,
            offline: false,
            warnings: vec![],
            install_scripts: vec![InstallScript {
                lockfile: "package-lock.json".into(),
                name: "esbuild".into(),
                version: "0.20.0".into(),
                dev: true,
                commands: vec![],
                flags: vec![],
            }],
            typosquats: vec![(
                pkg("lodahs", "1.0.0"),
                Suspect {
                    looks_like: "lodash".into(),
                    reason: "two letters swapped",
                },
            )],
        }
    }

    #[test]
    fn only_new_findings_survive_and_round_trip_is_exact() {
        let old_s = secrets(&["aaaa", "bbbb"]);
        let old_d = deps(vec![finding(pkg("lodash", "4.17.20"), "GHSA-1", false)]);
        let b = Baseline::from_reports(Some(&old_s), Some(&old_d), None);
        let text = b.to_json();
        assert_eq!(Baseline::parse(&text).unwrap(), b);
        assert_eq!(text, Baseline::parse(&text).unwrap().to_json());

        let mut s = secrets(&["aaaa", "cccc"]);
        assert_eq!(b.apply_secrets(&mut s).secrets, 1);
        assert_eq!(s.findings.len(), 1);
        assert_eq!(s.findings[0].fingerprint, "cccc");

        // Обновили lodash, но GHSA-1 не закрыт — не новое; GHSA-2 — новое.
        let mut d = deps(vec![
            finding(pkg("lodash", "4.17.21"), "GHSA-1", false),
            finding(pkg("lodash", "4.17.21"), "GHSA-2", false),
        ]);
        d.install_scripts[0].version = "0.21.0".into();
        let h = b.apply_deps(&mut d);
        assert_eq!((h.vulns, h.other), (1, 1));
        assert_eq!(d.findings.len(), 1);
        assert_eq!(d.findings[0].vuln.id, "GHSA-2");
        assert_eq!(d.install_scripts.len(), 1, "new version of a script is new");
        assert!(d.typosquats.is_empty());
    }

    #[test]
    fn malicious_packages_are_never_hidden() {
        let old = deps(vec![finding(pkg("flatmap-stream", "0.1.1"), "MAL-1", true)]);
        let b = Baseline::from_reports(None, Some(&old), None);
        assert!(!b.to_json().contains("MAL-1"));
        // Даже если ключ вписали в файл руками.
        let forged = Baseline::parse(
            r#"{"jetscan_baseline":1,"vulnerabilities":["npm:flatmap-stream:MAL-1"]}"#,
        )
        .unwrap();
        let mut d = old.clone();
        assert_eq!(forged.apply_deps(&mut d).vulns, 0);
        assert_eq!(d.findings.len(), 1);
    }

    #[test]
    fn rejects_files_that_are_not_baselines() {
        for bad in [
            "",
            "[]",
            r#"{"version":1}"#,
            r#"{"jetscan_baseline":2}"#,
            r#"{"jetscan_baseline":1,"secrets":"aaaa"}"#,
            r#"{"jetscan_baseline":1,"secrets":[1]}"#,
        ] {
            assert!(Baseline::parse(bad).is_err(), "{bad}");
        }
        let b = Baseline::parse("\u{feff}{\"jetscan_baseline\":1}").unwrap();
        assert!(b.is_empty());
    }

    #[test]
    fn workflow_issues_survive_line_shifts_and_new_ones_stay_visible() {
        let issue = |line, message: &str| Issue {
            id: "gha-unpinned-action",
            level: crate::hygiene::Level::Medium,
            path: ".github/workflows/ci.yml".into(),
            line,
            message: message.into(),
            fix: "pin it".into(),
        };
        let old = [issue(
            10,
            "third-party action a/b@v1 is pinned to a mutable tag or branch",
        )];
        let b = Baseline::parse(&Baseline::from_reports(None, None, Some(&old)).to_json()).unwrap();
        let mut now = vec![
            issue(
                14,
                "third-party action a/b@v1 is pinned to a mutable tag or branch",
            ),
            issue(
                20,
                "third-party action c/d@v2 is pinned to a mutable tag or branch",
            ),
        ];
        assert_eq!(b.apply_workflows(&mut now).other, 1);
        assert_eq!(now.len(), 1);
        assert!(now[0].message.contains("c/d@v2"));
    }
}
