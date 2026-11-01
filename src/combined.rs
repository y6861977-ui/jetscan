//! Сводный скан (T2.4): секреты + уязвимости зависимостей + GitHub Actions (T7.1)
//! за один запуск. `jetscan scan <проект>` и `jetscan machine --deps`.
//!
//! Движки работают как по отдельности; здесь — только сборка и общая сводка.
//! Секреты и workflow — всегда локально; зависимости — имена и версии пакетов
//! в OSV.dev (или только кэш при `--offline`).

use crate::deps::osv::{Http, OsvOptions};
use crate::deps::scan::DepsReport;
use crate::deps::{self, Severity, VulnFinding};
use crate::hygiene::{self, Issue};
use crate::json::{self, Json};
use crate::secrets::machine::MachineReport;
use crate::secrets::report as sreport;
use crate::secrets::scan::{self as sscan, ScanOptions, ScanReport};
use crate::ui;
use std::path::Path;

pub struct ProjectReport {
    pub secrets: ScanReport,
    /// `None` — скан одного файла: зависимости ищутся только в каталоге.
    pub deps: Option<DepsReport>,
    /// `None` — проверять нечего: нет `.github/workflows/` и `action.yml`
    /// (иначе «✓» выглядел бы как «проверено и чисто»).
    pub workflows: Option<Vec<Issue>>,
}

pub fn scan_project(
    root: &Path,
    secrets: &ScanOptions,
    osv: &OsvOptions,
    http: &dyn Http,
    sleep: &(dyn Fn(u64) + Sync),
) -> Result<ProjectReport, String> {
    let secrets = sscan::scan(root, secrets)?;
    let deps = if root.is_dir() {
        Some(deps::scan::scan(root, osv, http, sleep)?)
    } else {
        None
    };
    let has_workflows = root.join(".github").join("workflows").is_dir()
        || ["action.yml", "action.yaml"]
            .iter()
            .any(|n| root.join(n).is_file());
    let workflows = has_workflows.then(|| crate::workflows::check(root));
    Ok(ProjectReport {
        secrets,
        deps,
        workflows,
    })
}

/// Валит ли уязвимость сборку при пороге `--fail-on`. Вредоносный пакет — всегда;
/// неизвестная опасность — тоже (она может оказаться critical; принять её можно baseline'ом).
pub fn fails(f: &VulnFinding, fail_on: Severity) -> bool {
    f.vuln.malicious || f.vuln.severity == Severity::Unknown || f.vuln.severity >= fail_on
}

/// Код возврата для `--exit-code`: 1 — есть что чинить (`actionable`: секрет может
/// утечь, опасный workflow, гигиена High; или известная уязвимость не ниже `fail_on`);
/// 2 — находок нет, но часть пакетов проверить не удалось. `fail_on = Severity::Low` —
/// любая уязвимость.
pub fn exit_code(actionable: usize, deps: &[&DepsReport], fail_on: Severity) -> i32 {
    let vulns = deps
        .iter()
        .flat_map(|d| &d.findings)
        .filter(|f| fails(f, fail_on))
        .count();
    let unchecked: usize = deps.iter().map(|d| d.unchecked.len()).sum();
    if actionable > 0 || vulns > 0 {
        1
    } else if unchecked > 0 {
        2
    } else {
        0
    }
}

/// Итоговые строки «Секреты / Уязвимости» для обоих режимов (+ workflow у проекта).
fn summary_block(
    secrets_actionable: usize,
    secrets_note: &str,
    deps: &[&DepsReport],
    workflows: Option<&Option<Vec<Issue>>>,
) -> String {
    let mut out = format!("\n{}\n", ui::bold("Summary"));
    let s_line = if secrets_actionable > 0 {
        ui::red(&format!(
            "✗ {} can leak{secrets_note}",
            ui::plural(secrets_actionable, "secret", "secrets")
        ))
    } else {
        ui::green("✓ no leaked secrets")
    };
    out.push_str(&format!("  {}  {s_line}\n", ui::pad_right("Secrets", 16)));

    let packages: usize = deps.iter().map(|d| d.packages.len()).sum();
    let vulns: usize = deps.iter().map(|d| d.findings.len()).sum();
    let vuln_pkgs: usize = deps.iter().map(|d| d.vulnerable_packages()).sum();
    let unchecked: usize = deps.iter().map(|d| d.unchecked.len()).sum();
    let lockfiles: usize = deps.iter().map(|d| d.lockfiles.len()).sum();
    let critical: usize = deps
        .iter()
        .flat_map(|d| &d.findings)
        .filter(|f| f.vuln.severity == Severity::Critical)
        .count();
    let d_line = if lockfiles == 0 {
        ui::dim("— no lockfiles found, nothing to check")
    } else if vulns > 0 {
        let crit = if critical > 0 {
            format!(", {critical} critical")
        } else {
            String::new()
        };
        ui::red(&format!(
            "✗ {} in {} of {} packages{crit}",
            ui::plural(vulns, "known vulnerability", "known vulnerabilities"),
            vuln_pkgs,
            packages
        ))
    } else if unchecked > 0 && unchecked == packages {
        ui::yellow(&format!(
            "! {packages} packages NOT checked (OSV unreachable)"
        ))
    } else {
        ui::green(&format!("✓ none known in {packages} packages"))
    };
    out.push_str(&format!(
        "  {}  {d_line}\n",
        ui::pad_right("Dependencies", 16)
    ));
    let malicious: usize = deps.iter().map(|d| d.malicious_packages().len()).sum();
    if malicious > 0 {
        out.push_str(&format!(
            "  {}  {}\n",
            ui::pad_right("Malware", 16),
            ui::bold(&ui::red(&format!(
                "✗ {} — remove now",
                ui::plural(malicious, "malicious package", "malicious packages")
            )))
        ));
    }
    if unchecked > 0 && unchecked < packages {
        out.push_str(&format!(
            "  {}  {}\n",
            ui::pad_right("", 16),
            ui::yellow(&format!("! {unchecked} packages NOT checked — incomplete"))
        ));
    }
    if let Some(workflows) = workflows {
        let w_line = match workflows {
            None => ui::dim("— no GitHub Actions workflows found"),
            Some(issues) => {
                let high = issues_failing(issues);
                let rest = issues.len() - high;
                if high > 0 {
                    ui::red(&format!(
                        "✗ {} an attacker can exploit",
                        ui::plural(high, "pattern", "patterns")
                    ))
                } else if rest > 0 {
                    ui::yellow(&format!(
                        "! {} to harden",
                        ui::plural(rest, "weak spot", "weak spots")
                    ))
                } else {
                    ui::green("✓ no known risky patterns")
                }
            }
        };
        out.push_str(&format!(
            "  {}  {w_line}\n",
            ui::pad_right("GitHub Actions", 16)
        ));
    }
    out
}

pub fn render_text(p: &ProjectReport) -> String {
    let mut out = sreport::render_text(&p.secrets);
    let Some(d) = &p.deps else {
        return out;
    };
    out.push_str(&deps::report::render_text(d));
    if let Some(w) = &p.workflows {
        out.push_str(&issues_text(
            "GitHub Actions",
            "(workflow files: known attack patterns, checked locally)",
            w,
        ));
    }
    let committed = p
        .secrets
        .findings
        .iter()
        .filter(|f| f.tracking == crate::secrets::Tracking::Tracked)
        .count();
    let note = if committed > 0 {
        format!(" ({committed} already committed)")
    } else {
        String::new()
    };
    out.push_str(&summary_block(
        p.secrets.actionable(),
        &note,
        &[d],
        Some(&p.workflows),
    ));
    out
}

fn deps_summary(ds: &[&DepsReport]) -> Json {
    let n =
        |f: &dyn Fn(&DepsReport) -> usize| Json::Num(ds.iter().map(|d| f(d)).sum::<usize>() as f64);
    Json::Obj(
        [
            ("packages", n(&|d| d.packages.len())),
            ("vulnerabilities", n(&|d| d.findings.len())),
            ("vulnerable_packages", n(&|d| d.vulnerable_packages())),
            ("unchecked_packages", n(&|d| d.unchecked.len())),
            (
                "critical",
                n(&|d| {
                    d.findings
                        .iter()
                        .filter(|f| f.vuln.severity == Severity::Critical)
                        .count()
                }),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    )
}

pub fn render_json(p: &ProjectReport) -> String {
    let deps_list: Vec<&DepsReport> = p.deps.iter().collect();
    let mut summary = match deps_summary(&deps_list) {
        Json::Obj(m) => m,
        _ => unreachable!(),
    };
    summary.insert(
        "secrets_actionable".to_string(),
        Json::Num(p.secrets.actionable() as f64),
    );
    if let Some(w) = &p.workflows {
        summary.insert("workflow_issues".to_string(), Json::Num(w.len() as f64));
        summary.insert(
            "workflow_issues_high".to_string(),
            Json::Num(issues_failing(w) as f64),
        );
    }
    let doc = Json::Obj(
        [
            ("version", Json::Num(1.0)),
            ("mode", Json::Str("scan".into())),
            ("root", Json::Str(p.secrets.root.display().to_string())),
            ("secrets", sreport::to_json(&p.secrets)),
            (
                "deps",
                p.deps
                    .as_ref()
                    .map(deps::report::to_json)
                    .unwrap_or(Json::Null),
            ),
            (
                "workflows",
                p.workflows
                    .as_deref()
                    .map(issues_json)
                    .unwrap_or(Json::Null),
            ),
            ("summary", Json::Obj(summary)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    );
    json::stringify_pretty(&doc)
}

// --- машина ---

/// Уязвимости в каждом репозитории машины (в том же порядке, что `m.repos`).
/// Репозиторий без lockfile'ов даёт пустой отчёт; ошибка чтения — пропуск.
pub fn machine_deps(
    m: &MachineReport,
    osv: &OsvOptions,
    http: &dyn Http,
    sleep: &(dyn Fn(u64) + Sync),
) -> Vec<DepsReport> {
    m.repos
        .iter()
        .filter_map(|r| deps::scan::scan(&r.root, osv, http, sleep).ok())
        .collect()
}

/// Путь для команды, которую копируют в терминал: с пробелами — в кавычках.
pub fn shell_arg(p: &str) -> String {
    if p.contains(' ') {
        format!("\"{p}\"")
    } else {
        p.to_string()
    }
}

fn tilde(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.to_string_lossy().replace('\\', "/")),
        Err(_) => p.display().to_string(),
    }
}

/// Гигиена машины (T5.2): ключи без пароля, токены открытым текстом. В `Issue` нет
/// значений секретов (контракт `hygiene`); текст всё равно санитайзим — пути из ФС.
fn hygiene_text(issues: &[Issue]) -> String {
    issues_text(
        "Machine hygiene",
        "(how keys and tokens are stored — values are never shown)",
        issues,
    )
}

/// Список `Issue` (гигиена, workflow): в них только наши строки, но пути — из ФС,
/// поэтому санитайзим всё.
fn issues_text(title: &str, note: &str, issues: &[Issue]) -> String {
    if issues.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "
{} {}
",
        ui::bold(title),
        ui::dim(note)
    );
    for i in issues {
        let mark = match i.level {
            hygiene::Level::High => ui::red("✗"),
            hygiene::Level::Medium => ui::yellow("!"),
        };
        let place = if i.line > 0 {
            format!("{}:{}", i.path, i.line)
        } else {
            i.path.clone()
        };
        out.push_str(&format!(
            "  {mark} {} — {}
      {}
",
            ui::bold(&ui::sanitize_line(&place)),
            ui::sanitize_line(&i.message),
            ui::cyan(&ui::sanitize_line(&i.fix))
        ));
    }
    out
}

fn issues_json(issues: &[Issue]) -> Json {
    Json::Arr(
        issues
            .iter()
            .map(|i| {
                Json::Obj(
                    [
                        ("id", Json::Str(i.id.into())),
                        ("level", Json::Str(i.level.label().into())),
                        ("path", Json::Str(i.path.clone())),
                        ("line", Json::Num(i.line as f64)),
                        ("message", Json::Str(i.message.clone())),
                        ("fix", Json::Str(i.fix.clone())),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                )
            })
            .collect(),
    )
}

/// Сколько проблем валят `--exit-code`: только High (гигиена — доступ открытым
/// текстом; workflow — то, что эксплуатируется). Medium — «укрепить», CI не роняет.
pub fn issues_failing(issues: &[Issue]) -> usize {
    issues
        .iter()
        .filter(|i| i.level == hygiene::Level::High)
        .count()
}

pub fn render_machine_text(
    m: &MachineReport,
    deps: Option<&[DepsReport]>,
    hygiene: &[Issue],
) -> String {
    let mut out = sreport::render_machine_text(m);
    out.push_str(&hygiene_text(hygiene));
    let Some(ds) = deps else {
        return out;
    };
    let dirty: Vec<&DepsReport> = ds.iter().filter(|d| !d.findings.is_empty()).collect();
    if !dirty.is_empty() {
        out.push_str(&format!(
            "\n{} {}\n",
            ui::bold("Vulnerable dependencies"),
            ui::dim("(known CVEs in lockfiles)")
        ));
        for d in &dirty {
            let name = ui::sanitize_line(&tilde(&m.home, &d.root));
            let crit = d
                .findings
                .iter()
                .filter(|f| f.vuln.severity == Severity::Critical)
                .count();
            let crit = if crit > 0 {
                ui::red(&format!(", {crit} critical"))
            } else {
                String::new()
            };
            out.push_str(&format!(
                "  {} {} — {} in {}{crit}\n",
                ui::red("✗"),
                ui::bold(&name),
                ui::plural(d.findings.len(), "vulnerability", "vulnerabilities"),
                ui::plural(d.vulnerable_packages(), "package", "packages"),
            ));
            out.push_str(&format!(
                "      {}\n",
                ui::dim(&format!("details: jetscan deps {}", shell_arg(&name)))
            ));
        }
    }
    let refs: Vec<&DepsReport> = ds.iter().collect();
    out.push_str(&summary_block(m.actionable(), "", &refs, None));
    if ds.iter().any(|d| d.fresh > 0) {
        out.push_str(&format!("{}\n", ui::dim(deps::report::PRIVACY_NOTE)));
    }
    out
}

pub fn render_machine_json(
    m: &MachineReport,
    deps: Option<&[DepsReport]>,
    hygiene: &[Issue],
) -> String {
    let mut doc = match sreport::machine_to_json(m) {
        Json::Obj(map) => map,
        _ => unreachable!(),
    };
    doc.insert("hygiene".to_string(), issues_json(hygiene));
    if let Some(ds) = deps {
        let list = ds
            .iter()
            .map(|d| {
                let mut j = match deps::report::to_json(d) {
                    Json::Obj(map) => map,
                    _ => unreachable!(),
                };
                j.insert("root".to_string(), Json::Str(tilde(&m.home, &d.root)));
                Json::Obj(j)
            })
            .collect();
        doc.insert("deps".to_string(), Json::Arr(list));
        let refs: Vec<&DepsReport> = ds.iter().collect();
        doc.insert("deps_summary".to_string(), deps_summary(&refs));
    }
    json::stringify_pretty(&Json::Obj(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::scan::NoNetwork;
    use std::fs;

    #[test]
    fn project_scan_combines_secrets_and_deps() {
        let d = std::env::temp_dir().join(format!("jetscan-combined-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        fs::write(d.join("config.js"), format!("const t = \"{gh}\";\n")).unwrap();
        fs::write(
            d.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/ms":{"version":"2.1.3"}}}"#,
        )
        .unwrap();
        let osv = OsvOptions {
            cache_dir: None,
            no_cache: false,
            offline: true,
        };
        let opts = ScanOptions {
            history: false,
            ..ScanOptions::default()
        };
        let p = scan_project(&d, &opts, &osv, &NoNetwork, &|_| {}).unwrap();
        assert_eq!(p.secrets.actionable(), 1);
        let deps = p.deps.as_ref().unwrap();
        assert_eq!(deps.unchecked.len(), 1);
        // Секрет важнее «не проверено»: 1, а не 2.
        assert_eq!(exit_code(p.secrets.actionable(), &[deps], Severity::Low), 1);
        assert_eq!(exit_code(0, &[deps], Severity::Low), 2);

        let text = render_text(&p);
        assert!(text.contains("jetscan secrets") && text.contains("jetscan deps"));
        assert!(text.contains("Summary"));
        assert!(!text.contains(&gh), "raw secret must never be printed");

        let j = json::parse(&render_json(&p)).unwrap();
        assert_eq!(
            j.get("summary")
                .and_then(|s| s.get("secrets_actionable"))
                .and_then(Json::as_f64),
            Some(1.0)
        );
        assert_eq!(
            j.get("summary")
                .and_then(|s| s.get("unchecked_packages"))
                .and_then(Json::as_f64),
            Some(1.0)
        );
        assert!(!render_json(&p).contains(&gh));
        // Нет `.github/workflows` — не «✓ чисто», а «не нашли что проверять».
        assert!(p.workflows.is_none());
        assert!(text.contains("no GitHub Actions workflows found"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn project_scan_reports_workflows_and_only_high_fails() {
        let d = std::env::temp_dir().join(format!("jetscan-combined-gha-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join(".github/workflows")).unwrap();
        fs::write(
            d.join(".github/workflows/ci.yml"),
            "on: pull_request\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: vendor/tool@v1\n      - run: echo ${{ github.head_ref }}\n",
        )
        .unwrap();
        let osv = OsvOptions {
            cache_dir: None,
            no_cache: false,
            offline: true,
        };
        let opts = ScanOptions {
            history: false,
            ..ScanOptions::default()
        };
        let p = scan_project(&d, &opts, &osv, &NoNetwork, &|_| {}).unwrap();
        let w = p.workflows.as_deref().unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(issues_failing(w), 1);
        let text = render_text(&p);
        assert!(text.contains("GitHub Actions"));
        assert!(text.contains(".github/workflows/ci.yml:7"));
        assert!(text.contains("1 pattern an attacker can exploit"));
        let j = json::parse(&render_json(&p)).unwrap();
        let summary = j.get("summary").unwrap();
        assert_eq!(
            summary.get("workflow_issues_high").and_then(Json::as_f64),
            Some(1.0)
        );
        assert_eq!(
            j.get("workflows")
                .and_then(Json::as_array)
                .map(<[Json]>::len),
            Some(2)
        );
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod ci_tests {
    use super::*;
    use crate::deps::{Ecosystem, Package, Vuln};

    fn vf(severity: Severity, malicious: bool) -> VulnFinding {
        VulnFinding {
            package: Package {
                ecosystem: Ecosystem::Npm,
                name: "p".into(),
                version: "1.0.0".into(),
                lockfiles: vec![],
            },
            vuln: Vuln {
                id: "GHSA-x".into(),
                aliases: vec![],
                summary: String::new(),
                severity,
                cvss: None,
                fixed: vec![],
                malicious,
            },
            fix: None,
        }
    }

    #[test]
    fn fail_on_threshold() {
        use Severity::*;
        assert!(fails(&vf(Critical, false), High));
        assert!(fails(&vf(High, false), High));
        assert!(!fails(&vf(Medium, false), High));
        assert!(!fails(&vf(Low, false), Critical));
        // Неизвестная опасность и вредоносные — всегда.
        assert!(fails(&vf(Unknown, false), Critical));
        assert!(fails(&vf(Low, true), Critical));
        // Порог по умолчанию — любая уязвимость.
        for s in [Unknown, Low, Medium, High, Critical] {
            assert!(fails(&vf(s, false), Low));
        }
    }

    #[test]
    fn hygiene_section_is_sanitized_and_only_high_fails() {
        let issues = vec![
            Issue {
                id: "ssh-key-no-passphrase",
                level: hygiene::Level::High,
                path: "~/.ssh/id_\u{1b}[31mevil".into(),
                line: 0,
                message: "private key has no passphrase".into(),
                fix: "ssh-keygen -p -f ~/.ssh/id".into(),
            },
            Issue {
                id: "ssh-key-permissions",
                level: hygiene::Level::Medium,
                path: "~/.ssh/id".into(),
                line: 0,
                message: "readable by others".into(),
                fix: "chmod 600 ~/.ssh/id".into(),
            },
        ];
        let text = hygiene_text(&issues);
        assert!(text.contains("Machine hygiene"));
        assert!(!text.contains("\u{1b}[31mevil"));
        assert_eq!(issues_failing(&issues), 1);
        assert!(hygiene_text(&[]).is_empty());
        let j = json::stringify(&issues_json(&issues));
        assert!(j.contains("\"id\":\"ssh-key-no-passphrase\""));
        assert!(j.contains("\"level\":\"medium\""));
    }
}
