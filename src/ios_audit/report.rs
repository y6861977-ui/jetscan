//! Вывод iOS Source Audit: JSON (схема 2, форма как у web source / apk / android) и текст для
//! терминала. Всё недоверенное (пути, имена, фрагменты) проходит `ui::sanitize_line`; сырых секретов
//! в результате нет по построению.

use super::scan::IosScanResult;
use super::types::{CheckStatus, IosFinding, Severity};
use crate::json::{self, Json};
use crate::ui;
use std::collections::HashMap;

fn s(value: &str) -> Json {
    Json::Str(ui::sanitize_line(value))
}

fn opt(value: Option<&str>) -> Json {
    value.map_or(Json::Null, s)
}

fn num(n: i64) -> Json {
    Json::Num(n as f64)
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<HashMap<_, _>>(),
    )
}

fn strings(list: &[String]) -> Json {
    Json::Arr(list.iter().map(|v| s(v)).collect())
}

fn finding_json(f: &IosFinding) -> Json {
    obj(vec![
        ("id", s(&f.id)),
        ("rule_id", s(f.rule_id)),
        ("title", s(&f.title)),
        ("category", s(f.category)),
        ("severity", s(f.severity.label())),
        ("confidence", s(f.confidence.label())),
        (
            "location",
            obj(vec![
                ("path", s(&f.location.relative_path)),
                (
                    "line",
                    f.location.line.map_or(Json::Null, |l| num(i64::from(l))),
                ),
                (
                    "column",
                    f.location.column.map_or(Json::Null, |c| num(i64::from(c))),
                ),
                ("component", opt(f.location.component.as_deref())),
            ]),
        ),
        (
            "evidence",
            obj(vec![
                (
                    "redacted_excerpt",
                    opt(f.evidence.redacted_excerpt.as_deref()),
                ),
                ("secret_fingerprint", opt(f.evidence.fingerprint.as_deref())),
            ]),
        ),
        ("explanation", s(&f.explanation)),
        ("remediation_id", opt(f.remediation_id.as_deref())),
        (
            "references",
            Json::Arr(f.references.iter().map(|r| s(r)).collect()),
        ),
        (
            "cwe_ids",
            Json::Arr(f.cwe_ids.iter().map(|c| s(c)).collect()),
        ),
        ("tags", strings(&f.tags)),
    ])
}

pub fn to_json(result: &IosScanResult, target: &str) -> Json {
    let walk = &result.stats.walk;
    let st = &result.stats;
    obj(vec![
        ("schema_version", num(i64::from(result.schema_version))),
        (
            "scan",
            obj(vec![
                ("mode", s("ios_source")),
                ("target", s(target)),
                ("completed", Json::Bool(result.completed())),
                ("network_activity", strings(&result.network_activities)),
                (
                    "checks",
                    Json::Arr(
                        result
                            .checks
                            .iter()
                            .map(|c| {
                                obj(vec![
                                    ("id", s(&c.id)),
                                    ("status", s(c.status.label())),
                                    ("reason", opt(c.reason.as_deref())),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "projects",
                    Json::Arr(
                        result
                            .projects
                            .iter()
                            .map(|p| {
                                obj(vec![
                                    ("path", s(&p.path)),
                                    (
                                        "targets",
                                        Json::Arr(
                                            p.targets
                                                .iter()
                                                .map(|t| {
                                                    obj(vec![
                                                        ("name", s(&t.name)),
                                                        ("kind", s(&t.kind)),
                                                        (
                                                            "deployment_target",
                                                            opt(t.deployment_target.as_deref()),
                                                        ),
                                                        ("info_plists", strings(&t.info_plists)),
                                                        ("entitlements", strings(&t.entitlements)),
                                                    ])
                                                })
                                                .collect(),
                                        ),
                                    ),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "statistics",
                    obj(vec![
                        ("files_listed", num(walk.files_listed as i64)),
                        ("files_read", num(walk.files_read as i64)),
                        ("bytes_read", num(walk.bytes_read as i64)),
                        ("xcode_projects", num(st.xcode_projects as i64)),
                        ("swift_files_checked", num(st.swift_files_checked as i64)),
                        ("objc_files_checked", num(st.objc_files_checked as i64)),
                        ("test_files_skipped", num(st.test_files_skipped as i64)),
                        ("info_plists_checked", num(st.info_plists_checked as i64)),
                        ("entitlements_checked", num(st.entitlements_checked as i64)),
                        (
                            "files_scanned_for_secrets",
                            num(st.files_scanned_for_secrets as i64),
                        ),
                        ("skipped_large", num(walk.skipped_large as i64)),
                        ("skipped_binary", num(walk.skipped_binary as i64)),
                        ("skipped_unreadable", num(walk.skipped_unreadable as i64)),
                        ("symlinks_skipped", num(walk.symlinks_skipped as i64)),
                        ("budget_exhausted", Json::Bool(walk.budget_exhausted)),
                        ("ignored_inline", num(st.ignored_inline as i64)),
                    ]),
                ),
            ]),
        ),
        (
            "findings",
            Json::Arr(result.findings.iter().map(finding_json).collect()),
        ),
        ("limitations", strings(&result.limitations)),
    ])
}

pub fn render_json(result: &IosScanResult, target: &str) -> String {
    json::stringify_pretty(&to_json(result, target))
}

/// Текст для терминала, без цвета.
pub fn render_text(result: &IosScanResult, target: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("jetscan ios {}\n\n", ui::sanitize_line(target)));
    if result.projects.is_empty() {
        out.push_str("Xcode projects: none found\n");
    } else {
        out.push_str("Xcode projects:\n");
        for p in &result.projects {
            out.push_str(&format!("  {}\n", ui::sanitize_line(&p.path)));
            for t in &p.targets {
                out.push_str(&format!(
                    "    {} ({}{})\n",
                    ui::sanitize_line(&t.name),
                    ui::sanitize_line(&t.kind),
                    t.deployment_target
                        .as_deref()
                        .map(|d| format!(", deployment target {}", ui::sanitize_line(d)))
                        .unwrap_or_default()
                ));
            }
        }
    }
    out.push_str(&format!(
        "Scanned {} file(s); {} Swift and {} Objective-C file(s) checked for code patterns\n\n",
        result.stats.walk.files_read,
        result.stats.swift_files_checked,
        result.stats.objc_files_checked
    ));
    if result.findings.is_empty() {
        out.push_str(
            "No findings from the checks that ran (this is not proof the app is secure).\n",
        );
    }
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        for f in result.findings.iter().filter(|f| f.severity == severity) {
            let position = match (f.location.line, f.location.column) {
                (Some(l), Some(c)) => format!(":{l}:{c}"),
                (Some(l), None) => format!(":{l}"),
                _ => String::new(),
            };
            let component = f
                .location
                .component
                .as_deref()
                .map(|c| format!("  [{}]", ui::sanitize_line(c)))
                .unwrap_or_default();
            out.push_str(&format!(
                "{} [{}] {}  {}{}{}\n    {}\n",
                f.severity.label().to_ascii_uppercase(),
                f.confidence.label(),
                f.rule_id,
                ui::sanitize_line(&f.location.relative_path),
                position,
                component,
                ui::sanitize_line(&f.title),
            ));
            if let Some(excerpt) = &f.evidence.redacted_excerpt {
                out.push_str(&format!("    > {}\n", ui::sanitize_line(excerpt)));
            }
            out.push_str(&format!("    {}\n\n", ui::sanitize_line(&f.explanation)));
        }
    }
    let not_complete: Vec<_> = result
        .checks
        .iter()
        .filter(|c| c.status != CheckStatus::Completed)
        .collect();
    if !not_complete.is_empty() {
        out.push_str("Checks not fully run:\n");
        for c in not_complete {
            out.push_str(&format!(
                "  {} {}{}\n",
                c.status.label(),
                ui::sanitize_line(&c.id),
                c.reason
                    .as_deref()
                    .map(|r| format!(": {}", ui::sanitize_line(r)))
                    .unwrap_or_default()
            ));
        }
        out.push('\n');
    }
    out.push_str("Limitations:\n");
    for l in &result.limitations {
        out.push_str(&format!("  - {}\n", ui::sanitize_line(l)));
    }
    out
}
