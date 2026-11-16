//! Вывод Android Source Audit: JSON (схема 2, форма как у web source / apk) и текст для терминала.
//! Всё недоверенное (пути, имена, фрагменты) проходит `ui::sanitize_line`; сырых секретов в
//! результате нет по построению.

use super::scan::AndroidScanResult;
use super::types::{AndroidFinding, CheckStatus, Severity};
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

fn opt_num(n: Option<i32>) -> Json {
    n.map_or(Json::Null, |v| num(i64::from(v)))
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

fn finding_json(f: &AndroidFinding) -> Json {
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

pub fn to_json(result: &AndroidScanResult, target: &str) -> Json {
    let walk = &result.stats.walk;
    obj(vec![
        ("schema_version", num(i64::from(result.schema_version))),
        (
            "scan",
            obj(vec![
                ("mode", s("android_source")),
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
                    "modules",
                    Json::Arr(
                        result
                            .modules
                            .iter()
                            .map(|m| {
                                obj(vec![
                                    ("path", s(&m.dir)),
                                    ("kind", s(m.kind.label())),
                                    ("package", opt(m.package.as_deref())),
                                    ("application_id", opt(m.application_id.as_deref())),
                                    ("min_sdk", opt_num(m.min_sdk)),
                                    ("target_sdk", opt_num(m.target_sdk)),
                                    ("compile_sdk", opt_num(m.compile_sdk)),
                                    ("manifests", strings(&m.manifests)),
                                    ("manifests_not_merged", strings(&m.manifests_not_merged)),
                                    (
                                        "network_security_config",
                                        opt(m.network_security_config.as_deref()),
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
                        ("gradle_files", num(result.stats.gradle_files as i64)),
                        (
                            "code_files_checked",
                            num(result.stats.code_files_checked as i64),
                        ),
                        (
                            "test_files_skipped",
                            num(result.stats.test_files_skipped as i64),
                        ),
                        (
                            "files_scanned_for_secrets",
                            num(result.stats.files_scanned_for_secrets as i64),
                        ),
                        ("skipped_large", num(walk.skipped_large as i64)),
                        ("skipped_binary", num(walk.skipped_binary as i64)),
                        ("skipped_unreadable", num(walk.skipped_unreadable as i64)),
                        ("symlinks_skipped", num(walk.symlinks_skipped as i64)),
                        ("budget_exhausted", Json::Bool(walk.budget_exhausted)),
                        ("ignored_inline", num(result.stats.ignored_inline as i64)),
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

pub fn render_json(result: &AndroidScanResult, target: &str) -> String {
    json::stringify_pretty(&to_json(result, target))
}

/// Текст для терминала, без цвета.
pub fn render_text(result: &AndroidScanResult, target: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "jetscan android {}\n\n",
        ui::sanitize_line(target)
    ));
    if result.modules.is_empty() {
        out.push_str("Android modules: none found\n");
    } else {
        out.push_str("Android modules:\n");
        for m in &result.modules {
            let sdk = |label: &str, v: Option<i32>| match v {
                Some(v) => format!("{label} {v}"),
                None => format!("{label} unknown"),
            };
            out.push_str(&format!(
                "  {} ({}{}), {}, {}\n",
                ui::sanitize_line(&m.dir),
                m.kind.label(),
                m.package
                    .as_deref()
                    .map(|p| format!(", {}", ui::sanitize_line(p)))
                    .unwrap_or_default(),
                sdk("minSdk", m.min_sdk),
                sdk("targetSdk", m.target_sdk)
            ));
        }
    }
    out.push_str(&format!(
        "Scanned {} file(s), {} Kotlin/Java file(s) checked for code patterns\n\n",
        result.stats.walk.files_read, result.stats.code_files_checked
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
