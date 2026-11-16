//! Вывод APK Static Audit: JSON (схема 2, форма как у web source) и текст. Всё недоверенное —
//! через `ui::sanitize_line`; сырых секретов в результате нет по построению.

use super::scan::ApkScanResult;
use super::types::{ApkFinding, CheckStatus, Severity};
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

fn finding_json(f: &ApkFinding) -> Json {
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
                ("path", opt(f.location.archive_entry.as_deref())),
                ("archive_entry", opt(f.location.archive_entry.as_deref())),
                ("component", opt(f.location.component.as_deref())),
                (
                    "line",
                    f.location.line.map_or(Json::Null, |l| num(i64::from(l))),
                ),
                ("column", Json::Null),
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
        ("tags", Json::Arr(f.tags.iter().map(|t| s(t)).collect())),
    ])
}

pub fn to_json(result: &ApkScanResult, target: &str) -> Json {
    let apk = &result.apk;
    obj(vec![
        ("schema_version", num(i64::from(result.schema_version))),
        (
            "scan",
            obj(vec![
                ("mode", s("apk_static")),
                ("target", s(target)),
                ("completed", Json::Bool(result.completed())),
                (
                    "network_activity",
                    Json::Arr(result.network_activities.iter().map(|n| s(n)).collect()),
                ),
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
                    "apk",
                    obj(vec![
                        ("package", opt(apk.package.as_deref())),
                        (
                            "min_sdk",
                            apk.min_sdk.map_or(Json::Null, |v| num(i64::from(v))),
                        ),
                        (
                            "target_sdk",
                            apk.target_sdk.map_or(Json::Null, |v| num(i64::from(v))),
                        ),
                        ("entries", num(apk.entries as i64)),
                        (
                            "network_security_configs",
                            Json::Arr(apk.network_configs.iter().map(|c| s(c)).collect()),
                        ),
                    ]),
                ),
            ]),
        ),
        (
            "findings",
            Json::Arr(result.findings.iter().map(finding_json).collect()),
        ),
        (
            "limitations",
            Json::Arr(result.limitations.iter().map(|l| s(l)).collect()),
        ),
    ])
}

pub fn render_json(result: &ApkScanResult, target: &str) -> String {
    json::stringify_pretty(&to_json(result, target))
}

pub fn render_text(result: &ApkScanResult, target: &str) -> String {
    let apk = &result.apk;
    let mut out = format!(
        "jetscan apk {}\n\nPackage: {}  minSdk: {}  targetSdk: {}  entries: {}\n\n",
        ui::sanitize_line(target),
        apk.package
            .as_deref()
            .map_or("?".to_string(), ui::sanitize_line),
        apk.min_sdk.map_or("-".to_string(), |v| v.to_string()),
        apk.target_sdk.map_or("-".to_string(), |v| v.to_string()),
        apk.entries
    );
    if result.findings.is_empty() {
        out.push_str(
            "No findings from the checks that ran (this is not proof the app is secure).\n\n",
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
            let mut place = f.location.archive_entry.clone().unwrap_or_default();
            if let Some(line) = f.location.line {
                place.push_str(&format!(":{line}"));
            }
            out.push_str(&format!(
                "{} [{}] {}  {}\n    {}\n",
                f.severity.label().to_ascii_uppercase(),
                f.confidence.label(),
                f.rule_id,
                ui::sanitize_line(&place),
                ui::sanitize_line(&f.title)
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
