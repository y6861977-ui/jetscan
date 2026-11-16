//! Вывод результата Web Source Audit: JSON (схема 2, поля контракта V2) и текст для терминала.
//! Всё недоверенное (пути, имена переменных, фрагменты) проходит `ui::sanitize_line`.
//! Сырых секретов в `WebScanResult` нет по построению — здесь их и взять неоткуда.

use super::{CheckStatus, Severity, WebFinding, WebScanResult};
use crate::json::{self, Json};
use crate::ui;
use std::collections::HashMap;

fn s(value: &str) -> Json {
    Json::Str(ui::sanitize_line(value))
}

fn opt(value: Option<&str>) -> Json {
    value.map_or(Json::Null, s)
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<HashMap<_, _>>(),
    )
}

fn num(n: usize) -> Json {
    Json::Num(n as f64)
}

fn finding_json(f: &WebFinding) -> Json {
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
                    f.location.line.map_or(Json::Null, |l| num(l as usize)),
                ),
                (
                    "column",
                    f.location.column.map_or(Json::Null, |c| num(c as usize)),
                ),
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

/// JSON-представление. `target` — путь, как его указал пользователь (для отчёта).
pub fn to_json(result: &WebScanResult, target: &str) -> Json {
    let fw = &result.framework;
    let walk = &result.stats.walk;
    obj(vec![
        ("schema_version", num(result.schema_version as usize)),
        (
            "scan",
            obj(vec![
                ("mode", s("web_source")),
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
                    "framework",
                    obj(vec![
                        ("kind", s(fw.kind.label())),
                        ("version", opt(fw.version.as_deref())),
                        ("unsupported", opt(fw.unsupported.as_deref())),
                        ("app_router", Json::Bool(fw.app_router())),
                        ("pages_router", Json::Bool(fw.pages_router())),
                        ("uses_supabase", Json::Bool(fw.uses_supabase)),
                        ("uses_firebase", Json::Bool(fw.uses_firebase)),
                    ]),
                ),
                (
                    "statistics",
                    obj(vec![
                        ("files_scanned", num(walk.files_read)),
                        ("bytes_scanned", num(walk.bytes_read as usize)),
                        ("skipped_large", num(walk.skipped_large)),
                        ("skipped_binary", num(walk.skipped_binary)),
                        ("skipped_unsupported", num(walk.skipped_unsupported)),
                        ("skipped_unreadable", num(walk.skipped_unreadable)),
                        ("symlinks_skipped", num(walk.symlinks_skipped)),
                        ("budget_exhausted", Json::Bool(walk.budget_exhausted)),
                        ("ignored_inline", num(result.stats.ignored_inline)),
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

pub fn render_json(result: &WebScanResult, target: &str) -> String {
    json::stringify_pretty(&to_json(result, target))
}

/// Текст для терминала, без цвета (раскраску оставляем CLI).
pub fn render_text(result: &WebScanResult, target: &str) -> String {
    let mut out = String::new();
    let fw = &result.framework;
    out.push_str(&format!(
        "jetscan web source {}\n\nFramework: {}{}\nScanned {} file(s)\n\n",
        ui::sanitize_line(target),
        fw.kind.label(),
        match (fw.app_router(), fw.pages_router()) {
            (true, true) => " (App Router + Pages Router)",
            (true, false) => " (App Router)",
            (false, true) => " (Pages Router)",
            _ => "",
        },
        result.stats.walk.files_read
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
            out.push_str(&format!(
                "{} [{}] {}  {}{}\n    {}\n",
                f.severity.label().to_ascii_uppercase(),
                f.confidence.label(),
                f.rule_id,
                ui::sanitize_line(&f.location.relative_path),
                position,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::{self, fixture};
    use crate::web_audit::{WebScanOptions, scan_source};

    #[test]
    fn json_has_contract_fields_and_no_raw_secrets() {
        let project = fixture("next-app");
        let result = scan_source(project.path(), &WebScanOptions::default()).unwrap();
        let text = render_json(&result, "./next-app");
        let parsed = json::parse(&text).expect("valid JSON");
        assert_eq!(
            parsed.get("schema_version").and_then(Json::as_f64),
            Some(2.0)
        );
        let scan = parsed.get("scan").unwrap();
        assert_eq!(scan.get("mode").and_then(Json::as_str), Some("web_source"));
        // next-app/middleware.ts проверяет доступ → WEB-AUTH-004 partial → скан не «completed».
        assert_eq!(scan.get("completed").and_then(Json::as_bool), Some(false));
        let findings = parsed.get("findings").and_then(Json::as_array).unwrap();
        assert_eq!(findings.len(), result.findings.len());
        let first = &findings[0];
        for key in [
            "id",
            "rule_id",
            "title",
            "category",
            "severity",
            "confidence",
            "location",
            "evidence",
            "explanation",
            "remediation_id",
            "references",
            "cwe_ids",
            "tags",
        ] {
            assert!(first.get(key).is_some(), "missing {key}");
        }
        for raw in [
            testutil::stripe_secret(),
            testutil::github_token(),
            testutil::supabase_jwt("service_role"),
            testutil::body(24),
        ] {
            assert!(!text.contains(&raw));
        }
        // Детерминированность: тот же вход — тот же байт-в-байт вывод.
        let again = scan_source(project.path(), &WebScanOptions::default()).unwrap();
        assert_eq!(render_json(&again, "./next-app"), text);
    }

    #[test]
    fn text_report_lists_findings_checks_and_limitations() {
        let project = fixture("next-app");
        let result = scan_source(project.path(), &WebScanOptions::default()).unwrap();
        let text = render_text(&result, "next-app");
        assert!(text.contains("Framework: nextjs (App Router)"));
        assert!(
            text.contains("CRITICAL [potential] WEB-SECRET-001  app/components/Checkout.tsx:6:24")
        );
        assert!(text.contains("skipped WEB-DEPS-008: not implemented in this version"));
        assert!(text.contains("skipped WEB-RLS-009: not_checked"));
        assert!(text.contains("Limitations:"));
        assert!(!text.contains(&testutil::stripe_secret()));
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn empty_result_does_not_claim_secure() {
        let t = testutil::TempProject::new();
        t.write("index.js", "console.log(1)");
        let result = scan_source(t.path(), &WebScanOptions::default()).unwrap();
        let text = render_text(&result, ".");
        assert!(text.contains("not proof the app is secure"));
    }
}
