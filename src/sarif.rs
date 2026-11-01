//! SARIF 2.1.0 (T3.1) — формат, который принимают GitHub Code Scanning, GitLab, Azure DevOps.
//! `jetscan scan|secrets|deps --sarif` → находки во вкладке Security у пулл-реквеста
//! (у `scan` — и опасные GitHub Actions workflow).
//!
//! Безопасность: в SARIF только маска и отпечаток секрета — как в остальных отчётах.
//! Локальные секреты (файл в `.gitignore`) не выгружаем: в CI их нет, это не утечка.
//! Пути — относительно корня скана (так GitHub сопоставляет их с файлами репозитория).

use crate::deps::scan::DepsReport;
use crate::deps::{Severity, VulnFinding};
use crate::hygiene::{Issue, Level};
use crate::json::{self, Json};
use crate::secrets::scan::ScanReport;
use crate::secrets::{Confidence, Finding, Location};
use std::collections::BTreeMap;

const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn text(s: &str) -> Json {
    obj(vec![("text", Json::Str(s.to_string()))])
}

/// URI относительного пути по RFC 3986: `/` оставляем, остальное вне unreserved — `%XX`.
pub fn uri(path: &str) -> String {
    let mut out = String::new();
    for b in path.replace('\\', "/").bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn location(path: &str, line: usize, col: usize) -> Json {
    let mut region = vec![("startLine", Json::Num(line.max(1) as f64))];
    if col > 0 {
        region.push(("startColumn", Json::Num(col as f64)));
    }
    obj(vec![(
        "physicalLocation",
        obj(vec![
            ("artifactLocation", obj(vec![("uri", Json::Str(uri(path)))])),
            ("region", obj(region)),
        ]),
    )])
}

/// Правило SARIF. `security-severity` (0–10) — по нему GitHub ставит critical/high/...
struct RuleDef {
    id: String,
    name: String,
    short: String,
    level: &'static str,
    security_severity: f64,
    help_uri: Option<String>,
}

fn rule_json(r: &RuleDef) -> Json {
    let mut v = vec![
        ("id", Json::Str(r.id.clone())),
        ("name", Json::Str(r.name.clone())),
        ("shortDescription", text(&r.short)),
        (
            "defaultConfiguration",
            obj(vec![("level", Json::Str(r.level.to_string()))]),
        ),
        (
            "properties",
            obj(vec![
                (
                    "security-severity",
                    Json::Str(format!("{:.1}", r.security_severity)),
                ),
                ("tags", Json::Arr(vec![Json::Str("security".into())])),
            ]),
        ),
    ];
    if let Some(u) = &r.help_uri {
        v.push(("helpUri", Json::Str(u.clone())));
    }
    obj(v)
}

// --- секреты ---

fn secret_level(c: Confidence) -> (&'static str, f64) {
    // Утёкший ключ — это всегда серьёзно; уверенность правила влияет на уровень.
    match c {
        Confidence::High => ("error", 8.5),
        Confidence::Medium => ("warning", 7.0),
        Confidence::Low => ("note", 4.0),
    }
}

fn secret_result(f: &Finding) -> Json {
    let (level, _) = secret_level(f.rule.confidence);
    let (path, msg) = match &f.location {
        Location::File { path } => (
            path.to_string_lossy().replace('\\', "/"),
            format!(
                "{} found: {} ({}). Rotate it — {}.",
                f.rule.name,
                f.masked,
                f.tracking.label(),
                match f.tracking {
                    crate::secrets::Tracking::Tracked => "it is committed, every clone has it",
                    crate::secrets::Tracking::Untracked =>
                        "the file is not in .gitignore, one `git add .` away from a leak",
                    _ => "then move it out of the code",
                }
            ),
        ),
        Location::Git { commit, path } => (
            path.clone(),
            format!(
                "{} found in git history (commit {}): {}. Deleted from files but still in the \
                 repository — rotate it, then rewrite history.",
                f.rule.name,
                commit.get(..10).unwrap_or(commit),
                f.masked
            ),
        ),
    };
    let msg = match &f.verified {
        Some(crate::secrets::Liveness::Live) => {
            format!("{msg} Verified LIVE right now (--verify).")
        }
        Some(crate::secrets::Liveness::Revoked) => {
            format!("{msg} The provider reports it revoked (--verify).")
        }
        _ => msg,
    };
    obj(vec![
        ("ruleId", Json::Str(f.rule.id.to_string())),
        ("level", Json::Str(level.to_string())),
        ("message", text(&msg)),
        ("locations", Json::Arr(vec![location(&path, f.line, f.col)])),
        (
            "partialFingerprints",
            obj(vec![("jetscan/v1", Json::Str(f.fingerprint.clone()))]),
        ),
    ])
}

fn secrets_part(r: &ScanReport, rules: &mut BTreeMap<String, RuleDef>, results: &mut Vec<Json>) {
    for f in r.all_findings().filter(|f| f.is_actionable()) {
        let (level, sev) = secret_level(f.rule.confidence);
        rules
            .entry(f.rule.id.to_string())
            .or_insert_with(|| RuleDef {
                id: f.rule.id.to_string(),
                name: f.rule.name.to_string(),
                short: format!("Leaked secret: {}", f.rule.name),
                level,
                security_severity: sev,
                help_uri: None,
            });
        results.push(secret_result(f));
    }
}

// --- зависимости ---

fn vuln_level(s: Severity) -> (&'static str, f64) {
    match s {
        Severity::Critical => ("error", 9.5),
        Severity::High => ("error", 8.0),
        Severity::Medium => ("warning", 5.5),
        Severity::Low => ("note", 2.0),
        Severity::Unknown => ("warning", 5.0),
    }
}

fn vuln_result(f: &VulnFinding) -> Json {
    let (level, _) = vuln_level(f.vuln.severity);
    let p = &f.package;
    let cve = f
        .vuln
        .aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();
    let fix = match &f.fix {
        Some(v) => format!(" Upgrade to {v}."),
        None if f.vuln.fixed.is_empty() => " No fixed version yet.".to_string(),
        None => format!(" Fixed in: {}.", f.vuln.fixed.join(", ")),
    };
    let msg = if f.vuln.malicious {
        format!(
            "{} {} ({}) is a MALICIOUS package ({}) — {}. Remove it; upgrading does not help. \
             Treat machines that installed it with scripts as compromised and rotate their keys.",
            p.name,
            p.version,
            p.ecosystem.osv_name(),
            f.vuln.id,
            f.vuln.summary
        )
    } else {
        format!(
            "{} {} ({}) is vulnerable: {}{} — {}.{}",
            p.name,
            p.version,
            p.ecosystem.osv_name(),
            f.vuln.id,
            cve,
            f.vuln.summary,
            fix
        )
    };
    let locations = p.lockfiles.iter().map(|l| location(l, 1, 0)).collect();
    let fp = crate::hash::hex(
        &crate::hash::sha256(
            format!(
                "{}\n{}\n{}\n{}",
                p.ecosystem.osv_name(),
                p.name,
                p.version,
                f.vuln.id
            )
            .as_bytes(),
        )[..8],
    );
    obj(vec![
        ("ruleId", Json::Str(f.vuln.id.clone())),
        ("level", Json::Str(level.to_string())),
        ("message", text(&msg)),
        ("locations", Json::Arr(locations)),
        (
            "partialFingerprints",
            obj(vec![("jetscan/v1", Json::Str(fp))]),
        ),
    ])
}

fn deps_part(r: &DepsReport, rules: &mut BTreeMap<String, RuleDef>, results: &mut Vec<Json>) {
    for f in &r.findings {
        let (level, mapped) = vuln_level(f.vuln.severity);
        rules.entry(f.vuln.id.clone()).or_insert_with(|| RuleDef {
            id: f.vuln.id.clone(),
            name: f.vuln.id.clone(),
            short: if f.vuln.malicious {
                format!("Malicious package: {}", f.vuln.summary)
            } else if f.vuln.summary.is_empty() {
                format!("Known vulnerability {}", f.vuln.id)
            } else {
                f.vuln.summary.clone()
            },
            level: if f.vuln.malicious { "error" } else { level },
            // Вредонос — максимум шкалы: GitHub покажет его как critical.
            security_severity: if f.vuln.malicious {
                10.0
            } else {
                f.vuln.cvss.unwrap_or(mapped)
            },
            help_uri: Some(format!("https://osv.dev/vulnerability/{}", f.vuln.id)),
        });
        results.push(vuln_result(f));
    }
}

// --- GitHub Actions (T7.1) ---

fn workflow_rule(id: &str) -> &'static str {
    match id {
        "gha-script-injection" => "Untrusted input expanded into a workflow script",
        "gha-pwn-request" => "Privileged workflow checks out pull request code",
        "gha-unpinned-action" => "Third-party action not pinned to a commit",
        "gha-insecure-commands" => "Unsafe workflow commands enabled",
        "gha-write-all-permissions" => "Workflow token with write-all permissions",
        _ => "Risky GitHub Actions workflow pattern",
    }
}

fn workflows_part(
    issues: &[Issue],
    rules: &mut BTreeMap<String, RuleDef>,
    results: &mut Vec<Json>,
) {
    for i in issues {
        let (level, sev) = match i.level {
            Level::High => ("error", 8.0),
            Level::Medium => ("warning", 5.0),
        };
        rules.entry(i.id.to_string()).or_insert_with(|| RuleDef {
            id: i.id.to_string(),
            name: i.id.to_string(),
            short: workflow_rule(i.id).to_string(),
            level,
            security_severity: sev,
            help_uri: None,
        });
        // Без номера строки: сдвиг строк не делает находку новой (как в baseline).
        let fp = crate::hash::hex(
            &crate::hash::sha256(format!("{}\n{}\n{}", i.id, i.path, i.message).as_bytes())[..8],
        );
        results.push(obj(vec![
            ("ruleId", Json::Str(i.id.to_string())),
            ("level", Json::Str(level.to_string())),
            ("message", text(&format!("{}. Fix: {}.", i.message, i.fix))),
            ("locations", Json::Arr(vec![location(&i.path, i.line, 0)])),
            (
                "partialFingerprints",
                obj(vec![("jetscan/v1", Json::Str(fp))]),
            ),
        ]));
    }
}

/// SARIF-документ: один run (jetscan), правила — только те, что сработали.
pub fn render(
    secrets: Option<&ScanReport>,
    deps: Option<&DepsReport>,
    workflows: &[Issue],
) -> String {
    let mut rules = BTreeMap::new();
    let mut results = Vec::new();
    if let Some(s) = secrets {
        secrets_part(s, &mut rules, &mut results);
    }
    if let Some(d) = deps {
        deps_part(d, &mut rules, &mut results);
    }
    workflows_part(workflows, &mut rules, &mut results);
    let driver = obj(vec![
        ("name", Json::Str("jetscan".into())),
        ("version", Json::Str(env!("CARGO_PKG_VERSION").into())),
        ("rules", Json::Arr(rules.values().map(rule_json).collect())),
    ]);
    let run = obj(vec![
        ("tool", obj(vec![("driver", driver)])),
        ("results", Json::Arr(results)),
    ]);
    json::stringify_pretty(&obj(vec![
        ("$schema", Json::Str(SCHEMA.into())),
        ("version", Json::Str("2.1.0".into())),
        ("runs", Json::Arr(vec![run])),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::osv::OsvOptions;
    use crate::deps::scan::NoNetwork;
    use crate::secrets::scan::{self, ScanOptions};
    use std::fs;

    #[test]
    fn uri_encodes_spaces_and_unicode_but_keeps_slashes() {
        assert_eq!(uri("src/app.js"), "src/app.js");
        assert_eq!(
            uri("Annusyn proekdy/a b.env"),
            "Annusyn%20proekdy/a%20b.env"
        );
        assert_eq!(uri("dir\\x.txt"), "dir/x.txt");
        assert_eq!(uri("я.txt"), "%D1%8F.txt");
        assert_eq!(uri("a#b?c"), "a%23b%3Fc");
    }

    #[test]
    fn sarif_has_masked_secrets_only_and_valid_shape() {
        let d = std::env::temp_dir().join(format!("jetscan-sarif-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("my dir")).unwrap();
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        fs::write(
            d.join("my dir/config.js"),
            format!("x\nconst t = \"{gh}\";\n"),
        )
        .unwrap();
        let r = scan::scan(
            &d,
            &ScanOptions {
                history: false,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let deps = crate::deps::scan::scan(
            &d,
            &OsvOptions {
                cache_dir: None,
                no_cache: false,
                offline: true,
            },
            &NoNetwork,
            &|_| {},
        )
        .unwrap();
        let out = render(Some(&r), Some(&deps), &[]);
        assert!(!out.contains(&gh), "raw secret must never reach SARIF");

        let doc = json::parse(&out).unwrap();
        assert_eq!(doc.get("version").and_then(Json::as_str), Some("2.1.0"));
        let run = &doc.get("runs").and_then(Json::as_array).unwrap()[0];
        let rules = run
            .get("tool")
            .and_then(|t| t.get("driver"))
            .and_then(|d| d.get("rules"))
            .and_then(Json::as_array)
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].get("id").and_then(Json::as_str),
            Some("github-token")
        );
        let results = run.get("results").and_then(Json::as_array).unwrap();
        assert_eq!(results.len(), 1);
        let loc = &results[0]
            .get("locations")
            .and_then(Json::as_array)
            .unwrap()[0];
        let pl = loc.get("physicalLocation").unwrap();
        assert_eq!(
            pl.get("artifactLocation")
                .and_then(|a| a.get("uri"))
                .and_then(Json::as_str),
            Some("my%20dir/config.js")
        );
        assert_eq!(
            pl.get("region")
                .and_then(|r| r.get("startLine"))
                .and_then(Json::as_f64),
            Some(2.0)
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn workflow_issues_become_results_with_line_independent_fingerprints() {
        let issue = |line| Issue {
            id: "gha-script-injection",
            level: Level::High,
            path: ".github/workflows/ci.yml".into(),
            line,
            message: "untrusted ${{ github.head_ref }} is expanded into a shell script".into(),
            fix: "pass it through env".into(),
        };
        let medium = Issue {
            id: "gha-unpinned-action",
            level: Level::Medium,
            ..issue(3)
        };
        let results = |issues: &[Issue]| {
            let doc = json::parse(&render(None, None, issues)).unwrap();
            let run = doc.get("runs").and_then(Json::as_array).unwrap()[0].clone();
            let rules = run
                .get("tool")
                .and_then(|t| t.get("driver"))
                .and_then(|d| d.get("rules"))
                .and_then(Json::as_array)
                .unwrap()
                .len();
            let results = run
                .get("results")
                .and_then(Json::as_array)
                .unwrap()
                .to_vec();
            (rules, results)
        };
        let (rules, all) = results(&[issue(7), medium]);
        assert_eq!(rules, 2);
        let levels: Vec<_> = all
            .iter()
            .map(|r| r.get("level").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(levels, ["error", "warning"]);
        let fp = |line| {
            json::stringify(
                results(&[issue(line)]).1[0]
                    .get("partialFingerprints")
                    .unwrap(),
            )
        };
        assert_eq!(fp(7), fp(40));
    }
}
