//! HTML-панель T4.5: один самодостаточный файл, который можно открыть в браузере или
//! переслать руководителю.
//!
//! Контракт безопасности — не ослаблять:
//! - Один файл без внешних ресурсов; отчёт открывают офлайн. Встроенный CSS, без JS.
//! - Всё из отчёта — недоверенный текст: HTML-экранирование & < > " ' для каждой строки,
//!   в том числе в атрибутах.
//! - Только маски секретов; сырых секретов в ProjectReport нет.
//! - Детерминированно, порядок как в отчётах; дата — только если передана.
//! - Честно: если проверка неполная (OSV недоступен, история не прочитана, lockfile не
//!   разобран), страница говорит об этом, а не рисует «всё чисто».

use crate::combined::ProjectReport;
use crate::deps::scan::DepsReport;
use crate::deps::{Severity, VulnFinding, fix};
use crate::hygiene::{Issue, Level};
use crate::secrets::scan::HistoryOutcome;
use crate::secrets::{Finding, Liveness, Location, Tracking};
use std::fmt::Write as _;
use std::path::Path;

const STYLE: &str = r#"
:root{color-scheme:light dark;--bg:#f5f7fa;--panel:#fff;--text:#17212f;--muted:#5d6b7b;--line:#dce3eb;--accent:#3157a4;--bad:#a52222;--warn:#865c00;--good:#12633f;--soft:#eef2f7}
@media(prefers-color-scheme:dark){:root{--bg:#10151d;--panel:#19212c;--text:#e8edf4;--muted:#a5b1c0;--line:#303c4b;--accent:#a9c4ff;--bad:#ff9292;--warn:#ffd479;--good:#7fe0ad;--soft:#232e3b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:1180px;margin:0 auto;padding:32px 16px 48px}header{border-bottom:1px solid var(--line);padding:8px 0 24px;margin-bottom:24px}h1{font-size:clamp(1.7rem,4vw,2.4rem);line-height:1.15;margin:0 0 8px}h2{font-size:1.3rem;margin:34px 0 14px}h3{font-size:1rem;margin:0 0 8px}.meta,.muted{color:var(--muted)}.meta{display:flex;gap:12px;flex-wrap:wrap}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(170px,100%),1fr));gap:12px;margin:20px 0 30px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}.card strong{display:block;font-size:1.8rem;line-height:1.2;margin:6px 0}.card .label{color:var(--muted);font-size:.9rem}.sub{color:var(--muted);font-size:.84rem}.danger{color:var(--bad)}.warning{color:var(--warn)}.success{color:var(--good)}.soft{color:var(--muted)}.stack{display:grid;gap:12px}.package{border-left:4px solid var(--line)}.package.malware{border-left-color:var(--bad)}.package.vuln{border-left-color:var(--warn)}.package h3{overflow-wrap:anywhere}.badge{display:inline-block;background:var(--soft);border-radius:999px;padding:2px 8px;font-size:.78rem;margin:2px 4px 2px 0}.badge.critical,.badge.high{color:var(--bad)}.badge.medium{color:var(--warn)}.badge.low{color:var(--muted)}.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}table{border-collapse:collapse;width:100%;min-width:780px}th,td{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}th{font-size:.82rem;color:var(--muted);background:var(--soft)}tr:last-child td{border-bottom:0}td code,code{font:.88em ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}a{color:var(--accent);overflow-wrap:anywhere}.ids{display:flex;gap:6px;flex-wrap:wrap}.summary{color:var(--muted);margin-top:8px;white-space:pre-wrap;overflow-wrap:anywhere}.empty{padding:18px;border:1px dashed var(--line);border-radius:10px;color:var(--muted)}.verdict{padding:14px 18px;border-radius:10px;border:1px solid var(--line);background:var(--panel);font-weight:600}.gaps{border-left:4px solid var(--warn)}.gaps li{overflow-wrap:anywhere}details{margin-top:16px;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px}summary{cursor:pointer;font-weight:600}footer{border-top:1px solid var(--line);margin-top:40px;padding-top:18px;color:var(--muted);font-size:.88rem}footer p{margin:6px 0}.location{overflow-wrap:anywhere}.severity{white-space:nowrap}
"#;

/// Escapes untrusted strings in element text and quoted attribute values.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Last path component only; `.` (the default root) is resolved to the folder name.
fn project_name(root: &Path) -> String {
    // Last segment split on both separators: on Unix `C:\Users\me\app` is a single
    // file name, and the page must never show where the project lives.
    let name = |p: &Path| {
        p.file_name()
            .and_then(|n| {
                n.to_string_lossy()
                    .rsplit(['/', '\\'])
                    .next()
                    .map(str::to_owned)
            })
            .filter(|n| !n.is_empty())
    };
    name(root)
        .filter(|n| n != "." && n != "..")
        .or_else(|| root.canonicalize().ok().as_deref().and_then(name))
        .unwrap_or_else(|| "project".into())
}

fn count_severity(report: &ProjectReport, severity: Severity) -> usize {
    report.deps.as_ref().map_or(0, |deps| {
        deps.findings
            .iter()
            .filter(|f| !f.vuln.malicious && f.vuln.severity == severity)
            .count()
    })
}

fn count_history(report: &ProjectReport) -> usize {
    report
        .secrets
        .history_findings
        .iter()
        .filter(|f| f.is_actionable())
        .count()
}

fn count_verified_live(report: &ProjectReport) -> usize {
    report
        .secrets
        .all_findings()
        .filter(|f| f.is_actionable() && f.verified == Some(Liveness::Live))
        .count()
}

/// Everything that makes the result incomplete, in plain text (escaped by the caller).
fn coverage_gaps(p: &ProjectReport) -> Vec<String> {
    let mut gaps = Vec::new();
    if let HistoryOutcome::Failed(e) = &p.secrets.history {
        gaps.push(crate::secrets::report::history_warning(e));
    }
    let Some(d) = &p.deps else {
        gaps.push("Dependencies were not checked (the scan target is not a folder).".into());
        return gaps;
    };
    if d.lockfiles.is_empty() {
        gaps.push("No lockfiles found — dependencies were not checked.".into());
    }
    for l in &d.lockfiles {
        if let Some(e) = &l.error {
            gaps.push(format!("{}: not parsed — {e}", l.rel));
        }
    }
    if let Some(a) = d.stale_cache_age {
        gaps.push(format!(
            "{} — using cached data up to {} old; newer vulnerabilities may be missing.",
            if d.offline {
                "Offline"
            } else {
                "OSV is unreachable"
            },
            crate::deps::report::age(a)
        ));
    }
    if !d.unchecked.is_empty() {
        gaps.push(format!(
            "{} package(s) NOT checked ({}) — results are incomplete.",
            d.unchecked.len(),
            if d.offline {
                "offline, not in cache"
            } else {
                "OSV is unreachable, not in cache"
            }
        ));
    }
    gaps.extend(d.warnings.iter().cloned());
    gaps
}

fn section_title(out: &mut String, title: &str) {
    let _ = write!(out, "<h2>{}</h2>", escape(title));
}

fn stat_card(out: &mut String, label: &str, value: usize, sub: &str, class: &str) {
    let _ = write!(
        out,
        "<article class=\"card\"><span class=\"label\">{}</span><strong class=\"{}\">{}</strong><span class=\"sub\">{}</span></article>",
        escape(label),
        class,
        value,
        escape(sub)
    );
}

fn finding_location(finding: &Finding) -> String {
    match &finding.location {
        Location::File { path } => format!("{}:{}", path.display(), finding.line),
        Location::Git { commit, path } => format!("{commit}:{path}:{}", finding.line),
    }
}

fn finding_status(finding: &Finding, history: bool) -> &'static str {
    if history || matches!(finding.location, Location::Git { .. }) {
        "only in history"
    } else {
        match finding.tracking {
            Tracking::Tracked => "committed",
            Tracking::Untracked => "not ignored",
            Tracking::Ignored => "local (.gitignore)",
            Tracking::Unknown => "unknown",
        }
    }
}

fn verified_label(finding: &Finding) -> String {
    match &finding.verified {
        None => "not checked".into(),
        Some(Liveness::Live) => "LIVE — rotate now".into(),
        Some(Liveness::Revoked) => "revoked".into(),
        Some(Liveness::Unknown(reason)) => format!("unknown: {reason}"),
    }
}

fn render_secret_rows(out: &mut String, findings: &[(&Finding, bool)]) {
    out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Status</th><th>File / commit</th><th>Rule</th><th>Confidence</th><th>Masked</th><th>Fingerprint</th><th>Verified</th></tr></thead><tbody>");
    for (finding, history) in findings {
        let status = finding_status(finding, *history);
        let status_class = match status {
            "committed" | "not ignored" | "only in history" => "danger",
            "local (.gitignore)" => "soft",
            _ => "warning",
        };
        let verified = verified_label(finding);
        let verified_class = match finding.verified {
            Some(Liveness::Live) => "danger",
            Some(Liveness::Revoked) => "success",
            Some(Liveness::Unknown(_)) => "warning",
            None => "soft",
        };
        let _ = write!(
            out,
            "<tr><td class=\"{}\">{}</td><td class=\"location\">{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td class=\"{}\">{}</td></tr>",
            status_class,
            escape(status),
            escape(&finding_location(finding)),
            escape(finding.rule.name),
            escape(finding.rule.confidence.label()),
            escape(&finding.masked),
            escape(&finding.fingerprint),
            verified_class,
            escape(&verified)
        );
    }
    out.push_str("</tbody></table></div>");
}

fn render_secrets(out: &mut String, p: &ProjectReport) {
    section_title(out, "Secrets");
    let mut actionable_rows = Vec::new();
    let mut ignored_rows = Vec::new();
    for (finding, history) in p
        .secrets
        .findings
        .iter()
        .map(|f| (f, false))
        .chain(p.secrets.history_findings.iter().map(|f| (f, true)))
    {
        if finding.is_actionable() {
            actionable_rows.push((finding, history));
        } else {
            ignored_rows.push((finding, history));
        }
    }
    if actionable_rows.is_empty() {
        let note = if matches!(p.secrets.history, HistoryOutcome::Failed(_)) {
            "No leaked secrets in files (git history was NOT checked)."
        } else {
            "No leaked secrets found."
        };
        let _ = write!(out, "<p class=\"empty\">{note}</p>");
    } else {
        render_secret_rows(out, &actionable_rows);
    }
    if !ignored_rows.is_empty() {
        let _ = write!(
            out,
            "<details><summary>Local secrets in .gitignored files ({}) — not committed</summary>",
            ignored_rows.len()
        );
        render_secret_rows(out, &ignored_rows);
        out.push_str("</details>");
    }
}

/// OSV ids are plain ASCII (GHSA-…, CVE-…, MAL-…). Anything else is shown as text, not linked.
fn vuln_link(out: &mut String, id: &str) {
    let plain = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':'));
    if plain {
        let _ = write!(
            out,
            "<a href=\"https://osv.dev/vulnerability/{0}\" rel=\"noreferrer\">{0}</a>",
            escape(id)
        );
    } else {
        let _ = write!(out, "<code>{}</code>", escape(id));
    }
}

fn severity_badges(out: &mut String, findings: &[&VulnFinding]) {
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ] {
        let count = findings
            .iter()
            .filter(|f| f.vuln.severity == severity)
            .count();
        if count > 0 {
            let _ = write!(
                out,
                "<span class=\"badge {0}\">{1} {0}</span>",
                severity.label(),
                count
            );
        }
    }
}

fn render_malicious(out: &mut String, deps: &DepsReport) {
    let packages = deps.malicious_packages();
    if packages.is_empty() {
        return;
    }
    section_title(out, "Malicious packages — remove now");
    out.push_str("<div class=\"stack\">");
    for package in packages {
        let related: Vec<_> = deps
            .findings
            .iter()
            .filter(|f| f.package == *package && f.vuln.malicious)
            .collect();
        let _ = write!(
            out,
            "<article class=\"panel package malware\"><h3 class=\"danger\">{} {} <span class=\"badge\">{}</span></h3><div class=\"ids\">",
            escape(&package.name),
            escape(&package.version),
            escape(package.ecosystem.osv_name())
        );
        for finding in &related {
            vuln_link(out, &finding.vuln.id);
        }
        out.push_str("</div>");
        for finding in related {
            let _ = write!(
                out,
                "<p class=\"summary\">{}</p>",
                escape(&finding.vuln.summary)
            );
        }
        out.push_str("<p class=\"danger\">An upgrade does not undo this: remove the package and check every machine where it was installed (rotate credentials it could read).</p></article>");
    }
    out.push_str("</div>");
}

fn render_gaps(out: &mut String, gaps: &[String]) {
    if gaps.is_empty() {
        return;
    }
    section_title(out, "Coverage gaps — the result is incomplete");
    out.push_str("<div class=\"panel gaps\"><ul>");
    for g in gaps {
        let _ = write!(out, "<li class=\"warning\">{}</li>", escape(g));
    }
    out.push_str("</ul></div>");
}

fn render_vulnerabilities(out: &mut String, deps: &DepsReport) {
    section_title(out, "Known vulnerabilities by package");
    let malicious = deps.malicious_packages();
    let groups: Vec<_> = deps
        .upgrades()
        .into_iter()
        .filter(|upgrade| !malicious.contains(&upgrade.package))
        .filter_map(|upgrade| {
            let findings: Vec<_> = deps
                .findings
                .iter()
                .filter(|f| f.package == *upgrade.package && !f.vuln.malicious)
                .collect();
            (!findings.is_empty()).then_some((upgrade, findings))
        })
        .collect();
    if groups.is_empty() {
        let checked = deps.packages.len() - deps.unchecked.len();
        let note = if deps.lockfiles.is_empty() {
            "No lockfiles found — nothing was checked."
        } else if deps.packages.is_empty() {
            "No third-party packages in the lockfiles."
        } else if checked == 0 {
            "No packages could be checked — see coverage gaps."
        } else if !deps.unchecked.is_empty() {
            "No known vulnerabilities in the packages that were checked."
        } else {
            "No known vulnerabilities."
        };
        let _ = write!(out, "<p class=\"empty\">{note}</p>");
        return;
    }
    out.push_str("<div class=\"stack\">");
    for (upgrade, findings) in groups {
        let package = upgrade.package;
        let _ = write!(
            out,
            "<article class=\"panel package vuln\"><h3>{} {} <span class=\"badge\">{}</span></h3>",
            escape(&package.name),
            escape(&package.version),
            escape(package.ecosystem.osv_name())
        );
        out.push_str("<div>");
        severity_badges(out, &findings);
        if let Some(to) = &upgrade.to {
            let _ = write!(
                out,
                "<span class=\"badge\">upgrade to {}</span>",
                escape(to)
            );
        } else {
            out.push_str("<span class=\"badge medium\">no fixed version yet</span>");
        }
        out.push_str("</div><ul>");
        for finding in findings {
            out.push_str("<li class=\"severity\">");
            vuln_link(out, &finding.vuln.id);
            if !finding.vuln.aliases.is_empty() {
                out.push_str(" <span class=\"muted\">(");
                for (index, alias) in finding.vuln.aliases.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    vuln_link(out, alias);
                }
                out.push_str(")</span>");
            }
            let _ = write!(
                out,
                " <span class=\"badge {0}\">{0}</span><p class=\"summary\">{1}</p></li>",
                finding.vuln.severity.label(),
                escape(&finding.vuln.summary)
            );
        }
        out.push_str("</ul></article>");
    }
    out.push_str("</div>");
}

fn render_fix_plan(out: &mut String, deps: &DepsReport) {
    let plan = fix::plan(deps);
    if plan.is_empty() {
        return;
    }
    section_title(out, "Fix plan");
    out.push_str("<p class=\"muted\">jetscan does not run or edit anything — review these steps and apply them yourself.</p><div class=\"table-wrap\"><table><thead><tr><th>Lockfile</th><th>Package</th><th>Change</th><th>Do this</th></tr></thead><tbody>");
    for s in &plan {
        let change = if s.to.is_empty() {
            escape(&s.from)
        } else {
            format!("{} → {}", escape(&s.from), escape(&s.to))
        };
        let mut todo = String::new();
        if let Some(cmd) = &s.command {
            let _ = write!(todo, "<code>{}</code>", escape(cmd));
        }
        if let Some(edit) = &s.edit {
            let _ = write!(todo, "edit <code>{}</code>", escape(edit));
        }
        if let Some(note) = s.note {
            if !todo.is_empty() {
                todo.push_str("<br>");
            }
            let _ = write!(todo, "<span class=\"warning\">{}</span>", escape(note));
        }
        let _ = write!(
            out,
            "<tr><td class=\"location\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&s.lockfile),
            escape(&s.package),
            change,
            todo
        );
    }
    out.push_str("</tbody></table></div>");
}

fn render_scripts_and_typosquats(out: &mut String, deps: &DepsReport) {
    if deps.install_scripts.is_empty() && deps.typosquats.is_empty() {
        return;
    }
    section_title(out, "Install scripts and suspicious names");
    if !deps.install_scripts.is_empty() {
        out.push_str("<div class=\"panel\"><h3>Packages that run code on install</h3><div class=\"table-wrap\"><table><thead><tr><th>Package</th><th>Version</th><th>Lockfile</th><th>Scope</th><th>Commands</th><th>Flags</th></tr></thead><tbody>");
        for script in &deps.install_scripts {
            let commands = script
                .commands
                .iter()
                .map(|(hook, command)| {
                    format!("{}: <code>{}</code>", escape(hook), escape(command))
                })
                .collect::<Vec<_>>()
                .join("<br>");
            let flags = script
                .flags
                .iter()
                .map(|flag| escape(flag))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(
                out,
                "<tr><td>{}</td><td>{}</td><td class=\"location\">{}</td><td>{}</td><td>{}</td><td class=\"warning\">{}</td></tr>",
                escape(&script.name),
                escape(&script.version),
                escape(&script.lockfile),
                if script.dev { "dev only" } else { "production" },
                if commands.is_empty() {
                    "unknown until installed"
                } else {
                    &commands
                },
                flags
            );
        }
        out.push_str("</tbody></table></div><p class=\"muted\">These commands run with your user's permissions during install.</p></div>");
    }
    if !deps.typosquats.is_empty() {
        out.push_str("<div class=\"panel\"><h3>Suspicious names (a heuristic, not a verdict — check by hand)</h3><div class=\"table-wrap\"><table><thead><tr><th>Package</th><th>Version</th><th>Looks like</th><th>Why</th></tr></thead><tbody>");
        for (package, suspect) in &deps.typosquats {
            let _ = write!(
                out,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&package.name),
                escape(&package.version),
                escape(&suspect.looks_like),
                escape(suspect.reason)
            );
        }
        out.push_str("</tbody></table></div></div>");
    }
}

fn render_workflows(out: &mut String, issues: &[Issue]) {
    if issues.is_empty() {
        return;
    }
    section_title(out, "GitHub Actions workflows");
    out.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Risk</th><th>Location</th><th>Problem</th><th>Fix</th></tr></thead><tbody>");
    for i in issues {
        let (class, label) = match i.level {
            Level::High => ("danger", "exploitable"),
            Level::Medium => ("warning", "harden"),
        };
        let _ = write!(
            out,
            "<tr><td class=\"severity {class}\">{label}</td><td class=\"location\">{}:{}</td><td>{}</td><td><code>{}</code></td></tr>",
            escape(&i.path),
            i.line,
            escape(&i.message),
            escape(&i.fix)
        );
    }
    out.push_str("</tbody></table></div>");
}

fn render_footer(out: &mut String, p: &ProjectReport) {
    out.push_str("<footer><h2>What left this machine</h2>");
    match &p.deps {
        Some(deps) if deps.offline => out.push_str(
            "<p>OSV: offline mode — only the local cache was used, no network requests.</p>",
        ),
        Some(deps) if deps.fresh > 0 || deps.osv_unavailable => out.push_str(
            "<p>OSV: only package names and versions were sent to api.osv.dev. Source code, file paths and the project name were not.</p>",
        ),
        Some(deps) if deps.from_cache > 0 => out.push_str(
            "<p>OSV: all results came from the local cache — nothing was sent.</p>",
        ),
        _ => out.push_str("<p>OSV: no requests were made.</p>"),
    }
    if p.secrets.all_findings().any(|f| f.verified.is_some()) {
        out.push_str("<p>--verify: each found key was sent only to its own provider over HTTPS, to ask whether it still works. This report keeps only masks and fingerprints.</p>");
    } else {
        out.push_str("<p>Secrets: no secret was sent anywhere. This report keeps only masks and fingerprints.</p>");
    }
    out.push_str("<p>This file loads nothing from the network; vulnerability ids link to osv.dev only when clicked.</p></footer>");
}

/// Renders a complete deterministic, offline HTML document.
pub fn render(p: &ProjectReport) -> Result<String, String> {
    let name = escape(&project_name(&p.secrets.root));
    let actionable = p.secrets.actionable();
    let committed = p
        .secrets
        .all_findings()
        .filter(|f| f.is_actionable() && f.tracking == Tracking::Tracked)
        .count();
    let not_ignored = p
        .secrets
        .all_findings()
        .filter(|f| f.is_actionable() && f.tracking == Tracking::Untracked)
        .count();
    let history = count_history(p);
    let live = count_verified_live(p);
    let critical = count_severity(p, Severity::Critical);
    let high = count_severity(p, Severity::High);
    let medium = count_severity(p, Severity::Medium);
    let low = count_severity(p, Severity::Low);
    let unknown = count_severity(p, Severity::Unknown);
    let vulns = critical + high + medium + low + unknown;
    let malicious = p.deps.as_ref().map_or(0, |d| d.malicious_packages().len());
    let scripts = p.deps.as_ref().map_or(0, |d| d.install_scripts.len());
    let typosquats = p.deps.as_ref().map_or(0, |d| d.typosquats.len());
    let unchecked = p.deps.as_ref().map_or(0, |d| d.unchecked.len());
    let workflows = p.workflows.as_deref().unwrap_or_default();
    let exploitable = crate::combined::issues_failing(workflows);
    let gaps = coverage_gaps(p);

    let mut html = String::with_capacity(16 * 1024);
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><meta name=\"referrer\" content=\"no-referrer\"><title>jetscan report — ");
    html.push_str(&name);
    html.push_str("</title><style>");
    html.push_str(STYLE);
    html.push_str("</style></head><body><main><header><h1>jetscan report</h1><div class=\"meta\"><span>Project: <strong>");
    html.push_str(&name);
    let _ = write!(
        html,
        "</strong></span><span>jetscan {}</span><span>scanned locally</span></div></header><section aria-label=\"Summary\"><h2>Summary</h2><div class=\"cards\">",
        escape(env!("CARGO_PKG_VERSION"))
    );
    stat_card(
        &mut html,
        "Secrets that can leak",
        actionable,
        &format!(
            "committed: {committed} · not ignored: {not_ignored} · only in history: {history} · verified LIVE: {live}"
        ),
        if actionable == 0 { "success" } else { "danger" },
    );
    stat_card(
        &mut html,
        "Known vulnerabilities",
        vulns,
        &format!(
            "critical: {critical} · high: {high} · medium: {medium} · low: {low} · unknown: {unknown}"
        ),
        if critical + high > 0 {
            "danger"
        } else if vulns > 0 {
            "warning"
        } else {
            "success"
        },
    );
    stat_card(
        &mut html,
        "Malicious packages",
        malicious,
        "known malware (OSV / OpenSSF)",
        if malicious > 0 { "danger" } else { "success" },
    );
    stat_card(
        &mut html,
        "Install scripts",
        scripts,
        "packages that run code on install",
        if scripts > 0 { "warning" } else { "" },
    );
    stat_card(
        &mut html,
        "Suspicious names",
        typosquats,
        "possible typosquats, check by hand",
        if typosquats > 0 { "warning" } else { "" },
    );
    if p.workflows.is_some() {
        stat_card(
            &mut html,
            "Risky workflows",
            exploitable,
            &format!(
                "GitHub Actions · to harden: {}",
                workflows.len() - exploitable
            ),
            if exploitable > 0 {
                "danger"
            } else if workflows.is_empty() {
                "success"
            } else {
                "warning"
            },
        );
    }
    stat_card(
        &mut html,
        "Not checked",
        unchecked,
        "packages with no OSV result",
        if unchecked > 0 { "warning" } else { "" },
    );
    html.push_str("</div>");
    let verdict = if actionable + vulns + malicious + exploitable > 0 {
        "<p class=\"verdict danger\">✗ There is something to fix — start from the top of this page.</p>"
    } else if !gaps.is_empty() {
        "<p class=\"verdict warning\">! Nothing found, but the check was incomplete — see coverage gaps.</p>"
    } else {
        "<p class=\"verdict success\">✓ Nothing to fix: no leaked secrets, no known vulnerabilities, no malicious packages.</p>"
    };
    html.push_str(verdict);
    html.push_str("</section>");

    if let Some(deps) = &p.deps {
        render_malicious(&mut html, deps);
    }
    render_gaps(&mut html, &gaps);
    render_secrets(&mut html, p);
    if let Some(deps) = &p.deps {
        render_vulnerabilities(&mut html, deps);
        render_fix_plan(&mut html, deps);
        render_scripts_and_typosquats(&mut html, deps);
    }
    render_workflows(&mut html, workflows);
    render_footer(&mut html, p);
    html.push_str("</main></body></html>");
    Ok(html)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::scan::LockfileReport;
    use crate::deps::scripts::InstallScript;
    use crate::deps::typosquat::Suspect;
    use crate::deps::{Ecosystem, Package, Vuln};
    use crate::secrets::history::HistoryError;
    use crate::secrets::scan::ScanReport;
    use crate::secrets::walk::WalkStats;
    use crate::secrets::{Confidence, RuleInfo};
    use std::path::PathBuf;

    fn rule() -> RuleInfo {
        RuleInfo {
            id: "test-secret",
            name: "test secret rule",
            confidence: Confidence::High,
        }
    }

    fn finding(path: &str, tracking: Tracking, verified: Option<Liveness>) -> Finding {
        Finding {
            rule: rule(),
            location: Location::File {
                path: PathBuf::from(path),
            },
            line: 7,
            col: 3,
            masked: "safe********mask".into(),
            fingerprint: "0123456789abcdef".into(),
            tracking,
            verified,
        }
    }

    fn empty_project(root: &str) -> ProjectReport {
        ProjectReport {
            secrets: ScanReport {
                root: PathBuf::from(root),
                findings: Vec::new(),
                history_findings: Vec::new(),
                walk: WalkStats::default(),
                history: HistoryOutcome::Disabled,
                ignored: 0,
            },
            deps: None,
            workflows: None,
        }
    }

    fn package(name: &str, version: &str) -> Package {
        Package {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            lockfiles: vec!["package-lock.json".into()],
        }
    }

    fn deps(packages: Vec<Package>, findings: Vec<VulnFinding>) -> DepsReport {
        DepsReport {
            // Нет package.json — план исправлений не читает диск проекта.
            root: PathBuf::from("no-such-dir-for-html-tests"),
            lockfiles: vec![LockfileReport {
                rel: "package-lock.json".into(),
                label: "package-lock.json",
                ecosystem: Ecosystem::Npm,
                packages: packages.len(),
                error: None,
            }],
            packages,
            findings,
            unchecked: Vec::new(),
            from_cache: 0,
            fresh: 1,
            stale_cache_age: None,
            osv_unavailable: false,
            offline: false,
            warnings: Vec::new(),
            install_scripts: Vec::new(),
            typosquats: Vec::new(),
        }
    }

    fn vuln(id: &str, summary: &str, severity: Severity, malicious: bool) -> Vuln {
        Vuln {
            id: id.into(),
            aliases: Vec::new(),
            summary: summary.into(),
            severity,
            cvss: None,
            fixed: Vec::new(),
            malicious,
        }
    }

    #[test]
    fn escapes_untrusted_text_and_attributes() {
        let mut project = empty_project("C:/work/<script>alert(1)");
        project.secrets.findings.push(finding(
            r#""><img onerror=alert(1)> & '"#,
            Tracking::Untracked,
            Some(Liveness::Live),
        ));
        project.secrets.findings.push(finding(
            r#"<script>alert(1)</script>"#,
            Tracking::Tracked,
            None,
        ));
        let html = render(&project).unwrap();
        assert!(html.contains("&lt;script&gt;alert(1)"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("&quot;&gt;&lt;img onerror=alert(1)&gt; &amp; &#39;"));
        assert!(!html.to_ascii_lowercase().contains("<script"));
        assert!(!html.contains("<img"));
        assert!(html.contains("Content-Security-Policy"));
    }

    #[test]
    fn only_plain_ids_become_links() {
        let mut html = String::new();
        vuln_link(&mut html, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(
            html,
            "<a href=\"https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc\" rel=\"noreferrer\">GHSA-aaaa-bbbb-cccc</a>"
        );
        for hostile in [r#"GHSA-<x>&"'"#, "../../evil", "a b", "x?y=1", ""] {
            let mut html = String::new();
            vuln_link(&mut html, hostile);
            assert!(!html.contains("href"), "{hostile}: {html}");
        }
        let mut html = String::new();
        vuln_link(&mut html, r#"GHSA-<x>&"'"#);
        assert_eq!(html, "<code>GHSA-&lt;x&gt;&amp;&quot;&#39;</code>");
    }

    #[test]
    fn output_has_no_scripts_or_external_resources_and_has_only_osv_links() {
        let mut project = empty_project("repo");
        let pkg = package("pkg", "1.0.0");
        let mut v = vuln(
            "GHSA-aaaa-bbbb-cccc",
            "<script>alert(1)</script>",
            Severity::High,
            false,
        );
        v.aliases = vec!["CVE-2025-1234".into()];
        v.fixed = vec!["1.0.1".into()];
        project.deps = Some(deps(
            vec![pkg.clone()],
            vec![VulnFinding {
                package: pkg,
                vuln: v,
                fix: Some("1.0.1".into()),
            }],
        ));
        let html = render(&project).unwrap();
        assert!(!html.to_ascii_lowercase().contains("<script"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("http://"));
        assert_eq!(html.matches("https://").count(), 2); // primary id + CVE alias
        assert_eq!(
            html.matches("href=\"https://osv.dev/vulnerability/")
                .count(),
            2
        );
        for banned in [
            "<link", "<img", "<iframe", "<object", "<embed", "src=", "@import", "url(",
        ] {
            assert!(!html.contains(banned), "{banned}");
        }
        assert!(html.contains("default-src 'none'; style-src 'unsafe-inline'; img-src data:"));
        assert!(html.contains("upgrade to 1.0.1"));
        assert!(html.contains("Fix plan"));
    }

    #[test]
    fn deterministic_output_and_empty_report_message() {
        let project = empty_project(r"C:\projects\sample");
        let first = render(&project).unwrap();
        assert_eq!(first, render(&project).unwrap());
        assert!(first.contains("sample"));
        assert!(!first.contains("projects"));
        assert!(first.contains("No leaked secrets found."));
    }

    #[test]
    fn project_name_never_shows_a_full_path() {
        for (root, expected) in [
            (r"C:\Users\private\my-app", "my-app"),
            ("/home/private/my-app/", "my-app"),
        ] {
            assert_eq!(project_name(Path::new(root)), expected);
        }
        // `.` (the CLI default) resolves to the current folder's own name.
        let here = std::env::current_dir().unwrap();
        let expected = here.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(project_name(Path::new(".")), expected);
        assert_eq!(project_name(Path::new("")), "project");
    }

    #[test]
    fn exploitable_workflows_fail_the_verdict_and_weak_spots_do_not() {
        let issue = |level, path: &str| Issue {
            id: "gha-script-injection",
            level,
            path: path.into(),
            line: 12,
            message: "untrusted ${{ github.head_ref }} is expanded into a shell script".into(),
            fix: "use \"$VALUE\"".into(),
        };
        let mut project = empty_project("repo");
        project.deps = Some(deps(vec![package("a", "1.0.0")], Vec::new()));
        project.workflows = Some(vec![issue(Level::Medium, ".github/workflows/ci.yml")]);
        let html = render(&project).unwrap();
        assert!(html.contains("✓ Nothing to fix"));
        assert!(html.contains("GitHub Actions workflows"));
        project.workflows = Some(vec![issue(Level::High, ".github/workflows/<x>.yml")]);
        let html = render(&project).unwrap();
        assert!(!html.contains("✓ Nothing to fix"));
        assert!(html.contains("exploitable"));
        assert!(html.contains("&lt;x&gt;.yml:12"));
        assert!(html.contains("use &quot;$VALUE&quot;") || html.contains("use &#34;$VALUE&#34;"));
        assert!(!html.contains("<x>"));
    }

    #[test]
    fn clean_verdict_only_when_the_check_was_complete() {
        let mut project = empty_project("repo");
        project.deps = Some(deps(vec![package("a", "1.0.0")], Vec::new()));
        let html = render(&project).unwrap();
        assert!(html.contains("✓ Nothing to fix"));
        assert!(!html.contains("Coverage gaps"));

        // Lockfile без сторонних пакетов (как Cargo.lock самого jetscan) — не «не проверено».
        let mut empty = empty_project("repo");
        empty.deps = Some(deps(Vec::new(), Vec::new()));
        let html = render(&empty).unwrap();
        assert!(html.contains("No third-party packages"));
        assert!(!html.contains("could be checked"));

        // OSV недоступен: ни «всё чисто», ни «уязвимостей нет» без оговорки.
        let d = project.deps.as_mut().unwrap();
        d.unchecked = d.packages.clone();
        d.osv_unavailable = true;
        d.fresh = 0;
        project.secrets.history = HistoryOutcome::Failed(HistoryError::Git("<b>boom</b>".into()));
        let html = render(&project).unwrap();
        assert!(!html.contains("✓ Nothing to fix"));
        assert!(html.contains("Nothing found, but the check was incomplete"));
        assert!(html.contains("Coverage gaps"));
        assert!(html.contains("NOT checked"));
        assert!(html.contains("No packages could be checked"));
        assert!(html.contains("git history was NOT checked"));
        assert!(html.contains("&lt;b&gt;boom&lt;/b&gt;"));
        assert!(!html.contains("<b>"));
    }

    #[test]
    fn renders_malware_local_secrets_scripts_typosquats_and_liveness() {
        let mut project = empty_project("repo");
        project.secrets.findings.push(finding(
            "src/config.rs",
            Tracking::Tracked,
            Some(Liveness::Revoked),
        ));
        project
            .secrets
            .findings
            .push(finding("ignored.env", Tracking::Ignored, None));
        let malware = package("bad-package", "2.0.0");
        let mut d = deps(
            vec![malware.clone()],
            vec![VulnFinding {
                package: malware.clone(),
                vuln: vuln(
                    "MAL-2026-1",
                    "known malicious package",
                    Severity::Critical,
                    true,
                ),
                fix: None,
            }],
        );
        d.install_scripts = vec![InstallScript {
            lockfile: "package-lock.json".into(),
            name: "runs-on-install".into(),
            version: "1.0.0".into(),
            dev: true,
            commands: vec![("postinstall".into(), "echo <safe>".into())],
            flags: vec!["network"],
        }];
        d.typosquats = vec![(
            malware,
            Suspect {
                looks_like: "bad-package-real".into(),
                reason: "two letters swapped",
            },
        )];
        project.deps = Some(d);
        let html = render(&project).unwrap();
        let malware_at = html.find("Malicious packages — remove now").unwrap();
        let secrets_at = html.find("<h2>Secrets</h2>").unwrap();
        assert!(malware_at < secrets_at, "malware goes first");
        assert!(html.contains("<details><summary>Local secrets in .gitignored files (1)"));
        assert!(html.contains("committed"));
        assert!(html.contains("revoked"));
        assert!(html.contains("echo &lt;safe&gt;"));
        assert!(html.contains("Suspicious names"));
        assert!(html.contains("MALICIOUS")); // fix plan says remove, not upgrade
        // Вредоносный пакет не дублируется в обычных уязвимостях.
        assert!(html.contains("No known vulnerabilities."));
    }
}
