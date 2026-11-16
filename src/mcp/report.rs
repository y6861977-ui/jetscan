//! Tool output: Core reports -> Findings V2 (redacted), capped, plus a short summary
//! that an AI assistant can relay. Everything shown goes through
//! `ScanResultV2::redacted` first: no raw secret, not even a legacy mask, is ever
//! put into a tool result (an MCP result usually ends up in a cloud model's context).

use jetscan::deps::scan::DepsReport;
use jetscan::finding_v2::{
    CheckStatus, FindingV2, ModelError, RedactedScan, RedactionPolicy, RuleCheck, ScanResultV2,
    Severity, adapters,
};
use jetscan::json;
use jetscan::secrets::history::HistoryError;
use jetscan::secrets::scan::{HistoryOutcome, ScanReport};
use jetscan::ui;

/// Findings kept in the JSON part of a tool result.
pub const MAX_FINDINGS: usize = 50;
/// Findings listed one per line in the summary.
pub const MAX_SUMMARY_FINDINGS: usize = 20;
/// One summary line (limitation, reason) is cut here; the JSON keeps the full text.
const MAX_LINE: usize = 300;

pub struct Report {
    pub summary: String,
    /// Compact strict V2 JSON (the same document as `json`).
    pub json_text: String,
}

/// Extra summary sections a tool adds after the findings (fix advice, next steps).
#[derive(Default)]
pub struct Notes {
    pub sections: Vec<(String, Vec<String>)>,
}

impl Notes {
    pub fn add(&mut self, title: &str, lines: Vec<String>) {
        if !lines.is_empty() {
            self.sections.push((title.to_string(), lines));
        }
    }
}

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn status_label(s: CheckStatus) -> &'static str {
    match s {
        CheckStatus::Completed => "completed",
        CheckStatus::Partial => "partial",
        CheckStatus::Skipped => "skipped",
        CheckStatus::Error => "error",
    }
}

fn cut(text: &str) -> String {
    if text.chars().count() <= MAX_LINE {
        text.to_string()
    } else {
        let mut s: String = text.chars().take(MAX_LINE).collect();
        s.push('…');
        s
    }
}

fn order(findings: &mut [FindingV2]) {
    findings.sort_by(|a, b| {
        (a.severity, a.confidence, &a.location, &a.id).cmp(&(
            b.severity,
            b.confidence,
            &b.location,
            &b.id,
        ))
    });
}

/// Redacts `scan`, caps it at `MAX_FINDINGS` (highest severity first) and renders the
/// summary. `title` names the check, `target` the scanned path, `cli` the equivalent
/// terminal command for the full report.
pub fn render(
    title: &str,
    target: &str,
    cli: &str,
    scan: ScanResultV2,
    notes: &Notes,
) -> Result<Report, String> {
    let policy = RedactionPolicy::default();
    let refused =
        |e: ModelError| format!("the report could not be exported safely ({e}); nothing is shown");
    // Counts come from the full, merged result when it fits; a huge result (over the
    // V2 size limit) is counted before merging repeated findings.
    let (mut capped, counts_note) = match scan.redacted(&policy) {
        Ok(full) => (full.as_scan().clone(), None),
        Err(ModelError("v2_output_limit")) => (
            scan,
            Some("counts are before merging repeated findings (very large result)"),
        ),
        Err(e) => return Err(refused(e)),
    };
    let total = capped.findings.len();
    let mut by_sev = [0usize; 5];
    for f in &capped.findings {
        by_sev[f.severity as usize] += 1;
    }
    order(&mut capped.findings);
    if total > MAX_FINDINGS {
        capped.findings.truncate(MAX_FINDINGS);
        capped.limitations.push(format!(
            "Output capped for the AI context: {MAX_FINDINGS} of {total} findings are included \
             (highest severity first). Run `{cli}` in a terminal for the full report."
        ));
    }
    let safe = capped.redacted(&policy).map_err(refused)?;
    let summary = summary(title, target, &safe, total, &by_sev, counts_note, notes);
    Ok(Report {
        summary,
        json_text: json::stringify(&safe.to_json()),
    })
}

fn summary(
    title: &str,
    target: &str,
    safe: &RedactedScan,
    total: usize,
    by_sev: &[usize; 5],
    counts_note: Option<&str>,
    notes: &Notes,
) -> String {
    let scan = safe.as_scan();
    let mut out = format!("jetscan {title} — {target}\n");
    if total == 0 {
        out.push_str("No findings.");
    } else {
        let parts: Vec<String> = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
        .iter()
        .filter(|s| by_sev[**s as usize] > 0)
        .map(|s| {
            format!(
                "{} {}",
                by_sev[*s as usize],
                sev_label(*s).to_ascii_lowercase()
            )
        })
        .collect();
        out.push_str(&format!(
            "{}: {}.",
            ui::plural(total, "finding", "findings"),
            parts.join(", ")
        ));
        if let Some(n) = counts_note {
            out.push_str(&format!(" ({n})"));
        }
    }
    let complete = scan.completed();
    out.push_str(if complete {
        " Coverage: every check completed (this is coverage, not a security guarantee).\n"
    } else {
        " Coverage: INCOMPLETE — see \"Not checked\"; no findings there does not mean clean.\n"
    });
    if !scan.findings.is_empty() {
        let shown = scan.findings.len().min(MAX_SUMMARY_FINDINGS);
        out.push_str(&format!(
            "\nFindings, highest severity first ({shown} of {total} listed here; {} in the JSON):\n",
            scan.findings.len()
        ));
        // `redacted()` orders by id; the summary lists the most severe first.
        let mut list = scan.findings.clone();
        order(&mut list);
        for (i, f) in list.iter().take(shown).enumerate() {
            out.push_str(&format!("{:>3}. {}\n", i + 1, finding_line(f)));
            if let Some(e) = &f.evidence.redacted_excerpt {
                out.push_str(&format!("     evidence (masked): {}\n", cut(e)));
            }
        }
    }
    let not_checked: Vec<&RuleCheck> = scan
        .checks
        .iter()
        .filter(|c| c.status != CheckStatus::Completed)
        .collect();
    if !not_checked.is_empty() {
        out.push_str("\nNot checked / partial:\n");
        for c in not_checked {
            out.push_str(&format!(
                "  - {}: {} — {}\n",
                c.id,
                status_label(c.status),
                cut(c.reason.as_deref().unwrap_or(""))
            ));
        }
    }
    for (title, lines) in &notes.sections {
        out.push_str(&format!("\n{title}:\n"));
        for l in lines {
            out.push_str(&format!("  - {}\n", cut(&ui::sanitize_line(l))));
        }
    }
    if !scan.limitations.is_empty() {
        out.push_str("\nLimitations:\n");
        for l in &scan.limitations {
            out.push_str(&format!("  - {}\n", cut(l)));
        }
    }
    if scan.network_activities.is_empty() {
        out.push_str("\nNetwork: none — this check ran entirely on this machine.\n");
    } else {
        out.push_str("\nNetwork:\n");
        for n in &scan.network_activities {
            out.push_str(&format!("  - {}\n", cut(n)));
        }
    }
    out.push_str(
        "\nThe strict Findings V2 JSON follows in the next content item (secret values are \
         never included).",
    );
    out
}

fn finding_line(f: &FindingV2) -> String {
    let l = &f.location;
    let mut place = l.relative_path.clone();
    if let Some(line) = l.line {
        place.push_str(&format!(":{line}"));
        if let Some(col) = l.column {
            place.push_str(&format!(":{col}"));
        }
    }
    let mut extra = Vec::new();
    if let Some(c) = &l.component {
        if let Some(commit) = c.strip_prefix("git:") {
            extra.push(format!("git history, commit {commit}"));
        } else if c != &f.explanation {
            extra.push(c.clone());
        }
    }
    for t in &f.tags {
        if t.starts_with("tracking:")
            || t.starts_with("occurrences:")
            || t.starts_with("provider:")
            || t == "malicious-package"
        {
            extra.push(t.clone());
        }
    }
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!(" [{}]", extra.join(", "))
    };
    cut(&format!(
        "{} {} — {} — {}{}",
        sev_label(f.severity),
        f.rule_id,
        place,
        f.title,
        extra
    ))
}

// ---------------------------------------------------------------------------
// Core reports -> V2 (the Findings V2 module has per-finding adapters only).
// ---------------------------------------------------------------------------

fn check(id: &str, status: CheckStatus, reason: Option<String>) -> RuleCheck {
    RuleCheck {
        id: id.into(),
        status,
        reason,
    }
}

/// Secrets `ScanReport` -> V2: every finding through `adapters::secret`; walk skips,
/// history outcome and export failures become checks, never silence.
pub fn secrets_v2(rep: &ScanReport, history_requested: bool) -> ScanResultV2 {
    let mut scan = ScanResultV2::default();
    let mut failed = 0usize;
    for f in rep.all_findings() {
        match adapters::secret(f) {
            Ok(v2) => scan.findings.push(v2),
            Err(_) => failed += 1,
        }
    }
    let w = &rep.walk;
    scan.checks
        .push(if w.skipped_large + w.skipped_unreadable == 0 {
            check("secrets.files", CheckStatus::Completed, None)
        } else {
            check(
                "secrets.files",
                CheckStatus::Partial,
                Some(format!(
                    "{} not read: {} larger than the size limit, {} unreadable",
                    ui::plural(w.skipped_large + w.skipped_unreadable, "file", "files"),
                    w.skipped_large,
                    w.skipped_unreadable
                )),
            )
        });
    scan.checks.push(match &rep.history {
        HistoryOutcome::Scanned(_) => check("secrets.history", CheckStatus::Completed, None),
        HistoryOutcome::Disabled => check(
            "secrets.history",
            CheckStatus::Skipped,
            Some(if history_requested {
                "the path is a file, so git history was not scanned".into()
            } else {
                "not requested (history: false)".into()
            }),
        ),
        HistoryOutcome::Failed(HistoryError::NotARepo) => check(
            "secrets.history",
            CheckStatus::Skipped,
            Some("not a git repository".into()),
        ),
        HistoryOutcome::Failed(HistoryError::GitNotFound) => check(
            "secrets.history",
            CheckStatus::Partial,
            Some("git was not found on PATH, so git history was not scanned".into()),
        ),
        HistoryOutcome::Failed(HistoryError::Git(_)) => check(
            "secrets.history",
            CheckStatus::Error,
            Some("git log failed, so git history was not scanned".into()),
        ),
    });
    if failed > 0 {
        scan.checks.push(check(
            "secrets.export",
            CheckStatus::Partial,
            Some(format!(
                "{} could not be exported (non-portable file name); run `jetscan secrets` in a terminal",
                ui::plural(failed, "finding", "findings")
            )),
        ));
    }
    if rep.ignored > 0 {
        scan.limitations.push(format!(
            "{} suppressed by .jetscanignore or `jetscan:ignore` markers",
            ui::plural(rep.ignored, "finding", "findings")
        ));
    }
    if w.skipped_binary > 0 {
        scan.limitations.push(format!(
            "{} not scanned (binary)",
            ui::plural(w.skipped_binary, "file", "files")
        ));
    }
    scan.limitations.push(
        "Pattern matching: a finding is a possible credential to review (the tracking tag \
         says whether git tracks the file); it does not prove the key works. No findings \
         does not prove there are no secrets."
            .into(),
    );
    scan
}

/// Deps `DepsReport` -> V2. Advisories without a severity cannot be V2 findings (the
/// V2 enum has no "unknown"); they are returned separately for the summary and the
/// result is marked partial.
pub fn deps_v2(rep: &DepsReport) -> (ScanResultV2, Vec<String>) {
    let mut scan = ScanResultV2::default();
    let mut unknown = Vec::new();
    let mut failed = 0usize;
    for f in &rep.findings {
        match adapters::dependency(f) {
            Ok(list) => scan.findings.extend(list),
            Err(ModelError("legacy_unknown_severity_requires_review")) => unknown.push(format!(
                "{} {}@{}: advisory {} has no severity in OSV — review it manually",
                f.package.ecosystem.osv_name(),
                f.package.name,
                f.package.version,
                f.vuln.id
            )),
            Err(_) => failed += 1,
        }
    }
    let broken: Vec<&str> = rep
        .lockfiles
        .iter()
        .filter(|l| l.error.is_some())
        .map(|l| l.rel.as_str())
        .collect();
    scan.checks.push(if rep.lockfiles.is_empty() {
        check(
            "deps.lockfiles",
            CheckStatus::Skipped,
            Some("no supported lockfile found".into()),
        )
    } else if broken.is_empty() {
        check("deps.lockfiles", CheckStatus::Completed, None)
    } else {
        check(
            "deps.lockfiles",
            CheckStatus::Partial,
            Some(format!(
                "{} could not be read: {}",
                ui::plural(broken.len(), "lockfile", "lockfiles"),
                broken.join(", ")
            )),
        )
    });
    let n = rep.unchecked.len();
    scan.checks.push(if rep.packages.is_empty() {
        check(
            "deps.osv",
            CheckStatus::Skipped,
            Some("no packages to check".into()),
        )
    } else if n == 0 {
        check("deps.osv", CheckStatus::Completed, None)
    } else if rep.offline {
        check(
            "deps.osv",
            CheckStatus::Partial,
            Some(format!(
                "{} of {} not in the local OSV cache, so not checked (offline). Call again \
                 with offline: false to ask OSV.dev (sends package names and versions only)",
                ui::plural(n, "package", "packages"),
                rep.packages.len()
            )),
        )
    } else {
        check(
            "deps.osv",
            CheckStatus::Partial,
            Some(format!(
                "OSV.dev could not be reached: {} of {} not checked",
                ui::plural(n, "package", "packages"),
                rep.packages.len()
            )),
        )
    });
    if !unknown.is_empty() {
        scan.checks.push(check(
            "deps.severity",
            CheckStatus::Partial,
            Some(format!(
                "{} without a severity are listed in the summary, not as findings",
                ui::plural(unknown.len(), "advisory", "advisories")
            )),
        ));
    }
    if failed > 0 {
        scan.checks.push(check(
            "deps.export",
            CheckStatus::Partial,
            Some(format!(
                "{} could not be exported; run `jetscan deps` in a terminal",
                ui::plural(failed, "finding", "findings")
            )),
        ));
    }
    if let Some(age) = rep.stale_cache_age {
        scan.limitations.push(format!(
            "some results come from a cached OSV answer about {} old",
            ui::plural((age / 3600) as usize, "hour", "hours")
        ));
    }
    scan.limitations.push(
        "Advisories are matched to locked versions only; whether the vulnerable code is \
         reachable in this application was not checked."
            .into(),
    );
    if !rep.offline {
        if rep.fresh > 0 {
            scan.network_activities.push(format!(
                "api.osv.dev: asked about {} (names and versions only; no code, no file paths)",
                ui::plural(rep.fresh, "package", "packages")
            ));
        } else if rep.osv_unavailable {
            scan.network_activities
                .push("api.osv.dev: tried to ask about packages; no answer".into());
        }
    }
    (scan, unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetscan::finding_v2::{Confidence, Evidence, SourceLocation};
    use jetscan::json::Json;

    fn finding(i: usize, severity: Severity) -> FindingV2 {
        FindingV2 {
            id: String::new(),
            rule_id: "fixture-rule".into(),
            title: "Fixture".into(),
            category: "fixture".into(),
            severity,
            confidence: Confidence::Potential,
            location: SourceLocation {
                relative_path: format!("src/f{i}.js"),
                line: Some(1),
                column: None,
                archive_entry: None,
                component: None,
            },
            evidence: Evidence::default(),
            explanation: "x".into(),
            remediation_id: None,
            references: vec![],
            cwe_ids: vec![],
            tags: vec![],
        }
    }

    #[test]
    fn output_is_capped_highest_severity_first_with_true_counts() {
        let mut scan = ScanResultV2::default();
        scan.checks
            .push(check("fixture", CheckStatus::Completed, None));
        for i in 0..70 {
            scan.findings.push(finding(i, Severity::Low));
        }
        scan.findings.push(finding(99, Severity::Critical));
        let r = render("fixture", ".", "jetscan x", scan, &Notes::default()).unwrap();
        assert!(
            r.summary.contains("71 findings: 1 critical, 70 low."),
            "{}",
            r.summary
        );
        assert!(
            r.summary
                .contains("  1. CRITICAL fixture-rule — src/f99.js:1"),
            "{}",
            r.summary
        );
        assert!(r.summary.contains("(20 of 71 listed here; 50 in the JSON)"));
        let doc = json::parse(&r.json_text).unwrap();
        let findings = doc.get("findings").and_then(Json::as_array).unwrap();
        assert_eq!(findings.len(), MAX_FINDINGS);
        assert!(
            r.json_text
                .contains("Output capped for the AI context: 50 of 71")
        );
        assert!(r.summary.contains("Coverage: every check completed"));
    }

    #[test]
    fn empty_and_incomplete_results_say_so() {
        let mut scan = ScanResultV2::default();
        scan.checks.push(check(
            "secrets.history",
            CheckStatus::Partial,
            Some("git missing".into()),
        ));
        let r = render("fixture", ".", "jetscan x", scan, &Notes::default()).unwrap();
        assert!(r.summary.contains("No findings. Coverage: INCOMPLETE"));
        assert!(r.summary.contains("secrets.history: partial — git missing"));
        assert!(r.summary.contains("Network: none"));
    }
}
