//! Full legacy report projections. Pure adapters: no filesystem, process or
//! network work here. Missing telemetry is explicit Partial, never guessed.
pub use super::core_network::NetworkSummary;
use super::*;
use crate::{
    baseline::Hidden,
    combined::ProjectReport,
    deps::{self, scan::DepsReport},
    secrets::{
        self,
        history::HistoryError,
        scan::{HistoryOutcome, ScanReport},
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Directory,
    #[default]
    Unknown,
}
/// Supply facts captured by orchestration, not inferred from finding absence.
#[derive(Clone, Debug, Default)]
pub struct CoreContext {
    pub target: TargetKind,
    pub verification_requested: Option<bool>,
    pub network: Option<NetworkSummary>,
    /// None means the caller has not reported whether baseline filtering ran.
    pub baseline_hidden: Option<Hidden>,
}
#[derive(Clone, Copy, Debug)]
pub struct ReportCounts {
    secrets: usize,
    vulns: usize,
    other: usize,
}
impl ReportCounts {
    pub fn capture(report: &ProjectReport) -> Self {
        Self {
            secrets: report.secrets.total(),
            vulns: report.deps.as_ref().map_or(0, |d| d.findings.len()),
            other: report.workflows.as_ref().map_or(0, Vec::len)
                + report
                    .deps
                    .as_ref()
                    .map_or(0, |d| d.install_scripts.len() + d.typosquats.len()),
        }
    }
    pub fn hidden_since(self, report: &ProjectReport) -> Result<Hidden, ModelError> {
        let after = Self::capture(report);
        Ok(Hidden {
            secrets: self
                .secrets
                .checked_sub(after.secrets)
                .ok_or(ModelError("invalid_policy_counts"))?,
            vulns: self
                .vulns
                .checked_sub(after.vulns)
                .ok_or(ModelError("invalid_policy_counts"))?,
            other: self
                .other
                .checked_sub(after.other)
                .ok_or(ModelError("invalid_policy_counts"))?,
        })
    }
}
fn check(scan: &mut ScanResultV2, id: &str, status: CheckStatus, reason: String) {
    scan.checks.push(RuleCheck {
        id: id.into(),
        status,
        reason: Some(reason.clone()),
    });
    if status != CheckStatus::Completed {
        scan.limitations.push(format!("{id}: {reason}"));
    }
}
fn count_check(scan: &mut ScanResultV2, id: &str, count: usize, description: &str) {
    check(
        scan,
        id,
        if count == 0 {
            CheckStatus::Completed
        } else {
            CheckStatus::Partial
        },
        format!("{description}: {count}."),
    );
}
fn mapping_gap(scan: &mut ScanResultV2, kind: &str, err: ModelError) {
    scan.limitations.push(format!("{kind} could not be represented: {err}; other findings are retained. Consult the Core report for this item."));
}

pub fn secrets_report(
    report: &ScanReport,
    context: &CoreContext,
) -> Result<ScanResultV2, ModelError> {
    let mut scan = ScanResultV2::default();
    let mut failures = 0;
    for f in report.all_findings() {
        match adapters::secret(f) {
            Ok(f) => scan.findings.push(f),
            Err(e) => {
                failures += 1;
                mapping_gap(&mut scan, "Secret finding", e);
            }
        }
        if !output::is_core_fingerprint(&f.fingerprint) {
            failures += 1;
            mapping_gap(
                &mut scan,
                "Secret fingerprint",
                ModelError("noncanonical_fingerprint"),
            );
        }
    }
    count_check(
        &mut scan,
        "core.secrets.mapping",
        failures,
        "Unrepresentable secret findings or evidence fields",
    );
    let w = &report.walk;
    check(
        &mut scan,
        "core.secrets.walk",
        if w.skipped_binary > 0
            || w.skipped_large > 0
            || w.skipped_unreadable > 0
            || w.dirs_skipped > 0
        {
            CheckStatus::Partial
        } else {
            CheckStatus::Completed
        },
        format!(
            "Files scanned: {}; binary files excluded: {}; oversized files excluded: {}; unreadable entries: {}; directories excluded by policy: {}. Individual skipped paths are not recorded by Core.",
            w.files_scanned,
            w.skipped_binary,
            w.skipped_large,
            w.skipped_unreadable,
            w.dirs_skipped
        ),
    );
    count_check(
        &mut scan,
        "core.secrets.suppressions",
        report.ignored,
        "Findings suppressed by Core ignore policy (reported counter)",
    );
    check(&mut scan,"core.secrets.policy_coverage",CheckStatus::Partial,
        "Core does not count symlinks, inline-ignore matches or failed ignore-file reads separately; zero reported suppressions does not establish full policy coverage. No extra filesystem traversal was performed.".into());
    match &report.history {
        HistoryOutcome::Scanned(stats)=>check(&mut scan,"core.secrets.history",CheckStatus::Completed,format!("Git history scanned: {} commits, {} added lines.",stats.commits,stats.lines)),
        HistoryOutcome::Disabled=>check(&mut scan,"core.secrets.history",if context.target==TargetKind::File {CheckStatus::Skipped} else {CheckStatus::Partial},
            if context.target==TargetKind::File {"Git history is not applicable to a single-file scan."} else {"Git history was disabled or not applicable; Core did not distinguish the cause. History was not checked."}.into()),
        HistoryOutcome::Failed(error)=>check(&mut scan,"core.secrets.history",CheckStatus::Partial,match error {
            HistoryError::GitNotFound=>"Git history was not checked: git executable unavailable.",
            HistoryError::NotARepo=>"Git history was not checked: target is not a Git repository.",
            HistoryError::Git(_)=>"Git history failed; partial history matches are discarded by Core. Raw git stderr is intentionally omitted because it may contain secrets.",
        }.into()),
    }
    let mut live = 0;
    let mut revoked = 0;
    let mut unknown = 0;
    let mut absent = 0;
    for f in report.all_findings() {
        match &f.verified {
            Some(secrets::Liveness::Live) => live += 1,
            Some(secrets::Liveness::Revoked) => revoked += 1,
            Some(secrets::Liveness::Unknown(_)) => unknown += 1,
            None => absent += 1,
        }
    }
    let status = if unknown > 0
        || (context.verification_requested != Some(false) && absent > 0)
        || context.verification_requested.is_none()
    {
        CheckStatus::Partial
    } else if context.verification_requested == Some(false) && live + revoked == 0 {
        CheckStatus::Skipped
    } else {
        CheckStatus::Completed
    };
    check(
        &mut scan,
        "core.secrets.verification",
        status,
        format!(
            "Provider results on retained findings: live={live}, revoked={revoked}, unknown={unknown}, not checked={absent}; requested={:?}. Counts are findings, not requests; raw provider error text is omitted. Validity does not prove exposure or remediation.",
            context.verification_requested
        ),
    );
    scan.validate()?;
    Ok(scan)
}

pub fn dependencies_report(report: &DepsReport) -> Result<ScanResultV2, ModelError> {
    let mut scan = ScanResultV2::default();
    let mut failures = 0;
    for f in &report.findings {
        if f.package.lockfiles.is_empty() {
            failures += 1;
            mapping_gap(
                &mut scan,
                "Dependency finding",
                ModelError("missing_dependency_location"),
            );
        }
        // A malformed path must not also discard valid locations of the advisory.
        for path in &f.package.lockfiles {
            let mut one = f.clone();
            one.package.lockfiles = vec![path.clone()];
            match adapters::dependency(&one) {
                Ok(mut findings) => {
                    for finding in &mut findings {
                        finding
                            .tags
                            .extend(f.vuln.aliases.iter().map(|a| format!("alias:{a}")));
                        finding
                            .tags
                            .extend(f.vuln.fixed.iter().map(|v| format!("fixed-version:{v}")));
                        if let Some(fix) = &f.fix {
                            finding.tags.push(format!("recommended-version:{fix}"));
                        }
                    }
                    scan.findings.extend(findings);
                }
                Err(e) => {
                    failures += 1;
                    mapping_gap(&mut scan, "Dependency finding", e);
                    scan.limitations.push(format!("Unmapped advisory {} for {}:{}@{} in {}; legacy severity={}. No replacement severity was invented.",f.vuln.id,f.package.ecosystem.osv_name(),f.package.name,f.package.version,path,f.vuln.severity.label()));
                }
            }
        }
    }
    count_check(
        &mut scan,
        "core.deps.mapping",
        failures,
        "Unrepresentable dependency locations",
    );
    count_check(
        &mut scan,
        "core.deps.advisory_details",
        report
            .findings
            .iter()
            .filter(|f| {
                f.vuln.summary == "(details unavailable)"
                    || f.vuln.severity == deps::Severity::Unknown
            })
            .count(),
        "Advisory entries with missing details or unknown legacy severity",
    );
    let errors = report
        .lockfiles
        .iter()
        .filter(|l| l.error.is_some())
        .count();
    check(
        &mut scan,
        "core.deps.lockfiles",
        if errors > 0 {
            CheckStatus::Partial
        } else if report.lockfiles.is_empty() {
            CheckStatus::Skipped
        } else {
            CheckStatus::Completed
        },
        format!(
            "Discovered lockfiles: {}; read/parse failures: {errors}. An empty discovery result is not evidence that every directory was checked.",
            report.lockfiles.len()
        ),
    );
    for lock in &report.lockfiles {
        if lock.error.is_some() {
            scan.limitations.push(format!("Lockfile {} ({}) could not be read or parsed; raw parser/OS error text is omitted. Its dependencies were not fully checked.",lock.rel,lock.label));
        }
    }
    check(&mut scan,"core.deps.discovery",CheckStatus::Partial,
        "Core lockfile discovery omits directory read failures, entry errors, links, policy exclusions and the depth limit without counters. Parsers may omit unpinned, workspace/local or unsupported declarations. No complete dependency-inventory claim is possible from DepsReport.".into());
    count_check(
        &mut scan,
        "core.deps.unchecked",
        report.unchecked.len(),
        "Packages with no advisory result",
    );
    for p in &report.unchecked {
        scan.limitations.push(format!(
            "Unchecked package {}:{}@{}; lockfiles: {}.",
            p.ecosystem.osv_name(),
            p.name,
            p.version,
            p.lockfiles.join(", ")
        ));
    }
    check(
        &mut scan,
        "core.deps.advisory_data",
        if report.osv_unavailable || report.stale_cache_age.is_some() || !report.warnings.is_empty()
        {
            CheckStatus::Partial
        } else {
            CheckStatus::Completed
        },
        format!(
            "Packages in report: {}; served from cache: {}; fresh results: {}; offline={}; OSV unavailable={}; oldest fallback cache age seconds={:?}; warnings={}. Result counters are not HTTP request counters; raw warning bodies are omitted.",
            report.packages.len(),
            report.from_cache,
            report.fresh,
            report.offline,
            report.osv_unavailable,
            report.stale_cache_age,
            report.warnings.len()
        ),
    );
    scan.limitations.push("Advisory prose/CVSS and install-command bodies are not serialized by this adapter; advisory IDs, aliases, versions, severity and manual-upgrade metadata are retained where representable. No code was executed.".into());
    let mut local_failures = 0;
    let mut unknown_scripts = 0;
    for script in &report.install_scripts {
        if script.commands.is_empty() {
            unknown_scripts += 1;
        }
        let package = deps::Package {
            ecosystem: deps::Ecosystem::Npm,
            name: script.name.clone(),
            version: script.version.clone(),
            lockfiles: vec![script.lockfile.clone()],
        };
        match package_finding(
            "core-install-script",
            &package,
            &script.lockfile,
            "Package declares an installation script",
            Severity::Low,
            format!(
                "Core identified an installation hook; dev-only={}; known command entries={}. Command bodies are deliberately omitted and were not executed; review the package manually.",
                script.dev,
                script.commands.len()
            ),
        ) {
            Ok(mut f) => {
                f.tags.extend(
                    script
                        .flags
                        .iter()
                        .map(|flag| format!("script-flag:{flag}")),
                );
                if script.dev {
                    f.tags.push("dev-dependency".into());
                }
                scan.findings.push(f);
            }
            Err(e) => {
                local_failures += 1;
                mapping_gap(&mut scan, "Install-script finding", e);
            }
        }
    }
    for (package, suspect) in &report.typosquats {
        for path in &package.lockfiles {
            match package_finding(
                "core-typosquat",
                package,
                path,
                "Package name resembles a popular package",
                Severity::Medium,
                format!(
                    "Resembles {}; reason: {}. This heuristic is not proof of a malicious package.",
                    suspect.looks_like, suspect.reason
                ),
            ) {
                Ok(f) => scan.findings.push(f),
                Err(e) => {
                    local_failures += 1;
                    mapping_gap(&mut scan, "Typosquat finding", e);
                }
            }
        }
        if package.lockfiles.is_empty() {
            local_failures += 1;
            mapping_gap(
                &mut scan,
                "Typosquat finding",
                ModelError("missing_dependency_location"),
            );
        }
    }
    count_check(
        &mut scan,
        "core.deps.local_mapping",
        local_failures,
        "Unrepresentable install-script or typosquat findings",
    );
    count_check(
        &mut scan,
        "core.deps.script_details",
        unknown_scripts,
        "Install-script entries whose command bodies were unavailable to Core",
    );
    check(
        &mut scan,
        "core.deps.local_checks",
        CheckStatus::Partial,
        format!(
            "Install-script entries: {}; suspected package names: {}. Script metadata is limited to package-lock v2/v3 and installed package files; other formats, unreadable metadata and skipped heuristics have no complete coverage signal.",
            report.install_scripts.len(),
            report.typosquats.len()
        ),
    );
    scan.validate()?;
    Ok(scan)
}
fn package_finding(
    rule: &str,
    p: &deps::Package,
    path: &str,
    title: &str,
    severity: Severity,
    explanation: String,
) -> Result<FindingV2, ModelError> {
    let location = SourceLocation {
        relative_path: path.into(),
        line: None,
        column: None,
        archive_entry: None,
        component: Some(format!(
            "{}:{}@{}",
            p.ecosystem.osv_name(),
            p.name,
            p.version
        )),
    };
    location.validate()?;
    Ok(FindingV2 {
        id: output::pending_id("deps"),
        rule_id: rule.into(),
        title: title.into(),
        category: "dependency".into(),
        severity,
        confidence: Confidence::NeedsReview,
        location,
        evidence: Evidence::default(),
        explanation,
        remediation_id: Some("core-dependency:manual-review".into()),
        references: vec![],
        cwe_ids: vec![],
        tags: vec!["legacy-core".into(), "guidance-only".into()],
    })
}

pub fn project_report(
    report: &ProjectReport,
    context: &CoreContext,
) -> Result<ScanResultV2, ModelError> {
    let mut scan = secrets_report(&report.secrets, context)?;
    scan.limitations.push("V2 is a findings/coverage projection: absolute scan roots and the full inventory of successfully checked packages/lockfiles (including per-lockfile package counts) are not serialized. Aggregate scan/package counts and affected or unchecked package locations are retained.".into());
    if let Some(deps) = &report.deps {
        append(&mut scan, dependencies_report(deps)?);
    } else {
        check(
            &mut scan,
            "core.deps.applicability",
            if context.target == TargetKind::File {
                CheckStatus::Skipped
            } else {
                CheckStatus::Partial
            },
            "Dependency report absent; directory dependencies were not checked by this report."
                .into(),
        );
    }
    let mut wf = adapters::workflows(&[])?;
    let mut wf_failures = 0;
    if let Some(issues) = &report.workflows {
        for issue in issues {
            match adapters::workflows(std::slice::from_ref(issue)) {
                Ok(mut one) => wf.findings.append(&mut one.findings),
                Err(e) => {
                    wf_failures += 1;
                    mapping_gap(&mut wf, "Workflow finding", e);
                }
            }
        }
    } else {
        wf.limitations.push("Workflow discovery reported no applicable files; missing paths and metadata/read errors are not distinguished by ProjectReport.".into());
    }
    wf.limitations.push("Legacy workflow parsing/read completeness is not recorded, including empty workflow results; an empty result cannot verify absence.".into());
    append(&mut scan, wf);
    count_check(
        &mut scan,
        "core.workflows.mapping",
        wf_failures,
        "Unrepresentable workflow findings",
    );
    match context.baseline_hidden {
        Some(hidden)=>check(&mut scan,"core.policy.baseline",if hidden.secrets>0||hidden.vulns>0||hidden.other>0 {CheckStatus::Partial} else {CheckStatus::Completed},format!("Baseline exclusions: secrets={}, vulnerabilities={}, other={}. Suppressed findings are absent; run without the baseline to review all findings.",hidden.secrets,hidden.vulns,hidden.other)),
        None=>check(&mut scan,"core.policy.baseline",CheckStatus::Partial,"Baseline application/counts were not supplied by the caller; report completeness cannot be inferred after policy filtering.".into()),
    }
    match &context.network {
        Some(n) if !n.unavailable=>{
            scan.network_activities=n.activities.clone();
            check(&mut scan,"core.network",if n.failed_attempts>0 {CheckStatus::Partial} else {CheckStatus::Completed},format!("Observed existing-transport calls; failed or retryable attempts: {}. Counts include retries and attempts that may fail before sending bytes. No URL paths, payloads or credentials are retained.",n.failed_attempts));
        }
        _=>check(&mut scan,"core.network",CheckStatus::Partial,"No complete transport journal supplied. Network activity cannot be reconstructed from fresh/cache counts, offline dependency mode or provider liveness; no requests are invented.".into()),
    }
    scan.validate()?;
    Ok(scan)
}
fn append(to: &mut ScanResultV2, mut from: ScanResultV2) {
    to.findings.append(&mut from.findings);
    to.checks.append(&mut from.checks);
    to.limitations.append(&mut from.limitations);
    to.network_activities.append(&mut from.network_activities);
}
