//! Additive Findings V2 model. Legacy reports and CLI remain unchanged.
//! Adapter strings are untrusted; output must use the redacted representation.
use std::fmt;

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Confirmed,
    Potential,
    NeedsReview,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckStatus {
    Completed,
    Partial,
    Skipped,
    Error,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemediationState {
    GuidanceOnly,
    Available,
    AppliedUnverified,
    Verified,
    Failed,
    RolledBack,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceLocation {
    /// Portable project-relative path with slash separators.
    pub relative_path: String,
    /// One-based Unicode character coordinates, never byte offsets.
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub archive_entry: Option<String>,
    pub component: Option<String>,
}
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Evidence {
    pub redacted_excerpt: Option<String>,
    /// Core secrets fingerprint only (`secrets::fingerprint`: exactly 16
    /// lowercase hex). Any other value is dropped by `redacted()`.
    pub fingerprint: Option<String>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingV2 {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: SourceLocation,
    pub evidence: Evidence,
    pub explanation: String,
    pub remediation_id: Option<String>,
    pub references: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub tags: Vec<String>,
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleCheck {
    pub id: String,
    pub status: CheckStatus,
    pub reason: Option<String>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ScanResultV2 {
    pub schema_version: u32,
    pub findings: Vec<FindingV2>,
    pub checks: Vec<RuleCheck>,
    pub limitations: Vec<String>,
    pub network_activities: Vec<String>,
}

// Debug must not bypass the output boundary, including assertion failures.
macro_rules! opaque_debug {
    ($($t:ty),+ $(,)?) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($t), " { <untrusted data omitted> }"))
            }
        }
    )+};
}
opaque_debug!(SourceLocation, Evidence, FindingV2, RuleCheck, ScanResultV2);

/// Fixed codes only; never rejected input or underlying parser messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelError(pub &'static str);
impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ModelError {}

impl Default for ScanResultV2 {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            findings: Vec::new(),
            checks: Vec::new(),
            limitations: Vec::new(),
            network_activities: Vec::new(),
        }
    }
}
impl ScanResultV2 {
    /// Absence of findings is not coverage. Empty/invalid scans are incomplete,
    /// and so is any Partial/Error check. Skipped ("not applicable", "not
    /// implemented in this version", "not_checked: ...") does not break
    /// completeness, but `validate` requires it to carry a non-empty reason so
    /// the report can show it.
    pub fn completed(&self) -> bool {
        self.validate().is_ok()
            && !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|c| matches!(c.status, CheckStatus::Completed | CheckStatus::Skipped))
    }
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ModelError("unsupported_schema_version"));
        }
        let mut total = 0usize;
        let mut bounded = |text: &str| -> Result<(), ModelError> {
            total = total.saturating_add(text.len());
            if text.len() > 16 * 1024 || total > 1024 * 1024 {
                return Err(ModelError("v2_model_limit"));
            }
            Ok(())
        };
        if [
            self.findings.len(),
            self.checks.len(),
            self.limitations.len(),
            self.network_activities.len(),
        ]
        .iter()
        .any(|&len| len > 10_000)
        {
            return Err(ModelError("v2_model_limit"));
        }
        for text in self.limitations.iter().chain(&self.network_activities) {
            bounded(text)?;
        }
        for finding in &self.findings {
            for text in [
                &finding.id,
                &finding.rule_id,
                &finding.title,
                &finding.category,
                &finding.explanation,
                &finding.location.relative_path,
            ] {
                bounded(text)?;
            }
            for text in [
                &finding.remediation_id,
                &finding.evidence.redacted_excerpt,
                &finding.evidence.fingerprint,
                &finding.location.archive_entry,
                &finding.location.component,
            ]
            .into_iter()
            .flatten()
            {
                bounded(text)?;
            }
            for list in [&finding.references, &finding.cwe_ids, &finding.tags] {
                if list.len() > 10_000 {
                    return Err(ModelError("v2_model_limit"));
                }
                for text in list {
                    bounded(text)?;
                }
            }
            // An empty/malformed `id` is allowed here: `redacted()` computes it.
            if [&finding.rule_id, &finding.title, &finding.category]
                .iter()
                .any(|s| s.trim().is_empty())
            {
                return Err(ModelError("missing_finding_field"));
            }
            finding.location.validate()?;
        }
        for check in &self.checks {
            bounded(&check.id)?;
            if let Some(reason) = &check.reason {
                bounded(reason)?;
            }
            if check.id.trim().is_empty() {
                return Err(ModelError("missing_check_id"));
            }
            if check.status != CheckStatus::Completed
                && check.reason.as_ref().is_none_or(|s| s.trim().is_empty())
            {
                return Err(ModelError("incomplete_check_requires_reason"));
            }
        }
        Ok(())
    }
}
impl SourceLocation {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_relative_path(&self.relative_path)?;
        if let Some(entry) = &self.archive_entry {
            validate_relative_path(entry)?;
        }
        if self.line == Some(0)
            || self.column == Some(0)
            || (self.column.is_some() && self.line.is_none())
        {
            return Err(ModelError("invalid_coordinates"));
        }
        Ok(())
    }
}
/// Lexical report validation only; NOT authorization to read/write this path.
pub fn validate_relative_path(path: &str) -> Result<(), ModelError> {
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(ModelError("invalid_relative_path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coverage_requires_completed_checks_and_valid_version() {
        let mut scan = ScanResultV2::default();
        assert!(!scan.completed());
        scan.checks.push(RuleCheck {
            id: "fixture".into(),
            status: CheckStatus::Completed,
            reason: None,
        });
        assert!(scan.completed());
        for status in [
            CheckStatus::Partial,
            CheckStatus::Skipped,
            CheckStatus::Error,
        ] {
            scan.checks[0].status = status;
            // Every non-completed status needs a visible reason.
            assert!(scan.validate().is_err());
            assert!(!scan.completed());
            scan.checks[0].reason = Some("  ".into());
            assert!(scan.validate().is_err());
            scan.checks[0].reason = Some("not checked".into());
            assert!(scan.validate().is_ok());
            // Skipped-with-reason keeps the scan complete; Partial/Error never do.
            assert_eq!(scan.completed(), status == CheckStatus::Skipped);
            scan.checks[0].reason = None;
        }
        // One Partial among Completed/Skipped checks is enough to be incomplete.
        scan.checks[0] = RuleCheck {
            id: "a".into(),
            status: CheckStatus::Completed,
            reason: None,
        };
        scan.checks.push(RuleCheck {
            id: "b".into(),
            status: CheckStatus::Skipped,
            reason: Some("not implemented in this version".into()),
        });
        assert!(scan.completed());
        scan.checks.push(RuleCheck {
            id: "c".into(),
            status: CheckStatus::Partial,
            reason: Some("budget".into()),
        });
        assert!(!scan.completed());
        scan.checks.pop();
        scan.schema_version = 1;
        assert_eq!(
            scan.validate(),
            Err(ModelError("unsupported_schema_version"))
        );
    }
    #[test]
    fn paths_and_coordinates_are_portable_and_one_based() {
        for path in [
            "", "/root", "../file", "a/../b", "a//b", "C:/a", "a\\b", "a:stream", "./a",
        ] {
            assert!(validate_relative_path(path).is_err());
        }
        let mut location = SourceLocation {
            relative_path: "src/привет.ts".into(),
            line: Some(1),
            column: Some(1),
            archive_entry: None,
            component: None,
        };
        assert!(location.validate().is_ok());
        location.line = None;
        assert!(location.validate().is_err());
        location.line = Some(0);
        assert!(location.validate().is_err());
        location.line = Some(1);
        location.archive_entry = Some("../outside".into());
        assert!(location.validate().is_err());
    }
}

pub mod output;
pub use output::{RedactedScan, RedactionPolicy};

pub mod wire;

pub mod adapters;

pub mod cli;

#[cfg(test)]
mod scanner_tests;

pub mod core_capture;
pub mod core_network;
pub mod core_reports;

#[cfg(test)]
mod core_tests;
