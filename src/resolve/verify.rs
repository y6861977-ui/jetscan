//! `verify`: re-run the specific static check for each finding of a plan.
//!
//! Only the GitHub Actions check (`crate::workflows`, called read-only) can be
//! re-run here. For each finding of the plan:
//! - `still_present`: the scanner reports the same finding id again;
//! - `verified_specific_issue`: the scanner no longer reports it AND the
//!   scanner demonstrably parsed the patched file: a probe copy (the patched
//!   bytes with the original expression put back, see `recipes::canary`) in a
//!   temporary directory outside the project reports that same id;
//! - `unknown`: anything else (no re-check exists for the rule, absence that
//!   could be a parse failure, a credential whose revocation cannot be seen
//!   locally, unreadable file).
//!
//! It never says "secure": it speaks only about the findings in the plan.
//! The project is not written; the probe directory is removed afterwards.
use super::*;
use crate::finding_v2::{RedactionPolicy, RemediationState, adapters};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    VerifiedSpecificIssue,
    StillPresent,
    Unknown,
}
impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::VerifiedSpecificIssue => "verified_specific_issue",
            Self::StillPresent => "still_present",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyItem {
    pub finding_id: String,
    pub outcome: Outcome,
    /// Fixed reason code.
    pub reason: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub plan_id: String,
    /// `Verified` only if every finding of the plan is `verified_specific_issue`.
    /// Otherwise `AppliedUnverified` when every planned patch is in place, else
    /// the plan's own status (`Available` / `GuidanceOnly`).
    pub state: RemediationState,
    pub items: Vec<VerifyItem>,
    /// Per patched file: (path, fixed state code).
    pub files: Vec<(String, &'static str)>,
}
impl VerifyReport {
    pub fn count(&self, outcome: Outcome) -> usize {
        self.items.iter().filter(|i| i.outcome == outcome).count()
    }
}

pub fn verify(plan: &ResolvePlan) -> Result<VerifyReport, ResolveError> {
    verify_in(plan, &std::env::temp_dir())
}

/// Finding ids the workflow scanner reports for `root` (None: adapter refused).
fn workflow_ids(root: &Path) -> Option<BTreeSet<String>> {
    let scan = adapters::workflows(&crate::workflows::check(root))
        .ok()?
        .redacted(&RedactionPolicy::default())
        .ok()?;
    Some(
        scan.as_scan()
            .findings
            .iter()
            .map(|f| f.id.clone())
            .collect(),
    )
}

/// A private temporary directory, removed on drop.
struct Probe(PathBuf);
static NEXT: AtomicU64 = AtomicU64::new(0);
impl Probe {
    fn new(base: &Path) -> Result<Self, ResolveError> {
        for _ in 0..16 {
            let path = base.join(format!(
                "jetscan-verify-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => break,
            }
        }
        Err(ResolveError("probe_unavailable"))
    }
    fn write(&self, relative: &str, bytes: &[u8]) -> Result<(), ResolveError> {
        model::relative(relative)?;
        let path = self.0.join(relative);
        let dir = path.parent().ok_or(ResolveError("probe_unavailable"))?;
        fs::create_dir_all(dir).map_err(|_| ResolveError("probe_unavailable"))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| ResolveError("probe_unavailable"))?;
        file.write_all(bytes)
            .map_err(|_| ResolveError("probe_unavailable"))
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn verify_in(plan: &ResolvePlan, scratch: &Path) -> Result<VerifyReport, ResolveError> {
    plan.validate()?;
    let root = plan.root();
    if fs::canonicalize(root).ok().as_deref() != Some(root) {
        return Err(ResolveError("root_changed"));
    }
    let real = workflow_ids(root);
    let probe = Probe::new(scratch)?;
    let mut probed = false;
    let mut files = Vec::new();
    let mut all_in_place = true;
    for step in plan.steps() {
        let Step::FilePatch {
            file_path,
            expected_old_hash,
            expected_new_hash,
            ..
        } = step
        else {
            continue;
        };
        match fs_guard::read(root, file_path) {
            Ok(bytes) => {
                let current = digest(&bytes);
                let state = if current == *expected_new_hash {
                    "planned_change_in_place"
                } else {
                    all_in_place = false;
                    if current == *expected_old_hash {
                        "planned_change_not_applied"
                    } else {
                        "changed_since_plan"
                    }
                };
                files.push((file_path.clone(), state));
                if let Some(canary) = recipes::canary(&bytes) {
                    probe.write(file_path, &canary)?;
                    probed = true;
                }
            }
            Err(ResolveError(code)) => {
                all_in_place = false;
                files.push((file_path.clone(), code));
            }
        }
    }
    let canary = if probed {
        workflow_ids(&probe.0).unwrap_or_default()
    } else {
        BTreeSet::new()
    };
    drop(probe);
    let items: Vec<VerifyItem> = plan
        .finding_ids()
        .iter()
        .map(|id| {
            let (outcome, reason) = if id.starts_with("secrets/") {
                (
                    Outcome::Unknown,
                    "credential_revocation_cannot_be_checked_locally",
                )
            } else if !id.starts_with("workflows/") {
                (Outcome::Unknown, "no_static_recheck_for_this_rule")
            } else {
                match &real {
                    None => (Outcome::Unknown, "scanner_output_unavailable"),
                    Some(real) if real.contains(id) => {
                        (Outcome::StillPresent, "same_finding_reported_again")
                    }
                    Some(_) if canary.contains(id) => (
                        Outcome::VerifiedSpecificIssue,
                        "absent_and_patched_file_was_parsed",
                    ),
                    Some(_) => (Outcome::Unknown, "absent_but_absence_not_proven"),
                }
            };
            VerifyItem {
                finding_id: id.clone(),
                outcome,
                reason,
            }
        })
        .collect();
    let state = if !items.is_empty()
        && items
            .iter()
            .all(|i| i.outcome == Outcome::VerifiedSpecificIssue)
    {
        RemediationState::Verified
    } else if !files.is_empty() && all_in_place {
        RemediationState::AppliedUnverified
    } else {
        plan.status()
    };
    Ok(VerifyReport {
        plan_id: plan.id().into(),
        state,
        items,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::testutil::{Project, patch_plan};

    fn plan(p: &Project) -> ResolvePlan {
        patch_plan(
            p,
            &[
                ("workflows/pr-title.yml", ".github/workflows/pr-title.yml"),
                (
                    "workflows/issue-triage.yml",
                    ".github/workflows/issue-triage.yml",
                ),
            ],
        )
    }

    #[test]
    fn before_apply_still_present_after_apply_verified() {
        let p = Project::new();
        let scratch = Project::new();
        let plan = plan(&p);
        assert_eq!(plan.finding_ids().len(), 3);
        let before = verify_in(&plan, &scratch.0).unwrap();
        assert_eq!(before.count(Outcome::StillPresent), 3);
        assert_eq!(before.state, RemediationState::Available);
        assert!(
            before
                .files
                .iter()
                .all(|(_, s)| *s == "planned_change_not_applied")
        );
        apply(&plan, Some(plan.id())).unwrap();
        let snapshot = p.snapshot();
        let after = verify_in(&plan, &scratch.0).unwrap();
        assert_eq!(after.count(Outcome::VerifiedSpecificIssue), 3);
        assert_eq!(after.state, RemediationState::Verified);
        assert_eq!(
            p.snapshot(),
            snapshot,
            "verify writes nothing in the project"
        );
        assert_eq!(
            fs::read_dir(&scratch.0).unwrap().count(),
            0,
            "probe removed"
        );
    }

    #[test]
    fn absence_after_a_broken_edit_is_unknown_not_verified() {
        let p = Project::new();
        let scratch = Project::new();
        let plan = plan(&p);
        apply(&plan, Some(plan.id())).unwrap();
        // A tab indentation makes the workflow unparseable for the scanner.
        let path = p.0.join(".github/workflows/pr-title.yml");
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str("\tbroken: [\n");
        fs::write(&path, text).unwrap();
        let report = verify_in(&plan, &scratch.0).unwrap();
        assert_ne!(report.state, RemediationState::Verified);
        let unknown: Vec<_> = report
            .items
            .iter()
            .filter(|i| i.outcome == Outcome::Unknown)
            .collect();
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].reason, "absent_but_absence_not_proven");
        assert!(report.files.contains(&(
            ".github/workflows/pr-title.yml".into(),
            "changed_since_plan"
        )));
    }

    #[test]
    fn guidance_only_and_non_workflow_findings_are_never_verified() {
        let p = Project::new();
        let scratch = Project::new();
        p.copy_fixture("workflows/write-all.yml", ".github/workflows/write-all.yml");
        let scan = crate::resolve::testutil::workflow_scan(&p.0);
        let mut ids: Vec<String> = scan.findings.iter().map(|f| f.id.clone()).collect();
        ids.push("secrets/aws-access-key/0123456789abcdef".into());
        ids.push("web/web-xss-003/0123456789abcdef".into());
        let plan = ResolvePlan::new(
            &p.0,
            ids,
            vec![Step::Explain {
                description: "review".into(),
            }],
            vec!["gha-write-all-permissions".into()],
            vec![],
            &RedactionPolicy::default(),
        )
        .unwrap();
        let report = verify_in(&plan, &scratch.0).unwrap();
        assert_eq!(report.state, RemediationState::GuidanceOnly);
        let reasons: Vec<_> = report.items.iter().map(|i| i.reason).collect();
        assert!(reasons.contains(&"same_finding_reported_again"));
        assert!(reasons.contains(&"credential_revocation_cannot_be_checked_locally"));
        assert!(reasons.contains(&"no_static_recheck_for_this_rule"));
        // Fixed by hand: gone, but nothing proves the scanner parsed the file.
        p.write(
            ".github/workflows/write-all.yml",
            &crate::resolve::recipes::tests::fixture("workflows/write-all.yml")
                .replace("permissions: write-all", "permissions:\n  contents: read"),
        );
        let report = verify_in(&plan, &scratch.0).unwrap();
        assert_eq!(report.count(Outcome::VerifiedSpecificIssue), 0);
        let workflow = report
            .items
            .iter()
            .find(|i| i.finding_id.starts_with("workflows/"))
            .unwrap();
        assert_eq!(workflow.reason, "absent_but_absence_not_proven");
    }
}
