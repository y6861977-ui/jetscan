//! CX-RES-07: plan -> preview -> apply -> verify on reviewed fixtures, with
//! the real workflow scanner, and the cases that must stay manual.
use super::testutil::{Project, workflow_scan};
use super::*;
use crate::finding_v2::{RedactionPolicy, RemediationState};

fn fixture_bytes(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/resolve")
            .join(name),
    )
    .unwrap()
}

/// The full flow for one fixture; returns the patched file.
fn end_to_end(fixture: &str, findings: usize, diff: &[&str]) -> String {
    let p = Project::new();
    let rel = format!(".github/workflows/{}", fixture.rsplit('/').next().unwrap());
    p.copy_fixture(fixture, &rel);
    let policy = RedactionPolicy::default();
    // Scan with the real scanner, through the V2 adapter.
    let scan = workflow_scan(&p.0);
    assert_eq!(scan.findings.len(), findings);
    assert!(
        scan.findings
            .iter()
            .all(|f| f.rule_id == "gha-script-injection")
    );
    // Plan: one bound patch; the plan file roundtrips.
    let plan = planner::plan(&p.0, &scan, &policy).unwrap().plan;
    assert_eq!(plan.status(), RemediationState::Available);
    assert_eq!(plan.preconditions().len(), 1);
    let plan = ResolvePlan::parse(&plan.render_pretty().unwrap(), &policy).unwrap();
    // Preview: exact diff, nothing written.
    let before = p.snapshot();
    let shown = preview(&plan, &policy).unwrap();
    for line in diff {
        assert!(shown.text.contains(line), "{line}\n{}", shown.text);
    }
    assert_eq!(p.snapshot(), before);
    // Apply: refused without confirmation, then applied, unverified.
    assert_eq!(
        apply(&plan, None),
        Err(ResolveError("confirmation_required"))
    );
    assert_eq!(p.snapshot(), before);
    let applied = apply(&plan, Some(plan.id())).unwrap();
    assert_eq!(applied.state, RemediationState::AppliedUnverified);
    assert_eq!(applied.files, vec![(rel.clone(), FileOutcome::Written)]);
    // Verify: every finding of the plan is gone and the file was parsed.
    let checked = verify(&plan).unwrap();
    assert_eq!(checked.state, RemediationState::Verified);
    assert_eq!(checked.count(Outcome::VerifiedSpecificIssue), findings);
    assert!(workflow_scan(&p.0).findings.is_empty());
    String::from_utf8(std::fs::read(p.0.join(&rel)).unwrap()).unwrap()
}

#[test]
fn pull_request_title_block_script() {
    let fixed = end_to_end(
        "workflows/pr-title.yml",
        1,
        &[
            "+        env:\n+          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}\n         run: |\n-          title=\"${{ github.event.pull_request.title }}\"\n+          title=\"${PULL_REQUEST_TITLE}\"\n",
        ],
    );
    assert!(fixed.contains("if [[ ! \"$title\" =~ ^(feat|fix|docs|chore) ]]; then"));
}

#[test]
fn issue_title_and_body_with_existing_env() {
    let fixed = end_to_end(
        "workflows/issue-triage.yml",
        2,
        &[
            "-        run: echo \"New issue $ISSUE_NUMBER - ${{ github.event.issue.title }}\"\n+          ISSUE_TITLE: ${{ github.event.issue.title }}\n+        run: echo \"New issue $ISSUE_NUMBER - ${ISSUE_TITLE}\"\n",
            "-          case \"${{ github.event.issue.body }}\" in\n+          case \"${ISSUE_BODY}\" in\n",
        ],
    );
    // number (already in env), title and body: only as env values now.
    assert_eq!(fixed.matches("${{ github.event.issue.").count(), 3);
    assert_eq!(
        fixed
            .lines()
            .filter(|l| l.contains("${{"))
            .filter(|l| !l.trim_start().starts_with("ISSUE_"))
            .count(),
        0
    );
}

#[test]
fn unprovable_transform_is_manual_guidance_only() {
    let p = Project::new();
    let rel = ".github/workflows/unquoted-comment.yml";
    p.copy_fixture("workflows/unquoted-comment.yml", rel);
    let scan = workflow_scan(&p.0);
    assert_eq!(scan.findings.len(), 1);
    let plan = planner::plan(&p.0, &scan, &RedactionPolicy::default())
        .unwrap()
        .plan;
    assert_eq!(plan.status(), RemediationState::GuidanceOnly);
    assert!(plan.preconditions().is_empty());
    let text = plan.render_json().unwrap();
    assert!(text.contains("A safe automatic edit cannot be proven"));
    assert!(text.contains("recipe_expression_not_double_quoted"));
    let before = p.snapshot();
    let applied = apply(&plan, Some(plan.id())).unwrap();
    assert_eq!(applied.state, RemediationState::GuidanceOnly);
    assert_eq!(p.snapshot(), before);
    let checked = verify(&plan).unwrap();
    assert_eq!(checked.count(Outcome::StillPresent), 1);
    assert_eq!(
        std::fs::read(p.0.join(rel)).unwrap(),
        fixture_bytes("workflows/unquoted-comment.yml")
    );
}

#[test]
fn write_all_is_review_only_and_never_edited() {
    let p = Project::new();
    let rel = ".github/workflows/write-all.yml";
    p.copy_fixture("workflows/write-all.yml", rel);
    let scan = workflow_scan(&p.0);
    assert_eq!(scan.findings.len(), 1);
    assert_eq!(scan.findings[0].rule_id, "gha-write-all-permissions");
    let plan = planner::plan(&p.0, &scan, &RedactionPolicy::default())
        .unwrap()
        .plan;
    assert_eq!(plan.status(), RemediationState::GuidanceOnly);
    let text = preview(&plan, &RedactionPolicy::default()).unwrap().text;
    assert!(text.contains("Review only"));
    assert!(!text.contains("--- a/"), "no diff for write-all");
    let applied = apply(&plan, Some(plan.id())).unwrap();
    assert_eq!(applied.state, RemediationState::GuidanceOnly);
    assert_eq!(
        std::fs::read(p.0.join(rel)).unwrap(),
        fixture_bytes("workflows/write-all.yml")
    );
    assert_eq!(
        verify(&plan).unwrap().count(Outcome::StillPresent),
        1,
        "still there: nothing was changed"
    );
}
