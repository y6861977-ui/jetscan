use super::*;
use crate::deps::fix::Step as DepsFixStep;
use crate::finding_v2::{CheckStatus, FindingV2, RedactionPolicy, ScanResultV2};
use std::collections::BTreeMap;
use std::path::Path;

/// Exact advice the caller already has. Never computed here: Resolve runs no
/// package manager and sends nothing over the network.
#[derive(Default)]
pub struct Advice<'a> {
    /// `deps::fix::plan` output from an earlier `jetscan deps` run.
    pub dependency_steps: &'a [DepsFixStep],
}

#[derive(Clone, Debug)]
pub struct PlanBuild {
    pub plan: ResolvePlan,
    /// `Partial` when the input scan is incomplete or a recipe could not even
    /// read its file: the plan is then not a complete answer for the report.
    pub status: CheckStatus,
}

/// What a reviewed recipe can do for one workflow file.
enum Patch {
    Ready {
        old: String,
        new: String,
    },
    /// The file was read but a safe transform cannot be proven.
    Unprovable(&'static str),
    /// The file could not be read safely (link, size, missing): generator error.
    Unreadable(&'static str),
}

/// Read-only plan generation. Uses finding IDs supplied by the library/scanner;
/// never recomputes them, drops evidence hashes, or overrides global completion.
/// A file patch is offered only where the reviewed recipe proves a safe edit
/// for the current file bytes; everything else is manual guidance.
pub fn plan(
    root: &Path,
    scan: &ScanResultV2,
    policy: &RedactionPolicy<'_>,
) -> Result<PlanBuild, ResolveError> {
    plan_with(root, scan, policy, &Advice::default())
}

/// `plan` plus advice text the caller already has (see `Advice`).
pub fn plan_with(
    root: &Path,
    scan: &ScanResultV2,
    policy: &RedactionPolicy<'_>,
    advice: &Advice<'_>,
) -> Result<PlanBuild, ResolveError> {
    scan.validate()
        .map_err(|_| ResolveError("invalid_scan_result"))?;
    let root = std::fs::canonicalize(root).map_err(|_| ResolveError("invalid_project_root"))?;
    let mut findings = scan.findings.clone();
    findings.sort();
    findings.dedup();
    if findings.windows(2).any(|w| w[0].id == w[1].id) {
        return Err(ResolveError("conflicting_finding_ids"));
    }
    let mut steps = Vec::new();
    let mut ids = Vec::new();
    let mut rules = Vec::new();
    let mut warnings = scan.limitations.clone();
    let incomplete = scan.checks.is_empty()
        || scan
            .checks
            .iter()
            .any(|c| matches!(c.status, CheckStatus::Partial | CheckStatus::Error));
    for check in &scan.checks {
        if check.status != CheckStatus::Completed {
            warnings.push(format!(
                "Check {}: {:?}; {}",
                policy.text(&check.id),
                check.status,
                policy.text(
                    check
                        .reason
                        .as_deref()
                        .unwrap_or("No completeness information")
                )
            ));
        }
    }
    if incomplete {
        warnings.push(
            "The input scan is incomplete; this plan cannot establish absence of other issues."
                .into(),
        );
    }
    // One recipe attempt per workflow file that has a script-injection finding.
    let mut patches = BTreeMap::new();
    for f in &findings {
        let path = &f.location.relative_path;
        if f.rule_id == "gha-script-injection"
            && recipes::workflow_path(path)
            && !patches.contains_key(path)
        {
            patches.insert(path.clone(), try_recipe(&root, path));
        }
    }
    let mut generator_error = false;
    for (path, patch) in &patches {
        if let Patch::Unreadable(code) = patch {
            generator_error = true;
            warnings.push(format!(
                "Could not read {} safely for a reviewed recipe ({code}); guidance only.",
                policy.text(path)
            ));
        }
    }
    for f in &findings {
        ids.push(f.id.clone());
        rules.push(f.rule_id.clone());
        steps.push(Step::Explain { description:format!("Finding {}: {}. Severity: {:?}; confidence: {:?}. Static evidence only; verification must recheck this specific condition.",
            policy.text(&f.id),policy.text(&f.title),f.severity,f.confidence) });
        let resolver = if f.category == "secret_exposure" {
            registry::Resolver::Credential
        } else if f.category == "dependency" {
            registry::Resolver::DependencyAdvice
        } else {
            registry::lookup(&f.rule_id)
        };
        match resolver {
            registry::Resolver::Credential => steps.extend(credential_steps(f)),
            registry::Resolver::DependencyAdvice => steps.push(dependency_step(f, advice)),
            registry::Resolver::WorkflowExpression => {
                steps.push(workflow_step(patches.get(&f.location.relative_path)))
            }
            registry::Resolver::WorkflowReview if f.rule_id == "gha-write-all-permissions" => {
                steps.push(Step::ManualAction {
                    description: format!(
                        "{} Review only: list what each job really needs (for example contents: read, \
                         pull-requests: write) and replace write-all with exactly that. JetScan does not \
                         edit permissions, because removing a permission a job uses breaks the workflow.",
                        resolver.guidance()
                    ),
                })
            }
            other => steps.push(Step::ManualAction {
                description: other.guidance().into(),
            }),
        }
    }
    let mut patched = false;
    for (path, patch) in &patches {
        if let Patch::Ready { old, new } = patch {
            patched = true;
            steps.push(Step::FilePatch {
                description: format!(
                    "Move untrusted GitHub event data used in run: scripts of {} into step env \
                     variables, used as \"${{NAME}}\" in the script (recipe {}).",
                    policy.text(path),
                    Recipe::WorkflowRunEnv.id()
                ),
                file_path: path.clone(),
                expected_old_hash: old.clone(),
                expected_new_hash: new.clone(),
                recipe: Recipe::WorkflowRunEnv,
            });
        }
    }
    if patched {
        steps.push(Step::ManualAction {
            description: "Review the exact diff (jetscan resolve preview), apply it only with explicit \
                confirmation (jetscan resolve apply --confirm), then re-check (jetscan resolve verify). \
                Applied changes stay unverified until that re-check."
                .into(),
        });
    }
    if findings.is_empty() {
        steps.push(Step::Explain {description:"No findings selected. No files will be changed; absence of findings is not proof of security.".into()});
    }
    Ok(PlanBuild {
        plan: ResolvePlan::new(&root, ids, steps, rules, warnings, policy)?,
        status: if incomplete || generator_error {
            CheckStatus::Partial
        } else {
            CheckStatus::Completed
        },
    })
}

fn try_recipe(root: &Path, path: &str) -> Patch {
    let old = match fs_guard::read(root, path) {
        Ok(old) => old,
        Err(ResolveError(code)) => return Patch::Unreadable(code),
    };
    match recipes::transform(Recipe::WorkflowRunEnv, &old) {
        Ok(new) => Patch::Ready {
            old: digest(&old),
            new: digest(&new),
        },
        Err(ResolveError(code)) => Patch::Unprovable(code),
    }
}

fn workflow_step(patch: Option<&Patch>) -> Step {
    let guidance = registry::Resolver::WorkflowExpression.guidance();
    match patch {
        Some(Patch::Ready { .. }) => Step::Explain {
            description: format!(
                "A reviewed recipe ({}) covers this finding; see the file patch below.",
                Recipe::WorkflowRunEnv.id()
            ),
        },
        Some(Patch::Unprovable(code)) => Step::ManualAction {
            description: format!(
                "A safe automatic edit cannot be proven for this file ({code}), so nothing will be \
                 changed automatically. {guidance}"
            ),
        },
        Some(Patch::Unreadable(code)) => Step::ManualAction {
            description: format!(
                "The file could not be read safely ({code}), so no automatic edit is offered. {guidance}"
            ),
        },
        None => Step::ManualAction {
            description: guidance.into(),
        },
    }
}

/// Leaked credentials: guidance only, revoke/rotate first. Never a file patch:
/// deleting the text does not make a leaked key safe.
fn credential_steps(f: &FindingV2) -> Vec<Step> {
    let mut steps = vec![
        Step::ManualAction {
            description: format!(
                "{} 1. Revoke and rotate this credential with its provider first. Deleting the \
                 text does not fix a leaked key: anyone who already copied it can use it until \
                 it is revoked.",
                registry::Resolver::Credential.guidance()
            ),
        },
        Step::ManualAction {
            description:
                "2. Replace the value in the code with a reference to a secret that is not \
                committed (CI secret, secret manager or an untracked environment file)."
                    .into(),
        },
        Step::ManualAction {
            description:
                "3. The old value stays in Git history, forks, clones, caches and CI logs. \
                Rewriting history (for example git filter-repo) is optional cleanup after \
                rotation, not a fix, and needs coordination with everyone who has a clone."
                    .into(),
        },
    ];
    if f.tags.iter().any(|t| t == "git-history") {
        steps.push(Step::ManualAction {
            description: "This occurrence is in Git history: it is exposed even if the current \
                files no longer contain it."
                .into(),
        });
    }
    steps
}

/// Dependency advisories: text only, never a subprocess or network request.
/// Commands from `deps::fix` are already restricted to a shell-safe alphabet
/// there; they pass the redaction policy again in `ResolvePlan::new`.
fn dependency_step(f: &FindingV2, advice: &Advice<'_>) -> Step {
    let lockfile = &f.location.relative_path;
    let component = f.location.component.as_deref().unwrap_or("");
    let mut lines = Vec::new();
    for s in advice.dependency_steps {
        if s.lockfile != *lockfile || !component.ends_with(&format!(":{}@{}", s.package, s.from)) {
            continue;
        }
        if let Some(command) = &s.command {
            lines.push(format!("command to review and run yourself: {command}"));
        }
        if let Some(edit) = &s.edit {
            lines.push(format!("manifest edit to make yourself: {edit}"));
        }
        if let Some(note) = s.note {
            lines.push(format!("note: {note}"));
        }
    }
    let advice = if lines.is_empty() {
        "Run `jetscan deps --fix` in the project to print the exact upgrade command or manifest \
         edit (it asks OSV.dev unless --offline)."
            .to_owned()
    } else {
        format!(
            "Upgrade advice from jetscan deps --fix (not executed): {}.",
            lines.join("; ")
        )
    };
    Step::ManualAction {
        description: format!(
            "{} Package {component} in {lockfile}. {advice} Resolve itself runs no package \
             manager and sends nothing.",
            registry::Resolver::DependencyAdvice.guidance(),
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::finding_v2::*;
    use crate::resolve::testutil::workflow_scan;
    pub fn scan(rule: &str) -> ScanResultV2 {
        ScanResultV2 {
            findings: vec![FindingV2 {
                id: "fixture/finding/0123456789abcdef".into(),
                rule_id: rule.into(),
                title: "Fixture issue".into(),
                category: "test".into(),
                severity: Severity::High,
                confidence: Confidence::Potential,
                location: SourceLocation {
                    relative_path: ".github/workflows/ci.yml".into(),
                    line: Some(6),
                    column: Some(1),
                    archive_entry: None,
                    component: None,
                },
                evidence: Evidence::default(),
                explanation: "Fixture only".into(),
                remediation_id: None,
                references: vec![],
                cwe_ids: vec![],
                tags: vec![],
            }],
            checks: vec![RuleCheck {
                id: rule.into(),
                status: CheckStatus::Completed,
                reason: None,
            }],
            ..ScanResultV2::default()
        }
    }
    fn texts(plan: &ResolvePlan) -> String {
        plan.render_json().unwrap()
    }
    #[test]
    fn advice_is_deterministic_redacted_and_read_only() {
        let p = testutil::Project::new();
        p.write("untouched.txt", "original");
        let mut input = scan("WEB-SECRET-001");
        let raw = ["arbitrary", "password"].join("-");
        input.findings[0].title = raw.clone();
        let policy = RedactionPolicy::new([raw.as_str()]);
        let first = plan(&p.0, &input, &policy).unwrap();
        let second = plan(&p.0, &input, &policy).unwrap();
        assert_eq!(first.plan, second.plan);
        assert_eq!(first.plan.status(), RemediationState::GuidanceOnly);
        let output = first.plan.render_json().unwrap();
        assert!(!output.contains(&raw));
        assert!(output.contains("Revoke and rotate"));
        assert!(output.contains("Potential"));
        assert!(output.contains("High"));
        assert_eq!(
            std::fs::read_to_string(p.0.join("untouched.txt")).unwrap(),
            "original"
        );
        assert_eq!(std::fs::read_dir(&p.0).unwrap().count(), 1);
    }
    #[test]
    fn incomplete_and_unknown_checks_do_not_become_success() {
        let p = testutil::Project::new();
        let mut input = scan("unknown-rule");
        input.checks[0].status = CheckStatus::Partial;
        input.checks[0].reason = Some("unsupported syntax".into());
        let built = plan(&p.0, &input, &RedactionPolicy::default()).unwrap();
        assert_eq!(built.status, CheckStatus::Partial);
        assert!(
            built
                .plan
                .render_json()
                .unwrap()
                .contains("No reviewed resolver")
        );
        input.findings.clear();
        input.checks.clear();
        assert_eq!(
            plan(&p.0, &input, &RedactionPolicy::default())
                .unwrap()
                .status,
            CheckStatus::Partial
        );
    }
    #[test]
    fn provable_workflow_gets_one_bound_patch_and_others_stay_manual() {
        let p = testutil::Project::new();
        p.copy_fixture("workflows/pr-title.yml", ".github/workflows/pr-title.yml");
        p.copy_fixture(
            "workflows/unquoted-comment.yml",
            ".github/workflows/unquoted-comment.yml",
        );
        p.copy_fixture("workflows/write-all.yml", ".github/workflows/write-all.yml");
        let before = p.snapshot();
        let input = workflow_scan(&p.0);
        assert_eq!(input.findings.len(), 3);
        let built = plan(&p.0, &input, &RedactionPolicy::default()).unwrap();
        // The legacy workflow adapter never claims complete coverage.
        assert_eq!(built.status, CheckStatus::Partial);
        let plan = built.plan;
        assert_eq!(plan.status(), RemediationState::Available);
        assert_eq!(plan.preconditions().len(), 1);
        assert_eq!(
            plan.preconditions()[0].file_path,
            ".github/workflows/pr-title.yml"
        );
        let text = texts(&plan);
        assert!(text.contains("recipe_expression_not_double_quoted"));
        assert!(text.contains("Review only"));
        assert!(text.contains("write-all is never automatically reduced"));
        assert_eq!(p.snapshot(), before, "planning is read-only");
    }
    fn dependency_scan() -> ScanResultV2 {
        use crate::deps;
        let finding = deps::VulnFinding {
            package: deps::Package {
                ecosystem: deps::Ecosystem::Npm,
                name: "axios".into(),
                version: "0.21.0".into(),
                lockfiles: vec!["package-lock.json".into()],
            },
            vuln: deps::Vuln {
                id: "GHSA-4w2v-q235-vp99".into(),
                aliases: vec![],
                summary: "fixture".into(),
                severity: deps::Severity::High,
                cvss: None,
                fixed: vec!["0.21.1".into()],
                malicious: false,
            },
            fix: Some("0.21.1".into()),
        };
        let scan = ScanResultV2 {
            findings: adapters::dependency(&finding).unwrap(),
            checks: vec![RuleCheck {
                id: "deps".into(),
                status: CheckStatus::Completed,
                reason: None,
            }],
            ..ScanResultV2::default()
        };
        scan.redacted(&RedactionPolicy::default())
            .unwrap()
            .as_scan()
            .clone()
    }
    #[test]
    fn dependency_findings_get_text_advice_only() {
        let p = testutil::Project::new();
        p.write("package-lock.json", "{}");
        let before = p.snapshot();
        let input = dependency_scan();
        let generic = plan(&p.0, &input, &RedactionPolicy::default()).unwrap();
        let text = texts(&generic.plan);
        assert!(text.contains("Package npm:axios@0.21.0 in package-lock.json"));
        assert!(text.contains("jetscan deps --fix"));
        assert!(text.contains("runs no package manager"));
        assert_eq!(generic.plan.status(), RemediationState::GuidanceOnly);
        assert_eq!(generic.status, CheckStatus::Completed);
        // Exact command text from deps::fix when the caller has it.
        let fix = DepsFixStep {
            lockfile: "package-lock.json".into(),
            package: "axios".into(),
            from: "0.21.0".into(),
            to: "0.21.1".into(),
            command: Some("npm install axios@0.21.1".into()),
            edit: None,
            note: None,
        };
        let other = DepsFixStep {
            package: "lodash".into(),
            command: Some("npm install lodash@4.17.21".into()),
            ..fix.clone()
        };
        let steps = [fix, other];
        let exact = plan_with(
            &p.0,
            &input,
            &RedactionPolicy::default(),
            &Advice {
                dependency_steps: &steps,
            },
        )
        .unwrap();
        let text = texts(&exact.plan);
        assert!(text.contains("command to review and run yourself: npm install axios@0.21.1"));
        assert!(
            !text.contains("lodash"),
            "advice for other packages is not mixed in"
        );
        // Advice only: nothing to apply, nothing written, nothing run.
        assert!(exact.plan.preconditions().is_empty());
        let applied = apply(&exact.plan, Some(exact.plan.id())).unwrap();
        assert_eq!(applied.state, RemediationState::GuidanceOnly);
        assert_eq!(p.snapshot(), before);
        let scratch = testutil::Project::new();
        let checked = verify::verify_in(&exact.plan, &scratch.0).unwrap();
        assert_eq!(checked.items[0].reason, "no_static_recheck_for_this_rule");
        assert_eq!(p.snapshot(), before);
    }
    #[test]
    fn unreadable_recipe_input_makes_the_plan_partial() {
        let p = testutil::Project::new();
        p.copy_fixture("workflows/pr-title.yml", ".github/workflows/pr-title.yml");
        let mut input = workflow_scan(&p.0);
        input.checks[0].status = CheckStatus::Completed;
        input.checks[0].reason = None;
        // Same findings, file grown past the guard limit after the scan.
        let big = format!(
            "{}#{}\n",
            recipes::tests::fixture("workflows/pr-title.yml"),
            "x".repeat(fs_guard::MAX_FILE_BYTES as usize)
        );
        p.write(".github/workflows/pr-title.yml", &big);
        let built = plan(&p.0, &input, &RedactionPolicy::default()).unwrap();
        assert_eq!(built.status, CheckStatus::Partial);
        assert_eq!(built.plan.status(), RemediationState::GuidanceOnly);
        assert!(texts(&built.plan).contains("invalid_or_large_file"));
    }
}
