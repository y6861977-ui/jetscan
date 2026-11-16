//! CX-RES-09: property and regression tests for the write path and plans.
use super::testutil::{Project, patch_plan, workflow_scan};
use super::*;
use crate::finding_v2::{CheckStatus, RedactionPolicy, RemediationState};
use std::{
    fs,
    path::{Path, PathBuf},
};

const TITLE: (&str, &str) = ("workflows/pr-title.yml", ".github/workflows/pr-title.yml");
const TRIAGE: (&str, &str) = (
    "workflows/issue-triage.yml",
    ".github/workflows/issue-triage.yml",
);

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/resolve")
            .join(name),
    )
    .unwrap()
}

/// `\\?\C:\x` -> `C:\x` for cmd.exe.
#[cfg(windows)]
fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text).to_string())
}

/// A directory link: a real junction on Windows (`mklink /J` needs no
/// privileges, unlike symlinks), a symlink elsewhere.
fn link_dir(link: &Path, target: &Path) {
    #[cfg(windows)]
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(plain(link))
        .arg(plain(target))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link).is_ok();
    assert!(made, "could not create a directory link");
}
fn unlink_dir(link: &Path) {
    #[cfg(windows)]
    fs::remove_dir(link).unwrap();
    #[cfg(unix)]
    fs::remove_file(link).unwrap();
}

#[test]
fn applying_again_and_again_converges_to_one_result() {
    for files in [&[TITLE][..], &[TRIAGE], &[TITLE, TRIAGE]] {
        let p = Project::new();
        let plan = patch_plan(&p, files);
        let first = apply(&plan, Some(plan.id())).unwrap();
        assert!(first.files.iter().all(|(_, o)| *o == FileOutcome::Written));
        let after = p.snapshot();
        for _ in 0..3 {
            let again = apply(&plan, Some(plan.id())).unwrap();
            assert_eq!(again.state, RemediationState::AppliedUnverified);
            assert!(
                again
                    .files
                    .iter()
                    .all(|(_, o)| *o == FileOutcome::AlreadyApplied)
            );
            assert_eq!(p.snapshot(), after);
        }
        // A plan made from the patched project has nothing left to patch.
        let replanned = planner::plan(&p.0, &workflow_scan(&p.0), &RedactionPolicy::default())
            .unwrap()
            .plan;
        assert!(replanned.preconditions().is_empty());
    }
}

#[test]
fn source_changed_after_preview_is_rejected() {
    let p = Project::new();
    let plan = patch_plan(&p, &[TITLE, TRIAGE]);
    preview(&plan, &RedactionPolicy::default()).unwrap();
    // One byte changed in the second file, after the preview was shown.
    let path = p.0.join(TRIAGE.1);
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, &bytes).unwrap();
    let before = p.snapshot();
    assert_eq!(
        preview(&plan, &RedactionPolicy::default()),
        Err(ResolveError("source_changed"))
    );
    assert_eq!(
        apply(&plan, Some(plan.id())),
        Err(ResolveError("source_changed"))
    );
    assert_eq!(
        p.snapshot(),
        before,
        "the unchanged first file is not written either"
    );
}

#[test]
fn linked_workflow_directory_is_rejected_and_its_target_untouched() {
    let p = Project::new();
    let plan = patch_plan(&p, &[TITLE]);
    // Same bytes elsewhere, reachable through a link at the same path.
    let elsewhere = Project::new();
    elsewhere.copy_fixture(TITLE.0, "wf/pr-title.yml");
    let workflows = p.0.join(".github/workflows");
    fs::rename(&workflows, p.0.join(".github/real")).unwrap();
    link_dir(&workflows, &elsewhere.0.join("wf"));
    let outside = elsewhere.snapshot();
    assert_eq!(
        preview(&plan, &RedactionPolicy::default()),
        Err(ResolveError("linked_path"))
    );
    assert_eq!(
        apply(&plan, Some(plan.id())),
        Err(ResolveError("linked_path"))
    );
    assert_eq!(elsewhere.snapshot(), outside);
    unlink_dir(&workflows);
}

#[test]
fn swap_to_a_link_during_apply_is_rejected_and_rolled_back() {
    let p = Project::new();
    let plan = patch_plan(&p, &[TRIAGE, TITLE]);
    let elsewhere = Project::new();
    elsewhere.copy_fixture(TITLE.0, "wf/pr-title.yml");
    elsewhere.copy_fixture(TRIAGE.0, "wf/issue-triage.yml");
    let outside = elsewhere.snapshot();
    let workflows = p.0.join(".github/workflows");
    let real = p.0.join(".github/real");
    let report = apply::apply_with(&plan, Some(plan.id()), &mut |stage, index| {
        if (stage, index) == (apply::Stage::BeforeReplace, 1) {
            fs::rename(&workflows, &real).unwrap();
            link_dir(&workflows, &elsewhere.0.join("wf"));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(report.error, Some("linked_path"));
    // File 0 was replaced in the real directory before the swap; its restore
    // goes through the same guarded path, now a link, so it is refused and
    // the backup is kept: Failed, not silently "rolled back".
    assert_eq!(report.state, RemediationState::Failed);
    assert_eq!(report.files[0].1, FileOutcome::RestoreFailed);
    assert_eq!(
        elsewhere.snapshot(),
        outside,
        "nothing written through the link"
    );
    unlink_dir(&workflows);
    fs::rename(&real, &workflows).unwrap();
    // The kept backup holds the original bytes for a manual restore. (Temp
    // files of the second file stay in the moved directory: their cleanup is
    // never done through a link. Documented limitation.)
    let snapshot = p.snapshot();
    assert!(snapshot.iter().any(
        |(name, bytes)| name.contains(".issue-triage.yml.jetscan-backup-")
            && *bytes == fixture(TRIAGE.0)
    ));
    assert_eq!(
        fs::read(p.0.join(TITLE.1)).unwrap(),
        fixture(TITLE.0),
        "the second file was never replaced"
    );
}

#[test]
fn root_replaced_by_a_link_is_rejected() {
    let outer = Project::new();
    let root = outer.0.join("project");
    fs::create_dir(&root).unwrap();
    let p = Project(fs::canonicalize(&root).unwrap());
    let plan = patch_plan(&p, &[TITLE]);
    let twin = Project::new();
    twin.copy_fixture(TITLE.0, TITLE.1);
    let outside = twin.snapshot();
    fs::rename(&p.0, outer.0.join("moved")).unwrap();
    link_dir(&p.0, &twin.0);
    assert_eq!(
        apply(&plan, Some(plan.id())),
        Err(ResolveError("root_changed"))
    );
    assert_eq!(verify(&plan), Err(ResolveError("root_changed")));
    assert_eq!(twin.snapshot(), outside);
    unlink_dir(&p.0);
    fs::rename(outer.0.join("moved"), &p.0).unwrap();
}

#[test]
fn malicious_paths_in_plans_are_rejected() {
    let p = Project::new();
    let plan = patch_plan(&p, &[TITLE]);
    let json = plan.render_json().unwrap();
    let policy = RedactionPolicy::default();
    for path in [
        "../pr-title.yml",
        ".github/workflows/../../x.yml",
        "/etc/x.yml",
        "C:\\x.yml",
        "C:/x.yml",
        "\\\\server\\share\\x.yml",
        "//server/share/x.yml",
        ".github/workflows/pr-title.yml:stream",
        ".github/workflows/pr-title.yml::$DATA",
        ".github/workflows/./pr-title.yml",
        ".git/hooks/pre-commit",
        ".github/workflows/CON.yml",
        ".github/workflows/pr-title.yml.",
        "~/x.yml",
        ".github/workflows/\u{1b}[31m.yml",
    ] {
        let step = Step::FilePatch {
            description: "x".into(),
            file_path: path.into(),
            expected_old_hash: digest(b"a"),
            expected_new_hash: digest(b"b"),
            recipe: Recipe::WorkflowRunEnv,
        };
        let direct = ResolvePlan::new(
            &p.0,
            vec!["f".into()],
            vec![step],
            vec!["r".into()],
            vec![],
            &policy,
        );
        assert!(
            matches!(
                direct,
                Err(ResolveError(
                    "invalid_patch_path" | "protected_or_ambiguous_path" | "unsafe_plan_binding"
                ))
            ),
            "{path}"
        );
        // Same through a crafted plan file (the id is only a content hash).
        let escaped = crate::json::stringify(&crate::json::Json::Str(path.into()));
        let crafted = json.replace("\".github/workflows/pr-title.yml\"", &escaped);
        assert!(ResolvePlan::parse(&crafted, &policy).is_err(), "{path}");
    }
    // A clean relative path outside the workflow allowlist is never written.
    let other = ResolvePlan::new(
        &p.0,
        vec!["f".into()],
        vec![Step::FilePatch {
            description: "x".into(),
            file_path: "src/main.rs".into(),
            expected_old_hash: digest(b"a"),
            expected_new_hash: digest(b"b"),
            recipe: Recipe::WorkflowRunEnv,
        }],
        vec!["r".into()],
        vec![],
        &policy,
    )
    .unwrap();
    let before = p.snapshot();
    assert_eq!(
        apply(&other, Some(other.id())),
        Err(ResolveError("recipe_path_not_allowed"))
    );
    assert_eq!(p.snapshot(), before);
    // A plan file cannot carry a diff or a command.
    let with_diff = json.replace(
        "\"kind\":\"file_patch\"",
        "\"diff\":\"+x\",\"kind\":\"file_patch\"",
    );
    assert_eq!(
        ResolvePlan::parse(&with_diff, &policy),
        Err(ResolveError("unexpected_or_missing_plan_field"))
    );
}

#[test]
fn nothing_is_written_before_confirmation() {
    let p = Project::new();
    let plan = patch_plan(&p, &[TITLE, TRIAGE]);
    let before = p.snapshot();
    let text = plan.render_pretty().unwrap();
    let plan = ResolvePlan::parse(&text, &RedactionPolicy::default()).unwrap();
    preview(&plan, &RedactionPolicy::default()).unwrap();
    for id in [None, Some(""), Some("resolve/0"), Some(&plan.id()[..20])] {
        assert!(apply(&plan, id).is_err());
    }
    assert_eq!(p.snapshot(), before);
}

#[test]
fn rollback_restores_crlf_and_bom_files_byte_for_byte() {
    let p = Project::new();
    let crlf = String::from_utf8(fixture(TITLE.0))
        .unwrap()
        .replace('\n', "\r\n");
    p.write(".github/workflows/crlf.yml", &format!("\u{feff}{crlf}"));
    // patch_plan copies fixtures; add the CRLF file by hand afterwards.
    let base = patch_plan(&p, &[TRIAGE]);
    let old = fs::read(p.0.join(".github/workflows/crlf.yml")).unwrap();
    let new = recipes::transform(Recipe::WorkflowRunEnv, &old).unwrap();
    assert!(new.starts_with("\u{feff}".as_bytes()));
    assert!(
        !String::from_utf8(new.clone())
            .unwrap()
            .replace("\r\n", "")
            .contains('\n')
    );
    let mut steps = base.steps().to_vec();
    steps.push(Step::FilePatch {
        description: "crlf".into(),
        file_path: ".github/workflows/crlf.yml".into(),
        expected_old_hash: digest(&old),
        expected_new_hash: digest(&new),
        recipe: Recipe::WorkflowRunEnv,
    });
    let plan = ResolvePlan::new(
        &p.0,
        base.finding_ids().to_vec(),
        steps,
        base.verification_rule_ids().to_vec(),
        vec![],
        &RedactionPolicy::default(),
    )
    .unwrap();
    let before = p.snapshot();
    let report = apply::apply_with(&plan, Some(plan.id()), &mut |stage, index| {
        if (stage, index) == (apply::Stage::AfterReplace, 1) {
            Err(ResolveError("injected"))
        } else {
            Ok(())
        }
    })
    .unwrap();
    assert_eq!(report.state, RemediationState::RolledBack);
    assert_eq!(p.snapshot(), before);
    // And without the fault the CRLF + BOM file is written as planned.
    apply(&plan, Some(plan.id())).unwrap();
    assert_eq!(
        digest(&fs::read(p.0.join(".github/workflows/crlf.yml")).unwrap()),
        digest(&new)
    );
}

#[test]
fn concurrent_applies_never_leave_a_partial_file() {
    for _ in 0..8 {
        let p = Project::new();
        let plan = patch_plan(&p, &[TITLE, TRIAGE]);
        let old = p.snapshot();
        std::thread::scope(|s| {
            let a = s.spawn(|| apply(&plan, Some(plan.id())));
            let b = s.spawn(|| apply(&plan, Some(plan.id())));
            let _ = (a.join().unwrap(), b.join().unwrap());
        });
        let after = p.snapshot();
        assert_eq!(after.len(), old.len(), "no temp or backup files left");
        for step in plan.steps() {
            if let Step::FilePatch {
                file_path,
                expected_old_hash,
                expected_new_hash,
                ..
            } = step
            {
                let h = digest(&after[file_path]);
                assert!(h == *expected_old_hash || h == *expected_new_hash);
            }
        }
        // Whatever the interleaving, one more apply converges.
        apply(&plan, Some(plan.id())).unwrap();
        assert_eq!(verify(&plan).unwrap().state, RemediationState::Verified);
    }
}

#[test]
fn partial_generator_errors_give_a_partial_plan() {
    let q = Project::new();
    q.copy_fixture(TITLE.0, TITLE.1);
    let mut scan = workflow_scan(&q.0);
    // Count only generator errors: the input scan itself is marked complete.
    scan.checks[0].status = CheckStatus::Completed;
    scan.checks[0].reason = None;
    // A second finding whose file cannot be read (gone since the scan).
    let mut gone = scan.findings[0].clone();
    let last = if gone.id.ends_with('0') { "1" } else { "0" };
    gone.id = format!("{}{last}", &gone.id[..gone.id.len() - 1]);
    gone.location.relative_path = ".github/workflows/missing.yml".into();
    scan.findings.push(gone);
    let built = planner::plan(&q.0, &scan, &RedactionPolicy::default()).unwrap();
    assert_eq!(
        built.status,
        CheckStatus::Partial,
        "one recipe input unreadable"
    );
    assert_eq!(
        built.plan.preconditions().len(),
        1,
        "the readable file is still planned"
    );
    assert!(
        built
            .plan
            .render_json()
            .unwrap()
            .contains("file_unavailable")
    );
}

#[test]
fn leaked_secret_is_guidance_only_and_never_shown() {
    let p = Project::new();
    // Fake key built at runtime from pieces; never a real credential.
    let fake = format!("AKIA{}{}", "Q7MZ3X2W", "PLK4RT9N");
    p.write("config.js", &format!("const key = \"{fake}\";\n"));
    let before = p.snapshot();
    let mut scan = planner::tests::scan("aws-access-key");
    scan.findings[0].id = "secrets/aws-access-key/0123456789abcdef".into();
    scan.findings[0].category = "secret_exposure".into();
    scan.findings[0].location.relative_path = "config.js".into();
    scan.findings[0].title = format!("key {fake}");
    scan.findings[0].tags = vec!["git-history".into()];
    let built = planner::plan(&p.0, &scan, &RedactionPolicy::default()).unwrap();
    let plan = built.plan;
    assert_eq!(plan.status(), RemediationState::GuidanceOnly);
    assert!(plan.preconditions().is_empty());
    let text = plan.render_json().unwrap();
    let shown = preview(&plan, &RedactionPolicy::default()).unwrap().text;
    for out in [&text, &shown] {
        assert!(!out.contains(&fake), "raw secret never in plan or preview");
        assert!(out.contains("Revoke and rotate this credential with its provider first"));
        assert!(out.contains("Deleting the text does not fix a leaked key"));
        assert!(out.contains("Git history"));
        assert!(out.contains("not a fix"));
    }
    let applied = apply(&plan, Some(plan.id())).unwrap();
    assert_eq!(applied.state, RemediationState::GuidanceOnly);
    let checked = verify(&plan).unwrap();
    assert_eq!(
        checked.items[0].reason,
        "credential_revocation_cannot_be_checked_locally"
    );
    assert_eq!(p.snapshot(), before);
}

#[test]
fn control_characters_in_workflows_stay_manual_and_out_of_output() {
    let p = Project::new();
    let text = String::from_utf8(fixture(TITLE.0)).unwrap().replace(
        "permissions:",
        "# \u{1b}[2J\u{1b}[31mowned\u{1b}[0m\npermissions:",
    );
    p.write(TITLE.1, &text);
    let scan = workflow_scan(&p.0);
    let plan = planner::plan(&p.0, &scan, &RedactionPolicy::default())
        .unwrap()
        .plan;
    assert!(plan.preconditions().is_empty());
    let out =
        plan.render_json().unwrap() + &preview(&plan, &RedactionPolicy::default()).unwrap().text;
    assert!(!out.contains('\u{1b}'));
    assert_eq!(
        scan.findings.len(),
        1,
        "the scanner still sees the injection"
    );
    assert!(out.contains("recipe_control_characters"));
}
