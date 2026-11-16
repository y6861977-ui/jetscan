//! `apply`: the only code in Resolve that writes. All-or-nothing across files.
//!
//! 1. Nothing happens without the caller passing the exact plan id it
//!    confirmed (`--confirm` in the CLI); the check runs before any file access.
//! 2. Every target is checked before the first write: workflow path allowlist,
//!    no link/junction on any component, canonical containment in the plan
//!    root, regular non-read-only file, size bound, and hash. A file already
//!    equal to the planned result is skipped (second apply = no-op); any other
//!    hash than the planned source is refused (user edits are never overwritten).
//! 3. New bytes are recomputed from the recipe and must hash to the planned
//!    result. They are written to a temp file in the same directory (flushed
//!    and synced), permissions are copied, and a backup of the old bytes is
//!    written beside it.
//! 4. Right before each replace the path is re-checked and the file re-read: the
//!    hash, length and modification time must still match. Then an atomic
//!    same-directory rename replaces the file (directory synced on Unix).
//! 5. Any failure restores every file already replaced from its backup (only if
//!    it still holds our bytes), removes temp files and reports `RolledBack`;
//!    a file that could not be restored keeps its backup and gives `Failed`.
//!
//! Success is `AppliedUnverified`, never `Verified`: only `verify` can say that.
//! No shell, package manager, git or hook is ever run.
use super::*;
use crate::finding_v2::RemediationState;
use std::{
    fs::{self, OpenOptions, Permissions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::SystemTime,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOutcome {
    Written,
    AlreadyApplied,
    /// Replaced, then restored byte for byte from its backup.
    RolledBack,
    /// Not touched because an earlier step failed.
    NotWritten,
    /// Replaced but could not be restored (it changed after our write); the
    /// backup file was kept next to it.
    RestoreFailed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyReport {
    pub plan_id: String,
    /// `AppliedUnverified`, `GuidanceOnly` (nothing to apply), `RolledBack` or `Failed`.
    pub state: RemediationState,
    pub files: Vec<(String, FileOutcome)>,
    /// Fixed code of the failure that caused a rollback.
    pub error: Option<&'static str>,
}

/// Stages where tests inject failures or concurrent changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Temp file and backup are written; the target is not replaced yet.
    BeforeReplace,
    AfterReplace,
}

/// `confirmed_plan_id` must be the id of this plan, given after the user saw it.
pub fn apply(
    plan: &ResolvePlan,
    confirmed_plan_id: Option<&str>,
) -> Result<ApplyReport, ResolveError> {
    apply_with(plan, confirmed_plan_id, &mut |_, _| Ok(()))
}

struct Target {
    rel: String,
    path: PathBuf,
    old: Vec<u8>,
    new: Vec<u8>,
    stamp: Stamp,
    permissions: Permissions,
    expected_old: String,
    expected_new: String,
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: (u64, u64),
}
fn stamp(meta: &fs::Metadata) -> Stamp {
    Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino())
        },
    }
}

pub(crate) fn apply_with(
    plan: &ResolvePlan,
    confirmed_plan_id: Option<&str>,
    hook: &mut dyn FnMut(Stage, usize) -> Result<(), ResolveError>,
) -> Result<ApplyReport, ResolveError> {
    let confirmed = confirmed_plan_id.ok_or(ResolveError("confirmation_required"))?;
    if confirmed != plan.id() {
        return Err(ResolveError("confirmation_mismatch"));
    }
    plan.validate()?;
    let root = plan.root();
    let mut report = ApplyReport {
        plan_id: plan.id().into(),
        state: RemediationState::AppliedUnverified,
        files: Vec::new(),
        error: None,
    };
    if plan.status() != RemediationState::Available {
        report.state = RemediationState::GuidanceOnly;
        return Ok(report);
    }
    // Phase 1: check everything, write nothing.
    let mut pending = Vec::new();
    for step in plan.steps() {
        let Step::FilePatch {
            file_path,
            expected_old_hash,
            expected_new_hash,
            recipe,
            ..
        } = step
        else {
            continue;
        };
        if !recipes::workflow_path(file_path) {
            return Err(ResolveError("recipe_path_not_allowed"));
        }
        let path = fs_guard::checked_path(root, file_path)?;
        let meta = fs::symlink_metadata(&path).map_err(|_| ResolveError("file_unavailable"))?;
        let old = fs_guard::read(root, file_path)?;
        let current = digest(&old);
        if current == *expected_new_hash {
            report
                .files
                .push((file_path.clone(), FileOutcome::AlreadyApplied));
            continue;
        }
        if current != *expected_old_hash {
            return Err(ResolveError("source_changed"));
        }
        if meta.permissions().readonly() {
            return Err(ResolveError("read_only_target"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Replacing a hard-linked file would silently split the link.
            if meta.nlink() > 1 {
                return Err(ResolveError("hard_linked_target"));
            }
        }
        let new = recipes::transform(*recipe, &old)?;
        if digest(&new) != *expected_new_hash {
            return Err(ResolveError("recipe_output_mismatch"));
        }
        pending.push(Target {
            rel: file_path.clone(),
            path,
            old,
            new,
            stamp: stamp(&meta),
            permissions: meta.permissions(),
            expected_old: expected_old_hash.clone(),
            expected_new: expected_new_hash.clone(),
        });
    }
    // Phase 2: write all or nothing.
    let mut done: Vec<(usize, PathBuf)> = Vec::new();
    for (index, target) in pending.iter().enumerate() {
        match replace(root, target, index, hook) {
            Ok(backup) => done.push((index, backup)),
            Err((error, committed)) => {
                if let Some(backup) = committed {
                    done.push((index, backup));
                }
                report.error = Some(error.0);
                let mut restored_all = true;
                let mut outcomes = vec![FileOutcome::NotWritten; pending.len()];
                for (done_index, backup) in done.iter().rev() {
                    let t = &pending[*done_index];
                    if restore(root, t).is_ok() {
                        let _ = discard(backup);
                        outcomes[*done_index] = FileOutcome::RolledBack;
                    } else {
                        restored_all = false;
                        outcomes[*done_index] = FileOutcome::RestoreFailed;
                    }
                }
                report.state = if restored_all {
                    RemediationState::RolledBack
                } else {
                    RemediationState::Failed
                };
                for (t, outcome) in pending.iter().zip(outcomes) {
                    report.files.push((t.rel.clone(), outcome));
                }
                return Ok(report);
            }
        }
    }
    for ((_, backup), target) in done.iter().zip(&pending) {
        let _ = discard(backup);
        report
            .files
            .push((target.rel.clone(), FileOutcome::Written));
    }
    Ok(report)
}

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Remove one of our temp/backup files, but never through a directory that
/// became a link meanwhile (then it stays where it is).
fn discard(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let meta = fs::symlink_metadata(parent)?;
    if fs_guard::linked(&meta) || !meta.is_dir() {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    fs::remove_file(path)
}

/// A new sibling file `.<name>.jetscan-<kind>-<pid>-<n>`; never reuses a name.
fn sibling(
    path: &Path,
    kind: &str,
    bytes: &[u8],
    perms: &Permissions,
) -> Result<PathBuf, ResolveError> {
    let dir = path.parent().ok_or(ResolveError("invalid_parent"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(ResolveError("invalid_parent"))?;
    for _ in 0..16 {
        let candidate = dir.join(format!(
            ".{name}.jetscan-{kind}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate);
        let mut file = match file {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ResolveError("temp_file_failed")),
        };
        let written = file
            .write_all(bytes)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() || fs::set_permissions(&candidate, perms.clone()).is_err() {
            let _ = discard(&candidate);
            return Err(ResolveError("temp_file_failed"));
        }
        return Ok(candidate);
    }
    Err(ResolveError("temp_file_failed"))
}

/// The path and the bytes must still be exactly what phase 1 saw.
fn recheck(root: &Path, t: &Target, expected: &str) -> Result<(), ResolveError> {
    let path = fs_guard::checked_path(root, &t.rel)?;
    if path != t.path {
        return Err(ResolveError("path_changed"));
    }
    let bytes = fs_guard::read(root, &t.rel)?;
    if digest(&bytes) != expected {
        return Err(ResolveError("source_changed_during_apply"));
    }
    Ok(())
}

fn commit(tmp: &Path, target: &Path) -> Result<(), ResolveError> {
    if fs::rename(tmp, target).is_err() {
        let _ = discard(tmp);
        return Err(ResolveError("replace_failed"));
    }
    #[cfg(unix)]
    if let Some(dir) = target.parent()
        && let Ok(dir) = fs::File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Returns the backup path on success. On failure, `Some(backup)` means the
/// file was already replaced and the caller must roll it back.
fn replace(
    root: &Path,
    t: &Target,
    index: usize,
    hook: &mut dyn FnMut(Stage, usize) -> Result<(), ResolveError>,
) -> Result<PathBuf, (ResolveError, Option<PathBuf>)> {
    let tmp = sibling(&t.path, "tmp", &t.new, &t.permissions).map_err(|e| (e, None))?;
    let backup = match sibling(&t.path, "backup", &t.old, &t.permissions) {
        Ok(backup) => backup,
        Err(e) => {
            let _ = discard(&tmp);
            return Err((e, None));
        }
    };
    let cleanup = |e: ResolveError| {
        let _ = discard(&tmp);
        let _ = discard(&backup);
        (e, None)
    };
    hook(Stage::BeforeReplace, index).map_err(cleanup)?;
    recheck(root, t, &t.expected_old).map_err(cleanup)?;
    let meta =
        fs::symlink_metadata(&t.path).map_err(|_| cleanup(ResolveError("file_unavailable")))?;
    if stamp(&meta) != t.stamp {
        return Err(cleanup(ResolveError("source_changed_during_apply")));
    }
    if let Err(e) = commit(&tmp, &t.path) {
        let _ = discard(&backup);
        return Err((e, None));
    }
    if let Err(e) = hook(Stage::AfterReplace, index) {
        return Err((e, Some(backup)));
    }
    Ok(backup)
}

/// Put the old bytes back, only if the file still holds exactly our bytes.
fn restore(root: &Path, t: &Target) -> Result<(), ResolveError> {
    recheck(root, t, &t.expected_new)?;
    let tmp = sibling(&t.path, "restore", &t.old, &t.permissions)?;
    commit(&tmp, &t.path)?;
    let bytes = fs_guard::read(root, &t.rel)?;
    if digest(&bytes) != t.expected_old {
        return Err(ResolveError("restore_failed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_v2::RedactionPolicy;
    use crate::resolve::testutil::Project;

    pub(crate) fn two_file_plan(p: &Project) -> ResolvePlan {
        crate::resolve::testutil::patch_plan(
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
    fn writes_only_with_the_confirmed_plan_id_and_ends_unverified() {
        let p = Project::new();
        let plan = two_file_plan(&p);
        assert_eq!(plan.preconditions().len(), 2);
        let before = p.snapshot();
        assert_eq!(
            apply(&plan, None),
            Err(ResolveError("confirmation_required"))
        );
        assert_eq!(
            apply(&plan, Some("resolve/other")),
            Err(ResolveError("confirmation_mismatch"))
        );
        assert_eq!(p.snapshot(), before, "no write before confirmation");
        let report = apply(&plan, Some(plan.id())).unwrap();
        assert_eq!(report.state, RemediationState::AppliedUnverified);
        assert_eq!(report.error, None);
        assert!(report.files.iter().all(|(_, o)| *o == FileOutcome::Written));
        let after = p.snapshot();
        assert_eq!(after.len(), before.len(), "no temp or backup files left");
        for step in plan.steps() {
            if let Step::FilePatch {
                file_path,
                expected_new_hash,
                ..
            } = step
            {
                assert_eq!(digest(&after[file_path]), *expected_new_hash);
            }
        }
    }

    #[test]
    fn second_apply_is_a_no_op() {
        let p = Project::new();
        let plan = two_file_plan(&p);
        apply(&plan, Some(plan.id())).unwrap();
        let after = p.snapshot();
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

    #[test]
    fn any_failure_rolls_back_every_file_byte_for_byte() {
        for (stage, at) in [
            (Stage::BeforeReplace, 0),
            (Stage::BeforeReplace, 1),
            (Stage::AfterReplace, 0),
            (Stage::AfterReplace, 1),
        ] {
            let p = Project::new();
            let plan = two_file_plan(&p);
            let before = p.snapshot();
            let report = apply_with(&plan, Some(plan.id()), &mut |s, i| {
                if (s, i) == (stage, at) {
                    Err(ResolveError("injected"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
            assert_eq!(report.state, RemediationState::RolledBack, "{stage:?} {at}");
            assert_eq!(report.error, Some("injected"));
            assert!(
                report
                    .files
                    .iter()
                    .all(|(_, o)| matches!(o, FileOutcome::RolledBack | FileOutcome::NotWritten))
            );
            assert_eq!(
                p.snapshot(),
                before,
                "{stage:?} {at}: identical, no leftovers"
            );
        }
    }

    #[test]
    fn edit_between_check_and_replace_is_never_overwritten() {
        let p = Project::new();
        let plan = two_file_plan(&p);
        let user = p.0.join(".github/workflows/issue-triage.yml");
        let report = apply_with(&plan, Some(plan.id()), &mut |s, i| {
            if (s, i) == (Stage::BeforeReplace, 1) {
                fs::write(&user, "user edit\n").unwrap();
            }
            Ok(())
        })
        .unwrap();
        // Step 0 (pr-title) was replaced, then restored; the user's edit of
        // step 1 (issue-triage), made after the checks, is kept.
        assert_eq!(report.state, RemediationState::RolledBack);
        assert_eq!(report.error, Some("source_changed_during_apply"));
        assert_eq!(fs::read(&user).unwrap(), b"user edit\n");
        let title = fs::read(p.0.join(".github/workflows/pr-title.yml")).unwrap();
        assert_eq!(
            title,
            fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/resolve/workflows/pr-title.yml")
            )
            .unwrap()
        );
        assert_eq!(p.snapshot().len(), 2, "no temp or backup files left");
    }

    #[test]
    fn file_changed_since_plan_is_refused_before_any_write() {
        let p = Project::new();
        let plan = two_file_plan(&p);
        p.write(".github/workflows/pr-title.yml", "edited after preview\n");
        let before = p.snapshot();
        assert_eq!(
            apply(&plan, Some(plan.id())),
            Err(ResolveError("source_changed"))
        );
        assert_eq!(p.snapshot(), before);
    }

    #[test]
    fn guidance_only_plan_writes_nothing() {
        let p = Project::new();
        p.copy_fixture("workflows/write-all.yml", ".github/workflows/write-all.yml");
        let scan = crate::resolve::testutil::workflow_scan(&p.0);
        let plan = planner::plan(&p.0, &scan, &RedactionPolicy::default())
            .unwrap()
            .plan;
        let before = p.snapshot();
        let report = apply(&plan, Some(plan.id())).unwrap();
        assert_eq!(report.state, RemediationState::GuidanceOnly);
        assert!(report.files.is_empty());
        assert_eq!(p.snapshot(), before);
    }

    #[cfg(unix)]
    #[test]
    fn unix_mode_is_preserved() {
        use std::os::unix::fs::PermissionsExt;
        let p = Project::new();
        let plan = two_file_plan(&p);
        let file = p.0.join(".github/workflows/pr-title.yml");
        fs::set_permissions(&file, Permissions::from_mode(0o640)).unwrap();
        apply(&plan, Some(plan.id())).unwrap();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn read_only_target_is_refused_before_writing() {
        let p = Project::new();
        let plan = two_file_plan(&p);
        let file = p.0.join(".github/workflows/pr-title.yml");
        let mut perms = fs::metadata(&file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file, perms.clone()).unwrap();
        let before = p.snapshot();
        assert_eq!(
            apply(&plan, Some(plan.id())),
            Err(ResolveError("read_only_target"))
        );
        assert_eq!(p.snapshot(), before);
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(&file, perms).unwrap();
    }
}
