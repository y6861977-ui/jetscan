//! Free Resolve library. No license gate and no implicit command execution.
//!
//! scan report -> `plan` (read-only) -> `preview` (read-only diff) ->
//! `apply` (explicit confirmation; atomic, all-or-nothing) -> `verify`
//! (re-runs the specific check). See `docs/resolve/README.md`.
mod model;
pub use model::{FilePrecondition, Recipe, ResolvePlan, Step};
use std::fmt;

pub const PLAN_VERSION: u32 = 1;

/// Fixed error codes: never include source, paths, secrets or OS error messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveError(pub &'static str);
impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ResolveError {}
pub(crate) fn digest(bytes: &[u8]) -> String {
    crate::hash::hex(&crate::hash::sha256(bytes))
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use crate::finding_v2::{RedactionPolicy, ScanResultV2, adapters};
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    pub struct Project(pub PathBuf);
    impl Project {
        pub fn new() -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/resolve/.scratch");
            fs::create_dir_all(&root).unwrap();
            loop {
                let path = root.join(format!(
                    "{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                match fs::create_dir(&path) {
                    // Canonical, as a plan root is.
                    Ok(()) => return Self(fs::canonicalize(path).unwrap()),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(_) => panic!("test directory unavailable"),
                }
            }
        }
        pub fn write(&self, path: &str, text: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        /// Copy `fixtures/resolve/<from>` byte for byte to `<project>/<to>`.
        pub fn copy_fixture(&self, from: &str, to: &str) {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/resolve")
                .join(from);
            let target = self.0.join(to);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(source, target).unwrap();
        }
        /// Every file under the project (relative path -> bytes), links not followed.
        pub fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
            fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
                for entry in fs::read_dir(dir).unwrap().flatten() {
                    let path = entry.path();
                    let meta = fs::symlink_metadata(&path).unwrap();
                    let rel = path
                        .strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    if meta.is_dir() && !fs_guard::linked(&meta) {
                        walk(base, &path, out);
                    } else if meta.is_file() {
                        out.insert(rel, fs::read(&path).unwrap());
                    } else {
                        out.insert(rel, b"<link>".to_vec());
                    }
                }
            }
            let mut out = BTreeMap::new();
            walk(&self.0, &self.0, &mut out);
            out
        }
    }
    impl Drop for Project {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    /// Real workflow scanner output for a project, through the V2 adapter.
    pub fn workflow_scan(root: &Path) -> ScanResultV2 {
        adapters::workflows(&crate::workflows::check(root))
            .unwrap()
            .redacted(&RedactionPolicy::default())
            .unwrap()
            .as_scan()
            .clone()
    }
    /// A plan with one reviewed patch per (fixture, project path), hashes from
    /// disk, bound to the real workflow scanner findings of the project.
    pub fn patch_plan(project: &Project, files: &[(&str, &str)]) -> ResolvePlan {
        for (fixture, path) in files {
            project.copy_fixture(fixture, path);
        }
        let scan = workflow_scan(&project.0);
        let mut steps = Vec::new();
        for (_, path) in files {
            let old = fs::read(project.0.join(path)).unwrap();
            let new = recipes::transform(Recipe::WorkflowRunEnv, &old).unwrap();
            steps.push(Step::FilePatch {
                description: "Move event data to env".into(),
                file_path: (*path).into(),
                expected_old_hash: digest(&old),
                expected_new_hash: digest(&new),
                recipe: Recipe::WorkflowRunEnv,
            });
        }
        ResolvePlan::new(
            &project.0,
            scan.findings.iter().map(|f| f.id.clone()).collect(),
            steps,
            scan.findings.iter().map(|f| f.rule_id.clone()).collect(),
            vec![],
            &RedactionPolicy::default(),
        )
        .unwrap()
    }
}

pub mod registry;

pub mod planner;
pub use planner::{Advice, PlanBuild, plan, plan_with};

mod fs_guard;
mod preview;
mod recipes;
pub use preview::{Preview, preview};

mod apply;
pub use apply::{ApplyReport, FileOutcome, apply};

mod verify;
pub use verify::{Outcome, VerifyItem, VerifyReport, verify};

/// `jetscan resolve ...` runner (wired from `src/main.rs` by the integrator).
pub mod cli;

#[cfg(test)]
mod e2e;
#[cfg(test)]
mod regression;
