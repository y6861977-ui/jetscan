use super::*;
use crate::finding_v2::RedactionPolicy;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub plan_id: String,
    pub text: String,
}

/// For display only: `\\?\C:\x` reads as `C:\x` (verbatim UNC paths are kept). The plan
/// itself keeps the canonical root.
pub(super) fn display_path(path: &std::path::Path) -> String {
    let text = path.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with(r"UNC\") => rest.to_owned(),
        _ => text,
    }
}

/// All hunks are generated from exact recipe bytes. Diff text is never input to
/// apply; no commands run and no files are written here.
pub fn preview(plan: &ResolvePlan, policy: &RedactionPolicy<'_>) -> Result<Preview, ResolveError> {
    plan.validate()?;
    let mut text = format!(
        "Plan {}\nProject: {}\nStatus: {:?}\n",
        plan.id(),
        policy.text(&display_path(plan.root())),
        plan.status()
    );
    for warning in plan.warnings() {
        text.push_str(&format!("Warning: {}\n", policy.text(warning)));
    }
    for step in plan.steps() {
        match step {
            Step::Explain { description } | Step::ManualAction { description } => {
                text.push_str(&format!("{}\n", policy.text(description)))
            }
            Step::FilePatch {
                description,
                file_path,
                expected_old_hash,
                expected_new_hash,
                recipe,
            } => {
                if !recipes::workflow_path(file_path) {
                    return Err(ResolveError("recipe_path_not_allowed"));
                }
                let old = fs_guard::read(plan.root(), file_path)?;
                let current = digest(&old);
                if current == *expected_new_hash {
                    text.push_str(&format!(
                        "{}\nAlready applied: {} matches the planned result.\n",
                        policy.text(description),
                        policy.text(file_path)
                    ));
                    continue;
                }
                if current != *expected_old_hash {
                    return Err(ResolveError("source_changed"));
                }
                let new = recipes::transform(*recipe, &old)?;
                if digest(&new) != *expected_new_hash {
                    return Err(ResolveError("recipe_output_mismatch"));
                }
                let old =
                    std::str::from_utf8(&old).map_err(|_| ResolveError("unsupported_encoding"))?;
                let new =
                    std::str::from_utf8(&new).map_err(|_| ResolveError("unsupported_encoding"))?;
                text.push_str(&format!(
                    "{}\n--- a/{}\n+++ b/{}\n",
                    policy.text(description),
                    policy.text(file_path),
                    policy.text(file_path)
                ));
                for line in unified(old, new) {
                    // Hunk headers are ours; content lines are untrusted.
                    if line.starts_with("@@") {
                        text.push_str(&line);
                    } else {
                        let (mark, rest) = line.split_at(1);
                        text.push_str(mark);
                        text.push_str(&policy.text(rest));
                    }
                    text.push('\n');
                }
                if text.len() > 2 * 1024 * 1024 {
                    return Err(ResolveError("preview_limit"));
                }
            }
        }
    }
    Ok(Preview {
        plan_id: plan.id().into(),
        text,
    })
}

#[derive(Clone, Copy)]
enum Op {
    Equal(usize),
    Delete(usize),
    Insert(usize),
}

/// Myers shortest edit script; `None` when the work would exceed a fixed bound.
fn edit_script(a: &[&str], b: &[&str]) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = n + m;
    let offset = max + 1;
    let width = (2 * max + 3) as usize;
    let mut v = vec![0isize; width];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut budget: usize = 50_000_000;
    for d in 0..=max {
        budget = budget.checked_sub(width)?;
        trace.push(v.clone());
        let mut k = -d;
        while k <= d {
            let i = (k + offset) as usize;
            let mut x = if k == -d || (k != d && v[i - 1] < v[i + 1]) {
                v[i + 1]
            } else {
                v[i - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[i] = x;
            if x >= n && y >= m {
                return Some(backtrack(&trace, n, m, offset));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(trace: &[Vec<isize>], n: isize, m: isize, offset: isize) -> Vec<Op> {
    let (mut x, mut y) = (n, m);
    let mut ops = Vec::new();
    for (d, v) in trace.iter().enumerate().rev() {
        let d = d as isize;
        let k = x - y;
        let at = |k: isize| v[(k + offset) as usize];
        let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Equal((x - 1) as usize));
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(Op::Insert((y - 1) as usize));
            } else {
                ops.push(Op::Delete((x - 1) as usize));
            }
        }
        x = prev_x;
        y = prev_y;
    }
    ops.reverse();
    ops
}

/// Unified diff lines (`@@` headers and ` `/`-`/`+` lines) with 3 lines of context.
fn unified(old: &str, new: &str) -> Vec<String> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let Some(ops) = edit_script(&a, &b) else {
        // Bounded fallback: one whole-file hunk.
        let mut out = vec![format!("@@ -1,{} +1,{} @@", a.len(), b.len())];
        out.extend(a.iter().map(|l| format!("-{l}")));
        out.extend(b.iter().map(|l| format!("+{l}")));
        return out;
    };
    // Position in a and b before each op.
    let mut positions = Vec::with_capacity(ops.len() + 1);
    let (mut pa, mut pb) = (0usize, 0usize);
    for op in &ops {
        positions.push((pa, pb));
        match op {
            Op::Equal(_) => {
                pa += 1;
                pb += 1;
            }
            Op::Delete(_) => pa += 1,
            Op::Insert(_) => pb += 1,
        }
    }
    let changes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Op::Equal(_)))
        .map(|(i, _)| i)
        .collect();
    let mut out = Vec::new();
    let mut index = 0;
    while index < changes.len() {
        let first = changes[index];
        let mut last = first;
        while index + 1 < changes.len() && changes[index + 1] - last <= 7 {
            index += 1;
            last = changes[index];
        }
        index += 1;
        let start = first.saturating_sub(3);
        let end = (last + 4).min(ops.len());
        let (sa, sb) = positions[start];
        let hunk = &ops[start..end];
        let la = hunk.iter().filter(|o| !matches!(o, Op::Insert(_))).count();
        let lb = hunk.iter().filter(|o| !matches!(o, Op::Delete(_))).count();
        let pos = |p: usize, len: usize| if len == 0 { p } else { p + 1 };
        out.push(format!("@@ -{},{la} +{},{lb} @@", pos(sa, la), pos(sb, lb)));
        for op in hunk {
            out.push(match *op {
                Op::Equal(i) => format!(" {}", a[i]),
                Op::Delete(i) => format!("-{}", a[i]),
                Op::Insert(j) => format!("+{}", b[j]),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preview_is_stable_minimal_diff_and_read_only() {
        let p = testutil::Project::new();
        let plan = testutil::patch_plan(
            &p,
            &[("workflows/pr-title.yml", ".github/workflows/ci.yml")],
        );
        let before = p.snapshot();
        let a = preview(&plan, &RedactionPolicy::default()).unwrap();
        assert_eq!(a, preview(&plan, &RedactionPolicy::default()).unwrap());
        assert!(!a.text.contains(r"\\?\"), "{}", a.text);
        assert!(
            a.text
                .contains(&format!("Project: {}\n", display_path(plan.root()))),
            "{}",
            a.text
        );
        assert!(a.text.contains(
            "@@ -9,8 +9,10 @@\n     runs-on: ubuntu-latest\n     steps:\n       - name: Check the title format\n+        env:\n+          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}\n         run: |\n-          title=\"${{ github.event.pull_request.title }}\"\n+          title=\"${PULL_REQUEST_TITLE}\"\n"
        ), "{}", a.text);
        assert_eq!(p.snapshot(), before);
        p.write(".github/workflows/ci.yml", "user edit");
        assert_eq!(
            preview(&plan, &RedactionPolicy::default()),
            Err(ResolveError("source_changed"))
        );
    }
    #[test]
    fn displayed_paths_drop_only_the_drive_verbatim_prefix() {
        use std::path::Path;
        assert_eq!(display_path(Path::new(r"\\?\C:\work\app")), r"C:\work\app");
        assert_eq!(
            display_path(Path::new(r"\\?\UNC\srv\share")),
            r"\\?\UNC\srv\share"
        );
        assert_eq!(display_path(Path::new("/home/u/app")), "/home/u/app");
    }
    #[test]
    fn diff_hunks_are_exact_for_edge_cases() {
        assert_eq!(unified("a\nb\n", "a\nb\n"), Vec::<String>::new());
        assert_eq!(unified("", "x\n"), vec!["@@ -0,0 +1,1 @@", "+x"]);
        assert_eq!(unified("x\n", ""), vec!["@@ -1,1 +0,0 @@", "-x"]);
        let old: String = (1..=20).map(|i| format!("{i}\n")).collect();
        let new: String = (1..=20)
            .map(|i| match i {
                2 => "two\n".to_owned(),
                19 => "nineteen\n".to_owned(),
                i => format!("{i}\n"),
            })
            .collect();
        assert_eq!(
            unified(&old, &new),
            vec![
                "@@ -1,5 +1,5 @@",
                " 1",
                "-2",
                "+two",
                " 3",
                " 4",
                " 5",
                "@@ -16,5 +16,5 @@",
                " 16",
                " 17",
                " 18",
                "-19",
                "+nineteen",
                " 20",
            ]
        );
    }
    #[test]
    fn unknown_source_and_controls_are_not_copied_to_diff() {
        let p = testutil::Project::new();
        let old = "unknown shell syntax";
        p.write(".github/workflows/ci.yml", old);
        let plan = ResolvePlan::new(
            &p.0,
            vec!["f".into()],
            vec![Step::FilePatch {
                description: "review".into(),
                file_path: ".github/workflows/ci.yml".into(),
                expected_old_hash: digest(old.as_bytes()),
                expected_new_hash: digest(b"other"),
                recipe: Recipe::WorkflowRunEnv,
            }],
            vec!["gha-script-injection".into()],
            vec![],
            &RedactionPolicy::default(),
        )
        .unwrap();
        assert_eq!(
            preview(&plan, &RedactionPolicy::default()),
            Err(ResolveError("recipe_unsupported_yaml"))
        );
    }
}
