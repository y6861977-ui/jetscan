//! `jetscan resolve ...`. `src/main.rs` needs only one dispatch line (exact
//! diff in `HANDOFF_RESOLVE.md`); everything else lives here.
//!
//! Exit codes: 0 done (plan written, preview shown, applied or nothing to
//! apply, every finding verified); 1 `apply` rolled back / failed, or `verify`
//! found a finding still present; 2 usage or input error, refusal (no
//! `--confirm`, changed file, other project), or `verify` could not prove the
//! result (`unknown`). Errors are fixed codes on stderr; nothing runs a shell,
//! package manager or git, and nothing is sent over the network.
use super::*;
use crate::finding_v2::{ModelError, RedactionPolicy, RemediationState, adapters, wire};
use crate::ui;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub const USAGE: &str = "\
usage: jetscan resolve plan <report-v2.json | project-folder> [--root <folder>] [--out plan.json]
       jetscan resolve preview <plan.json>
       jetscan resolve apply <plan.json> --confirm [--root <folder>]
       jetscan resolve verify <plan.json>

plan     read-only: builds a fix plan from a V2 JSON report (findings are relative to
         --root, default: current folder) or, for a folder, from its GitHub Actions check.
         Only reviewed, provably safe edits become file patches; everything else is advice.
preview  read-only: the exact diff and every step of the plan.
apply    writes only with --confirm, only from the current folder (or --root) that the
         plan was made for, only if each file is unchanged since the plan; all files or
         none (rollback). Result: applied, not yet verified.
verify   re-runs the specific check per finding: verified_specific_issue, still_present
         or unknown. It speaks only about the findings in the plan, never \"secure\".

exit: 0 done; 1 rolled back / still present; 2 error, refusal or unknown";

/// `args` are the arguments after `resolve`.
pub fn run(args: &[String]) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    run_to(args, &cwd, &mut std::io::stdout().lock())
}

struct Args {
    input: PathBuf,
    root: Option<PathBuf>,
    out: Option<PathBuf>,
    confirm: bool,
}

fn parse(command: &str, rest: &[String]) -> Result<Option<Args>, String> {
    let mut args = Args {
        input: PathBuf::new(),
        root: None,
        out: None,
        confirm: false,
    };
    let mut input = None;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--root" if matches!(command, "plan" | "apply") => {
                args.root = Some(PathBuf::from(it.next().ok_or("--root needs a folder")?));
            }
            "--out" if command == "plan" => {
                args.out = Some(PathBuf::from(it.next().ok_or("--out needs a file name")?));
            }
            "--confirm" if command == "apply" => args.confirm = true,
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option '{}'", ui::sanitize_line(flag)));
            }
            value if input.is_none() => input = Some(PathBuf::from(value)),
            _ => return Err("only one input file can be given".into()),
        }
    }
    args.input = input.ok_or_else(|| format!("resolve {command} needs an input file"))?;
    Ok(Some(args))
}

pub(crate) fn run_to(args: &[String], cwd: &Path, out: &mut dyn Write) -> i32 {
    let Some(command) = args.first().map(String::as_str) else {
        let _ = writeln!(out, "{USAGE}");
        return 0;
    };
    if matches!(command, "-h" | "--help") {
        let _ = writeln!(out, "{USAGE}");
        return 0;
    }
    if !matches!(command, "plan" | "preview" | "apply" | "verify") {
        return usage_error(&format!(
            "unknown resolve command '{}' (expected plan, preview, apply or verify)",
            ui::sanitize_line(command)
        ));
    }
    let a = match parse(command, &args[1..]) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let _ = writeln!(out, "{USAGE}");
            return 0;
        }
        Err(e) => return usage_error(&e),
    };
    let input = absolute(cwd, &a.input);
    let result = match command {
        "plan" => cmd_plan(&a, &input, cwd, out),
        "preview" => cmd_preview(&input, out),
        "apply" => cmd_apply(&a, &input, cwd, out),
        _ => cmd_verify(&input, out),
    };
    match result {
        Ok(code) => code,
        Err(ResolveError(code)) => {
            ui::eprint_error(&format!("resolve {command} refused: {code}"));
            if let Some(hint) = hint(code) {
                ui::eprint_hint(hint);
            }
            2
        }
    }
}

fn hint(code: &str) -> Option<&'static str> {
    Some(match code {
        "confirmation_required" => {
            "nothing was written; review `jetscan resolve preview <plan>` and rerun with --confirm"
        }
        "source_changed" => {
            "a file changed since the plan was made; nothing was written. Make a new plan"
        }
        "other_project" => {
            "run it from the project folder the plan was made for, or pass --root <that folder>"
        }
        "output_exists" => "choose another --out file or delete the old one",
        _ => return None,
    })
}

fn usage_error(e: &str) -> i32 {
    ui::eprint_error(e);
    ui::eprint_hint("run `jetscan resolve --help`");
    2
}

fn absolute(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// A bounded regular file (report or plan; not a project file).
fn read_input(path: &Path) -> Result<String, ResolveError> {
    let meta = fs::metadata(path).map_err(|_| ResolveError("input_unavailable"))?;
    if !meta.is_file() || meta.len() > 1024 * 1024 + 16 {
        return Err(ResolveError("input_not_a_bounded_file"));
    }
    let mut text = String::new();
    fs::File::open(path)
        .and_then(|f| f.take(1024 * 1024 + 17).read_to_string(&mut text))
        .map_err(|_| ResolveError("input_unreadable"))?;
    Ok(text)
}

fn load_plan(path: &Path) -> Result<ResolvePlan, ResolveError> {
    ResolvePlan::parse(&read_input(path)?, &RedactionPolicy::default())
}

fn state_label(state: RemediationState) -> &'static str {
    match state {
        RemediationState::GuidanceOnly => "guidance_only",
        RemediationState::Available => "available",
        RemediationState::AppliedUnverified => "applied_unverified",
        RemediationState::Verified => "verified",
        RemediationState::Failed => "failed",
        RemediationState::RolledBack => "rolled_back",
    }
}

/// For display only: `\\?\C:\x` reads as `C:\x` (UNC verbatim paths are kept).
fn show(path: &Path) -> String {
    ui::sanitize_line(&super::preview::display_path(path))
}

fn cmd_plan(a: &Args, input: &Path, cwd: &Path, out: &mut dyn Write) -> Result<i32, ResolveError> {
    let policy = RedactionPolicy::default();
    let (root, scan) = if input.is_dir() {
        if a.root.is_some() {
            return Err(ResolveError("root_given_twice"));
        }
        // Local, read-only GitHub Actions check of that folder.
        let scan = adapters::workflows(&crate::workflows::check(input))
            .and_then(|s| s.redacted(&policy))
            .map_err(|_| ResolveError("scanner_output_unavailable"))?;
        (input.to_path_buf(), scan)
    } else {
        let scan = wire::parse(&read_input(input)?, &policy)
            .map_err(|ModelError(code)| ResolveError(code))?;
        let root = a
            .root
            .as_deref()
            .map_or_else(|| cwd.to_path_buf(), |r| absolute(cwd, r));
        (root, scan)
    };
    let built = planner::plan(&root, scan.as_scan(), &policy)?;
    let plan = built.plan;
    let json = plan.render_pretty()?;
    let patches = plan.preconditions().len();
    let summary = format!(
        "Plan {} for {}\n{} finding(s), {} file patch(es), status {}{}",
        plan.id(),
        show(plan.root()),
        plan.finding_ids().len(),
        patches,
        state_label(plan.status()),
        if built.status == crate::finding_v2::CheckStatus::Partial {
            "; input coverage is partial (see warnings)"
        } else {
            ""
        }
    );
    match &a.out {
        None => {
            let _ = writeln!(out, "{json}");
        }
        Some(file) => {
            let file = absolute(cwd, file);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        ResolveError("output_exists")
                    } else {
                        ResolveError("output_unwritable")
                    }
                })?;
            f.write_all(format!("{json}\n").as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|_| ResolveError("output_unwritable"))?;
            let _ = writeln!(
                out,
                "{summary}\nWritten to {}. Nothing in the project was changed.\nNext: jetscan resolve preview {}",
                show(&file),
                show(&file)
            );
        }
    }
    Ok(0)
}

fn cmd_preview(input: &Path, out: &mut dyn Write) -> Result<i32, ResolveError> {
    let plan = load_plan(input)?;
    let shown = preview(&plan, &RedactionPolicy::default())?;
    let _ = write!(out, "{}", shown.text);
    if plan.status() == RemediationState::Available {
        let _ = writeln!(
            out,
            "\nNothing was changed. To write exactly this diff: jetscan resolve apply {} --confirm",
            show(input)
        );
    } else {
        let _ = writeln!(
            out,
            "\nThis plan is advice only: there is nothing to apply."
        );
    }
    Ok(0)
}

fn cmd_apply(a: &Args, input: &Path, cwd: &Path, out: &mut dyn Write) -> Result<i32, ResolveError> {
    let plan = load_plan(input)?;
    if !a.confirm {
        return Err(ResolveError("confirmation_required"));
    }
    let here = a
        .root
        .as_deref()
        .map_or_else(|| cwd.to_path_buf(), |r| absolute(cwd, r));
    if fs::canonicalize(&here).ok().as_deref() != Some(plan.root()) {
        return Err(ResolveError("other_project"));
    }
    let report = apply(&plan, Some(plan.id()))?;
    let _ = writeln!(
        out,
        "Plan {} for {}: {}",
        plan.id(),
        show(plan.root()),
        state_label(report.state)
    );
    for (file, outcome) in &report.files {
        let label = match outcome {
            FileOutcome::Written => "written",
            FileOutcome::AlreadyApplied => "already applied",
            FileOutcome::RolledBack => "rolled back",
            FileOutcome::NotWritten => "not written",
            FileOutcome::RestoreFailed => "NOT restored (backup kept next to it)",
        };
        let _ = writeln!(out, "  {label:<16} {}", ui::sanitize_line(file));
    }
    match report.state {
        RemediationState::AppliedUnverified => {
            let _ = writeln!(
                out,
                "Not verified yet. Next: jetscan resolve verify {}",
                show(input)
            );
            Ok(0)
        }
        RemediationState::GuidanceOnly => {
            let _ = writeln!(out, "Advice only: nothing to apply, nothing written.");
            Ok(0)
        }
        _ => {
            let _ = writeln!(
                out,
                "Failed: {}. Every file listed as rolled back is byte-identical to before.",
                report.error.unwrap_or("unknown")
            );
            Ok(1)
        }
    }
}

fn cmd_verify(input: &Path, out: &mut dyn Write) -> Result<i32, ResolveError> {
    let plan = load_plan(input)?;
    let report = verify(&plan)?;
    let _ = writeln!(out, "Plan {} for {}", plan.id(), show(plan.root()));
    for (file, state) in &report.files {
        let _ = writeln!(out, "  file {}: {state}", ui::sanitize_line(file));
    }
    for item in &report.items {
        let _ = writeln!(
            out,
            "  {:<24} {} ({})",
            item.outcome.label(),
            ui::sanitize_line(&item.finding_id),
            item.reason
        );
    }
    let verified = report.count(Outcome::VerifiedSpecificIssue);
    let _ = writeln!(
        out,
        "{verified} of {} finding(s) in this plan verified; state {}. This covers only \
         these findings, not the whole project.",
        report.items.len(),
        state_label(report.state)
    );
    Ok(if report.state == RemediationState::Verified {
        0
    } else if report.count(Outcome::StillPresent) > 0 {
        1
    } else {
        2
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::testutil::Project;

    fn run(args: &[&str], cwd: &Path) -> (i32, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut buffer = Vec::new();
        let code = run_to(&args, cwd, &mut buffer);
        (code, String::from_utf8(buffer).unwrap())
    }

    #[test]
    fn plan_preview_apply_verify_from_a_folder() {
        let p = Project::new();
        p.copy_fixture("workflows/pr-title.yml", ".github/workflows/pr-title.yml");
        let work = Project::new();
        let elsewhere = Project::new();
        let plan_file = work.0.join("plan.json");
        let plan_arg = plan_file.to_str().unwrap();
        let project = p.0.to_str().unwrap();
        let (code, text) = run(&["plan", project, "--out", plan_arg], &work.0);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("1 finding(s), 1 file patch(es), status available"));
        assert!(text.contains("input coverage is partial"));
        // --out never overwrites.
        let saved = fs::read(&plan_file).unwrap();
        assert_eq!(run(&["plan", project, "--out", plan_arg], &work.0).0, 2);
        assert_eq!(fs::read(&plan_file).unwrap(), saved);
        let before = p.snapshot();
        let (code, text) = run(&["preview", "plan.json"], &work.0);
        assert_eq!(code, 0);
        assert!(text.contains("+          title=\"${PULL_REQUEST_TITLE}\""));
        assert!(text.contains("Nothing was changed"));
        // No --confirm, or another folder: refused, nothing written.
        assert_eq!(run(&["apply", plan_arg], &p.0).0, 2);
        assert_eq!(run(&["apply", plan_arg, "--confirm"], &elsewhere.0).0, 2);
        assert_eq!(p.snapshot(), before);
        assert_eq!(run(&["verify", plan_arg], &work.0).0, 1, "still present");
        let (code, text) = run(&["apply", plan_arg, "--confirm"], &p.0);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("applied_unverified"));
        assert!(text.contains("written"));
        let (code, text) = run(&["verify", plan_arg], &work.0);
        assert_eq!(code, 0, "{text}");
        assert!(text.contains("verified_specific_issue"));
        assert!(text.contains("1 of 1 finding(s) in this plan verified; state verified"));
        // Idempotent through the CLI as well.
        let (code, text) = run(
            &["apply", plan_arg, "--confirm", "--root", project],
            &work.0,
        );
        assert_eq!(code, 0);
        assert!(text.contains("already applied"));
    }

    #[test]
    fn plan_from_a_v2_report_file_and_advice_only_plans() {
        let p = Project::new();
        p.copy_fixture("workflows/write-all.yml", ".github/workflows/write-all.yml");
        let work = Project::new();
        let report = adapters::workflows(&crate::workflows::check(&p.0))
            .unwrap()
            .redacted(&RedactionPolicy::default())
            .unwrap()
            .render_json();
        work.write("report-v2.json", &report);
        let (code, json) = run(
            &["plan", "report-v2.json", "--root", p.0.to_str().unwrap()],
            &work.0,
        );
        assert_eq!(code, 0);
        let plan = ResolvePlan::parse(&json, &RedactionPolicy::default()).unwrap();
        assert_eq!(plan.status(), RemediationState::GuidanceOnly);
        work.write("plan.json", &json);
        let (code, text) = run(&["preview", "plan.json"], &work.0);
        assert_eq!(code, 0);
        assert!(text.contains("advice only"));
        let before = p.snapshot();
        let plan_path = work.0.join("plan.json");
        let (code, text) = run(&["apply", plan_path.to_str().unwrap(), "--confirm"], &p.0);
        assert_eq!((code, text.contains("nothing written")), (0, true));
        assert_eq!(p.snapshot(), before);
        assert_eq!(run(&["verify", "plan.json"], &work.0).0, 1);
        // A tampered plan is refused.
        work.write("bad.json", &json.replace("write-all", "write-none"));
        assert_eq!(run(&["preview", "bad.json"], &work.0).0, 2);
        // A report that is not strict V2 is refused.
        work.write("v1.json", "{\"version\":1}");
        assert_eq!(run(&["plan", "v1.json"], &work.0).0, 2);
    }

    #[test]
    fn usage_and_errors() {
        let work = Project::new();
        for args in [
            &["nope"][..],
            &["plan"],
            &["plan", "a", "b"],
            &["plan", "a", "--out"],
            &["preview", "a", "--confirm"],
            &["verify", "a", "--root", "x"],
            &["apply", "missing.json", "--confirm"],
            &["preview", "missing.json"],
        ] {
            assert_eq!(run(args, &work.0).0, 2, "{args:?}");
        }
        for args in [&[][..], &["--help"], &["plan", "--help"], &["apply", "-h"]] {
            let (code, text) = run(args, &work.0);
            assert_eq!(code, 0);
            assert!(text.contains("usage: jetscan resolve plan"));
        }
        assert_eq!(fs::read_dir(&work.0).unwrap().count(), 0);
    }
}
