//! Strict shared V2 JSON for `jetscan web source` and `jetscan apk`.
//! `src/main.rs` routes here when the arguments ask for V2 JSON (exact diff
//! in `HANDOFF_FINDINGS.md`); everything else stays in the scanners' own CLIs.
//!
//! Same arguments, scan options and exit codes as `web_audit::cli` /
//! `apk_audit::cli`: 0; with `--exit-code` 1 on a critical/high finding, else
//! 2 if a check is partial/error; 2 on argument/read errors or if the V2 export
//! is refused (fixed error code on stderr, nothing on stdout).
use super::*;
use crate::apk_audit::{self, ApkScanOptions};
use crate::ui;
use crate::web_audit::{self, WebScanOptions};
use std::io::Write;
use std::path::PathBuf;

/// Both spellings select V2 here, so `main.rs` can route either `--json-v2`
/// only, or `--json` too (see the recommendation in `HANDOFF_FINDINGS.md`).
fn is_v2_flag(arg: &str) -> bool {
    arg == "--json-v2" || arg == "--json"
}

struct Args {
    path: PathBuf,
    exit_code: bool,
    max_file_bytes: Option<u64>,
}

/// `Ok(None)` = show help. `web` expects `source` first and allows `--max-size`.
fn parse(args: &[String], web: bool) -> Result<Option<Args>, String> {
    let rest = if web {
        match args.first().map(String::as_str) {
            Some("source") => &args[1..],
            None | Some("-h") | Some("--help") => return Ok(None),
            Some(other) => {
                return Err(format!(
                    "unknown web command '{}' (expected 'source')",
                    ui::sanitize_line(other)
                ));
            }
        }
    } else {
        args
    };
    let (mut path, mut v2, mut exit_code, mut max_file_bytes) = (None, false, false, None);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            flag if is_v2_flag(flag) => v2 = true,
            "--exit-code" => exit_code = true,
            "--max-size" if web => {
                let kb: u64 = it
                    .next()
                    .ok_or("--max-size needs a number of KB")?
                    .parse()
                    .ok()
                    .filter(|kb| *kb > 0)
                    .ok_or("--max-size needs a positive number of KB")?;
                max_file_bytes = Some(kb.saturating_mul(1024));
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option '{}'", ui::sanitize_line(flag)));
            }
            value if path.is_none() => path = Some(PathBuf::from(value)),
            _ => return Err("only one path can be scanned at a time".to_string()),
        }
    }
    if !v2 {
        return Err("internal: V2 output requested without --json-v2".to_string());
    }
    let path = match path {
        Some(path) => path,
        None if web => PathBuf::from("."),
        None => return Ok(None),
    };
    Ok(Some(Args {
        path,
        exit_code,
        max_file_bytes,
    }))
}

/// `jetscan web source [path] --json-v2 [--exit-code] [--max-size <KB>]`.
pub fn run_web(args: &[String]) -> i32 {
    run_web_to(args, &mut std::io::stdout().lock())
}

/// `jetscan apk <file.apk> --json-v2 [--exit-code]`.
pub fn run_apk(args: &[String]) -> i32 {
    run_apk_to(args, &mut std::io::stdout().lock())
}

fn run_web_to(args: &[String], out: &mut dyn Write) -> i32 {
    let a = match parse(args, true) {
        Ok(Some(a)) => a,
        Ok(None) => return usage(out, web_audit::cli::USAGE),
        Err(e) => return arg_error(&e, "web"),
    };
    let mut options = WebScanOptions::default();
    if let Some(bytes) = a.max_file_bytes {
        options.budgets.max_file_bytes = bytes;
    }
    match web_audit::scan_source(&a.path, &options) {
        Ok(r) => emit(adapters::web(&r), a.exit_code, out),
        Err(e) => scan_error(&e),
    }
}

fn run_apk_to(args: &[String], out: &mut dyn Write) -> i32 {
    let a = match parse(args, false) {
        Ok(Some(a)) => a,
        Ok(None) => return usage(out, apk_audit::cli::USAGE),
        Err(e) => return arg_error(&e, "apk"),
    };
    match apk_audit::scan_apk(&a.path, &ApkScanOptions::default()) {
        Ok(r) => emit(adapters::apk(&r), a.exit_code, out),
        Err(e) => scan_error(&e),
    }
}

fn usage(out: &mut dyn Write, scanner_usage: &str) -> i32 {
    let _ = writeln!(
        out,
        "{scanner_usage}\n  --json-v2        strict shared Findings V2 JSON (schema_version 2)"
    );
    0
}
fn arg_error(e: &str, command: &str) -> i32 {
    ui::eprint_error(e);
    ui::eprint_hint(&format!("run `jetscan {command} --help`"));
    2
}
fn scan_error(e: &str) -> i32 {
    ui::eprint_error(&ui::sanitize_line(e));
    2
}

/// Render only through the redacted path; a refused export prints nothing.
fn emit(adapted: Result<ScanResultV2, ModelError>, exit_code: bool, out: &mut dyn Write) -> i32 {
    let safe = match adapted.and_then(|v2| v2.redacted(&RedactionPolicy::default())) {
        Ok(safe) => safe,
        Err(e) => {
            ui::eprint_error(&format!("V2 export refused: {e}"));
            return 2;
        }
    };
    let _ = writeln!(out, "{}", safe.render_json());
    let scan = safe.as_scan();
    if !exit_code {
        0
    } else if scan
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
    {
        1
    } else if scan
        .checks
        .iter()
        .any(|c| matches!(c.status, CheckStatus::Partial | CheckStatus::Error))
    {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::{TempProject, fixture};
    use std::path::Path;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    fn capture(run: fn(&[String], &mut dyn Write) -> i32, list: &[&str]) -> (i32, String) {
        let mut buffer = Vec::new();
        let code = run(&strings(list), &mut buffer);
        (code, String::from_utf8(buffer).unwrap())
    }

    #[test]
    fn web_v2_output_is_strict_v2_with_scanner_exit_codes() {
        let project = fixture("next-app");
        let path = project.path().display().to_string();
        for flag in ["--json-v2", "--json"] {
            let (code, json) = capture(run_web_to, &["source", &path, flag, "--exit-code"]);
            assert_eq!(code, 1, "critical/high finding");
            let parsed = wire::parse(json.trim_end(), &RedactionPolicy::default()).unwrap();
            let r = web_audit::scan_source(project.path(), &WebScanOptions::default()).unwrap();
            let direct = adapters::web(&r)
                .unwrap()
                .redacted(&RedactionPolicy::default())
                .unwrap();
            assert_eq!(parsed, direct);
            assert_eq!(json.trim_end(), direct.render_json());
        }
        assert_eq!(capture(run_web_to, &["source", &path, "--json-v2"]).0, 0);

        let clean = TempProject::new();
        clean.write("index.js", "console.log(1)");
        let clean_path = clean.path().display().to_string();
        let (code, json) = capture(
            run_web_to,
            &["source", &clean_path, "--json-v2", "--exit-code"],
        );
        assert_eq!(code, 0);
        assert!(
            wire::parse(json.trim_end(), &RedactionPolicy::default())
                .unwrap()
                .as_scan()
                .completed()
        );
        // Incomplete scan without findings is not clean.
        clean.write("big.js", &"a".repeat(4096));
        let args = [
            "source",
            &clean_path,
            "--json-v2",
            "--exit-code",
            "--max-size",
            "1",
        ];
        let (code, json) = capture(run_web_to, &args);
        assert_eq!(code, 2);
        assert!(
            !wire::parse(json.trim_end(), &RedactionPolicy::default())
                .unwrap()
                .as_scan()
                .completed()
        );
    }

    #[test]
    fn apk_v2_output_roundtrips_with_scanner_exit_codes() {
        let demo = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/apk/demo/demo.apk");
        let demo = demo.display().to_string();
        let (code, json) = capture(run_apk_to, &[&demo, "--json-v2", "--exit-code"]);
        assert_eq!(code, 1, "DEBUG-002 is high");
        let parsed = wire::parse(json.trim_end(), &RedactionPolicy::default()).unwrap();
        assert_eq!(parsed.as_scan().findings.len(), 4);
        assert!(parsed.as_scan().completed());
        assert_eq!(capture(run_apk_to, &[&demo, "--json-v2"]).0, 0);
        let missing = format!("{demo}.missing");
        let (code, out) = capture(run_apk_to, &[&missing, "--json-v2"]);
        assert_eq!((code, out.as_str()), (2, ""));
    }

    #[test]
    fn arguments_and_help() {
        for list in [
            &["url", "--json-v2"][..],
            &["source", "--json-v2", "--nope"],
            &["source", "a", "b", "--json-v2"],
            &["source", "--json-v2", "--max-size"],
            &["source", "--json-v2", "--max-size", "0"],
            &["source", "a"],
        ] {
            assert_eq!(capture(run_web_to, list).0, 2, "{list:?}");
        }
        assert_eq!(
            capture(run_apk_to, &["a.apk", "--json-v2", "--max-size", "1"]).0,
            2
        );
        assert_eq!(capture(run_apk_to, &["a.apk", "b.apk", "--json-v2"]).0, 2);
        for (run, list) in [
            (
                run_web_to as fn(&[String], &mut dyn Write) -> i32,
                &["source", "--json-v2", "--help"][..],
            ),
            (run_web_to, &[]),
            (run_apk_to, &["--json-v2"]),
            (run_apk_to, &["--json-v2", "-h"]),
        ] {
            let (code, text) = capture(run, list);
            assert_eq!(code, 0);
            assert!(text.contains("usage:") && text.contains("--json-v2"));
        }
    }
}
