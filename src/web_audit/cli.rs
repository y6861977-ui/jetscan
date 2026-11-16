//! `jetscan web source <path> [--json] [--exit-code] [--max-size <KB>]`.
//!
//! Живёт здесь, чтобы интегратору хватило одной строки в `src/main.rs`
//! (`Some("web") => return jetscan::web_audit::cli::run(&args[1..]),`, см. `HANDOFF_WEB.md`).
//!
//! Коды выхода (как у ядра): 0 — скан прошёл; с `--exit-code`: 1 — есть находка `critical`/`high`,
//! 2 — находок такой тяжести нет, но какая-то проверка `partial`/`error` (не «чисто»);
//! 2 — ошибка аргументов или корень не открыть.

use super::{CheckStatus, Severity, WebScanOptions, report, scan_source};
use crate::ui;
use std::io::Write;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: jetscan web source [path] [--json] [--exit-code] [--max-size <KB>]

Static audit of a Next.js (App/Pages Router) or Vite React project. Nothing is built,
executed or sent anywhere. Findings are review pointers (potential / needs_review), never proof.

Rules:
  WEB-SECRET-001    privileged provider keys in client-side code
  WEB-ENV-002       secrets in NEXT_PUBLIC_ / VITE_ variables (inlined into the bundle)
  WEB-XSS-003       non-constant HTML written through dangerouslySetInnerHTML / innerHTML / ...
  WEB-AUTH-004      state-changing Next.js handlers and Server Actions with no visible access check
  WEB-SUPABASE-005  Supabase service-role / secret keys where the browser can see them
  WEB-CORS-006      CORS that reflects any origin with credentials
  WEB-DEBUG-007     public browser source maps in the production build config
  WEB-DEPS-008      not in this command: use `jetscan deps`

  --json           machine-readable output (schema_version 2)
  --exit-code      exit 1 on a critical/high finding; exit 2 if a check did not fully run
  --max-size <KB>  skip files larger than this (default 1024)";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    json: bool,
    exit_code: bool,
    max_file_bytes: Option<u64>,
}

/// `Ok(None)` — показать справку.
fn parse(args: &[String]) -> Result<Option<Args>, String> {
    match args.first().map(String::as_str) {
        Some("source") => {}
        None | Some("-h") | Some("--help") => return Ok(None),
        Some(other) => {
            return Err(format!(
                "unknown web command '{}' (expected 'source')",
                ui::sanitize_line(other)
            ));
        }
    }
    let mut parsed = Args {
        path: PathBuf::from("."),
        json: false,
        exit_code: false,
        max_file_bytes: None,
    };
    let mut path = None;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--json" => parsed.json = true,
            "--exit-code" => parsed.exit_code = true,
            "--max-size" => {
                let value = rest.next().ok_or("--max-size needs a number of KB")?;
                let kb: u64 = value
                    .parse()
                    .ok()
                    .filter(|kb| *kb > 0)
                    .ok_or("--max-size needs a positive number of KB")?;
                parsed.max_file_bytes = Some(kb.saturating_mul(1024));
            }
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option '{}'", ui::sanitize_line(flag)));
            }
            value if path.is_none() => path = Some(PathBuf::from(value)),
            _ => return Err("only one path can be scanned at a time".to_string()),
        }
    }
    if let Some(path) = path {
        parsed.path = path;
    }
    Ok(Some(parsed))
}

/// Точка входа для `src/main.rs`. Печатает отчёт в stdout, ошибки — в stderr.
pub fn run(args: &[String]) -> i32 {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_to(args, &mut out)
}

fn run_to(args: &[String], out: &mut dyn Write) -> i32 {
    let a = match parse(args) {
        Ok(Some(a)) => a,
        Ok(None) => {
            let _ = writeln!(out, "{USAGE}");
            return 0;
        }
        Err(e) => {
            ui::eprint_error(&e);
            ui::eprint_hint("run `jetscan web --help`");
            return 2;
        }
    };
    let mut options = WebScanOptions::default();
    if let Some(bytes) = a.max_file_bytes {
        options.budgets.max_file_bytes = bytes;
    }
    let result = match scan_source(&a.path, &options) {
        Ok(result) => result,
        Err(e) => {
            ui::eprint_error(&ui::sanitize_line(&e));
            return 2;
        }
    };
    let target = a.path.display().to_string();
    let rendered = if a.json {
        report::render_json(&result, &target)
    } else {
        report::render_text(&result, &target)
    };
    let _ = writeln!(out, "{rendered}");
    if !a.exit_code {
        return 0;
    }
    if result
        .findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High))
    {
        1
    } else if result
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
pub(crate) mod tests {
    use super::*;
    use crate::web_audit::testutil::{TempProject, fixture};

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_flags_and_path() {
        let a = parse(&strings(&["source", "app", "--json", "--max-size", "2"]))
            .unwrap()
            .unwrap();
        assert_eq!(a.path, PathBuf::from("app"));
        assert!(a.json && !a.exit_code);
        assert_eq!(a.max_file_bytes, Some(2048));
        assert_eq!(
            parse(&strings(&["source"])).unwrap().unwrap().path,
            PathBuf::from(".")
        );
        assert_eq!(parse(&strings(&[])).unwrap(), None);
        assert_eq!(parse(&strings(&["source", "--help"])).unwrap(), None);
    }

    #[test]
    fn rejects_bad_arguments() {
        assert!(parse(&strings(&["url"])).is_err());
        assert!(parse(&strings(&["source", "--nope"])).is_err());
        assert!(parse(&strings(&["source", "a", "b"])).is_err());
        assert!(parse(&strings(&["source", "--max-size"])).is_err());
        assert!(parse(&strings(&["source", "--max-size", "0"])).is_err());
    }

    pub(crate) fn run_capture(list: &[String]) -> (i32, String) {
        let mut buffer = Vec::new();
        let code = run_to(list, &mut buffer);
        (code, String::from_utf8(buffer).unwrap())
    }

    #[test]
    fn exit_codes() {
        let project = fixture("next-app");
        let path = project.path().display().to_string();
        let (code, text) = run_capture(&strings(&["source", &path]));
        assert_eq!(code, 0);
        assert!(text.contains("WEB-SECRET-001"));
        let (code, json) = run_capture(&strings(&["source", &path, "--json", "--exit-code"]));
        assert_eq!(code, 1);
        assert!(crate::json::parse(&json).is_ok());

        let clean = TempProject::new();
        clean.write("index.js", "console.log(1)");
        let clean_path = clean.path().display().to_string();
        assert_eq!(
            run_capture(&strings(&["source", &clean_path, "--exit-code"])).0,
            0
        );

        // Неполный скан без находок — не «чисто».
        clean.write("big.js", &"a".repeat(4096));
        let (code, _) = run_capture(&strings(&[
            "source",
            &clean_path,
            "--exit-code",
            "--max-size",
            "1",
        ]));
        assert_eq!(code, 2);

        let missing = clean.path().join("missing").display().to_string();
        assert_eq!(run_capture(&strings(&["source", &missing])).0, 2);
    }
}
