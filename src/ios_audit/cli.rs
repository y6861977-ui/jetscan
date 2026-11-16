//! `jetscan ios [path] [--json] [--exit-code] [--max-size <KB>]`.
//! Подключается одной строкой в `src/main.rs` (точный diff — в `HANDOFF_IOS.md`).
//!
//! Коды выхода (как у `jetscan web source` / `apk` / `android`): 0 — скан прошёл; с `--exit-code`:
//! 1 — есть находка `critical`/`high`, иначе 2 — какая-то проверка `partial`/`error` (не «чисто»);
//! 2 — ошибка аргументов или корень не открыть.

use super::report;
use super::scan::{IosScanOptions, scan_source};
use super::types::{CheckStatus, Severity};
use crate::ui;
use std::io::Write;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: jetscan ios [project-folder] [--json] [--exit-code] [--max-size <KB>]

Static audit of an iOS app's source project (Xcode project, Swift/Objective-C, plists,
entitlements). Nothing is built, installed, executed or sent anywhere. Findings are review
pointers (potential / needs_review), never proof. The built .ipa is not analysed.

Rules:
  IOS-ATS-001           App Transport Security disabled or relaxed (Info.plist)
  IOS-URLSCHEME-002     custom URL schemes: entry points that must validate input (info)
  IOS-ENTITLEMENTS-003  get-task-allow in release, wildcard associated domains / keychain groups
  IOS-SECRET-004        provider keys and secret-named values in code, plists, xcconfig, .env
  IOS-SIGNING-005       signing material in the tree (.p12, AuthKey_*.p8, ...; never opened)
  IOS-STORAGE-006       tokens / passwords written to UserDefaults
  IOS-KEYCHAIN-007      Keychain items with kSecAttrAccessibleAlways(ThisDeviceOnly)
  IOS-TLS-008           trust-all URLSession challenge handlers and TLS validation switches
  IOS-WEBVIEW-009       UIWebView, file:// access in WKWebView, file base URLs
  IOS-CRYPTO-010        ECB / DES / RC4, fast hashes near passwords
  IOS-LOG-011           secret-named variables passed to print / NSLog / loggers
  IOS-PASTEBOARD-012    secret-named variables copied to the general pasteboard

  --json           machine-readable output (schema_version 2)
  --exit-code      exit 1 on a critical/high finding; exit 2 if a check did not fully run
  --max-size <KB>  skip files larger than this (default 1024; project.pbxproj up to 16 MB)";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    json: bool,
    exit_code: bool,
    max_file_bytes: Option<u64>,
}

/// `Ok(None)` — показать справку.
fn parse(args: &[String]) -> Result<Option<Args>, String> {
    let mut parsed = Args {
        path: PathBuf::from("."),
        json: false,
        exit_code: false,
        max_file_bytes: None,
    };
    let mut path = None;
    let mut rest = args.iter();
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
            _ => return Err("only one project folder can be scanned at a time".to_string()),
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
            ui::eprint_hint("run `jetscan ios --help`");
            return 2;
        }
    };
    let mut options = IosScanOptions::default();
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
mod tests {
    use super::*;
    use crate::ios_audit::testutil::fixture;
    use crate::web_audit::testutil::TempProject;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_flags_and_path() {
        let a = parse(&strings(&[
            "proj",
            "--json",
            "--max-size",
            "2",
            "--exit-code",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(a.path, PathBuf::from("proj"));
        assert!(a.json && a.exit_code);
        assert_eq!(a.max_file_bytes, Some(2048));
        assert_eq!(
            parse(&strings(&[])).unwrap().unwrap().path,
            PathBuf::from(".")
        );
        assert_eq!(parse(&strings(&["--help"])).unwrap(), None);
        assert!(parse(&strings(&["--nope"])).is_err());
        assert!(parse(&strings(&["a", "b"])).is_err());
        assert!(parse(&strings(&["--max-size"])).is_err());
        assert!(parse(&strings(&["--max-size", "0"])).is_err());
    }

    fn run_capture(list: &[String]) -> (i32, String) {
        let mut buffer = Vec::new();
        let code = run_to(list, &mut buffer);
        (code, String::from_utf8(buffer).unwrap())
    }

    #[test]
    fn exit_codes() {
        let project = fixture("insecure-app");
        let path = project.path().display().to_string();
        let (code, text) = run_capture(&strings(&[&path]));
        assert_eq!(code, 0);
        assert!(text.contains("IOS-ATS-001"));
        let (code, json) = run_capture(&strings(&[&path, "--json", "--exit-code"]));
        assert_eq!(code, 1);
        assert!(crate::json::parse(&json).is_ok());

        let clean = fixture("hardened-app");
        let clean_path = clean.path().display().to_string();
        let (code, text) = run_capture(&strings(&[&clean_path, "--exit-code"]));
        assert_eq!(code, 0, "{text}");

        let missing = clean.path().join("missing").display().to_string();
        assert_eq!(run_capture(&strings(&[&missing])).0, 2);

        // Не iOS-проект: всё skipped, код 0.
        let empty = TempProject::new();
        empty.write("README.md", "hi");
        let empty_path = empty.path().display().to_string();
        let (code, text) = run_capture(&strings(&[&empty_path, "--exit-code"]));
        assert_eq!(code, 0);
        assert!(text.contains("no Xcode project"));
        let (code, help) = run_capture(&strings(&["--help"]));
        assert_eq!(code, 0);
        assert!(help.contains("IOS-PASTEBOARD-012"));
    }
}
