//! `jetscan apk <file.apk> [--json] [--exit-code]`.
//! Подключается одной строкой в `src/main.rs` (точный diff — в `HANDOFF_APK.md`).
//!
//! Коды выхода (как у `jetscan web source`): 0 — скан прошёл; с `--exit-code`: 1 — есть находка
//! `critical`/`high`, иначе 2 — какая-то проверка `partial`/`error` (битый APK — не «чисто»);
//! 2 — ошибка аргументов или файл не прочитать.

use super::report;
use super::scan::{ApkScanOptions, scan_apk};
use super::types::{CheckStatus, Severity};
use crate::ui;
use std::io::Write;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: jetscan apk <file.apk> [--json] [--exit-code]

Static audit of an Android APK: debuggable builds, exported components, backup, cleartext
traffic and user-trusted CAs, sensitive permissions, provider keys in resources and assets.
The APK is never installed or run; nothing is sent anywhere. DEX code and signatures are
not analysed.

  --json        machine-readable output (schema_version 2)
  --exit-code   exit 1 on a critical/high finding; exit 2 if a check did not fully run";

#[derive(Debug, PartialEq, Eq)]
struct Args {
    path: PathBuf,
    json: bool,
    exit_code: bool,
}

fn parse(args: &[String]) -> Result<Option<Args>, String> {
    let mut path = None;
    let (mut json, mut exit_code) = (false, false);
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--json" => json = true,
            "--exit-code" => exit_code = true,
            flag if flag.starts_with('-') => {
                return Err(format!("unknown option '{}'", ui::sanitize_line(flag)));
            }
            value if path.is_none() => path = Some(PathBuf::from(value)),
            _ => return Err("only one APK can be scanned at a time".to_string()),
        }
    }
    match path {
        Some(path) => Ok(Some(Args {
            path,
            json,
            exit_code,
        })),
        None => Ok(None),
    }
}

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
            ui::eprint_hint("run `jetscan apk --help`");
            return 2;
        }
    };
    let result = match scan_apk(&a.path, &ApkScanOptions::default()) {
        Ok(r) => r,
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

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_arguments() {
        let a = parse(&strings(&["x.apk", "--json", "--exit-code"]))
            .unwrap()
            .unwrap();
        assert_eq!(a.path, PathBuf::from("x.apk"));
        assert!(a.json && a.exit_code);
        assert_eq!(parse(&strings(&[])).unwrap(), None);
        assert_eq!(parse(&strings(&["--help"])).unwrap(), None);
        assert!(parse(&strings(&["a.apk", "b.apk"])).is_err());
        assert!(parse(&strings(&["--nope"])).is_err());
    }

    pub(crate) fn run_capture(list: &[String]) -> (i32, String) {
        let mut buffer = Vec::new();
        let code = run_to(list, &mut buffer);
        (code, String::from_utf8(buffer).unwrap())
    }

    #[test]
    fn missing_file_is_exit_2() {
        assert_eq!(run_capture(&strings(&["definitely-missing.apk"])).0, 2);
    }
}
