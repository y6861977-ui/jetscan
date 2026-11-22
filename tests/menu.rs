//! `jetscan menu` end to end: the real binary, scripted stdin, captured output.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

// jetscan Pro: the Pro items through the license gate (tests/menu/pro.rs, private repository only).
#[cfg(feature = "pro")]
#[path = "menu/pro.rs"]
#[rustfmt::skip] // Pro-only file: absent from the public export, so `cargo fmt` must not open it
mod pro;

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jetscan-menu-it-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Temp(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `jetscan <args>` in `cwd` with `script` on stdin. Returns (exit code, stdout, stderr).
fn jetscan(args: &[&str], cwd: &Path, script: &str) -> (i32, String, String) {
    jetscan_colors(args, cwd, script, false)
}

/// `jetscan`, with `NO_COLOR` unset when `maybe_colors` (stdout and stderr stay pipes).
fn jetscan_colors(
    args: &[&str],
    cwd: &Path,
    script: &str,
    maybe_colors: bool,
) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jetscan"));
    if maybe_colors {
        command.env_remove("NO_COLOR");
    } else {
        command.env("NO_COLOR", "1");
    }
    let mut child = command
        .args(args)
        .current_dir(cwd)
        .env_remove("JETSCAN_LICENSE")
        // No license file of this machine, no ~/.jetscan state: this test's own folder.
        .env("JETSCAN_HOME", cwd)
        // Resolve plans go to the temp folder: keep them inside this test's folder.
        .env("TMP", cwd)
        .env("TEMP", cwd)
        .env("TMPDIR", cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // jetscan may exit without reading stdin (e.g. no terminal -> usage); a closed pipe is fine.
    if let Err(e) = child.stdin.take().unwrap().write_all(script.as_bytes()) {
        assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe, "{e}");
    }
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn plain(path: &Path) -> String {
    let text = path.display().to_string();
    text.strip_prefix(r"\\?\")
        .map_or(text.clone(), str::to_string)
}

#[test]
fn secrets_scan_from_the_menu() {
    let project = Temp::new("secrets");
    // Assembled at runtime so this repository never contains a complete token.
    let token = format!("{}{}", "ghp_", "Zq8".repeat(12));
    fs::write(
        project.0.join("config.js"),
        format!("const token = \"{token}\";\n"),
    )
    .unwrap();
    let dir = plain(&project.0);
    let (code, out, err) = jetscan(&["menu"], &project.0, &format!("2\n\"{dir}\"\n\n0\n"));
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("never uploaded"), "{out}");
    assert!(out.contains("config.js"), "{out}");
    assert!(out.contains("GitHub"), "{out}");
    assert!(
        !out.contains(&token),
        "the secret itself is never printed: {out}"
    );
    assert!(out.contains("Equivalent command:"), "{out}");
    assert!(out.contains(&format!("jetscan secrets {dir}")), "{out}");
    assert!(out.trim_end().ends_with("Bye."), "{out}");
}

/// The console keeps the same number in free and Pro builds.
const CONSOLE: &str = "12";

#[test]
fn the_console_runs_jetscan_commands_in_this_process_and_nothing_else() {
    let project = Temp::new("console");
    // Assembled at runtime so this repository never contains a complete token.
    let token = format!("{}{}", "ghp_", "Zq8".repeat(12));
    fs::write(
        project.0.join("config.js"),
        format!("const token = \"{token}\";\n"),
    )
    .unwrap();
    let dir = plain(&project.0);
    let script = format!(
        "{CONSOLE}\njetscan.exe secrets \"{dir}\" --exit-code\ncmd /c echo hacked-marker\n\
         mcp\nmenu\nhistory\nexit\n0\n"
    );
    let (code, out, err) = jetscan(&["menu"], &project.0, &script);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.contains("jetscan console — type jetscan commands"),
        "{out}"
    );
    assert!(out.contains("jetscan> "), "{out}");
    // The scan ran in-process, its finding is masked, and its exit code is said in words.
    assert!(out.contains("config.js") && out.contains("GitHub"), "{out}");
    assert!(
        !out.contains(&token),
        "the secret itself is never printed: {out}"
    );
    assert!(out.contains("found issues (exit 1)"), "{out}");
    // Anything else is refused, and nothing was started.
    assert!(out.contains("That is not a jetscan command"), "{out}");
    assert!(
        out.contains("Only jetscan commands work here. Type `help`."),
        "{out}"
    );
    assert!(
        !out.lines().any(|l| l.trim() == "hacked-marker"),
        "no shell ran: {out}"
    );
    assert!(out.contains("server for AI editors"), "{out}");
    assert!(out.contains("in the menu already"), "{out}");
    assert!(out.contains("    2  [refused command]"), "{out}");
    assert!(out.trim_end().ends_with("Bye."), "{out}");
}

#[test]
fn no_arguments_without_a_terminal_still_prints_usage() {
    let t = Temp::new("usage");
    let (code, out, _) = jetscan(&[], &t.0, "2\n");
    assert_eq!(code, 0);
    assert!(out.starts_with("jetscan "), "{out}");
    assert!(out.contains("usage: jetscan scan"), "{out}");
    assert!(!out.contains("Type a number and press Enter"), "{out}");
    assert_eq!(jetscan(&["menu", "extra"], &t.0, "").0, 2);
}

#[test]
fn ai_editor_setup_shows_this_jetscan_path() {
    let t = Temp::new("ai");
    // An empty PATH: Claude Code is never found, so nothing is offered or run.
    let empty = Temp::new("ai-path");
    let mut child = Command::new(env!("CARGO_BIN_EXE_jetscan"))
        .arg("menu")
        .current_dir(&t.0)
        .env("NO_COLOR", "1")
        .env("PATH", &empty.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"6\n\n0\n").unwrap();
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    let exe = plain(Path::new(env!("CARGO_BIN_EXE_jetscan")));
    let escaped = exe.replace('\\', "\\\\");
    assert!(
        text.contains(&format!("\"command\": \"{escaped}\",")),
        "{text}"
    );
    assert!(text.contains("claude mcp add jetscan -- "), "{text}");
    assert!(!text.contains("to run it now"), "{text}");
    assert!(text.trim_end().ends_with("Bye."), "{text}");
}

#[test]
fn end_of_input_quits() {
    let t = Temp::new("eof");
    let (code, out, _) = jetscan(&["menu"], &t.0, "");
    assert_eq!(code, 0);
    assert!(out.contains("Type a number and press Enter:"), "{out}");
    assert!(out.trim_end().ends_with("Bye."), "{out}");
}

#[test]
fn menu_output_without_colors_has_no_escape_codes() {
    let project = Temp::new("plain");
    fs::write(project.0.join(".env"), "PASSWORD=hunter2-not-a-real-one\n").unwrap();
    let dir = plain(&project.0);
    // Questions, a scan with findings, license, AI-editor setup (two Enters: one more for the
    // "run it now?" question if Claude Code is on PATH), a bad choice, back, and quit.
    let script = format!("2\n\"{dir}\"\n\n5\n\n6\n\n\n42\n1\n0\n0\n");
    // NO_COLOR, and also a pipe without NO_COLOR (CI, `| more`): plain text either way.
    for maybe_colors in [false, true] {
        let (code, out, err) = jetscan_colors(&["menu"], &project.0, &script, maybe_colors);
        assert_eq!(code, 0, "{out}\n{err}");
        assert!(out.contains("Equivalent command:"), "{out}");
        assert!(out.contains("'42' is not on the list"), "{out}");
        for text in [&out, &err] {
            assert!(!text.contains("\x1b["), "{maybe_colors}: {text}");
            assert!(!text.contains('\x1b'), "{maybe_colors}: {text}");
        }
    }
}

#[test]
fn the_menu_fits_an_80_column_console() {
    let t = Temp::new("width");
    let (_, out, _) = jetscan(&["menu"], &t.0, "");
    let menu: Vec<&str> = out.lines().collect();
    assert!(menu.len() > 10, "{out}");
    for line in &menu {
        assert!(line.chars().count() <= 78, "too wide: {line:?}");
    }
    for group in ["CHECK A PROJECT", "FIX AND TOOLS", "JETSCAN PRO"] {
        assert!(menu.iter().any(|l| l.trim() == group), "{group}: {out}");
    }
    // Numbers are right-aligned in six columns, the text starts three spaces later.
    assert!(menu.contains(&"     2   Leaked secrets only"), "{out}");
    assert!(menu.contains(&"     0   Quit"), "{out}");
    let blank_before = |line: &str| {
        let at = menu.iter().position(|l| *l == line).unwrap();
        menu[at - 1].is_empty()
    };
    assert!(blank_before("     0   Quit"), "{out}");
    assert!(blank_before("  CHECK A PROJECT"), "{out}");
}

fn workflow_project(tag: &str) -> (Temp, PathBuf, Vec<u8>) {
    let project = Temp::new(tag);
    let file = project.0.join(".github/workflows/pr-title.yml");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/resolve/workflows/pr-title.yml"),
        &file,
    )
    .unwrap();
    let before = fs::read(&file).unwrap();
    (project, file, before)
}

#[test]
fn resolve_writes_nothing_without_yes() {
    let (project, file, before) = workflow_project("resolve-no");
    for answer in ["", "y", "YES please", "no"] {
        let (code, out, err) = jetscan(&["menu"], &project.0, &format!("3\n\n{answer}\n\n0\n"));
        assert_eq!(code, 0, "{out}\n{err}");
        assert!(out.contains("Apply these changes?"), "{out}\n{err}");
        assert!(out.contains("Cancelled. Nothing was changed."), "{out}");
        assert!(!out.contains("Running: jetscan resolve apply"), "{out}");
        assert_eq!(fs::read(&file).unwrap(), before, "answer {answer:?}");
    }
}

#[test]
fn resolve_applies_and_verifies_after_yes() {
    let (project, file, before) = workflow_project("resolve-yes");
    let (code, out, err) = jetscan(&["menu"], &project.0, "3\n\nyes\n\n0\n");
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("Step 4 of 4: verify"), "{out}\n{err}");
    assert!(out.contains("verified_specific_issue"), "{out}");
    assert!(out.contains("Equivalent commands:"), "{out}");
    assert!(out.contains("--confirm --root ."), "{out}");
    assert_ne!(fs::read(&file).unwrap(), before);
}
