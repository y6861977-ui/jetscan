//! `jetscan menu` end to end: the real binary, scripted stdin, captured output.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let mut child = Command::new(env!("CARGO_BIN_EXE_jetscan"))
        .args(args)
        .current_dir(cwd)
        .env("NO_COLOR", "1")
        .env_remove("JETSCAN_LICENSE")
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

#[test]
fn no_arguments_without_a_terminal_still_prints_usage() {
    let t = Temp::new("usage");
    let (code, out, _) = jetscan(&[], &t.0, "2\n");
    assert_eq!(code, 0);
    assert!(out.starts_with("jetscan "), "{out}");
    assert!(out.contains("usage: jetscan scan"), "{out}");
    assert!(!out.contains("What do you want to do?"), "{out}");
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
    child.stdin.take().unwrap().write_all(b"10\n\n0\n").unwrap();
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
    assert!(out.contains("What do you want to do?"));
    assert!(out.trim_end().ends_with("Bye."), "{out}");
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
        let (code, out, err) = jetscan(&["menu"], &project.0, &format!("7\n\n{answer}\n\n0\n"));
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
    let (code, out, err) = jetscan(&["menu"], &project.0, "7\n\nyes\n\n0\n");
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("Step 4 of 4: verify"), "{out}\n{err}");
    assert!(out.contains("verified_specific_issue"), "{out}");
    assert!(out.contains("Equivalent commands:"), "{out}");
    assert!(out.contains("--confirm --root ."), "{out}");
    assert_ne!(fs::read(&file).unwrap(), before);
}
