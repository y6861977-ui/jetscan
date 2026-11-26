//! `jetscan guide` end to end: the real binary writes the guide page under JETSCAN_HOME and
//! prints its path. A browser is never started here: stdout is a pipe, and JETSCAN_NO_OPEN
//! is set as well.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "jetscan-guide-it-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Temp(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// `jetscan <args>` with `home` as JETSCAN_HOME and no license key. (exit, stdout, stderr).
fn jetscan(args: &[&str], home: &Path, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jetscan"));
    command
        .args(args)
        .current_dir(home)
        .env("NO_COLOR", "1")
        .env("JETSCAN_HOME", home)
        .env("JETSCAN_NO_OPEN", "1")
        .env_remove("JETSCAN_LICENSE")
        .env_remove("LC_ALL")
        .env_remove("LC_MESSAGES")
        .env_remove("LANG");
    for (k, v) in env {
        command.env(k, v);
    }
    let out = command.output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The page path printed after "written: ".
fn printed_path(out: &str) -> PathBuf {
    let line = out
        .lines()
        .find(|l| l.contains(" written: "))
        .unwrap_or_else(|| panic!("{out}"));
    PathBuf::from(line.split(" written: ").nth(1).unwrap())
}

#[test]
fn guide_writes_the_page_under_jetscan_home_and_prints_the_path() {
    let t = Temp::new("write");
    // A locale variable decides before the Windows regional format, so the default is
    // deterministic on any machine.
    let (code, out, err) = jetscan(&["guide"], &t.0, &[("LANG", "en_US.UTF-8")]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(
        out.starts_with("Guide for your plan (Free) written: "),
        "{out}"
    );
    let path = printed_path(&out);
    let want = format!("jetscan-guide-{}-en.html", env!("CARGO_PKG_VERSION"));
    assert_eq!(path.file_name().unwrap().to_string_lossy(), want);
    assert_eq!(path.parent().unwrap().file_name().unwrap(), "guide");
    assert!(
        path.starts_with(&t.0),
        "{} under {}",
        path.display(),
        t.0.display()
    );
    let html = fs::read_to_string(&path).unwrap();
    assert!(html.starts_with("<!doctype html>"), "{html}");
    assert!(html.contains("<html lang=\"en\">"));
    assert!(html.contains("<strong>Your plan: Free</strong>"), "{html}");
    assert!(html.contains("jetscan guide"));
    assert!(!html.contains("<script"));
    // Nothing else was written, and a second run replaces the page.
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    let (code, out2, _) = jetscan(&["guide", "--no-open"], &t.0, &[("LANG", "en_US.UTF-8")]);
    assert_eq!((code, printed_path(&out2)), (0, path.clone()));
    assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
}

#[test]
fn aliases_language_and_locale() {
    let t = Temp::new("lang");
    for alias in ["instructions", "docs"] {
        let (code, out, err) = jetscan(&[alias, "--lang", "ru", "--no-open"], &t.0, &[]);
        assert_eq!(code, 0, "{alias}: {out}\n{err}");
        let html = fs::read_to_string(printed_path(&out)).unwrap();
        assert!(html.contains("<html lang=\"ru\">"), "{alias}");
        assert!(
            html.contains("<strong>Ваш тариф: Бесплатный</strong>"),
            "{alias}"
        );
        assert!(html.contains("Справочник jetscan"), "{alias}");
    }
    // A Russian locale picks Russian; --lang wins over it.
    let (_, out, _) = jetscan(&["guide"], &t.0, &[("LANG", "ru_RU.UTF-8")]);
    assert!(out.trim_end().contains("-ru.html"), "{out}");
    let (_, out, _) = jetscan(&["guide", "--lang", "en"], &t.0, &[("LANG", "ru_RU.UTF-8")]);
    assert!(out.contains("-en.html"), "{out}");
}

#[test]
fn help_and_bad_options() {
    let t = Temp::new("help");
    let (code, out, _) = jetscan(&["guide", "--help"], &t.0, &[]);
    assert_eq!(code, 0);
    assert!(
        out.starts_with("usage: jetscan guide [--lang en|ru] [--no-open]"),
        "{out}"
    );
    assert!(out.contains("nothing is sent over the network"), "{out}");
    assert!(!t.0.join("guide").exists(), "--help writes nothing");
    for bad in [
        &["guide", "--lang", "de"][..],
        &["guide", "--open"],
        &["docs", "x"],
    ] {
        let (code, _, err) = jetscan(bad, &t.0, &[]);
        assert_eq!(code, 2, "{bad:?}");
        assert!(err.contains("jetscan guide --help"), "{err}");
    }
    // `--help` lists it, and an unknown command points to it.
    let (_, out, _) = jetscan(&["--help"], &t.0, &[]);
    assert!(out.contains("jetscan guide [--lang en|ru]"), "{out}");
    let (code, _, err) = jetscan(&["sacn"], &t.0, &[]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown command 'sacn'"), "{err}");
    assert!(
        err.contains("`jetscan guide` for the full user guide"),
        "{err}"
    );
}

#[test]
fn an_unwritable_home_is_an_error() {
    let t = Temp::new("blocked");
    // A file where the guide folder should be.
    fs::write(t.0.join("guide"), "not a folder").unwrap();
    let (code, out, err) = jetscan(&["guide"], &t.0, &[]);
    assert_eq!(code, 2, "{out}\n{err}");
    assert!(err.contains("cannot"), "{err}");
}
