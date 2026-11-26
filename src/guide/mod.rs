//! `jetscan guide` (also `jetscan instructions`, `jetscan docs`): the user guide, built into
//! this program, written as one self-contained HTML page and opened in the default browser.
//!
//! - The free build embeds the public guide (`docs/guide/public-en.md`, `public-ru.md`); the
//!   jetscan Pro build embeds the full guide (`docs/guide/en.md`, `ru.md`) from a Pro-only file.
//! - The page is tailored to the plan on this machine (`plan.rs`): a "Your plan" box, and the
//!   chapters the plan does not unlock shortened. The key and the trial counter are only read.
//! - The page goes to `<JETSCAN_HOME or ~/.jetscan>/guide/jetscan-guide-<version>-<lang>.html`
//!   (temp file + rename), then the browser is started with the path as one argument, never
//!   through a shell: `explorer.exe` (Windows), `open` (macOS), `xdg-open` (other Unix, only
//!   with a graphical desktop). Not with `--no-open`, `JETSCAN_NO_OPEN`, or when stdout is not
//!   a terminal. The path is always printed. Nothing is sent over the network.
//! - Language: `--lang`, else `ru` if the first set of `LC_ALL`, `LC_MESSAGES`, `LANG` starts
//!   with `ru`, else (Windows) the user's regional format, else `en`.

pub mod plan;
#[cfg(feature = "pro")]
#[rustfmt::skip] // Pro-only file: absent from the public export, so `cargo fmt` must not open it
mod pro;
pub mod render;

use crate::{edition, license, ui};
use std::path::{Path, PathBuf};

/// The guide's language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Ru,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ru => "ru",
        }
    }

    pub fn parse(s: &str) -> Option<Lang> {
        match s.to_ascii_lowercase().as_str() {
            "en" => Some(Lang::En),
            "ru" => Some(Lang::Ru),
            _ => None,
        }
    }
}

/// The guide built into this program, in Markdown, untailored: the full guide (Pro).
#[cfg(feature = "pro")]
pub fn markdown(lang: Lang) -> &'static str {
    pro::markdown(lang)
}

/// The guide built into this program, in Markdown, untailored: the public guide.
#[cfg(not(feature = "pro"))]
pub fn markdown(lang: Lang) -> &'static str {
    match lang {
        Lang::En => include_str!("../../docs/guide/public-en.md"),
        Lang::Ru => include_str!("../../docs/guide/public-ru.md"),
    }
}

/// The default language: `ru` if the first non-empty of `LC_ALL`, `LC_MESSAGES`, `LANG`
/// starts with `ru` (`ru_RU.UTF-8`); on Windows, where those are rarely set, the user's
/// regional format (`HKCU\Control Panel\International`, `LocaleName`, e.g. `ru-RU`); else `en`.
pub fn default_lang() -> Lang {
    if let Some(lang) = lang_from(|name| std::env::var(name).ok()) {
        return lang;
    }
    #[cfg(windows)]
    if let Some(lang) = windows_locale().as_deref().and_then(lang_from_reg_query) {
        return lang;
    }
    Lang::En
}

/// `Some` when a locale variable is set: `Ru` if it starts with `ru`, else `En`.
fn lang_from(var: impl Fn(&str) -> Option<String>) -> Option<Lang> {
    let locale = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|name| var(name).filter(|v| !v.trim().is_empty()))?;
    Some(if locale.trim().to_ascii_lowercase().starts_with("ru") {
        Lang::Ru
    } else {
        Lang::En
    })
}

/// The output of `reg query "HKCU\Control Panel\International" /v LocaleName`, from
/// `%SystemRoot%\System32\reg.exe` with fixed arguments (no shell). Read-only; `None` on
/// any failure.
#[cfg(windows)]
fn windows_locale() -> Option<String> {
    let root = std::env::var_os("SystemRoot")?;
    let reg = Path::new(&root).join("System32").join("reg.exe");
    let out = std::process::Command::new(reg)
        .args([
            "query",
            r"HKCU\Control Panel\International",
            "/v",
            "LocaleName",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `LocaleName    REG_SZ    ru-RU` -> `Ru`; another locale -> `En`; no such line -> `None`.
#[cfg_attr(not(windows), allow(dead_code))]
fn lang_from_reg_query(output: &str) -> Option<Lang> {
    let line = output
        .lines()
        .find(|line| line.trim_start().starts_with("LocaleName"))?;
    let value = line.split_whitespace().nth(2)?;
    Some(if value.to_ascii_lowercase().starts_with("ru") {
        Lang::Ru
    } else {
        Lang::En
    })
}

pub const USAGE: &str = "\
usage: jetscan guide [--lang en|ru] [--no-open]
       (also: jetscan instructions, jetscan docs)

Opens the full jetscan user guide in your web browser: every command, option and exit code,
for the plan on this computer (Free, Trial, Pro, Teams). The guide is built into this
program: it works offline and nothing is sent over the network.

options:
  --lang en|ru   the language. Default: ru if LC_ALL, LC_MESSAGES or LANG (the first one
                 set) starts with \"ru\" or, on Windows, the regional format is Russian;
                 else en
  --no-open      only write the page and print its path
  -h, --help     show this help

The page is saved as ~/.jetscan/guide/jetscan-guide-<version>-<lang>.html (JETSCAN_HOME
replaces ~/.jetscan). The browser is not started with --no-open, when JETSCAN_NO_OPEN is
set, or when the output is not a terminal; the path is printed either way.";

#[derive(Debug)]
struct Options {
    lang: Lang,
    no_open: bool,
}

/// `None`: `--help`.
fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let mut o = Options {
        lang: default_lang(),
        no_open: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" | "help" => return Ok(None),
            "--no-open" => o.no_open = true,
            "--lang" => {
                let v = it.next().ok_or("--lang needs a language: en or ru")?;
                o.lang = Lang::parse(v).ok_or_else(|| {
                    format!(
                        "--lang: unknown language '{}' (en or ru)",
                        ui::sanitize_line(v)
                    )
                })?;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{}'", ui::sanitize_line(other)));
            }
            other => {
                return Err(format!(
                    "unexpected argument '{}'",
                    ui::sanitize_line(other)
                ));
            }
        }
    }
    Ok(Some(o))
}

/// `jetscan guide <args>`: exit 0 when the page was written (opened or not), 2 on an error.
pub fn run(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(Some(o)) => o,
        Ok(None) => {
            println!("{USAGE}");
            return 0;
        }
        Err(e) => {
            ui::eprint_error(&e);
            ui::eprint_hint("run `jetscan guide --help`");
            return 2;
        }
    };
    let Some(home) = license::jetscan_home() else {
        ui::eprint_error(
            "cannot find your home folder (USERPROFILE / HOME is not set); set JETSCAN_HOME",
        );
        return 2;
    };
    let checked = license::load_checked();
    let used = license::trial_used_in(&checked, Some(&home));
    let plan = plan::YourPlan::of(&checked, used, edition::PRO);
    let md = plan::tailor(markdown(o.lang), o.lang, &plan);
    let html = render::render_page(&md, o.lang.code());
    let dir = std::path::absolute(&home).unwrap_or(home).join("guide");
    let name = format!(
        "jetscan-guide-{}-{}.html",
        env!("CARGO_PKG_VERSION"),
        o.lang.code()
    );
    let path = match write_atomic(&dir, &name, html.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            ui::eprint_error(&ui::sanitize_line(&e));
            return 2;
        }
    };
    let shown = ui::sanitize_line(&path.display().to_string());
    let summary = ui::sanitize_line(&plan.summary());
    let opened = if o.no_open {
        Err(None)
    } else {
        may_open().and_then(|()| open(&path).map_err(Some))
    };
    match opened {
        Ok(()) => {
            println!("Guide for your plan ({summary}) opened: {shown}");
            println!(
                "  {}",
                ui::dim("It opened in your default browser. Nothing was sent over the network.")
            );
        }
        Err(why) => {
            println!("Guide for your plan ({summary}) written: {shown}");
            let hint = match why {
                Some(why) => format!(
                    "The browser did not start ({}). Open that file in any web browser.",
                    ui::sanitize_line(&why)
                ),
                None => "Open that file in any web browser; it works offline.".to_string(),
            };
            println!("  {}", ui::dim(&hint));
        }
    }
    0
}

/// Whether to start a browser at all. `Err(None)`: quietly not (tests, pipes, CI).
fn may_open() -> Result<(), Option<String>> {
    use std::io::IsTerminal;
    if std::env::var_os("JETSCAN_NO_OPEN").is_some_and(|v| !v.is_empty())
        || !std::io::stdout().is_terminal()
    {
        return Err(None);
    }
    let desktop = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|v| !v.is_empty()));
    if cfg!(all(unix, not(target_os = "macos"))) && !desktop {
        return Err(Some("no graphical desktop: DISPLAY is not set".into()));
    }
    Ok(())
}

/// Writes `bytes` to `dir/name` through a new temporary file in `dir` and a rename, so a
/// reader never sees half a page.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let path = dir.join(name);
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp); // left over from a crashed run with the same pid
    let write = || -> std::io::Result<()> {
        // `create_new`: never writes through a file or link that is already there.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot write {}: {e}", path.display())
    })?;
    Ok(path)
}

/// Starts the default browser on `path`: the path is one argument, no shell.
fn open(path: &Path) -> Result<(), String> {
    use std::process::{Command, Stdio};
    let (program, arg): (PathBuf, std::ffi::OsString) = if cfg!(windows) {
        // explorer.exe from the Windows folder, not whatever is first on PATH. It does not
        // understand `/` or the `\\?\` prefix.
        let windows = std::env::var_os("SystemRoot")
            .map(|r| Path::new(&r).join("explorer.exe"))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| PathBuf::from("explorer.exe"));
        let text = path.display().to_string().replace('/', "\\");
        let text = text.strip_prefix(r"\\?\").unwrap_or(&text).to_string();
        (windows, text.into())
    } else if cfg!(target_os = "macos") {
        (PathBuf::from("/usr/bin/open"), path.into())
    } else {
        (PathBuf::from("xdg-open"), path.into())
    };
    let name = program
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let mut child = Command::new(&program)
        .arg(arg)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{name}: {e}"))?;
    // These helpers hand the file to the browser and exit; give them a few seconds to say
    // they could not. explorer.exe exits with 1 even when it worked.
    for _ in 0..50 {
        match child.try_wait() {
            Ok(Some(status)) if status.success() || cfg!(windows) => return Ok(()),
            Ok(Some(status)) => return Err(format!("{name} stopped with {status}")),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => return Err(format!("{name}: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_language_follows_the_locale_variables_in_order() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(lang_from(env(&[])), None);
        assert_eq!(lang_from(env(&[("LANG", "ru_RU.UTF-8")])), Some(Lang::Ru));
        assert_eq!(lang_from(env(&[("LANG", "RU")])), Some(Lang::Ru));
        assert_eq!(lang_from(env(&[("LANG", "en_US.UTF-8")])), Some(Lang::En));
        assert_eq!(lang_from(env(&[("LANG", "C.UTF-8")])), Some(Lang::En));
        // LC_ALL wins over LANG; an empty variable is skipped.
        assert_eq!(
            lang_from(env(&[("LC_ALL", "en_GB"), ("LANG", "ru_RU")])),
            Some(Lang::En)
        );
        assert_eq!(
            lang_from(env(&[
                ("LC_ALL", ""),
                ("LC_MESSAGES", "ru_UA"),
                ("LANG", "en")
            ])),
            Some(Lang::Ru)
        );
    }

    #[test]
    fn the_windows_regional_format_picks_the_language() {
        let out = "\r\nHKEY_CURRENT_USER\\Control Panel\\International\r\n    LocaleName    REG_SZ    ru-RU\r\n\r\n";
        assert_eq!(lang_from_reg_query(out), Some(Lang::Ru));
        assert_eq!(
            lang_from_reg_query("    LocaleName    REG_SZ    tk-TM\r\n"),
            Some(Lang::En)
        );
        assert_eq!(lang_from_reg_query("ERROR: not found"), None);
        assert_eq!(lang_from_reg_query(""), None);
    }

    #[test]
    fn options_are_parsed_strictly() {
        let p = |a: &[&str]| parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let o = p(&["--lang", "RU", "--no-open"]).unwrap().unwrap();
        assert_eq!((o.lang, o.no_open), (Lang::Ru, true));
        assert!(p(&["--help"]).unwrap().is_none());
        assert!(p(&["--lang"]).unwrap_err().contains("en or ru"));
        assert!(
            p(&["--lang", "de"])
                .unwrap_err()
                .contains("unknown language 'de'")
        );
        assert!(p(&["--open"]).unwrap_err().contains("unknown option"));
        assert!(p(&["x"]).unwrap_err().contains("unexpected argument"));
    }

    #[test]
    fn the_page_is_written_atomically_and_replaced() {
        let dir = std::env::temp_dir().join(format!(
            "jetscan-guide-write-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let p = write_atomic(&dir.join("guide"), "g.html", b"one").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        let p = write_atomic(&dir.join("guide"), "g.html", b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        let left: Vec<_> = std::fs::read_dir(dir.join("guide")).unwrap().collect();
        assert_eq!(left.len(), 1, "no temporary file is left");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_free_build_embeds_only_the_public_guide() {
        for lang in [Lang::En, Lang::Ru] {
            let md = markdown(lang);
            assert!(md.starts_with("# "), "{lang:?}");
            // Pro-only chapters of the full guide (docs/guide/en.md, ru.md).
            for pro_only in ["WEB-RLS-009", "ANDROID-SIGNING-008", "URL-HSTS-001"] {
                assert_eq!(md.contains(pro_only), cfg!(feature = "pro"), "{pro_only}");
            }
        }
        assert!(markdown(Lang::Ru).contains("jetscan guide"));
        assert!(markdown(Lang::En).contains("jetscan guide"));
    }

    /// `#…` links of a page that point to no `id`.
    pub(crate) fn broken_links(html: &str) -> Vec<String> {
        let ids: std::collections::HashSet<&str> = html
            .split(" id=\"")
            .skip(1)
            .filter_map(|s| s.split('"').next())
            .collect();
        html.split("href=\"#")
            .skip(1)
            .filter_map(|s| s.split('"').next())
            .filter(|id| !ids.contains(id))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn every_link_inside_the_page_works_for_every_plan() {
        use license::{Area, Claims, License, Plan, ed25519, issue_with, today, verify};
        let seed = [42u8; 32]; // the license tests' throwaway fixture, never a real key
        let key = |claims: Claims| {
            let l = License {
                id: "JS-GUIDE-LINKS".into(),
                org: "Acme".into(),
                plan: claims.plan.as_str().into(),
                seats: 20,
                issued: today() - 1,
                expires: today() + 100,
            };
            let key = issue_with(&l, &claims, &seed).unwrap();
            verify(&key, &[ed25519::public_key(&seed)], today())
        };
        let plans = [
            license::Checked::free(),
            key(Claims::trial(Area::Web, 2)),
            key(Claims::plan(Plan::Pro)),
            key(Claims::plan(Plan::Teams)),
        ];
        for lang in [Lang::En, Lang::Ru] {
            let full = render::render_page(markdown(lang), lang.code());
            assert_eq!(broken_links(&full), Vec::<String>::new(), "{lang:?}");
            for checked in &plans {
                let p = plan::YourPlan::of(checked, 0, edition::PRO);
                let md = plan::tailor(markdown(lang), lang, &p);
                let html = render::render_page(&md, lang.code());
                assert_eq!(
                    broken_links(&html),
                    Vec::<String>::new(),
                    "{lang:?} {}",
                    p.summary()
                );
            }
        }
    }

    #[test]
    fn the_page_is_self_contained() {
        for lang in [Lang::En, Lang::Ru] {
            let free = plan::YourPlan::of(&license::Checked::free(), 0, edition::PRO);
            let html = render::render_page(&plan::tailor(markdown(lang), lang, &free), lang.code());
            assert!(html.contains(
                "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
                 style-src 'unsafe-inline'\">"
            ));
            assert!(html.contains("prefers-color-scheme: dark"));
            assert!(html.contains(&format!("<html lang=\"{}\">", lang.code())));
            for external in ["<script", "<link", "<img", "src=\"http", "@import", "url("] {
                assert!(!html.contains(external), "{lang:?}: {external}");
            }
        }
    }
}
