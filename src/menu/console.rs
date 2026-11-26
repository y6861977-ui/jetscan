//! The "jetscan console" menu item: a prompt inside the menu that accepts jetscan commands
//! only, for people who have no terminal open (jetscan.exe started by a double click).
//!
//! Each line is split into arguments ([`split_args`], Windows-friendly quoting), a leading
//! `jetscan` / `jetscan.exe` / `.\jetscan.exe` is dropped, and the arguments go to the same
//! entry point the command line uses (`exec`, which is `jetscan_main` in the binary, run in
//! this process with `catch_unwind`). The console never dispatches a shell or arbitrary program;
//! scanners keep their existing git/curl behavior.
//! `guide` (also `instructions`, `docs`) opens the user guide in the browser, like the menu item.
//! A first word that is not a jetscan command is refused, and so are `menu` / `console`
//! (already here) and `mcp` (a stdio server for AI editors, which would take over this window).

use super::*;

/// jetscan's own commands, as the first word of a console line (both builds: in the free
/// build a Pro command explains where it comes from).
const COMMANDS: &[&str] = &[
    "scan",
    "secrets",
    "deps",
    "machine",
    "hook",
    "license",
    "resolve",
    "guide",
    "instructions",
    "docs",
];

/// `help`: the commands of every build.
const HELP_FREE: &[(&str, &str)] = &[
    (
        "scan [folder]",
        "secrets + vulnerable packages + GitHub Actions",
    ),
    ("secrets [folder]", "leaked secrets only (offline)"),
    ("deps [folder]", "vulnerable packages only (OSV.dev)"),
    ("machine", "exposed credentials on this whole computer"),
    (
        "hook install [repo]",
        "git pre-commit hook that blocks secrets",
    ),
    ("license", "license key: plan, expiry, what it unlocks"),
    (
        "resolve plan [folder]",
        "fix plan for GitHub Actions (alpha)",
    ),
    ("guide", "the full user guide in your browser (offline)"),
];

/// `help`: the jetscan Pro commands of this build.
#[cfg(feature = "pro")]
const HELP_PRO: &[(&str, &str)] = &[
    (
        "web source [folder]",
        "website source code (Next.js / React)",
    ),
    (
        "apk <file.apk>",
        "Android app file (never installed or run)",
    ),
    ("android [folder]", "Android app source code"),
    ("ios [folder]", "iOS app source code"),
    ("url <https://site>", "passive check of a live website"),
    (
        "url verify <https://site>",
        "prove you own a site (meta tag, file, DNS)",
    ),
    (
        "  ... --write-file <folder>",
        "jetscan creates the file in your site's code",
    ),
    ("  ... --check", "check it after you published"),
    ("url status", "sites you verified"),
];

/// The keep-it-small history list.
const HISTORY_MAX: usize = 100;

/// Splits a typed command line into arguments.
///
/// - Spaces separate arguments; `"double quotes"` group them (and can sit inside a word:
///   `--x="a b"` is `--x=a b`). A backslash is an ordinary character there, so Windows paths
///   work as typed or pasted, including `"C:\dir\"`.
/// - `'single quotes'` group only at the start of an argument (PowerShell's drag-and-drop
///   `& 'C:\x y\app.apk'`; `''` inside is one `'`); elsewhere `'` is a letter (`O'Brien`).
/// - `backslash_escapes` (macOS / Linux terminals): outside quotes, `\` keeps the next
///   character (`My\ App.apk`).
///
/// An unclosed quote is an error, not a guess.
pub(super) fn split_args(line: &str, backslash_escapes: bool) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    args.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        None => return Err(unclosed('"')),
                        Some('"') => break,
                        Some(c) => word.push(c),
                    }
                }
            }
            '\'' if !in_word => {
                in_word = true;
                loop {
                    match chars.next() {
                        None => return Err(unclosed('\'')),
                        Some('\'') if chars.peek() == Some(&'\'') => {
                            chars.next();
                            word.push('\'');
                        }
                        Some('\'') => break,
                        Some(c) => word.push(c),
                    }
                }
            }
            '\\' if backslash_escapes => {
                in_word = true;
                word.push(chars.next().unwrap_or('\\'));
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        args.push(word);
    }
    Ok(args)
}

fn unclosed(q: char) -> String {
    format!("a {q} quote is not closed. Close it, or leave the quotes out.")
}

/// `jetscan`, `jetscan.exe`, `.\jetscan.exe`, `C:\x\jetscan-pro.exe`, `./jetscan`.
fn is_jetscan(word: &str) -> bool {
    let name = word.rsplit(['/', '\\']).next().unwrap_or(word);
    let name = name.to_ascii_lowercase();
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    stem == "jetscan" || stem.starts_with("jetscan-")
}

/// The words of a console line as jetscan arguments: a leading PowerShell `&` and a leading
/// jetscan program name are dropped.
fn jetscan_args(mut words: Vec<String>) -> Vec<String> {
    if words.first().is_some_and(|w| w == "&") {
        words.remove(0);
    }
    if words.first().is_some_and(|w| is_jetscan(w)) {
        words.remove(0);
    }
    words
}

/// What a console line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Line {
    Nothing,
    Exit,
    Help,
    HelpFor(Vec<String>),
    History,
    Clear,
    /// A refusal or a parse error, in plain words.
    Refuse(String),
    Run(Vec<String>),
}

const NOT_JETSCAN: &str = "Only jetscan commands work here: `help` lists them, `guide` explains.";

/// Why a jetscan command does not run in the console; `None`: it does.
fn refused(word: &str) -> Option<String> {
    Some(match word {
        "menu" => "You are in the menu already. Type exit to go back to it.".to_string(),
        "console" => "You are in the console already.".to_string(),
        "mcp" => "`jetscan mcp` is a server for AI editors: the editor starts it, not you. \
                  Menu item 6 shows how to connect it."
            .to_string(),
        w if COMMANDS.contains(&w)
            || edition::PRO_COMMANDS.iter().any(|(name, _)| *name == w)
            || matches!(w, "--help" | "-h" | "--version" | "-V") =>
        {
            return None;
        }
        // Two lines: the second, the rule, is never wrapped apart.
        _ => format!("That is not a jetscan command.\n{NOT_JETSCAN}"),
    })
}

fn classify(line: &str) -> Line {
    let words = match split_args(line, !cfg!(windows)) {
        Ok(w) => jetscan_args(w),
        Err(e) => return Line::Refuse(e),
    };
    let Some(first) = words.first() else {
        // Nothing typed, or only `jetscan`: the list of commands.
        return if line.trim().is_empty() {
            Line::Nothing
        } else {
            Line::Help
        };
    };
    match (first.to_ascii_lowercase().as_str(), words.len()) {
        ("exit" | "quit" | "q" | "0", 1) => Line::Exit,
        ("help" | "?", 1) => Line::Help,
        ("help", _) => {
            let rest = words[1..].to_vec();
            if matches!(rest[0].as_str(), "console" | "help") {
                return Line::Help;
            }
            match refused(&rest[0]) {
                Some(why) => Line::Refuse(why),
                None => Line::HelpFor(rest),
            }
        }
        ("history", 1) => Line::History,
        ("clear" | "cls", 1) => Line::Clear,
        _ => match refused(first) {
            Some(why) => Line::Refuse(why),
            None => Line::Run(words),
        },
    }
}

/// Keep only a safe in-memory history. License arguments may contain a key that is not a
/// scanner-recognized secret, so omit them regardless of syntax or validity.
fn history_line(line: &str, parsed: &Line) -> String {
    match parsed {
        Line::Refuse(_) => "[refused command]".into(),
        Line::Run(args) | Line::HelpFor(args) if args.first().is_some_and(|a| a == "license") => {
            "license [arguments omitted]".into()
        }
        _ => RedactionPolicy::default().text(line),
    }
}

/// The exit code in plain words.
fn outcome(args: &[String], code: i32) -> String {
    let check = args.first().is_some_and(|a| a == "url")
        && args.iter().any(|a| a == "verify")
        && args.iter().any(|a| a == "--check");
    match code {
        0 => "done".to_string(),
        1 if check => "not verified yet (exit 1)".to_string(),
        1 => "found issues (exit 1)".to_string(),
        2 => "error (exit 2)".to_string(),
        n => format!("stopped (exit {n})"),
    }
}

impl<R: BufRead, W: Write> Session<'_, R, W> {
    /// The console. Returns to the menu on exit / quit / 0 or the end of input.
    pub(super) fn console(&mut self) -> Step<()> {
        self.title("jetscan console");
        self.text(
            "Type a jetscan command and press Enter, for example: secrets .   or   \
             scan \"C:\\My Projects\\app\"",
        );
        self.hint(
            "Only jetscan's own commands run here. help = the list, \
             exit = back to the menu. Paths with spaces go in \"double quotes\" (dragging a \
             file or folder into this window adds them).",
        );
        loop {
            self.say("");
            let raw = match self.ask("jetscan> ") {
                Ok(line) => line,
                // The end of input: back to the menu (which then ends too).
                Err(_) => return Err(Stop::Back),
            };
            let line = raw.trim();
            let parsed = classify(line);
            if !matches!(parsed, Line::Nothing | Line::History) {
                if self.history.len() == HISTORY_MAX {
                    self.history.remove(0);
                }
                self.history.push(history_line(line, &parsed));
            }
            match parsed {
                Line::Nothing => {}
                Line::Exit => return Err(Stop::Back),
                Line::Help => self.console_help(),
                Line::HelpFor(mut words) => {
                    // `hook` and `license` have no `--help` of their own: the full usage.
                    if matches!(words[0].as_str(), "hook" | "license") {
                        words = vec!["--help".to_string()];
                    } else {
                        words.push("--help".to_string());
                    }
                    self.console_exec(&words);
                }
                Line::History => {
                    if self.history.is_empty() {
                        self.hint("Nothing typed yet.");
                    }
                    let lines: Vec<String> = self
                        .history
                        .iter()
                        .enumerate()
                        .map(|(i, l)| format!("  {:>3}  {l}", i + 1))
                        .collect();
                    for l in lines {
                        self.say(&l);
                    }
                }
                Line::Clear => {
                    if ui::colors() {
                        let _ = write!(self.out, "\x1b[2J\x1b[H");
                    } else {
                        self.say("\n\n");
                    }
                }
                Line::Refuse(why) => {
                    for part in why.lines() {
                        self.warn(part);
                    }
                }
                Line::Run(args) => self.console_exec(&args),
            }
        }
    }

    /// Runs one jetscan command in this process and says how it ended.
    fn console_exec(&mut self, args: &[String]) {
        self.say("");
        let _ = self.out.flush();
        let code = (self.exec)(args);
        let _ = std::io::stdout().flush();
        let words = outcome(args, code);
        let line = format!("  {words}");
        self.say("");
        self.say(&match code {
            0 => ui::green(&line),
            1 => ui::yellow(&line),
            _ => ui::red(&line),
        });
    }

    fn console_help(&mut self) {
        self.title("Commands (type them without \"jetscan\" in front, or with it):");
        let list = |s: &mut Self, items: &[(&str, &str)]| {
            for (cmd, what) in items {
                s.say(&format!("  {}  {what}", ui::cyan(&ui::pad_right(cmd, 26))));
            }
        };
        list(self, HELP_FREE);
        #[cfg(feature = "pro")]
        {
            self.say("");
            self.say(&format!("  {}", ui::bold("jetscan Pro")));
            list(self, HELP_PRO);
        }
        #[cfg(not(feature = "pro"))]
        self.hint(&format!(
            "jetscan Pro adds web, apk, android, ios and url: {}",
            edition::SITE
        ));
        self.say("");
        self.hint(
            "help <command> = its options (e.g. help secrets). guide = the full user guide in \
             your browser. history = this session's commands (sensitive values omitted). \
             clear = clear the screen. exit = back to the menu.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Temp, drive, strings};
    use super::*;

    fn split(line: &str) -> Vec<String> {
        split_args(line, false).unwrap()
    }

    #[test]
    fn splits_like_a_windows_user_expects() {
        assert_eq!(split("secrets ."), strings(&["secrets", "."]));
        assert_eq!(split("  scan   proj  "), strings(&["scan", "proj"]));
        assert_eq!(split(""), Vec::<String>::new());
        assert_eq!(split("   "), Vec::<String>::new());
        // Quoted paths with spaces, as typed or drag-and-dropped.
        assert_eq!(
            split(r#"apk "C:\Users\Me\My Apps\app.apk""#),
            strings(&["apk", r"C:\Users\Me\My Apps\app.apk"])
        );
        // A trailing backslash before the closing quote is a backslash, not an escape.
        assert_eq!(
            split(r#"secrets "C:\My Projects\" --no-history"#),
            strings(&["secrets", r"C:\My Projects\", "--no-history"])
        );
        // Unquoted Windows paths keep their backslashes.
        assert_eq!(
            split(r"secrets C:\work\app"),
            strings(&["secrets", r"C:\work\app"])
        );
        // Quotes inside a word, an empty quoted argument.
        assert_eq!(split(r#"a--x="b c"d"#), strings(&[r"a--x=b cd"]));
        assert_eq!(split(r#"x "" y"#), strings(&["x", "", "y"]));
        // PowerShell drag-and-drop: & 'C:\x y\app.apk'; '' is one quote; ' inside a word.
        assert_eq!(
            split(r"& 'C:\x y\jetscan.exe' apk 'C:\O''Brien\a.apk'"),
            strings(&["&", r"C:\x y\jetscan.exe", "apk", r"C:\O'Brien\a.apk"])
        );
        assert_eq!(
            split(r"secrets C:\Users\O'Brien\app"),
            strings(&["secrets", r"C:\Users\O'Brien\app"])
        );
        // Unbalanced quotes are an error.
        for bad in [r#"apk "C:\x y\app.apk"#, "secrets 'C:\\x", "\""] {
            let e = split_args(bad, false).unwrap_err();
            assert!(e.contains("quote is not closed"), "{bad}: {e}");
        }
        // macOS / Linux terminals escape spaces with a backslash.
        assert_eq!(
            split_args(r"apk /Users/me/My\ App.apk", true).unwrap(),
            strings(&["apk", "/Users/me/My App.apk"])
        );
        assert_eq!(
            split_args(r#"apk "/a\b""#, true).unwrap(),
            strings(&["apk", r"/a\b"])
        );
    }

    #[test]
    fn a_leading_jetscan_is_dropped() {
        for line in [
            "secrets .",
            "jetscan secrets .",
            "jetscan.exe secrets .",
            r".\jetscan.exe secrets .",
            "./jetscan secrets .",
            r#""C:\Users\Me\Desktop\jetscan-pro.exe" secrets ."#,
            r"& 'C:\x y\JetScan.EXE' secrets .",
        ] {
            assert_eq!(
                jetscan_args(split(line)),
                strings(&["secrets", "."]),
                "{line}"
            );
        }
        assert_eq!(classify("jetscan"), Line::Help);
        // Only the first word: `secrets jetscan` scans a folder named jetscan.
        assert_eq!(
            classify("secrets jetscan"),
            Line::Run(strings(&["secrets", "jetscan"]))
        );
    }

    #[test]
    fn only_jetscan_commands_are_accepted() {
        for line in [
            "dir",
            "cmd /c whoami",
            "powershell -c ls",
            "rm -rf /",
            "notepad.exe",
            "jetscan dir",
            "& calc.exe",
            "git status",
        ] {
            match classify(line) {
                Line::Refuse(why) => assert!(why.contains(NOT_JETSCAN), "{line}: {why}"),
                other => panic!("{line}: {other:?}"),
            }
        }
        for (line, needle) in [
            ("menu", "in the menu already"),
            ("jetscan menu", "in the menu already"),
            ("console", "in the console already"),
            ("mcp", "server for AI editors"),
            ("jetscan.exe mcp --root .", "server for AI editors"),
            ("help mcp", "server for AI editors"),
            (r#"apk "C:\x"#, "quote is not closed"),
        ] {
            match classify(line) {
                Line::Refuse(why) => assert!(why.contains(needle), "{line}: {why}"),
                other => panic!("{line}: {other:?}"),
            }
        }
        for line in [
            "scan",
            "deps . --offline",
            "machine",
            "hook install",
            "license",
            "resolve plan .",
            "guide",
            "instructions --lang ru",
            "jetscan docs --no-open",
            "web source .",
            "apk a.apk",
            "android",
            "ios",
            "url https://example.com",
            "--version",
            "-h",
        ] {
            assert!(matches!(classify(line), Line::Run(_)), "{line}");
        }
        assert_eq!(classify(""), Line::Nothing);
        for exit in ["exit", "quit", "0", "EXIT", "q"] {
            assert_eq!(classify(exit), Line::Exit, "{exit}");
        }
        assert_eq!(classify("help"), Line::Help);
        assert_eq!(
            classify("help secrets"),
            Line::HelpFor(strings(&["secrets"]))
        );
        assert_eq!(classify("history"), Line::History);
        assert_eq!(classify("clear"), Line::Clear);
    }

    #[test]
    fn exit_codes_in_plain_words() {
        let a = strings(&["secrets", "."]);
        assert_eq!(outcome(&a, 0), "done");
        assert_eq!(outcome(&a, 1), "found issues (exit 1)");
        assert_eq!(outcome(&a, 2), "error (exit 2)");
        let check = strings(&["url", "verify", "https://a.example", "--check"]);
        assert_eq!(outcome(&check, 1), "not verified yet (exit 1)");
    }

    #[test]
    fn the_console_runs_only_jetscan_commands_and_returns_to_the_menu() {
        let t = Temp::new("console");
        let script = format!(
            "{}\nsecrets \"C:\\My Projects\\app\" --no-history\njetscan.exe scan .\ndir\nmenu\n\
             mcp\nhelp\nhelp secrets\nhistory\nclear\nexit\n0\n",
            CONSOLE
        );
        let mut codes = vec![1, 0, 0].into_iter();
        let (code, text, ran) = drive(&script, &t.0, &mut |_| codes.next().unwrap_or(2));
        assert_eq!(code, 0);
        assert_eq!(
            ran,
            vec![
                strings(&["secrets", r"C:\My Projects\app", "--no-history"]),
                strings(&["scan", "."]),
                strings(&["secrets", "--help"]),
            ],
            "{text}"
        );
        assert!(text.contains("jetscan> "), "{text}");
        assert!(text.contains("found issues (exit 1)"), "{text}");
        assert!(text.contains("  done"), "{text}");
        assert!(text.contains("That is not a jetscan command"), "{text}");
        assert!(text.contains(NOT_JETSCAN), "{text}");
        assert!(text.contains("in the menu already"), "{text}");
        assert!(text.contains("server for AI editors"), "{text}");
        assert!(text.contains("secrets [folder]"), "{text}");
        assert_eq!(
            text.contains("url verify <https://site>"),
            cfg!(feature = "pro")
        );
        // history lists what was typed, numbered, without itself.
        assert!(
            text.contains("    1  secrets \"C:\\My Projects\\app\" --no-history"),
            "{text}"
        );
        assert!(text.contains("    4  [refused command]"), "{text}");
        assert!(
            !text.lines().any(|l| l.ends_with("  history")
                && l.trim_start().starts_with(|c: char| c.is_ascii_digit())),
            "{text}"
        );
        for line in text.lines() {
            // Typed input is not echoed here: in a console the prompt line ends at Enter.
            let line = line.strip_prefix("jetscan> ").unwrap_or(line);
            assert!(line.chars().count() <= WIDTH, "too wide: {line:?}");
        }
        // Back in the menu: no "Equivalent command" block for console lines, then Bye.
        assert!(!text.contains("Equivalent command"), "{text}");
        assert!(text.trim_end().ends_with("Bye."), "{text}");
        // The end of input inside the console: back to the menu, which ends too.
        let (code, text, ran) = drive(&format!("{CONSOLE}\nsecrets .\n"), &t.0, &mut |_| 0);
        assert_eq!((code, ran.len()), (0, 1));
        assert!(text.trim_end().ends_with("Bye."), "{text}");
    }

    #[test]
    fn history_is_kept_small() {
        let t = Temp::new("console-history");
        let mut script = format!("{CONSOLE}\n");
        for i in 0..(HISTORY_MAX + 5) {
            script.push_str(&format!("help secrets --fixture-{i}\n"));
        }
        script.push_str("history\n");
        let (_, text, ran) = drive(&script, &t.0, &mut |_| 0);
        assert_eq!(ran.len(), HISTORY_MAX + 5);
        assert!(
            text.contains(&format!(
                "  {HISTORY_MAX}  help secrets --fixture-{}",
                HISTORY_MAX + 4
            )),
            "{text}"
        );
        assert!(!text.contains("  1  help secrets --fixture-0\n"), "{text}");
    }

    #[test]
    fn console_history_and_refusals_do_not_echo_secrets_or_license_arguments() {
        let t = Temp::new("console-redaction");
        let token = ["ghp_", &"Zq8".repeat(12)].concat();
        let key = ["private", "license-value"].join("-");
        let script = format!(
            "{CONSOLE}\n{token}\nsecrets {token}\nlicense activate {key}\nlicense \"{key}\nhistory\nexit\n0\n"
        );
        let (_, text, ran) = drive(&script, &t.0, &mut |_| 2);
        assert_eq!(ran.len(), 2);
        assert!(!text.contains(&token) && !text.contains(&key), "{text}");
        assert!(text.contains("[redacted]") && text.contains("license [arguments omitted]"));
        assert!(text.contains("error (exit 2)"));
    }
}
