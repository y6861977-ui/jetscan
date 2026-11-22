//! `jetscan` with no arguments in a terminal (or `jetscan menu`): a numbered menu for people
//! who do not want to type commands — typically jetscan.exe started by a double click.
//!
//! The menu only asks questions and builds an argument vector; every action runs through the
//! same entry point as the CLI (`exec`, which is `jetscan_main` in the binary), so output and
//! exit codes are exactly those of the equivalent command, which is printed after each run.
//! Input and output are injected (`BufRead` + `Write`) so the dialogue is testable.
//!
//! The one item that is not a jetscan command, "Connect jetscan to your AI editor", only prints
//! setup instructions. It never edits an editor's config file; the only thing it may run is
//! `claude mcp add ...`, and only when Claude Code is on PATH and the user types exactly `yes`.
//!
//! The "jetscan console" item (`menu/console.rs`) is a prompt that accepts jetscan commands
//! only; it runs them through `exec` too and never starts any other program.
//!
//! Items 1-6 and 12 (the console) are the same in every build. jetscan Pro (`menu/pro.rs`)
//! adds 7-11. The console sits in the FIX AND TOOLS group.

use jetscan::finding_v2::{RedactionPolicy, RemediationState};
use jetscan::resolve::ResolvePlan;
use jetscan::{edition, ui};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// Why a dialogue stopped early: end of input (quit jetscan) or "0" (back to the menu).
#[derive(Debug, PartialEq)]
enum Stop {
    Quit,
    Back,
}

type Step<T> = Result<T, Stop>;

/// Runs one jetscan command (arguments without the program name) and returns its exit code.
pub type Exec<'a> = dyn FnMut(&[String]) -> i32 + 'a;

/// What the menu needs from this computer besides running jetscan itself (injected for tests).
pub trait Host {
    /// This jetscan program, readable (`C:\x\jetscan.exe`, not `\\?\C:\x\jetscan.exe`).
    fn jetscan_exe(&self) -> Option<PathBuf>;
    /// The Claude Code command-line tool, if it is on PATH.
    fn claude(&self) -> Option<PathBuf>;
    /// Runs `program args` in this terminal and waits. `None`: it could not be started.
    fn spawn(&mut self, program: &Path, args: &[String]) -> Option<i32>;
    /// Waits (jetscan Pro: the pause between two ownership checks of a website).
    #[cfg_attr(not(feature = "pro"), allow(dead_code))]
    fn wait(&mut self, time: std::time::Duration);
}

/// The real computer.
pub struct System;

impl Host for System {
    fn jetscan_exe(&self) -> Option<PathBuf> {
        std::env::current_exe()
            .ok()
            .map(|p| PathBuf::from(plain(&p)))
    }

    fn claude(&self) -> Option<PathBuf> {
        // npm installs `claude.cmd`, the native installer `claude.exe`.
        let names: &[&str] = if cfg!(windows) {
            &["claude.exe", "claude.cmd"]
        } else {
            &["claude"]
        };
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .filter(|dir| dir.is_absolute())
            .flat_map(|dir| names.iter().map(move |n| dir.join(n)))
            .find(|p| p.is_file())
    }

    fn spawn(&mut self, program: &Path, args: &[String]) -> Option<i32> {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .ok()?;
        Some(status.code().unwrap_or(1))
    }

    fn wait(&mut self, time: std::time::Duration) {
        std::thread::sleep(time);
    }
}

struct Session<'a, R: BufRead, W: Write> {
    input: &'a mut R,
    out: &'a mut W,
    exec: &'a mut Exec<'a>,
    host: &'a mut dyn Host,
    cwd: &'a Path,
    /// Where `resolve plan --out` writes its plan (never inside the project).
    plan_dir: PathBuf,
    /// Commands run by the current action, for the "Equivalent command" lines.
    ran: Vec<Vec<String>>,
    /// Lines typed into the console, for its `history` (this menu session only).
    history: Vec<String>,
}

mod console;
#[cfg(feature = "pro")]
mod pro;
/// Stable in free and Pro builds; numbers 7-11 belong to Pro.
const CONSOLE: &str = "12";

/// Whether `jetscan` without arguments should open the menu instead of printing usage.
pub fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// The menu loop. Returns the process exit code (0: the user quit or input ended).
pub fn run<R: BufRead, W: Write>(
    input: &mut R,
    out: &mut W,
    cwd: &Path,
    plan_dir: &Path,
    exec: &mut Exec<'_>,
    host: &mut dyn Host,
) -> i32 {
    let mut s = Session {
        input,
        out,
        exec,
        host,
        cwd,
        plan_dir: plan_dir.to_path_buf(),
        ran: Vec::new(),
        history: Vec::new(),
    };
    s.header();
    loop {
        s.show_menu();
        s.say("");
        let Ok(choice) = s.ask(&format!(
            "  {} ",
            ui::bold("Type a number and press Enter:")
        )) else {
            return s.bye();
        };
        s.ran.clear();
        let result = match choice.trim().to_ascii_lowercase().as_str() {
            "1" => s.scan(),
            "2" => s.secrets(),
            "3" => s.resolve(),
            "4" => s.machine(),
            "5" => s.license(),
            "6" => s.connect(),
            c if c == CONSOLE => s.console(),
            "0" | "q" | "quit" | "exit" => return s.bye(),
            "" => continue,
            other => match s.pro_choice(other) {
                Some(result) => result,
                None => {
                    s.warn(&format!(
                        "'{}' is not on the list. Type one of the numbers shown above.",
                        ui::sanitize_line(other)
                    ));
                    continue;
                }
            },
        };
        if result == Err(Stop::Quit) {
            return s.bye();
        }
        if !s.ran.is_empty() {
            s.show_commands();
            if s.pause().is_err() {
                return s.bye();
            }
        }
    }
}

/// The widest line the menu writes itself (paths and commands excepted): an 80-column
/// console with a margin.
const WIDTH: usize = 78;
/// Menu numbers are right-aligned in this many columns; the item text follows 3 spaces on.
const NUMBER: usize = 6;
/// Item text is padded to this width before a tag such as "alpha".
const ITEM_TEXT: usize = 55;
/// The answer prompt of every question.
const PROMPT: &str = "  > ";

/// Words of `text` in lines of at most `width` columns (a longer word gets its own line),
/// each starting with `indent`.
fn wrap(text: &str, indent: &str, width: usize) -> Vec<String> {
    let room = width.saturating_sub(indent.chars().count()).max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let len = line.chars().count();
        if len > 0 && len + 1 + word.chars().count() > room {
            lines.push(format!("{indent}{line}"));
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(format!("{indent}{line}"));
    }
    lines
}

impl<R: BufRead, W: Write> Session<'_, R, W> {
    fn say(&mut self, line: &str) {
        let _ = writeln!(self.out, "{line}");
    }

    /// Prints `prompt` and reads one line (without the line break). End of input: quit.
    fn ask(&mut self, prompt: &str) -> Step<String> {
        let _ = write!(self.out, "{prompt}");
        let _ = self.out.flush();
        let mut line = Vec::new();
        match self.input.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => {
                let _ = writeln!(self.out);
                Err(Stop::Quit)
            }
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                // Windows PowerShell 5.1 prefixes piped input with a UTF-8 BOM.
                let text = text.trim_start_matches('\u{feff}');
                Ok(text.trim_end_matches(['\n', '\r']).to_string())
            }
        }
    }

    /// A paragraph, wrapped to the menu width.
    fn text(&mut self, text: &str) {
        for line in wrap(text, "  ", WIDTH) {
            self.say(&line);
        }
    }

    /// A short dimmed hint under a question or a title, wrapped.
    fn hint(&mut self, text: &str) {
        for line in wrap(text, "    ", WIDTH) {
            self.say(&ui::dim(&line));
        }
    }

    /// A warning or "try again" line, wrapped.
    fn warn(&mut self, text: &str) {
        for line in wrap(text, "  ", WIDTH) {
            self.say(&ui::yellow(&line));
        }
    }

    /// A blank line, then a bold title or question.
    fn title(&mut self, text: &str) {
        self.say("");
        for line in wrap(text, "  ", WIDTH) {
            self.say(&ui::bold(&line));
        }
    }

    fn header(&mut self) {
        self.say("");
        self.say(&format!(
            "  {}  {}",
            ui::bold(&format!("jetscan {}", edition::version())),
            ui::dim("—  security scanner")
        ));
        self.say(&format!(
            "  {}",
            ui::dim("Everything runs on this computer. Your code and files are never uploaded.")
        ));
    }

    fn show_menu(&mut self) {
        self.group("CHECK A PROJECT");
        self.item(
            "1",
            "Leaked secrets, vulnerable packages and risky GitHub Actions",
            None,
        );
        self.item("2", "Leaked secrets only", None);
        self.group("FIX AND TOOLS");
        self.item(
            "3",
            "Fix what was found  (plan → preview → apply → verify)",
            Some("alpha"),
        );
        self.item(
            "4",
            "Scan this whole computer for exposed credentials",
            None,
        );
        self.item("5", "License status / where to buy", None);
        self.item(
            "6",
            "Connect jetscan to your AI editor (Claude Code, Cursor, VS Code…)",
            None,
        );
        self.item(CONSOLE, "jetscan console — type jetscan commands", None);
        self.group("JETSCAN PRO");
        self.pro_menu();
        self.say("");
        self.item("0", "Quit", None);
    }

    /// A blank line and a group heading (bold capitals; plain capitals without colors).
    fn group(&mut self, name: &str) {
        self.say("");
        self.say(&format!("  {}", ui::bold(name)));
    }

    /// `     7   Text ...    alpha`: the number right-aligned, an optional tag in its column.
    fn item(&mut self, key: &str, text: &str, tag: Option<&str>) {
        let number = format!(
            "{}{}",
            " ".repeat(NUMBER.saturating_sub(key.len())),
            ui::cyan(key)
        );
        let line = match tag {
            Some(tag) => format!(
                "{number}   {}  {}",
                ui::pad_right(text, ITEM_TEXT),
                ui::dim(tag)
            ),
            None => format!("{number}   {text}"),
        };
        self.say(&line);
    }

    /// The free build lists no Pro items, only where jetscan Pro comes from.
    #[cfg(not(feature = "pro"))]
    fn pro_menu(&mut self) {
        let indent = " ".repeat(NUMBER + 3);
        self.say(&ui::dim(&format!(
            "{indent}jetscan Pro adds website, APK, Android, iOS and live-site checks"
        )));
        self.say(&format!("{indent}{}", ui::cyan(edition::SITE)));
    }

    #[cfg(not(feature = "pro"))]
    fn pro_choice(&mut self, _choice: &str) -> Option<Step<()>> {
        None
    }

    fn bye(&mut self) -> i32 {
        self.say("");
        self.say("  Bye.");
        let _ = self.out.flush();
        0
    }

    /// Runs one command through the CLI entry point and remembers it.
    fn run(&mut self, args: Vec<String>) -> i32 {
        self.say("");
        self.say(&format!(
            "  {}",
            ui::dim(&format!("Running: {}", command_line(&args)))
        ));
        self.say("");
        let _ = self.out.flush();
        let code = (self.exec)(&args);
        let _ = std::io::stdout().flush();
        self.ran.push(args);
        code
    }

    fn show_commands(&mut self) {
        let label = if self.ran.len() == 1 {
            "Equivalent command:"
        } else {
            "Equivalent commands:"
        };
        self.say("");
        self.say(&format!("  {}", ui::bold(label)));
        let lines: Vec<String> = self.ran.iter().map(|a| command_line(a)).collect();
        for line in lines {
            self.say(&format!("    {}", ui::cyan(&line)));
        }
    }

    /// A folder to work on. `None`: the current folder (the CLI default). `note`: a hint
    /// under the question ("" for none).
    fn folder(&mut self, question: &str, note: &str) -> Step<Option<String>> {
        self.title(question);
        if !note.is_empty() {
            self.hint(note);
        }
        self.hint("Press Enter for this folder:");
        let here = shown(self.cwd);
        self.say(&format!("      {}", ui::cyan(&here)));
        self.hint("Or type another path (you can drag the folder into this window). 0 = back");
        loop {
            let raw = self.ask(PROMPT)?;
            let typed = clean_path(&raw);
            if typed.is_empty() {
                return Ok(None);
            }
            if typed == "0" {
                return Err(Stop::Back);
            }
            let path = self.absolute(&typed);
            if path.is_dir() {
                return Ok(Some(typed));
            }
            let why = if path.exists() {
                "That is a file, not a folder"
            } else {
                "No such folder"
            };
            self.warn(&format!(
                "{why}: {}. Try again, or 0 to go back.",
                shown(&path)
            ));
        }
    }

    /// A yes/no question with an optional hint (`note`, "" for none).
    fn yes_no(&mut self, question: &str, note: &str, default: bool) -> Step<bool> {
        self.title(question);
        if !note.is_empty() {
            self.hint(note);
        }
        self.hint(&format!(
            "Type y or n. Enter = {}. 0 = back",
            if default { "yes" } else { "no" }
        ));
        loop {
            let answer = self.ask(PROMPT)?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                "0" => return Err(Stop::Back),
                _ => self.warn("Please answer y or n (or 0 to go back)."),
            }
        }
    }

    fn absolute(&self, typed: &str) -> PathBuf {
        let p = Path::new(typed);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.cwd.join(p)
        }
    }

    /// Asks about git history only where there is one; `true` adds `--no-history`.
    fn skip_history(&mut self, folder: &Option<String>) -> Step<bool> {
        let dir = folder
            .as_deref()
            .map_or_else(|| self.cwd.to_path_buf(), |f| self.absolute(f));
        if !dir.join(".git").exists() {
            return Ok(false);
        }
        let check = self.yes_no(
            "Also check the git history (old commits)?",
            "Slower on big projects.",
            true,
        )?;
        Ok(!check)
    }

    fn scan(&mut self) -> Step<()> {
        let folder = self.folder("Which project folder should be scanned?", "")?;
        let no_history = self.skip_history(&folder)?;
        let online = self.yes_no(
            "Look up vulnerable packages online (OSV.dev)?",
            "Only package names and versions are sent, never code or file paths.",
            true,
        )?;
        let mut args = vec!["scan".to_string()];
        args.extend(folder);
        if no_history {
            args.push("--no-history".into());
        }
        if !online {
            args.push("--offline".into());
        }
        self.run(args);
        Ok(())
    }

    fn secrets(&mut self) -> Step<()> {
        let folder = self.folder("Which project folder should be scanned for secrets?", "")?;
        let no_history = self.skip_history(&folder)?;
        let mut args = vec!["secrets".to_string()];
        args.extend(folder);
        if no_history {
            args.push("--no-history".into());
        }
        self.run(args);
        Ok(())
    }

    fn machine(&mut self) -> Step<()> {
        self.say("");
        self.text(
            "This looks through your home folder: saved passwords and tokens, SSH keys, shell \
             history and every git repository. It can take several minutes.",
        );
        let deps = self.yes_no(
            "Also check the packages of every repository for known vulnerabilities?",
            "Only package names and versions are sent to OSV.dev.",
            false,
        )?;
        let mut args = vec!["machine".to_string()];
        if deps {
            args.push("--deps".into());
        }
        self.run(args);
        Ok(())
    }

    fn license(&mut self) -> Step<()> {
        self.run(vec!["license".to_string()]);
        Ok(())
    }

    /// Setup instructions for `jetscan mcp` in AI editors. Prints only; the one optional
    /// action is `claude mcp add`, and only after an exact `yes`.
    fn connect(&mut self) -> Step<()> {
        self.title("Connect jetscan to your AI editor");
        self.text(
            "Your AI coding tool can then run jetscan's checks itself after it writes code: \
             leaked secrets, vulnerable packages, risky GitHub Actions.",
        );
        self.say("");
        self.text(
            "jetscan runs on this computer and uploads nothing. The AI tool sends jetscan's \
             reports (never the secret values) to its own AI model, like any text it reads. \
             The AI gets reports and fix plans only: jetscan changes no files for it.",
        );
        let Some(exe) = self.host.jetscan_exe() else {
            self.say("");
            self.warn(
                "Could not tell where this jetscan program is. Follow the guide and use the full \
                 path of the jetscan program:",
            );
            self.say(&format!("    {}", ui::cyan(MCP_GUIDE)));
            return self.pause();
        };
        let exe = exe.display().to_string();
        let add = |scope: &[&str]| {
            let mut a = strings_of(&["mcp", "add"]);
            a.extend(strings_of(scope));
            a.extend(strings_of(&["jetscan", "--", &exe, "mcp"]));
            a
        };
        let project_add = add(&[]);
        let user_add = add(&["--scope", "user"]);
        self.title("Claude Code: run one of these in a terminal");
        self.hint("For one project (run it in that project's folder):");
        self.say(&format!(
            "      {}",
            ui::cyan(&program_line("claude", &project_add))
        ));
        self.hint("For every project:");
        self.say(&format!(
            "      {}",
            ui::cyan(&program_line("claude", &user_add))
        ));
        self.hint("Check it with: claude mcp list");
        self.title("Cursor: save this as .cursor/mcp.json in your project");
        self.hint("Not yet tested with Cursor.");
        self.snippet(&editor_json("mcpServers", &exe));
        self.title("VS Code (Copilot): save this as .vscode/mcp.json in your project");
        self.hint("Not yet tested with VS Code.");
        self.snippet(&editor_json("servers", &exe));
        self.say("");
        self.text(
            "If the file already exists, add only the \"jetscan\" entry to it. Then restart the \
             editor or reload its MCP servers.",
        );
        self.say("");
        self.hint(&format!(
            "Free through the AI: secrets, packages, GitHub Actions, fix plans.{}",
            pro_connect_note()
        ));
        self.hint(&format!("Other editors and details: {MCP_GUIDE}"));
        if let Some(claude) = self.host.claude() {
            self.say("");
            self.text(&format!(
                "Claude Code is installed here ({}). jetscan can run the \"every project\" \
                 command above for you.",
                shown(&claude)
            ));
            self.say("");
            let answer = self.ask(&format!(
                "  Type {} to run it now, anything else skips: ",
                ui::bold("yes")
            ))?;
            if answer.trim() != "yes" {
                self.text("Skipped. Nothing was changed.");
                return self.pause();
            }
            self.say("");
            self.say(&format!(
                "  {}",
                ui::dim(&format!("Running: {}", program_line("claude", &user_add)))
            ));
            self.say("");
            let _ = self.out.flush();
            match self.host.spawn(&claude, &user_add) {
                Some(0) => self.say(&ui::green(
                    "  Done. Start a new Claude Code session; /mcp lists jetscan.",
                )),
                Some(code) => self.warn(&format!(
                    "claude stopped with exit code {code} (see above). You can run the command \
                     yourself."
                )),
                None => self.warn("claude could not be started. You can run the command yourself."),
            }
        }
        self.pause()
    }

    fn snippet(&mut self, text: &str) {
        for line in text.lines() {
            self.say(&format!("    {}", ui::sanitize_line(line)));
        }
    }

    fn pause(&mut self) -> Step<()> {
        self.say("");
        self.ask(&format!(
            "  {}",
            ui::dim("Press Enter to return to the menu")
        ))?;
        Ok(())
    }

    /// plan → preview → (exactly "yes") → apply --confirm → verify.
    fn resolve(&mut self) -> Step<()> {
        self.say("");
        self.text(
            "jetscan makes a fix plan for the project's GitHub Actions workflows and shows the \
             exact changes. Nothing is changed unless you type yes.",
        );
        let folder = self
            .folder("Which project folder?", "")?
            .unwrap_or_else(|| ".".to_string());
        let plan = self.plan_dir.join(format!(
            "jetscan-plan-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let plan_arg = plan.display().to_string();
        self.title("Step 1 of 4: make a fix plan (read-only)");
        let code = self.run(vec![
            "resolve".into(),
            "plan".into(),
            folder.clone(),
            "--out".into(),
            plan_arg.clone(),
        ]);
        if code != 0 {
            self.say("");
            self.warn("No plan was made (see above). Nothing was changed.");
            return Ok(());
        }
        self.title("Step 2 of 4: preview the changes (read-only)");
        if self.run(vec!["resolve".into(), "preview".into(), plan_arg.clone()]) != 0 {
            self.say("");
            self.warn("The plan could not be shown. Nothing was changed.");
            return Ok(());
        }
        if !applicable(&plan) {
            self.say("");
            self.warn(
                "There is nothing jetscan can change automatically here; the plan above is \
                 advice only. Nothing was changed.",
            );
            return Ok(());
        }
        self.title("Step 3 of 4: apply");
        self.say("");
        let answer = match self.ask(&format!(
            "  Apply these changes? Type {} to write them, anything else cancels: ",
            ui::bold("yes")
        )) {
            Ok(a) => a,
            Err(stop) => {
                self.text("Cancelled. Nothing was changed.");
                return Err(stop);
            }
        };
        if answer.trim() != "yes" {
            self.text("Cancelled. Nothing was changed. The plan is kept at:");
            self.say(&format!("    {}", shown(&plan)));
            return Ok(());
        }
        let code = self.run(vec![
            "resolve".into(),
            "apply".into(),
            plan_arg.clone(),
            "--confirm".into(),
            "--root".into(),
            folder,
        ]);
        if code != 0 {
            self.say("");
            self.warn("Apply did not finish (see above).");
            return Ok(());
        }
        self.title("Step 4 of 4: verify");
        self.run(vec!["resolve".into(), "verify".into(), plan_arg]);
        Ok(())
    }
}

#[cfg(not(feature = "pro"))]
fn pro_connect_note() -> &'static str {
    ""
}
#[cfg(feature = "pro")]
use pro::pro_connect_note;

/// Where the AI-editor setup is documented in full.
const MCP_GUIDE: &str = "https://github.com/y6861977-ui/jetscan/blob/main/docs/mcp/README.md";

/// An editor's MCP config (`key`: Cursor `mcpServers`, VS Code `servers`) that starts this
/// jetscan as a stdio server for the workspace folder. The path is JSON-escaped.
fn editor_json(key: &str, exe: &str) -> String {
    use jetscan::json::{Json, stringify};
    let command = stringify(&Json::Str(exe.to_string()));
    [
        "{".to_string(),
        format!("  \"{key}\": {{"),
        "    \"jetscan\": {".to_string(),
        "      \"type\": \"stdio\",".to_string(),
        format!("      \"command\": {command},"),
        "      \"args\": [\"mcp\", \"--root\", \"${workspaceFolder}\"]".to_string(),
        "    }".to_string(),
        "  }".to_string(),
        "}".to_string(),
    ]
    .join("\n")
}

/// For display: `\\?\C:\x` reads as `C:\x` (verbatim UNC paths are kept).
fn plain(p: &Path) -> String {
    let text = p.display().to_string();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with(r"UNC\") => rest.to_string(),
        _ => text,
    }
}

fn strings_of(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// Whether the saved plan has file patches to apply (not advice only).
fn applicable(plan: &Path) -> bool {
    std::fs::read_to_string(plan)
        .ok()
        .and_then(|text| ResolvePlan::parse(&text, &RedactionPolicy::default()).ok())
        .is_some_and(|p| p.status() == RemediationState::Available)
}

fn shown(p: &Path) -> String {
    ui::sanitize_line(&p.display().to_string())
}

/// A typed or drag-and-dropped path: trims, removes surrounding quotes (Windows Terminal,
/// Explorer "Copy as path"), PowerShell's `& '...'`, and on Unix the backslash escapes and
/// `~/` that terminals and shells use.
fn clean_path(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("& ") {
        s = rest.trim();
    }
    for q in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(q) && s.ends_with(q) {
            return s[1..s.len() - 1].to_string();
        }
    }
    if cfg!(windows) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            out.extend(chars.next());
        } else {
            out.push(c);
        }
    }
    if let (Some(rest), Some(home)) = (out.strip_prefix("~/"), std::env::var_os("HOME")) {
        return Path::new(&home).join(rest).display().to_string();
    }
    out
}

/// `jetscan <args>` as it can be typed back into a shell (quoted only where needed).
fn command_line(args: &[String]) -> String {
    program_line("jetscan", args)
}

/// `<program> <args>` as it can be typed into a shell (quoted only where needed).
fn program_line(program: &str, args: &[String]) -> String {
    let mut line = String::from(program);
    for a in args {
        line.push(' ');
        line.push_str(&quote(a));
    }
    ui::sanitize_line(&line)
}

fn quote(a: &str) -> String {
    let plain = !a.is_empty()
        && a.chars().all(|c| {
            c.is_ascii_alphanumeric() || "-_./:=+,@".contains(c) || (cfg!(windows) && c == '\\')
        });
    if plain {
        a.to_string()
    } else if cfg!(windows) {
        format!("\"{a}\"")
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    pub(super) struct Temp(pub(super) PathBuf);
    impl Temp {
        pub(super) fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir()
                .join(format!("jetscan-menu-{tag}-{}-{nanos}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Temp(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A computer with a known jetscan path, maybe Claude Code, and recorded program runs.
    pub(super) struct Fake {
        exe: Option<PathBuf>,
        claude: Option<PathBuf>,
        exit: Option<i32>,
        spawned: Vec<(PathBuf, Vec<String>)>,
        #[cfg_attr(not(feature = "pro"), allow(dead_code))]
        pub(super) waited: Vec<std::time::Duration>,
    }

    impl Fake {
        pub(super) fn new(exe: &str, claude: Option<&str>) -> Self {
            Fake {
                exe: Some(PathBuf::from(exe)),
                claude: claude.map(PathBuf::from),
                exit: Some(0),
                spawned: Vec::new(),
                waited: Vec::new(),
            }
        }
    }

    impl Host for Fake {
        fn jetscan_exe(&self) -> Option<PathBuf> {
            self.exe.clone()
        }
        fn claude(&self) -> Option<PathBuf> {
            self.claude.clone()
        }
        fn spawn(&mut self, program: &Path, args: &[String]) -> Option<i32> {
            self.spawned.push((program.to_path_buf(), args.to_vec()));
            self.exit
        }
        fn wait(&mut self, time: std::time::Duration) {
            self.waited.push(time);
        }
    }

    /// Feeds `script` to the menu; `exec` gets every command. Returns (exit, output, commands).
    pub(super) fn drive(
        script: &str,
        cwd: &Path,
        exec: &mut dyn FnMut(&[String]) -> i32,
    ) -> (i32, String, Vec<Vec<String>>) {
        drive_on(script, cwd, exec, &mut Fake::new("jetscan", None))
    }

    pub(super) fn drive_on(
        script: &str,
        cwd: &Path,
        exec: &mut dyn FnMut(&[String]) -> i32,
        host: &mut dyn Host,
    ) -> (i32, String, Vec<Vec<String>>) {
        let mut input = std::io::Cursor::new(script.as_bytes().to_vec());
        let mut out = Vec::new();
        let mut ran = Vec::new();
        let mut record = |args: &[String]| {
            ran.push(args.to_vec());
            exec(args)
        };
        let code = run(&mut input, &mut out, cwd, cwd, &mut record, host);
        // Colors depend on the terminal `cargo test` runs in: compare plain text.
        (code, strip_colors(&String::from_utf8(out).unwrap()), ran)
    }

    /// `text` without `ESC [ ... m` color codes.
    fn strip_colors(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(i) = rest.find("\x1b[") {
            out.push_str(&rest[..i]);
            let tail = &rest[i + 2..];
            rest = tail.find('m').map_or("", |m| &tail[m + 1..]);
        }
        out.push_str(rest);
        out
    }

    /// The menu items as (number, text column, tag column) for lines shaped like
    /// `     7   Text   alpha`.
    pub(super) fn items(text: &str) -> Vec<(usize, usize, Option<usize>)> {
        text.lines()
            .filter_map(|line| {
                let chars: Vec<char> = line.chars().collect();
                if chars.len() <= NUMBER + 3 || chars[NUMBER..NUMBER + 3] != [' '; 3] {
                    return None;
                }
                let head: String = chars[..NUMBER].iter().collect();
                let key = head.trim_start();
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let tag = ["alpha", "soon"]
                    .iter()
                    .find(|t| line.ends_with(&format!("  {t}")))
                    .map(|t| chars.len() - t.len());
                Some((key.parse().unwrap(), NUMBER + 3, tag))
            })
            .collect()
    }

    #[test]
    fn menu_is_grouped_aligned_and_fits_80_columns() {
        let t = Temp::new("layout");
        let (_, text, _) = drive("", &t.0, &mut |_| 0);
        let lines: Vec<&str> = text.lines().collect();
        for line in &lines {
            assert!(line.chars().count() <= WIDTH, "too wide: {line:?}");
        }
        for group in ["CHECK A PROJECT", "FIX AND TOOLS", "JETSCAN PRO"] {
            let at = lines.iter().position(|l| l.trim() == group).expect(group);
            assert_eq!(lines[at - 1], "", "a blank line before {group}");
        }
        let found = items(&text);
        let keys: Vec<usize> = found.iter().map(|i| i.0).collect();
        // The console is always 12; the free build has no items 7-11.
        let console: usize = CONSOLE.parse().unwrap();
        assert_eq!(console, 12);
        let pro = if cfg!(feature = "pro") { 7..12 } else { 7..7 };
        let want: Vec<usize> = (1..=6).chain([console]).chain(pro).chain([0]).collect();
        assert_eq!(keys, want, "{text}");
        let tools = lines
            .iter()
            .position(|l| l.trim() == "FIX AND TOOLS")
            .unwrap();
        let pro = lines
            .iter()
            .position(|l| l.trim() == "JETSCAN PRO")
            .unwrap();
        let at = lines
            .iter()
            .position(|l| l.contains("jetscan console — type jetscan commands"))
            .unwrap();
        assert!(tools < at && at < pro, "{text}");
        assert!(found.iter().all(|i| i.1 == NUMBER + 3));
        let tags: Vec<usize> = found.iter().filter_map(|i| i.2).collect();
        assert_eq!(tags.len(), if cfg!(feature = "pro") { 6 } else { 1 });
        assert!(tags.iter().all(|&c| c == tags[0]), "one alpha column");
        let quit = lines.iter().position(|l| l.trim() == "0   Quit").unwrap();
        assert_eq!(lines[quit - 1], "");
        let prompt = lines
            .iter()
            .position(|l| l.starts_with("  Type a number and press Enter:"))
            .unwrap();
        assert_eq!(lines[prompt - 1], "", "a blank line before the prompt");
        assert_eq!(
            text.contains("jetscan Pro adds website, APK, Android, iOS and live-site checks"),
            !cfg!(feature = "pro")
        );
        assert!(text.contains(edition::SITE) != cfg!(feature = "pro"));
    }

    #[test]
    fn questions_and_results_are_spaced() {
        let t = Temp::new("spacing");
        let (_, text, _) = drive("5\n\n4\n", &t.0, &mut |_| 0);
        let lines: Vec<&str> = text.lines().collect();
        let before = |needle: &str| {
            let at = lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle}: {text}"));
            lines[at - 1]
        };
        // Typed answers are not echoed here: in a console the Enter ends the prompt line and
        // the menu's own line break leaves a blank line under it.
        assert_eq!(
            before("Running: jetscan license"),
            "  Type a number and press Enter: "
        );
        assert_eq!(before("Equivalent command:"), "");
        assert_eq!(before("Press Enter to return to the menu"), "");
        // A question: a blank line, the question, short hints, then the prompt.
        let q = lines
            .iter()
            .position(|l| l.contains("Also check the packages of every repository"))
            .unwrap();
        assert_eq!(lines[q - 1], "");
        assert!(lines[q + 1].contains("OSV.dev"), "{text}");
        assert!(lines[q + 2].contains("Enter = no"), "{text}");
        assert!(lines[q + 3].starts_with(PROMPT), "{text}");
        // A folder question shows the default folder on its own line.
        let (_, text, _) = drive("2\n", &t.0, &mut |_| 0);
        let lines: Vec<&str> = text.lines().collect();
        let enter = lines
            .iter()
            .position(|l| l.contains("Press Enter for this folder:"))
            .unwrap();
        assert_eq!(lines[enter + 1].trim(), shown(&t.0));
    }

    #[test]
    fn long_text_wraps_at_word_boundaries() {
        let text = "one two three four five six seven eight nine ten";
        let lines = wrap(text, "  ", 20);
        assert!(lines.iter().all(|l| l.chars().count() <= 20), "{lines:?}");
        assert!(lines.iter().all(|l| l.starts_with("  ")));
        assert_eq!(
            lines
                .join(" ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            text
        );
        // A word longer than the line is kept whole.
        assert_eq!(wrap("https://example.com/very/long", "  ", 10).len(), 1);
        assert!(wrap("", "  ", 10).is_empty());
    }

    #[test]
    fn strip_colors_removes_only_color_codes() {
        assert_eq!(strip_colors("\x1b[1mA\x1b[0m b \x1b[36m7\x1b[0m"), "A b 7");
    }

    const EXE: &str = r"C:\Program Files\jet scan\jetscan.exe";

    #[test]
    fn ai_editor_setup_prints_commands_and_configs() {
        let t = Temp::new("ai");
        let mut host = Fake::new(EXE, None);
        let (code, text, ran) = drive_on("6\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert_eq!(code, 0);
        assert!(ran.is_empty(), "no jetscan command runs: {ran:?}");
        assert!(host.spawned.is_empty());
        assert!(text.contains("Connect jetscan to your AI editor"), "{text}");
        assert!(text.contains("uploads nothing"), "{text}");
        let user = strings(&["mcp", "add", "--scope", "user", "jetscan", "--", EXE, "mcp"]);
        let project = strings(&["mcp", "add", "jetscan", "--", EXE, "mcp"]);
        for args in [&user, &project] {
            assert!(text.contains(&program_line("claude", args)), "{text}");
        }
        // The path with spaces is quoted for the shell and JSON-escaped in the configs.
        if cfg!(windows) {
            assert!(text.contains(&format!("-- \"{EXE}\" mcp")), "{text}");
        }
        assert!(
            text.contains(r#""command": "C:\\Program Files\\jet scan\\jetscan.exe","#),
            "{text}"
        );
        assert!(text.contains(r#""mcpServers": {"#), "{text}");
        assert!(text.contains(r#""servers": {"#), "{text}");
        assert!(text.contains("${workspaceFolder}"), "{text}");
        // Only jetscan Pro has MCP tools that need a key.
        assert_eq!(
            text.contains("license key"),
            cfg!(feature = "pro"),
            "{text}"
        );
        assert!(text.contains("docs/mcp/README.md"), "{text}");
        assert!(
            !text.contains("Type yes to run it now"),
            "no claude, no offer"
        );
        assert!(text.contains("Press Enter to return to the menu"));
    }

    #[test]
    fn ai_editor_setup_runs_claude_only_after_exactly_yes() {
        let t = Temp::new("ai-yes");
        let claude = r"C:\tools\claude.exe";
        for answer in ["", "y", "Yes", "yes please", "no"] {
            let mut host = Fake::new(EXE, Some(claude));
            let (_, text, _) =
                drive_on(&format!("6\n{answer}\n\n0\n"), &t.0, &mut |_| 0, &mut host);
            assert!(text.contains("to run it now"), "{text}");
            assert!(text.contains("Skipped. Nothing was changed."), "{answer:?}");
            assert!(host.spawned.is_empty(), "{answer:?}");
        }
        let mut host = Fake::new(EXE, Some(claude));
        let (code, text, ran) = drive_on("6\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert_eq!(code, 0);
        assert!(ran.is_empty());
        let user = strings(&["mcp", "add", "--scope", "user", "jetscan", "--", EXE, "mcp"]);
        assert_eq!(host.spawned, vec![(PathBuf::from(claude), user)]);
        assert!(text.contains("Done."), "{text}");

        let mut host = Fake::new(EXE, Some(claude));
        host.exit = Some(1);
        let (_, text, _) = drive_on("6\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert!(text.contains("exit code 1"), "{text}");
        host.exit = None;
        let (_, text, _) = drive_on("6\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert!(text.contains("could not be started"), "{text}");
    }

    #[test]
    fn ai_editor_setup_without_a_known_path_points_to_the_guide() {
        let t = Temp::new("ai-nopath");
        let mut host = Fake::new(EXE, Some("claude"));
        host.exe = None;
        let (code, text, _) = drive_on("6\nyes\n0\n", &t.0, &mut |_| 0, &mut host);
        assert_eq!(code, 0);
        assert!(text.contains("Could not tell where"), "{text}");
        assert!(text.contains("docs/mcp/README.md"), "{text}");
        assert!(host.spawned.is_empty(), "nothing runs without a path");
    }

    #[test]
    fn verbatim_prefix_is_hidden() {
        assert_eq!(
            plain(Path::new(r"\\?\C:\x\jetscan.exe")),
            r"C:\x\jetscan.exe"
        );
        assert_eq!(plain(Path::new(r"\\?\UNC\srv\s")), r"\\?\UNC\srv\s");
        assert_eq!(plain(Path::new("/usr/bin/jetscan")), "/usr/bin/jetscan");
    }

    pub(super) fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn end_of_input_quits_cleanly() {
        let t = Temp::new("eof");
        for script in ["", "2\n", "2\n\n", "5\n", "6\n", "x\n"] {
            let (code, text, ran) = drive(script, &t.0, &mut |_| 0);
            assert_eq!(code, 0, "{script:?}");
            assert!(text.contains("Bye."), "{script:?}: {text}");
            assert!(text.contains("never uploaded"));
            if script.is_empty() || script == "x\n" {
                assert!(ran.is_empty());
            }
        }
        let (_, _, ran) = drive("q\n2\n", &t.0, &mut |_| 0);
        assert!(ran.is_empty(), "q quits before anything runs");
    }

    #[test]
    fn bom_prefixed_input_is_understood() {
        let t = Temp::new("bom");
        let (_, text, ran) = drive("\u{feff}5\n\n0\n", &t.0, &mut |_| 0);
        assert!(!text.contains("is not on the list"), "{text}");
        assert_eq!(ran, vec![vec!["license".to_string()]]);
    }

    #[test]
    fn invalid_choices_and_paths_ask_again() {
        let t = Temp::new("reask");
        fs::write(t.0.join("file.txt"), "x").unwrap();
        let missing = t.0.join("missing").display().to_string();
        let file = t.0.join("file.txt").display().to_string();
        let script = format!(
            "42\nhello\n2\n{missing}\n{file}\n\"{}\"\n\n0\n",
            t.0.display()
        );
        let (code, text, ran) = drive(&script, &t.0, &mut |_| 0);
        assert_eq!(code, 0);
        assert!(text.contains("'42' is not on the list"));
        assert!(text.contains("Type one of the numbers shown above."));
        assert!(text.contains("'hello' is not on the list"));
        assert!(text.contains("No such folder"));
        assert!(text.contains("That is a file, not a folder"));
        let dir = t.0.display().to_string();
        assert_eq!(ran, vec![strings(&["secrets", &dir])]);
        assert!(text.contains("Equivalent command:"));
        assert!(text.contains(&format!("jetscan secrets {}", quote(&dir))));
        assert!(text.contains("Press Enter to return to the menu"));
    }

    #[test]
    fn each_item_builds_the_cli_command() {
        let t = Temp::new("items");
        fs::create_dir_all(t.0.join("repo/.git")).unwrap();
        let repo = t.0.join("repo").display().to_string();
        let cases: Vec<(String, Vec<String>)> = vec![
            ("1\n\n\n".into(), strings(&["scan"])),
            (
                format!("1\n{repo}\nn\nn\n"),
                strings(&["scan", &repo, "--no-history", "--offline"]),
            ),
            (format!("2\n{repo}\ny\n"), strings(&["secrets", &repo])),
            ("4\n\n".into(), strings(&["machine"])),
            ("4\nyes\n".into(), strings(&["machine", "--deps"])),
            ("5\n".into(), strings(&["license"])),
        ];
        for (script, want) in cases {
            let (code, text, ran) = drive(&format!("{script}\n0\n"), &t.0, &mut |_| 0);
            assert_eq!(code, 0);
            assert_eq!(ran, vec![want.clone()], "{script:?}\n{text}");
            assert!(text.contains(&command_line(&want)), "{text}");
        }
    }

    #[test]
    fn zero_goes_back_without_running_anything() {
        let t = Temp::new("back");
        for script in ["2\n0\n", "4\n0\n", "1\n\n0\n", "3\n0\n"] {
            let (code, text, ran) = drive(&format!("{script}0\n"), &t.0, &mut |_| 0);
            assert_eq!(code, 0);
            assert!(ran.is_empty(), "{script:?}");
            assert!(!text.contains("Press Enter to return"), "{script:?}");
        }
    }

    #[test]
    fn yes_no_asks_again_on_other_answers() {
        let t = Temp::new("yn");
        let (_, text, ran) = drive("4\nmaybe\nN\n\n0\n", &t.0, &mut |_| 0);
        assert!(text.contains("Please answer y or n"));
        assert_eq!(ran, vec![strings(&["machine"])]);
    }

    #[test]
    fn resolve_stops_when_the_plan_fails() {
        let t = Temp::new("resolve-fail");
        let (_, text, ran) = drive("3\n\n\n0\n", &t.0, &mut |_| 2);
        assert_eq!(ran.len(), 1, "{ran:?}");
        assert_eq!(&ran[0][..3], &strings(&["resolve", "plan", "."])[..]);
        assert_eq!(ran[0][3], "--out");
        assert!(text.contains("No plan was made"));
        assert!(!text.contains("Apply these changes?"));
    }

    #[test]
    fn resolve_without_a_plan_file_never_asks_to_apply() {
        // The plan "succeeds" but wrote nothing readable: treated as nothing to apply.
        let t = Temp::new("resolve-empty");
        let (_, text, ran) = drive("3\n\nyes\n\n0\n", &t.0, &mut |_| 0);
        assert_eq!(ran.len(), 2, "plan and preview only: {ran:?}");
        assert!(text.contains("advice only"));
        assert!(!text.contains("Apply these changes?"));
    }

    #[test]
    fn paths_are_cleaned() {
        assert_eq!(
            clean_path("  \"C:\\My Projects\\app\"  "),
            "C:\\My Projects\\app"
        );
        assert_eq!(clean_path("'/tmp/a b'"), "/tmp/a b");
        assert_eq!(clean_path("& 'C:\\x y\\app.apk'"), "C:\\x y\\app.apk");
        assert_eq!(clean_path("plain"), "plain");
        assert_eq!(clean_path("\"\""), "");
        assert_eq!(clean_path("\""), "\"");
        if !cfg!(windows) {
            assert_eq!(clean_path("/tmp/a\\ b"), "/tmp/a b");
        }
    }

    #[test]
    fn commands_are_quoted_only_when_needed() {
        assert_eq!(
            command_line(&strings(&["scan", "proj", "--no-history"])),
            "jetscan scan proj --no-history"
        );
        let spaced = command_line(&strings(&["secrets", "my proj"]));
        if cfg!(windows) {
            assert_eq!(spaced, "jetscan secrets \"my proj\"");
        } else {
            assert_eq!(spaced, "jetscan secrets 'my proj'");
            assert_eq!(quote("it's"), r"'it'\''s'");
        }
        // Terminal control characters never reach the screen.
        assert!(!command_line(&strings(&["x\u{1b}[31m"])).contains('\u{1b}'));
    }
}
