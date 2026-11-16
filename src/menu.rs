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

use jetscan::finding_v2::{RedactionPolicy, RemediationState};
use jetscan::resolve::ResolvePlan;
use jetscan::ui;
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
}

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
    };
    s.header();
    loop {
        s.show_menu();
        let Ok(choice) = s.ask(&format!("{} ", ui::bold("Choose a number (0 to quit):"))) else {
            return s.bye();
        };
        s.ran.clear();
        let result = match choice.trim().to_ascii_lowercase().as_str() {
            "1" => s.scan(),
            "2" => s.secrets(),
            "3" => s.web(),
            "4" => s.apk(),
            "5" => s.android(),
            "6" => s.ios(),
            "7" => s.resolve(),
            "8" => s.machine(),
            "9" => s.license(),
            "10" => s.connect(),
            "0" | "q" | "quit" | "exit" => return s.bye(),
            "" => continue,
            other => {
                s.say(&ui::yellow(&format!(
                    "'{}' is not on the list. Type a number from 0 to 10.",
                    ui::sanitize_line(other)
                )));
                continue;
            }
        };
        if result == Err(Stop::Quit) {
            return s.bye();
        }
        if !s.ran.is_empty() {
            s.show_commands();
            if s.ask(&ui::dim("Press Enter to return to the menu"))
                .is_err()
            {
                return s.bye();
            }
        }
    }
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

    fn header(&mut self) {
        self.say(&format!(
            "{} {}",
            ui::bold(&format!("jetscan {}", env!("CARGO_PKG_VERSION"))),
            ui::dim("— security scanner")
        ));
        self.say(&ui::dim(
            "Everything runs on this computer. Your code and files are never uploaded.",
        ));
    }

    fn show_menu(&mut self) {
        let alpha = ui::dim("(alpha)");
        let items: [(&str, &str, bool); 11] = [
            (
                "1",
                "Scan a project for leaked secrets, vulnerable packages and risky GitHub Actions",
                false,
            ),
            ("2", "Scan a project for leaked secrets only", false),
            ("3", "Check a website's source code (Next.js / React)", true),
            ("4", "Check an Android app (.apk)", true),
            (
                "5",
                "Check an Android app's source code (Gradle project)",
                true,
            ),
            ("6", "Check an iOS app's source code (Xcode project)", true),
            (
                "7",
                "Fix what was found (plan → preview → apply → verify)",
                true,
            ),
            (
                "8",
                "Scan this whole computer for exposed credentials",
                false,
            ),
            ("9", "License status / where to buy", false),
            (
                "10",
                "Connect jetscan to your AI editor (Claude Code, Cursor, VS Code…)",
                false,
            ),
            ("0", "Quit", false),
        ];
        self.say("");
        self.say(&ui::bold("What do you want to do?"));
        for (key, text, is_alpha) in items {
            let tail = if is_alpha {
                format!(" {alpha}")
            } else {
                String::new()
            };
            self.say(&format!(
                "  {}  {text}{tail}",
                ui::cyan(&format!("{key:>2}"))
            ));
        }
    }

    fn bye(&mut self) -> i32 {
        self.say("Bye.");
        let _ = self.out.flush();
        0
    }

    /// Runs one command through the CLI entry point and remembers it.
    fn run(&mut self, args: Vec<String>) -> i32 {
        self.say(&ui::dim(&format!("Running: {}", command_line(&args))));
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
        self.say(&ui::bold(label));
        let lines: Vec<String> = self.ran.iter().map(|a| command_line(a)).collect();
        for line in lines {
            self.say(&format!("  {}", ui::cyan(&line)));
        }
    }

    /// A folder to work on. `None`: the current folder (the CLI default).
    fn folder(&mut self, what: &str) -> Step<Option<String>> {
        self.say("");
        self.say(&ui::bold(what));
        self.say(&format!(
            "  {} {}",
            ui::dim("Enter = this folder:"),
            shown(self.cwd)
        ));
        self.say(&ui::dim(
            "  Or type a path (you can drag the folder into this window). 0 = back",
        ));
        loop {
            let raw = self.ask("> ")?;
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
            self.say(&ui::yellow(&format!(
                "{why}: {}. Try again, or 0 to go back.",
                shown(&path)
            )));
        }
    }

    /// An existing file (no default).
    fn file(&mut self, what: &str) -> Step<String> {
        self.say("");
        self.say(&ui::bold(what));
        self.say(&ui::dim(
            "  Type the path (you can drag the file into this window). 0 = back",
        ));
        loop {
            let raw = self.ask("> ")?;
            let typed = clean_path(&raw);
            if typed == "0" {
                return Err(Stop::Back);
            }
            if typed.is_empty() {
                self.say(&ui::yellow(
                    "Please type the path of the file, or 0 to go back.",
                ));
                continue;
            }
            let path = self.absolute(&typed);
            if path.is_file() {
                return Ok(typed);
            }
            let why = if path.is_dir() {
                "That is a folder, not a file"
            } else {
                "No such file"
            };
            self.say(&ui::yellow(&format!(
                "{why}: {}. Try again, or 0 to go back.",
                shown(&path)
            )));
        }
    }

    fn yes_no(&mut self, question: &str, default: bool) -> Step<bool> {
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        loop {
            let answer = self.ask(&format!("{question} {} ", ui::dim(hint)))?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "" => return Ok(default),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                "0" => return Err(Stop::Back),
                _ => self.say(&ui::yellow("Please answer y or n (or 0 to go back).")),
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
            "Also check the git history (old commits)? Slower on big projects.",
            true,
        )?;
        Ok(!check)
    }

    fn scan(&mut self) -> Step<()> {
        let folder = self.folder("Which project folder should be scanned?")?;
        let no_history = self.skip_history(&folder)?;
        self.say(&ui::dim(
            "Vulnerable packages are looked up on OSV.dev: only package names and versions are \
             sent, never code or file paths.",
        ));
        let online = self.yes_no("Look up packages online?", true)?;
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
        let folder = self.folder("Which project folder should be scanned for secrets?")?;
        let no_history = self.skip_history(&folder)?;
        let mut args = vec!["secrets".to_string()];
        args.extend(folder);
        if no_history {
            args.push("--no-history".into());
        }
        self.run(args);
        Ok(())
    }

    fn web(&mut self) -> Step<()> {
        let folder = self.folder(
            "Which website project folder (the one with package.json)? This reads source code, \
             not a live URL.",
        )?;
        let mut args = vec!["web".to_string(), "source".to_string()];
        args.extend(folder);
        self.run(args);
        Ok(())
    }

    fn apk(&mut self) -> Step<()> {
        let file = self.file("Which .apk file? It is only read, never installed or run.")?;
        self.run(vec!["apk".to_string(), file]);
        Ok(())
    }

    fn android(&mut self) -> Step<()> {
        let folder = self.folder(
            "Which Android project folder (the one with settings.gradle or build.gradle)? \
             Nothing is built or run.",
        )?;
        let mut args = vec!["android".to_string()];
        args.extend(folder);
        self.run(args);
        Ok(())
    }

    fn ios(&mut self) -> Step<()> {
        let folder = self.folder(
            "Which iOS project folder (the one with the .xcodeproj, Package.swift or Info.plist)? \
             Nothing is built or run.",
        )?;
        let mut args = vec!["ios".to_string()];
        args.extend(folder);
        self.run(args);
        Ok(())
    }

    fn machine(&mut self) -> Step<()> {
        self.say("");
        self.say(
            "This looks through your home folder: saved passwords and tokens, SSH keys, shell \
             history and every git repository. It can take several minutes.",
        );
        self.say(&ui::dim(
            "Checking packages sends only package names and versions to OSV.dev.",
        ));
        let deps = self.yes_no(
            "Also check the packages of every repository for known vulnerabilities?",
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
        self.say("");
        self.say(&ui::bold("Connect jetscan to your AI editor"));
        self.say(
            "Your AI coding tool can then run jetscan's checks itself after it writes code: \
             leaked secrets, vulnerable packages, risky GitHub Actions.",
        );
        self.say(
            "jetscan runs on this computer and uploads nothing. The AI tool sends jetscan's \
             reports (never the secret values) to its own AI model, like any text it reads.",
        );
        self.say("The AI gets reports and fix plans only: jetscan changes no files for it.");
        let Some(exe) = self.host.jetscan_exe() else {
            self.say(&ui::yellow(
                "Could not tell where this jetscan program is. Follow the guide and use the full \
                 path of the jetscan program:",
            ));
            self.say(&format!("  {MCP_GUIDE}"));
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
        self.say("");
        self.say(&ui::bold("Claude Code: run one of these in a terminal"));
        self.say(&ui::dim(
            "  For one project (run it in that project's folder):",
        ));
        self.say(&format!(
            "    {}",
            ui::cyan(&program_line("claude", &project_add))
        ));
        self.say(&ui::dim("  For every project:"));
        self.say(&format!(
            "    {}",
            ui::cyan(&program_line("claude", &user_add))
        ));
        self.say(&ui::dim("  Check it with: claude mcp list"));
        self.say("");
        self.say(&format!(
            "{} {}",
            ui::bold("Cursor: save this as .cursor/mcp.json in your project"),
            ui::dim("(not yet tested with Cursor)")
        ));
        self.snippet(&editor_json("mcpServers", &exe));
        self.say("");
        self.say(&format!(
            "{} {}",
            ui::bold("VS Code (Copilot): save this as .vscode/mcp.json in your project"),
            ui::dim("(not yet tested with VS Code)")
        ));
        self.snippet(&editor_json("servers", &exe));
        self.say("");
        self.say(
            "If the file already exists, add only the \"jetscan\" entry to it. Then restart the \
             editor or reload its MCP servers.",
        );
        self.say(&ui::dim(
            "Free through the AI: secrets, packages, GitHub Actions, fix plans. The website, APK, \
             Android and iOS source audits need a jetscan license key there.",
        ));
        self.say(&ui::dim(&format!("Other editors and details: {MCP_GUIDE}")));
        if let Some(claude) = self.host.claude() {
            self.say("");
            self.say(&format!(
                "Claude Code is installed here ({}). jetscan can run the \"every project\" \
                 command above for you.",
                shown(&claude)
            ));
            let answer = self.ask(&format!(
                "Type {} to run it now, anything else skips: ",
                ui::bold("yes")
            ))?;
            if answer.trim() != "yes" {
                self.say("Skipped. Nothing was changed.");
                return self.pause();
            }
            self.say(&ui::dim(&format!(
                "Running: {}",
                program_line("claude", &user_add)
            )));
            self.say("");
            let _ = self.out.flush();
            match self.host.spawn(&claude, &user_add) {
                Some(0) => self.say(&ui::green(
                    "Done. Start a new Claude Code session; /mcp lists jetscan.",
                )),
                Some(code) => self.say(&ui::yellow(&format!(
                    "claude stopped with exit code {code} (see above). You can run the command \
                     yourself."
                ))),
                None => self.say(&ui::yellow(
                    "claude could not be started. You can run the command yourself.",
                )),
            }
        }
        self.pause()
    }

    fn snippet(&mut self, text: &str) {
        for line in text.lines() {
            self.say(&format!("  {}", ui::sanitize_line(line)));
        }
    }

    fn pause(&mut self) -> Step<()> {
        self.say("");
        self.ask(&ui::dim("Press Enter to return to the menu"))?;
        Ok(())
    }

    /// plan → preview → (exactly "yes") → apply --confirm → verify.
    fn resolve(&mut self) -> Step<()> {
        self.say("");
        self.say(
            "jetscan makes a fix plan for the project's GitHub Actions workflows and shows the \
             exact changes. Nothing is changed unless you type yes.",
        );
        let folder = self
            .folder("Which project folder?")?
            .unwrap_or_else(|| ".".to_string());
        let plan = self.plan_dir.join(format!(
            "jetscan-plan-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let plan_arg = plan.display().to_string();
        self.say("");
        self.say(&ui::bold("Step 1 of 4: make a fix plan (read-only)"));
        let code = self.run(vec![
            "resolve".into(),
            "plan".into(),
            folder.clone(),
            "--out".into(),
            plan_arg.clone(),
        ]);
        if code != 0 {
            self.say(&ui::yellow(
                "No plan was made (see above). Nothing was changed.",
            ));
            return Ok(());
        }
        self.say("");
        self.say(&ui::bold("Step 2 of 4: preview the changes (read-only)"));
        if self.run(vec!["resolve".into(), "preview".into(), plan_arg.clone()]) != 0 {
            self.say(&ui::yellow(
                "The plan could not be shown. Nothing was changed.",
            ));
            return Ok(());
        }
        if !applicable(&plan) {
            self.say(&ui::yellow(
                "There is nothing jetscan can change automatically here; the plan above is \
                 advice only. Nothing was changed.",
            ));
            return Ok(());
        }
        self.say("");
        self.say(&ui::bold("Step 3 of 4: apply"));
        let answer = match self.ask(&format!(
            "Apply these changes? Type {} to write them, anything else cancels: ",
            ui::bold("yes")
        )) {
            Ok(a) => a,
            Err(stop) => {
                self.say("Cancelled. Nothing was changed.");
                return Err(stop);
            }
        };
        if answer.trim() != "yes" {
            self.say(&format!(
                "Cancelled. Nothing was changed. The plan is kept at {}",
                shown(&plan)
            ));
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
            self.say(&ui::yellow("Apply did not finish (see above)."));
            return Ok(());
        }
        self.say("");
        self.say(&ui::bold("Step 4 of 4: verify"));
        self.run(vec!["resolve".into(), "verify".into(), plan_arg]);
        Ok(())
    }
}

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

    struct Temp(PathBuf);
    impl Temp {
        fn new(tag: &str) -> Self {
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
    struct Fake {
        exe: Option<PathBuf>,
        claude: Option<PathBuf>,
        exit: Option<i32>,
        spawned: Vec<(PathBuf, Vec<String>)>,
    }

    impl Fake {
        fn new(exe: &str, claude: Option<&str>) -> Self {
            Fake {
                exe: Some(PathBuf::from(exe)),
                claude: claude.map(PathBuf::from),
                exit: Some(0),
                spawned: Vec::new(),
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
    }

    /// Feeds `script` to the menu; `exec` gets every command. Returns (exit, output, commands).
    fn drive(
        script: &str,
        cwd: &Path,
        exec: &mut dyn FnMut(&[String]) -> i32,
    ) -> (i32, String, Vec<Vec<String>>) {
        drive_on(script, cwd, exec, &mut Fake::new("jetscan", None))
    }

    fn drive_on(
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
        (code, String::from_utf8(out).unwrap(), ran)
    }

    const EXE: &str = r"C:\Program Files\jet scan\jetscan.exe";

    #[test]
    fn ai_editor_setup_prints_commands_and_configs() {
        let t = Temp::new("ai");
        let mut host = Fake::new(EXE, None);
        let (code, text, ran) = drive_on("10\n\n0\n", &t.0, &mut |_| 0, &mut host);
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
        assert!(text.contains("license key"), "{text}");
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
                drive_on(&format!("10\n{answer}\n\n0\n"), &t.0, &mut |_| 0, &mut host);
            assert!(text.contains("to run it now"), "{text}");
            assert!(text.contains("Skipped. Nothing was changed."), "{answer:?}");
            assert!(host.spawned.is_empty(), "{answer:?}");
        }
        let mut host = Fake::new(EXE, Some(claude));
        let (code, text, ran) = drive_on("10\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert_eq!(code, 0);
        assert!(ran.is_empty());
        let user = strings(&["mcp", "add", "--scope", "user", "jetscan", "--", EXE, "mcp"]);
        assert_eq!(host.spawned, vec![(PathBuf::from(claude), user)]);
        assert!(text.contains("Done."), "{text}");

        let mut host = Fake::new(EXE, Some(claude));
        host.exit = Some(1);
        let (_, text, _) = drive_on("10\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert!(text.contains("exit code 1"), "{text}");
        host.exit = None;
        let (_, text, _) = drive_on("10\nyes\n\n0\n", &t.0, &mut |_| 0, &mut host);
        assert!(text.contains("could not be started"), "{text}");
    }

    #[test]
    fn ai_editor_setup_without_a_known_path_points_to_the_guide() {
        let t = Temp::new("ai-nopath");
        let mut host = Fake::new(EXE, Some("claude"));
        host.exe = None;
        let (code, text, _) = drive_on("10\nyes\n0\n", &t.0, &mut |_| 0, &mut host);
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

    fn strings(list: &[&str]) -> Vec<String> {
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
        let (_, text, ran) = drive("\u{feff}9\n\n0\n", &t.0, &mut |_| 0);
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
            "11\nhello\n2\n{missing}\n{file}\n\"{}\"\n\n0\n",
            t.0.display()
        );
        let (code, text, ran) = drive(&script, &t.0, &mut |_| 0);
        assert_eq!(code, 0);
        assert!(text.contains("'11' is not on the list"));
        assert!(text.contains("Type a number from 0 to 10."));
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
        fs::write(t.0.join("app.apk"), "not really").unwrap();
        let repo = t.0.join("repo").display().to_string();
        let apk = t.0.join("app.apk").display().to_string();
        let cases: Vec<(String, Vec<String>)> = vec![
            ("1\n\n\n".into(), strings(&["scan"])),
            (
                format!("1\n{repo}\nn\nn\n"),
                strings(&["scan", &repo, "--no-history", "--offline"]),
            ),
            (format!("2\n{repo}\ny\n"), strings(&["secrets", &repo])),
            ("3\n\n".into(), strings(&["web", "source"])),
            (format!("4\n\n{apk}\n"), strings(&["apk", &apk])),
            ("5\n\n".into(), strings(&["android"])),
            (format!("5\n{repo}\n"), strings(&["android", &repo])),
            ("6\n\n".into(), strings(&["ios"])),
            (format!("6\n{repo}\n"), strings(&["ios", &repo])),
            ("8\n\n".into(), strings(&["machine"])),
            ("8\nyes\n".into(), strings(&["machine", "--deps"])),
            ("9\n".into(), strings(&["license"])),
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
        for script in [
            "2\n0\n", "4\n0\n", "5\n0\n", "6\n0\n", "8\n0\n", "1\n\n0\n", "7\n0\n",
        ] {
            let (code, text, ran) = drive(&format!("{script}0\n"), &t.0, &mut |_| 0);
            assert_eq!(code, 0);
            assert!(ran.is_empty(), "{script:?}");
            assert!(!text.contains("Press Enter"), "{script:?}");
        }
    }

    #[test]
    fn yes_no_asks_again_on_other_answers() {
        let t = Temp::new("yn");
        let (_, text, ran) = drive("8\nmaybe\nN\n\n0\n", &t.0, &mut |_| 0);
        assert!(text.contains("Please answer y or n"));
        assert_eq!(ran, vec![strings(&["machine"])]);
    }

    #[test]
    fn resolve_stops_when_the_plan_fails() {
        let t = Temp::new("resolve-fail");
        let (_, text, ran) = drive("7\n\n\n0\n", &t.0, &mut |_| 2);
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
        let (_, text, ran) = drive("7\n\nyes\n\n0\n", &t.0, &mut |_| 0);
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
