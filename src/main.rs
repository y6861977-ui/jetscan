use jetscan::baseline::{Baseline, Hidden};
use jetscan::deps::Severity;
use jetscan::license::{self, Status};
use jetscan::secrets::{machine, report, scan};
use jetscan::{combined, deps, edition, hook, html, hygiene, sarif, sbom, ui};
use std::path::{Path, PathBuf};

mod mcp;
mod menu;
#[cfg(feature = "pro")]
#[rustfmt::skip] // Pro-only file: absent from the public export, so `cargo fmt` must not open it
mod pro;

const USAGE_COMMANDS: &str = "\
usage: jetscan scan [path] [options]      secrets + vulnerable dependencies + GitHub Actions
       jetscan secrets [path] [options]   leaked secrets only (fully offline)
       jetscan deps [path] [options]      vulnerable dependencies only
       jetscan machine [options]          secrets on this whole machine (+ --deps)
       jetscan hook install|uninstall     git pre-commit hook: block commits with secrets
       jetscan license                    show the license key: plan, expiry, what it unlocks
       jetscan menu                       numbered menu, no commands to type (also: no arguments);
                                          its \"jetscan console\" item takes jetscan commands
       jetscan mcp                        MCP server on stdio for AI coding tools (see `jetscan mcp --help`)

Alpha (rules may change; see `<command> --help`):
       jetscan resolve plan [path]        fix plan -> preview -> apply --confirm -> verify";

/// The jetscan Pro commands, listed only by the Pro build.
#[cfg(feature = "pro")]
const USAGE_PRO: &str = "
jetscan Pro (alpha; see `<command> --help`):
       jetscan web source [path]          Next.js / Vite React source audit
       jetscan apk <file.apk>             Android APK static audit (nothing is run)
       jetscan android [path]             Android source project audit (Gradle, Kotlin/Java)
       jetscan ios [path]                 iOS source project audit (Xcode, Swift/Objective-C)
       jetscan url <https://site>         passive check of a published website (browser-like GETs)";

/// The free build points to jetscan Pro in one line.
#[cfg(not(feature = "pro"))]
const USAGE_PRO: &str = "
jetscan Pro adds website source, live website (URL), APK, Android and iOS app audits: https://jetscan.jet.kim";

const USAGE_DETAILS: &str = "
Secrets: API keys, tokens, private keys, .env passwords in files and git history.
`machine` also checks plaintext credential stores (~/.git-credentials, ~/.npmrc,
~/.aws/credentials...), SSH keys without a passphrase, shell history and every git
repository under your home folder. Secret scanning runs locally — nothing leaves your machine.

GitHub Actions (scan): .github/workflows/*.yml and action.yml are checked for known
attack patterns: untrusted PR/issue text expanded into scripts, privileged workflows
that check out PR code, actions not pinned to a commit. Fully local.

Dependencies: lockfiles are checked against OSV.dev. Only package names and
versions are sent — never code or file paths. --offline sends nothing.

options:
  --json           machine-readable output
  --sarif          SARIF 2.1.0 for GitHub / GitLab code scanning (not for machine)
  --sbom <fmt>     deps: print an SBOM instead of the report: cyclonedx (1.6) or spdx (2.3)
  --html <file>    scan: also write a self-contained HTML report (no external resources)
  --exit-code      exit 1 if something needs fixing: a secret that can leak
                   (secrets in .gitignored files do not count), a known
                   vulnerability or an exploitable workflow (weak spots such as
                   unpinned actions are shown but do not fail); exit 2 if some
                   packages could not be checked
  --fail-on <sev>  with --exit-code: fail only on vulnerabilities of this severity or
                   higher: critical, high, medium, low (default). Malicious packages and
                   unknown severity always fail
  --baseline <f>   show and fail only on findings that are NOT in this baseline file
                   (CI: adopt jetscan in an old project, fix the old debt gradually)
  --write-baseline <f>  save the current findings as a baseline file (no secrets in it)
  --no-history     skip git history (faster)
  --verify         secrets: ask each key's own provider whether it works (network;
                   one read-only 'who am I' request per key, sent only to that provider)
  --staged         secrets: check only staged changes (what the next commit adds)
  --max-size <KB>  skip files larger than this (default 1024)
  --offline        dependencies: cached OSV results only, no network
  --no-cache       dependencies: ask OSV again even if the cache is fresh
  --deps           machine: also check dependencies of every repository
  --fix            dependencies: print the exact upgrade commands / manifest edits
                   (nothing is run or changed)
  --depth <N>      machine: how deep to look for repositories (default 6)
  -h, --help       show this help

jetscan Teams (CI reports): --sarif, --sbom, --baseline and --write-baseline need a
license key in JETSCAN_LICENSE or ~/.jetscan/license. It is checked on this machine —
no account, no network. Everything else is free.

Cache: ~/.jetscan/osv-cache (24 h). Proxy: HTTPS_PROXY.";

fn main() {
    // Before any output: a Windows console renders colors only after this (else none).
    ui::init_console();
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(jetscan_main(&args));
}

#[derive(Clone, Copy, PartialEq)]
enum Cmd {
    Scan,
    Secrets,
    Deps,
    Machine,
}

fn jetscan_main(args: &[String]) -> i32 {
    let cmd = match args.first().map(String::as_str) {
        // Double-clicked jetscan.exe / typed `jetscan` in a terminal: the menu. Pipes and CI
        // still get the usage text below.
        None if menu::interactive() => return run_menu(),
        Some("menu") if args.len() == 1 => return run_menu(),
        Some("menu") => {
            ui::eprint_error("`jetscan menu` takes no arguments");
            return 2;
        }
        None | Some("-h") | Some("--help") => {
            println!("jetscan {}\n\n{}", edition::version(), usage());
            return 0;
        }
        Some("-V") | Some("--version") => {
            println!("jetscan {}", edition::version());
            return 0;
        }
        Some("scan") => Cmd::Scan,
        Some("secrets") => Cmd::Secrets,
        Some("deps") => Cmd::Deps,
        Some("machine") => Cmd::Machine,
        Some("hook") => return run_hook(&args[1..]),
        Some("license") if args.len() == 1 => return run_license(),
        Some("license") if matches!(args[1].as_str(), "--help" | "-h" | "help") => {
            println!(
                "usage: jetscan license\n\nShows the license key on this machine: plan, expiry, what it \
                 unlocks and trial scans left.\nThe key itself is never printed. Put a key in \
                 JETSCAN_LICENSE or ~/.jetscan/license.\nGet one at https://jetscan.jet.kim"
            );
            return 0;
        }
        // MCP server over stdio for AI coding tools (src/mcp/).
        Some("mcp") => return mcp::run(&args[1..]),
        // jetscan Pro (alpha): web source, apk, android, ios, url. Each scan goes through the
        // license gate in src/pro.rs (private source).
        #[cfg(feature = "pro")]
        Some(cmd) if pro::is_pro(cmd) => return pro::run(cmd, &args[1..]),
        // The free build: a Pro command says where it comes from instead of "unknown command".
        #[cfg(not(feature = "pro"))]
        Some(other) if edition::pro_only(other).is_some() => {
            ui::eprint_error(&edition::pro_only(other).unwrap_or_default());
            return 2;
        }
        // Free Resolve (plan / preview / apply --confirm / verify).
        Some("resolve") => return jetscan::resolve::cli::run(&args[1..]),
        Some(other) => {
            ui::eprint_error(&format!("unknown command '{}'", ui::sanitize_line(other)));
            ui::eprint_hint("run `jetscan --help`");
            return 2;
        }
    };
    let a = match parse(cmd, &args[1..]) {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{}", usage());
            return 0;
        }
        Err(e) => {
            ui::eprint_error(&e);
            ui::eprint_hint("run `jetscan --help`");
            return 2;
        }
    };
    if let Some(flag) = a.paid_flag()
        && let Err(e) = teams(flag, &license::load())
    {
        ui::eprint_error(&e);
        return 2;
    }
    match cmd {
        Cmd::Scan => run_scan(a),
        Cmd::Secrets => run_secrets(a),
        Cmd::Deps => run_deps(a),
        Cmd::Machine => run_machine(a),
    }
}

struct Args {
    path: Option<PathBuf>,
    json: bool,
    sarif: bool,
    staged: bool,
    fix: bool,
    sbom: Option<String>,
    html: Option<PathBuf>,
    exit_code: bool,
    opts: scan::ScanOptions,
    osv: deps::osv::OsvOptions,
    deps: bool,
    depth: usize,
    baseline: Option<PathBuf>,
    write_baseline: Option<PathBuf>,
    fail_on: Severity,
}

/// Флаги, которые есть у команды: чужой флаг — ошибка, а не тихое игнорирование
/// (`secrets --offline` выглядел бы как «проверил офлайн», хотя сети там и так нет).
fn allowed(cmd: Cmd, flag: &str) -> bool {
    let secrets = matches!(cmd, Cmd::Scan | Cmd::Secrets | Cmd::Machine);
    let deps = matches!(cmd, Cmd::Scan | Cmd::Deps | Cmd::Machine);
    match flag {
        "--json" | "--exit-code" => true,
        "--sarif" => cmd != Cmd::Machine,
        "--staged" => cmd == Cmd::Secrets,
        "--no-history" | "--max-size" | "--verify" => secrets,
        "--offline" | "--no-cache" => deps,
        "--deps" | "--depth" => cmd == Cmd::Machine,
        "--fix" => matches!(cmd, Cmd::Scan | Cmd::Deps),
        "--sbom" => cmd == Cmd::Deps,
        "--html" => cmd == Cmd::Scan,
        "--baseline" | "--write-baseline" => cmd != Cmd::Machine,
        "--fail-on" => deps,
        _ => false,
    }
}

fn parse(cmd: Cmd, args: &[String]) -> Result<Option<Args>, String> {
    let mut a = Args {
        path: None,
        json: false,
        sarif: false,
        staged: false,
        fix: false,
        sbom: None,
        html: None,
        exit_code: false,
        opts: scan::ScanOptions::default(),
        osv: deps::osv::OsvOptions {
            cache_dir: deps::osv::default_cache_dir(),
            no_cache: false,
            offline: false,
        },
        deps: false,
        depth: machine::MachineOptions::default().max_depth,
        baseline: None,
        write_baseline: None,
        fail_on: Severity::Low,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let flag = arg.as_str();
        if flag == "-h" || flag == "--help" {
            return Ok(None);
        }
        if flag.starts_with('-') && !allowed(cmd, flag) {
            return Err(format!("unknown option '{}'", ui::sanitize_line(flag)));
        }
        match flag {
            "--json" => a.json = true,
            "--sarif" => a.sarif = true,
            "--staged" => a.staged = true,
            "--fix" => a.fix = true,
            "--html" => {
                let v = it.next().ok_or("--html needs a file path")?;
                a.html = Some(PathBuf::from(v));
            }
            "--sbom" => {
                let v = it
                    .next()
                    .ok_or("--sbom needs a format: cyclonedx or spdx")?;
                if !matches!(v.as_str(), "cyclonedx" | "spdx") {
                    return Err(format!(
                        "--sbom: unknown format '{}' (cyclonedx or spdx)",
                        ui::sanitize_line(v)
                    ));
                }
                a.sbom = Some(v.clone());
            }
            "--exit-code" => a.exit_code = true,
            "--baseline" => {
                let v = it.next().ok_or("--baseline needs a file path")?;
                a.baseline = Some(PathBuf::from(v));
            }
            "--write-baseline" => {
                let v = it.next().ok_or("--write-baseline needs a file path")?;
                a.write_baseline = Some(PathBuf::from(v));
            }
            "--fail-on" => {
                let v = it
                    .next()
                    .ok_or("--fail-on needs a severity: critical, high, medium or low")?;
                a.fail_on = Severity::from_label(v)
                    .filter(|s| *s != Severity::Unknown)
                    .ok_or_else(|| {
                        format!(
                            "--fail-on: unknown severity '{}' (critical, high, medium or low)",
                            ui::sanitize_line(v)
                        )
                    })?;
            }
            "--no-history" => a.opts.history = false,
            "--verify" => a.opts.verify = true,
            "--offline" => a.osv.offline = true,
            "--no-cache" => a.osv.no_cache = true,
            "--deps" => a.deps = true,
            "--depth" => {
                let v = it.next().ok_or("--depth needs a number")?;
                a.depth = v
                    .parse()
                    .map_err(|_| format!("--depth: '{}' is not a number", ui::sanitize_line(v)))?;
            }
            "--max-size" => {
                let v = it.next().ok_or("--max-size needs a value in KB")?;
                let kb: u64 = v.parse().map_err(|_| {
                    format!("--max-size: '{}' is not a number", ui::sanitize_line(v))
                })?;
                a.opts.walk.max_file_bytes = kb.saturating_mul(1024);
            }
            p if cmd == Cmd::Machine => {
                return Err(format!(
                    "`jetscan machine` takes no path ('{}') — it scans your home folder; \
                     for one project use `jetscan scan <path>`",
                    ui::sanitize_line(p)
                ));
            }
            p if a.path.is_none() => a.path = Some(PathBuf::from(p)),
            extra => {
                return Err(format!(
                    "unexpected argument '{}'",
                    ui::sanitize_line(extra)
                ));
            }
        }
    }
    if [a.json, a.sarif, a.sbom.is_some()]
        .iter()
        .filter(|x| **x)
        .count()
        > 1
    {
        return Err("--json, --sarif and --sbom are mutually exclusive".to_string());
    }
    if a.staged && a.write_baseline.is_some() {
        return Err("--write-baseline needs a full scan, not --staged".to_string());
    }
    Ok(Some(a))
}

impl Args {
    /// Первый флаг из jetscan Teams (CI-отчёты), если он есть.
    fn paid_flag(&self) -> Option<&'static str> {
        [
            (self.sarif, "--sarif"),
            (self.sbom.is_some(), "--sbom"),
            (self.baseline.is_some(), "--baseline"),
            (self.write_baseline.is_some(), "--write-baseline"),
        ]
        .into_iter()
        .find_map(|(on, flag)| on.then_some(flag))
    }
}

/// Пускает платный флаг или объясняет, почему нет. Предупреждения — в stderr:
/// stdout у SARIF / JSON / SBOM должен остаться чистым документом.
fn teams(flag: &str, status: &Status) -> Result<(), String> {
    let get = "Get a key at https://jetscan.jet.kim and put it in JETSCAN_LICENSE (a CI secret) \
               or ~/.jetscan/license";
    match status {
        Status::Active { license, days_left } => {
            if *days_left <= 30 {
                eprintln!(
                    "! jetscan Teams license for {} expires on {} ({} left)",
                    ui::sanitize_line(&license.org),
                    license::format_date(license.expires),
                    ui::plural(*days_left as usize, "day", "days")
                );
            }
            Ok(())
        }
        Status::Grace { license, days_over } => {
            eprintln!(
                "! jetscan Teams license for {} expired on {}; {flag} keeps working for {} more",
                ui::sanitize_line(&license.org),
                license::format_date(license.expires),
                ui::plural((license::GRACE_DAYS - days_over) as usize, "day", "days")
            );
            Ok(())
        }
        Status::Free => Err(format!(
            "{flag} is part of jetscan Teams (CI reports: --sarif, --sbom, --baseline). \
             {get}; it is checked on this machine, nothing is sent. Without {flag}, every \
             scan stays free"
        )),
        Status::Expired { license, .. } => Err(format!(
            "the jetscan Teams license for {} expired on {}, so {flag} is off. Scans without \
             it keep working; renew at https://jetscan.jet.kim to turn it back on",
            ui::sanitize_line(&license.org),
            license::format_date(license.expires)
        )),
        Status::Invalid(reason) => Err(format!(
            "{flag} needs a valid jetscan Teams license: {reason}. {get}"
        )),
    }
}

/// The full `--help` text of this build.
fn usage() -> String {
    format!("{USAGE_COMMANDS}\n{USAGE_PRO}\n{USAGE_DETAILS}")
}

/// `jetscan license`: the plan, expiry, what the key unlocks and (trial) the scans left.
/// The key itself is never printed. Exit 2 if a key is present but not accepted.
fn run_license() -> i32 {
    license::print_status()
}

fn fail(e: &str) -> i32 {
    ui::eprint_error(&ui::sanitize_line(e));
    2
}

fn root(a: &Args) -> PathBuf {
    a.path.clone().unwrap_or_else(|| PathBuf::from("."))
}

fn shown(p: &Path) -> String {
    ui::sanitize_line(&p.display().to_string())
}

/// `--baseline` / `--write-baseline`: сначала читаем старый (тот же файл можно
/// перезаписать), потом пишем полный снимок, потом скрываем известное.
/// Возвращает строку для отчёта: что скрыто (иначе «✓» выглядел бы как «всё чисто»).
fn apply_baseline(
    a: &Args,
    mut secrets: Option<&mut scan::ScanReport>,
    mut deps: Option<&mut deps::scan::DepsReport>,
    mut workflows: Option<&mut Vec<hygiene::Issue>>,
) -> Result<Option<String>, String> {
    let old = a.baseline.as_deref().map(Baseline::load).transpose()?;
    if let Some(path) = &a.write_baseline {
        Baseline::from_reports(
            secrets.as_deref(),
            deps.as_deref(),
            workflows.as_deref().map(Vec::as_slice),
        )
        .write(path)?;
        eprintln!("Baseline written to {}", shown(path));
    }
    if let (Some(b), Some(path)) = (old, &a.baseline) {
        let mut hidden = Hidden::default();
        if let Some(s) = secrets.as_mut() {
            hidden.add(b.apply_secrets(s));
        }
        if let Some(d) = deps.as_mut() {
            hidden.add(b.apply_deps(d));
        }
        if let Some(w) = workflows.as_mut() {
            hidden.add(b.apply_workflows(w));
        }
        let mut note = format!(
            "Baseline {}: {} hidden ({} secrets, {} vulnerabilities, {} other) — only NEW findings are shown",
            shown(path),
            ui::plural(hidden.total(), "known finding", "known findings"),
            hidden.secrets,
            hidden.vulns,
            hidden.other
        );
        if hidden.total() > 0 {
            note.push_str("; run without --baseline to see everything");
        }
        return Ok(Some(note));
    }
    Ok(None)
}

/// В тексте — в stdout под итогом, рядом с «✓»; в `--json` / `--sarif` — в stderr.
fn print_baseline_note(note: &Option<String>, text: bool) {
    match note {
        Some(n) if text => println!(
            "
{}",
            ui::yellow(&format!("! {n}"))
        ),
        Some(n) => eprintln!("{n}"),
        None => {}
    }
}

/// Exit codes везде: 0 — ок (или находки без `--exit-code`); 1 — есть что чинить;
/// 2 — ошибка или (с `--exit-code`) часть пакетов не проверена.
fn run_scan(a: Args) -> i32 {
    let mut p = match combined::scan_project(
        &root(&a),
        &a.opts,
        &a.osv,
        &deps::osv::Curl,
        &deps::osv::real_sleep,
    ) {
        Ok(p) => p,
        Err(e) => return fail(&e),
    };
    let note = match apply_baseline(
        &a,
        Some(&mut p.secrets),
        p.deps.as_mut(),
        p.workflows.as_mut(),
    ) {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    if let Some(path) = &a.html {
        let page = match html::render(&p) {
            Ok(page) => page,
            Err(e) => return fail(&e),
        };
        if let Err(e) = std::fs::write(path, page) {
            return fail(&format!("cannot write {}: {e}", path.display()));
        }
        eprintln!("HTML report written to {}", shown(path));
    }
    if a.sarif {
        println!(
            "{}",
            sarif::render(
                Some(&p.secrets),
                p.deps.as_ref(),
                p.workflows.as_deref().unwrap_or_default()
            )
        );
    } else if a.json {
        println!("{}", combined::render_json(&p));
    } else {
        print!("{}", combined::render_text(&p));
        if let (true, Some(d)) = (a.fix, &p.deps) {
            print!("{}", deps::report::render_fix(d));
        }
    }
    print_baseline_note(&note, !a.sarif && !a.json);
    if !a.exit_code {
        return 0;
    }
    let deps: Vec<&deps::scan::DepsReport> = p.deps.iter().collect();
    let workflows = p.workflows.as_deref().map_or(0, combined::issues_failing);
    combined::exit_code(p.secrets.actionable() + workflows, &deps, a.fail_on)
}

fn run_secrets(a: Args) -> i32 {
    let rep = if a.staged {
        scan::scan_staged(&root(&a))
    } else {
        scan::scan(&root(&a), &a.opts)
    };
    let mut rep = match rep {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let note = match apply_baseline(&a, Some(&mut rep), None, None) {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    if a.sarif {
        println!("{}", sarif::render(Some(&rep), None, &[]));
    } else if a.json {
        println!("{}", report::render_json(&rep));
    } else if a.staged {
        print!("{}", report::render_staged_text(&rep));
    } else {
        print!("{}", report::render_text(&rep));
    }
    print_baseline_note(&note, !a.sarif && !a.json);
    if a.exit_code && rep.actionable() > 0 {
        1
    } else {
        0
    }
}

fn run_deps(a: Args) -> i32 {
    let mut rep =
        match deps::scan::scan(&root(&a), &a.osv, &deps::osv::Curl, &deps::osv::real_sleep) {
            Ok(r) => r,
            Err(e) => return fail(&e),
        };
    let note = match apply_baseline(&a, None, Some(&mut rep), None) {
        Ok(n) => n,
        Err(e) => return fail(&e),
    };
    if let Some(fmt) = &a.sbom {
        let doc = if fmt == "spdx" {
            sbom::spdx(&rep)
        } else {
            sbom::cyclonedx(&rep)
        };
        match doc {
            Ok(d) => println!("{d}"),
            Err(e) => return fail(&e),
        }
    } else if a.sarif {
        println!("{}", sarif::render(None, Some(&rep), &[]));
    } else if a.json {
        println!("{}", deps::report::render_json(&rep));
    } else {
        print!("{}", deps::report::render_text(&rep));
        if a.fix {
            print!("{}", deps::report::render_fix(&rep));
        }
    }
    print_baseline_note(&note, a.sbom.is_none() && !a.sarif && !a.json);
    if a.exit_code {
        combined::exit_code(0, &[&rep], a.fail_on)
    } else {
        0
    }
}

fn run_machine(a: Args) -> i32 {
    let Some(home) = machine::home_dir() else {
        return fail("cannot find your home folder (USERPROFILE / HOME is not set)");
    };
    if !a.json {
        eprintln!("Scanning this machine — every repository can take a while…");
    }
    let opts = machine::MachineOptions {
        scan: a.opts,
        max_depth: a.depth,
    };
    let rep = match machine::scan_machine(&home, &opts) {
        Ok(r) => r,
        Err(e) => return fail(&e),
    };
    let deps = a
        .deps
        .then(|| combined::machine_deps(&rep, &a.osv, &deps::osv::Curl, &deps::osv::real_sleep));
    let issues = hygiene::check(&home);
    if a.json {
        println!(
            "{}",
            combined::render_machine_json(&rep, deps.as_deref(), &issues)
        );
    } else {
        print!(
            "{}",
            combined::render_machine_text(&rep, deps.as_deref(), &issues)
        );
    }
    if !a.exit_code {
        return 0;
    }
    let refs: Vec<&deps::scan::DepsReport> = deps.iter().flatten().collect();
    combined::exit_code(
        rep.actionable() + combined::issues_failing(&issues),
        &refs,
        a.fail_on,
    )
}

/// The interactive menu: every action runs through `jetscan_main`, exactly as typed.
fn menu_input() -> std::io::BufReader<std::io::Stdin> {
    // Not `stdin().lock()` for the whole menu: a command run from the console that reads a
    // line itself (`url active` asks for the consent sentence) would wait for that lock forever.
    // Do not prefetch later lines: nested commands read from the same stdin.
    std::io::BufReader::with_capacity(1, std::io::stdin())
}

fn run_menu() -> i32 {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut input = menu_input();
    let mut out = std::io::stdout();
    menu::run(
        &mut input,
        &mut out,
        &cwd,
        &std::env::temp_dir(),
        &mut |args: &[String]| {
            // A bug in one check must not close the window the user is reading.
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| jetscan_main(args)))
                .unwrap_or_else(|_| {
                    ui::eprint_error("jetscan stopped on an internal error (see above)");
                    2
                })
        },
        &mut menu::System,
    )
}

/// `jetscan hook install|uninstall [repo]`.
fn run_hook(args: &[String]) -> i32 {
    let (action, repo) = match args {
        [a] => (a.as_str(), PathBuf::from(".")),
        [a, r] => (a.as_str(), PathBuf::from(r)),
        _ => (
            args.first().map(String::as_str).unwrap_or(""),
            PathBuf::from("."),
        ),
    };
    match action {
        "install" if args.len() <= 2 => {
            let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("jetscan"));
            match hook::install(&repo, &exe) {
                Ok(p) => {
                    println!(
                        "{}",
                        ui::green(&format!(
                            "✓ pre-commit hook installed: {}",
                            ui::sanitize_line(&p.display().to_string())
                        ))
                    );
                    println!("  every `git commit` now checks the staged changes for secrets");
                    0
                }
                Err(e) => fail(&e),
            }
        }
        "uninstall" if args.len() <= 2 => match hook::uninstall(&repo) {
            Ok(Some(p)) => {
                println!(
                    "✓ pre-commit hook removed: {}",
                    ui::sanitize_line(&p.display().to_string())
                );
                0
            }
            Ok(None) => {
                println!("no jetscan pre-commit hook here");
                0
            }
            Err(e) => fail(&e),
        },
        _ => {
            ui::eprint_error("usage: jetscan hook install|uninstall [repo]");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_command_does_not_prefetch_nested_stdin() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        const CHILD: &str = "JETSCAN_TEST_SHARED_INPUT";
        if std::env::var_os(CHILD).is_some() {
            let mut output = Vec::new();
            let mut reads = 0;
            let code = menu::run(
                &mut menu_input(),
                &mut output,
                std::path::Path::new("."),
                &std::env::temp_dir(),
                &mut |args| {
                    assert_eq!(args, &["secrets", "."]);
                    let mut answer = String::new();
                    std::io::stdin().read_line(&mut answer).unwrap();
                    assert_eq!(answer.trim(), "nested answer");
                    reads += 1;
                    0
                },
                &mut menu::System,
            );
            assert_eq!((code, reads), (0, 1));
            assert!(String::from_utf8(output).unwrap().contains("  done"));
            return;
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::menu_command_does_not_prefetch_nested_stdin",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"12\nsecrets .\nnested answer\nexit\n0\n")
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }

    fn args(cmd: Cmd, list: &[&str]) -> Args {
        let list: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        parse(cmd, &list).unwrap().unwrap()
    }

    #[test]
    fn only_ci_report_flags_are_paid() {
        assert_eq!(args(Cmd::Scan, &["--sarif"]).paid_flag(), Some("--sarif"));
        assert_eq!(
            args(Cmd::Deps, &["--sbom", "spdx"]).paid_flag(),
            Some("--sbom")
        );
        assert_eq!(
            args(Cmd::Scan, &["--baseline", "b.json"]).paid_flag(),
            Some("--baseline")
        );
        assert_eq!(
            args(Cmd::Secrets, &["--write-baseline", "b.json"]).paid_flag(),
            Some("--write-baseline")
        );
        for free in [
            &["--json", "--exit-code"][..],
            &["--html", "r.html", "--fix", "--fail-on", "high"],
            &["--no-history", "--verify", "--offline"],
        ] {
            assert_eq!(args(Cmd::Scan, free).paid_flag(), None, "{free:?}");
        }
    }

    #[test]
    fn the_gate_opens_only_for_active_or_grace_licenses() {
        let l = license::License {
            id: "JS-1".into(),
            org: "Acme".into(),
            plan: "teams".into(),
            seats: 25,
            issued: 20_000,
            expires: 20_365,
        };
        assert!(
            teams(
                "--sarif",
                &Status::Active {
                    license: l.clone(),
                    days_left: 200
                }
            )
            .is_ok()
        );
        assert!(
            teams(
                "--sarif",
                &Status::Grace {
                    license: l.clone(),
                    days_over: 3
                }
            )
            .is_ok()
        );
        for closed in [
            Status::Free,
            Status::Expired {
                license: l,
                days_over: 15,
            },
            Status::Invalid("bad".into()),
        ] {
            let e = teams("--sarif", &closed).unwrap_err();
            assert!(e.contains("--sarif"), "{e}");
        }
    }

    #[test]
    fn ci_flags_stay_teams_only_for_every_plan() {
        // Throwaway signing secret (the license tests' fixture), never a real key.
        let seed = [0x2a; 32];
        let pk = license::ed25519::public_key(&seed);
        let today = license::today();
        let key = |claims: license::Claims| {
            let teams = claims.plan == license::Plan::Teams;
            let l = license::License {
                id: format!("J-{}", claims.plan.as_str()),
                org: if teams { "Acme" } else { "personal" }.into(),
                plan: claims.plan.as_str().into(),
                seats: if teams { 20 } else { 1 },
                issued: today - 10,
                expires: today + 10,
            };
            license::issue_with(&l, &claims, &seed).unwrap()
        };
        let teams_key = key(license::Claims::plan(license::Plan::Teams));
        assert!(teams("--sarif", &license::check(&teams_key, &[pk], today)).is_ok());
        for claims in [
            license::Claims::plan(license::Plan::Pro),
            license::Claims::plan(license::Plan::Audit),
            license::Claims::trial(license::Area::Web, 2),
        ] {
            let status = license::check(&key(claims), &[pk], today);
            let e = teams("--baseline", &status).unwrap_err();
            assert!(e.contains("not the jetscan Teams CI reports"), "{e}");
        }
    }
}
