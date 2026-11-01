use jetscan::baseline::{Baseline, Hidden};
use jetscan::deps::Severity;
use jetscan::license::{self, Status};
use jetscan::secrets::{machine, report, scan};
use jetscan::{combined, deps, hook, html, hygiene, sarif, sbom, ui};
use std::path::{Path, PathBuf};

const USAGE: &str = "\
usage: jetscan scan [path] [options]      secrets + vulnerable dependencies + GitHub Actions
       jetscan secrets [path] [options]   leaked secrets only (fully offline)
       jetscan deps [path] [options]      vulnerable dependencies only
       jetscan machine [options]          secrets on this whole machine (+ --deps)
       jetscan hook install|uninstall     git pre-commit hook: block commits with secrets
       jetscan license                    show the jetscan Teams license status

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
        None | Some("-h") | Some("--help") => {
            println!("jetscan {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Some("-V") | Some("--version") => {
            println!("jetscan {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Some("scan") => Cmd::Scan,
        Some("secrets") => Cmd::Secrets,
        Some("deps") => Cmd::Deps,
        Some("machine") => Cmd::Machine,
        Some("hook") => return run_hook(&args[1..]),
        Some("license") if args.len() == 1 => return run_license(),
        Some(other) => {
            ui::eprint_error(&format!("unknown command '{}'", ui::sanitize_line(other)));
            ui::eprint_hint("run `jetscan --help`");
            return 2;
        }
    };
    let a = match parse(cmd, &args[1..]) {
        Ok(Some(a)) => a,
        Ok(None) => {
            println!("{USAGE}");
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
    let get = "Put the key in JETSCAN_LICENSE (a CI secret) or ~/.jetscan/license";
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
             it keep working; renew the key to turn it back on",
            ui::sanitize_line(&license.org),
            license::format_date(license.expires)
        )),
        Status::Invalid(reason) => Err(format!(
            "{flag} needs a valid jetscan Teams license: {reason}. {get}"
        )),
    }
}

/// `jetscan license`: какой ключ стоит. Сам ключ не печатается никогда.
fn run_license() -> i32 {
    let status = license::load();
    let show = |l: &license::License, state: String| {
        println!(
            "jetscan Teams — {} · {} · {} · issued {}\n{state}",
            ui::sanitize_line(&l.org),
            ui::plural(l.seats as usize, "seat", "seats"),
            ui::sanitize_line(&l.id),
            license::format_date(l.issued)
        )
    };
    match &status {
        Status::Free => {
            println!("jetscan Free — no license key (JETSCAN_LICENSE or ~/.jetscan/license).");
            println!("Every scan is free; --sarif, --sbom and --baseline need jetscan Teams.");
        }
        Status::Active {
            license: l,
            days_left,
        } => show(
            l,
            ui::green(&format!(
                "✓ valid until {} ({} left)",
                license::format_date(l.expires),
                ui::plural(*days_left as usize, "day", "days")
            )),
        ),
        Status::Grace {
            license: l,
            days_over,
        } => show(
            l,
            ui::yellow(&format!(
                "! expired on {}; paid features stop in {}",
                license::format_date(l.expires),
                ui::plural((license::GRACE_DAYS - days_over) as usize, "day", "days")
            )),
        ),
        Status::Expired { license: l, .. } => show(
            l,
            ui::red(&format!(
                "✗ expired on {} — paid features are off, free scans keep working",
                license::format_date(l.expires)
            )),
        ),
        Status::Invalid(reason) => {
            ui::eprint_error(&format!("license key not accepted: {reason}"));
            return 2;
        }
    }
    0
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
}
