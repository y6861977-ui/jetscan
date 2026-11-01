//! Отчёт `jetscan deps`: текст для человека и JSON для CI. Все строки из lockfile'ов
//! и OSV — недоверенные, перед выводом проходят `ui::sanitize_line`.

use super::scan::DepsReport;
use super::scripts::InstallScript;
use super::{Severity, VulnFinding};
use crate::json::{self, Json};
use crate::ui;

/// Что уходит в сеть — говорим в каждом отчёте, не только в `--help`.
pub const PRIVACY_NOTE: &str =
    "Only package names and versions were sent to api.osv.dev — no code, no file paths.";

fn sev_colored(s: Severity) -> String {
    // Выравнивание — до раскраски: ANSI-коды не должны сбивать колонку.
    let label = format!("{:<8}", s.label().to_ascii_uppercase());
    match s {
        Severity::Critical | Severity::High => ui::bold(&ui::red(&label)),
        Severity::Medium => ui::yellow(&label),
        Severity::Low | Severity::Unknown => ui::dim(&label),
    }
}

/// Вредоносные пакеты — первыми и отдельно: это не дыра, а чужой код, который уже
/// мог выполниться (T4.1, источник — OpenSSF malicious packages / CWE-506 через OSV).
fn malicious_section(r: &DepsReport, malicious: &[&crate::deps::Package]) -> String {
    if malicious.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{} {}\n",
        ui::bold(&ui::red("Malicious packages — remove now")),
        ui::dim("(known malware, not a bug: upgrading does not help)")
    );
    for p in malicious {
        let f = r
            .findings
            .iter()
            .find(|f| &&f.package == p && f.vuln.malicious)
            .expect("listed because it has a malicious finding");
        out.push_str(&format!(
            "  {} {} {}  {}  {}\n      {}\n",
            ui::red("✗"),
            ui::bold(&ui::sanitize_line(&p.name)),
            ui::sanitize_line(&p.version),
            ui::dim(&ui::sanitize_line(&f.vuln.id)),
            ui::dim(&format!("· {}", ui::sanitize_line(&p.lockfiles.join(", ")))),
            ui::sanitize_line(&f.vuln.summary)
        ));
    }
    out
}

/// Сколько дыр показывать на пакет в тексте; все — в `--json` и SARIF.
const VULNS_PER_PACKAGE: usize = 3;

fn short(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max - 1).collect();
    t.push('…');
    t
}

/// Один блок на пакет: сводка по уровням, самые опасные дыры, «… ещё N».
/// Находки уже отсортированы по опасности — первые и есть самые опасные.
fn package_block(group: &[&VulnFinding]) -> String {
    let p = &group[0].package;
    let mut by = Vec::new();
    for s in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Unknown,
    ] {
        let n = group.iter().filter(|f| f.vuln.severity == s).count();
        if n > 0 {
            by.push(format!("{n} {}", s.label()));
        }
    }
    let mut out = format!(
        "  {} {} {}  {}  {}\n",
        ui::red("✗"),
        ui::bold(&ui::sanitize_line(&p.name)),
        ui::sanitize_line(&p.version),
        ui::plural(group.len(), "vulnerability", "vulnerabilities")
            + &format!(" ({})", by.join(", ")),
        ui::dim(&format!("· {}", ui::sanitize_line(&p.lockfiles.join(", "))))
    );
    // Если «ещё» была бы одна строка — показываем её вместо «… ещё 1».
    let shown = if group.len() <= VULNS_PER_PACKAGE + 1 {
        group.len()
    } else {
        VULNS_PER_PACKAGE
    };
    for f in &group[..shown] {
        let cve = f
            .vuln
            .aliases
            .iter()
            .find(|a| a.starts_with("CVE-"))
            .map(|c| format!("  {c}"))
            .unwrap_or_default();
        out.push_str(&format!(
            "      {}  {}{}  {}\n",
            sev_colored(f.vuln.severity),
            ui::dim(&ui::sanitize_line(&f.vuln.id)),
            ui::dim(&ui::sanitize_line(&cve)),
            ui::sanitize_line(&short(&f.vuln.summary, 72))
        ));
    }
    if group.len() > shown {
        out.push_str(&format!(
            "      {}\n",
            ui::dim(&format!(
                "… and {} more — `jetscan deps --json` lists all",
                group.len() - shown
            ))
        ));
    }
    out
}

pub(crate) fn age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{} min", s / 60),
        s if s < 2 * 86400 => format!("{} h", s / 3600),
        s => format!("{} days", s / 86400),
    }
}

pub fn render_text(r: &DepsReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n{} {}\n",
        ui::bold("jetscan deps"),
        ui::dim(&ui::sanitize_line(&r.root.display().to_string()))
    ));

    if r.lockfiles.is_empty() {
        out.push_str(&format!(
            "\n{}\n{}\n",
            ui::yellow("! No lockfiles found — nothing was checked."),
            ui::dim("  Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.lock, go.mod, requirements*.txt, poetry.lock, Pipfile.lock, uv.lock")
        ));
        return out;
    }

    out.push('\n');
    for l in &r.lockfiles {
        let rel = ui::sanitize_line(&l.rel);
        match &l.error {
            None => out.push_str(&format!(
                "  {} {}\n",
                rel,
                ui::dim(&format!(
                    "({}, {})",
                    l.ecosystem.osv_name(),
                    ui::plural(l.packages, "package", "packages")
                ))
            )),
            Some(e) => out.push_str(&format!(
                "  {} {}\n",
                rel,
                ui::yellow(&format!("— not checked: {}", ui::sanitize_line(e)))
            )),
        }
    }

    let malicious = r.malicious_packages();
    out.push_str(&malicious_section(r, &malicious));
    if r.findings.iter().any(|f| !malicious.contains(&&f.package)) {
        out.push('\n');
        for u in r.upgrades() {
            if malicious.contains(&u.package) {
                continue; // уже показан выше: обновлять вредонос бессмысленно
            }
            let group: Vec<&VulnFinding> = r
                .findings
                .iter()
                .filter(|f| &f.package == u.package)
                .collect();
            out.push_str(&package_block(&group));
        }
    }

    out.push_str(&scripts_section(r));
    out.push_str(&typosquat_section(r));

    // --- сводка ---
    out.push('\n');
    let checked = r.packages.len() - r.unchecked.len();
    let mut src = Vec::new();
    if r.fresh > 0 {
        src.push(format!("{} fresh from OSV", r.fresh));
    }
    if r.from_cache > 0 {
        src.push(format!("{} from cache", r.from_cache));
    }
    let mut line = format!("Checked {}", ui::plural(checked, "package", "packages"));
    if !src.is_empty() {
        line.push_str(&format!(" ({})", src.join(", ")));
    }
    out.push_str(&format!("{}\n", ui::dim(&line)));
    if let Some(a) = r.stale_cache_age {
        out.push_str(&format!(
            "{}\n",
            ui::yellow(&format!(
                "! {} — using cached data up to {} old; newer vulnerabilities may be missing",
                if r.offline {
                    "Offline"
                } else {
                    "OSV is unreachable"
                },
                age(a)
            ))
        ));
    }
    if !r.unchecked.is_empty() {
        out.push_str(&format!(
            "{}\n",
            ui::yellow(&format!(
                "! {} NOT checked ({}) — {}",
                ui::plural(r.unchecked.len(), "package", "packages"),
                if r.offline {
                    "offline, not in cache"
                } else {
                    "OSV is unreachable, not in cache"
                },
                "results are incomplete"
            ))
        ));
    }
    for w in &r.warnings {
        out.push_str(&format!(
            "{}\n",
            ui::yellow(&format!("! {}", ui::sanitize_line(w)))
        ));
    }

    if r.findings.is_empty() {
        let msg = if r.unchecked.is_empty() && checked > 0 {
            "✓ No known vulnerabilities".to_string()
        } else if checked > 0 {
            "✓ No known vulnerabilities in the packages that were checked".to_string()
        } else {
            String::new()
        };
        if !msg.is_empty() {
            out.push_str(&format!("\n{}\n", ui::bold_green(&msg)));
        }
    } else {
        let mut by = Vec::new();
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Unknown,
        ] {
            let n = r.findings.iter().filter(|f| f.vuln.severity == s).count();
            if n > 0 {
                by.push(format!("{n} {}", s.label()));
            }
        }
        let head = format!(
            "✗ Found {} in {} ({})",
            ui::plural(
                r.findings.len(),
                "known vulnerability",
                "known vulnerabilities"
            ),
            ui::plural(r.vulnerable_packages(), "package", "packages"),
            by.join(", ")
        );
        out.push_str(&format!("\n{}\n", ui::bold(&ui::red(&head))));
        out.push_str(&format!("\n{}\n", ui::bold("What to do")));
        let mut any_unfixed = false;
        if !malicious.is_empty() {
            out.push_str(&format!(
                "  {} {}\n",
                ui::red("→"),
                ui::bold(&ui::red(
                    "Malicious packages: remove them now (and the dependency that pulled them in)."
                ))
            ));
            out.push_str("    If one was installed with install scripts, treat that machine as compromised:\n    rotate the keys jetscan machine lists there.\n");
        }
        for u in r.upgrades() {
            if malicious.contains(&u.package) {
                continue;
            }
            let name = format!(
                "{} {}",
                ui::sanitize_line(&u.package.name),
                ui::sanitize_line(&u.package.version)
            );
            let mut line = match &u.to {
                Some(to) => format!(
                    "  {} {} {} {}  {}",
                    ui::dim("→"),
                    ui::bold(&name),
                    ui::dim("→"),
                    ui::green(&ui::sanitize_line(to)),
                    ui::dim(&format!(
                        "fixes {}",
                        ui::plural(u.fixes, "vulnerability", "vulnerabilities")
                    ))
                ),
                None => format!("  {} {}", ui::dim("→"), ui::bold(&name)),
            };
            if u.unfixed > 0 {
                any_unfixed = true;
                line.push_str(&ui::yellow(&format!(
                    "{}{} without a fix yet",
                    if u.to.is_some() { ", " } else { "  " },
                    u.unfixed
                )));
            }
            out.push_str(&format!("{line}\n"));
        }
        out.push_str(&format!(
            "  {} upgrade in package.json / Cargo.toml / requirements and re-run jetscan deps\n",
            ui::dim("→")
        ));
        if any_unfixed {
            out.push_str(&format!(
                "  {} no fix yet: check if the vulnerable code is reachable, or replace the package\n",
                ui::dim("→")
            ));
        }
    }
    if r.fresh > 0 {
        out.push_str(&format!("{}\n", ui::dim(PRIVACY_NOTE)));
    }
    out
}

/// Похожие на популярные имена (T4.4). Подсказка, не вердикт: на код возврата не влияет.
fn typosquat_section(r: &DepsReport) -> String {
    if r.typosquats.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{} {}\n",
        ui::bold("Suspicious names"),
        ui::dim("(look like a popular package — typosquatting? check the name)")
    );
    for (p, s) in &r.typosquats {
        out.push_str(&format!(
            "  {} {} {}  {}  {}\n",
            ui::yellow("!"),
            ui::bold(&ui::sanitize_line(&p.name)),
            ui::sanitize_line(&p.version),
            ui::yellow(&format!("looks like {}", ui::sanitize_line(&s.looks_like))),
            ui::dim(&format!("({})", s.reason))
        ));
    }
    out
}

/// Сколько пакетов со скриптами показывать в тексте; все — в `--json`.
const SCRIPTS_SHOWN: usize = 12;

fn scripts_section(r: &DepsReport) -> String {
    if r.install_scripts.is_empty() {
        return String::new();
    }
    // Сначала помеченные, затем прод-зависимости, затем dev; внутри — по имени.
    let mut list: Vec<&InstallScript> = r.install_scripts.iter().collect();
    list.sort_by(|a, b| {
        a.flags
            .is_empty()
            .cmp(&b.flags.is_empty())
            .then(a.dev.cmp(&b.dev))
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });
    list.dedup_by(|a, b| a.name == b.name && a.version == b.version);
    let mut out = format!(
        "\n{} {}\n",
        ui::bold("Install scripts"),
        ui::dim("(run with your permissions on `npm install`)")
    );
    for s in list.iter().take(SCRIPTS_SHOWN) {
        let mark = if s.flags.is_empty() {
            ui::dim("•")
        } else {
            ui::yellow("!")
        };
        let what = match s.commands.first() {
            Some((hook, cmd)) => format!("{hook}: {cmd}"),
            None => "not installed — command unknown until `npm install`".to_string(),
        };
        let mut line = format!(
            "  {mark} {} {}  {}",
            ui::bold(&s.name),
            s.version,
            ui::dim(&what)
        );
        if s.commands.len() > 1 {
            line.push_str(&ui::dim(&format!(" (+{} more)", s.commands.len() - 1)));
        }
        if s.dev {
            line.push_str(&ui::dim(" · dev"));
        }
        if !s.flags.is_empty() {
            line.push_str(&ui::yellow(&format!("  [{}]", s.flags.join(", "))));
        }
        out.push_str(&line);
        out.push('\n');
    }
    if list.len() > SCRIPTS_SHOWN {
        out.push_str(&format!(
            "  {}\n",
            ui::dim(&format!(
                "… and {} more — `jetscan deps --json` lists all",
                list.len() - SCRIPTS_SHOWN
            ))
        ));
    }
    let flagged = list.iter().filter(|s| !s.flags.is_empty()).count();
    if flagged > 0 {
        out.push_str(&format!(
            "  {} {}\n",
            ui::dim("→"),
            ui::dim("[network]/[eval]/[encoded] are hints where to look first, not a verdict")
        ));
    }
    out
}

fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

fn arr(v: &[String]) -> Json {
    Json::Arr(v.iter().map(|x| s(x)).collect())
}

pub fn render_json(r: &DepsReport) -> String {
    json::stringify_pretty(&to_json(r))
}

/// JSON-документ — для `render_json` и сводного отчёта.
pub fn to_json(r: &DepsReport) -> Json {
    let findings = r
        .findings
        .iter()
        .map(|f| {
            obj(vec![
                ("ecosystem", s(f.package.ecosystem.osv_name())),
                ("package", s(&f.package.name)),
                ("version", s(&f.package.version)),
                ("lockfiles", arr(&f.package.lockfiles)),
                ("id", s(&f.vuln.id)),
                ("aliases", arr(&f.vuln.aliases)),
                ("summary", s(&f.vuln.summary)),
                ("severity", s(f.vuln.severity.label())),
                ("cvss", f.vuln.cvss.map(Json::Num).unwrap_or(Json::Null)),
                ("fix", f.fix.as_deref().map(s).unwrap_or(Json::Null)),
                ("fixed", arr(&f.vuln.fixed)),
                ("malicious", Json::Bool(f.vuln.malicious)),
            ])
        })
        .collect();
    let lockfiles = r
        .lockfiles
        .iter()
        .map(|l| {
            obj(vec![
                ("path", s(&l.rel)),
                ("format", s(l.label)),
                ("ecosystem", s(l.ecosystem.osv_name())),
                ("packages", Json::Num(l.packages as f64)),
                ("error", l.error.as_deref().map(s).unwrap_or(Json::Null)),
            ])
        })
        .collect();
    let unchecked = r
        .unchecked
        .iter()
        .map(|p| {
            obj(vec![
                ("ecosystem", s(p.ecosystem.osv_name())),
                ("package", s(&p.name)),
                ("version", s(&p.version)),
            ])
        })
        .collect();
    let count = |sev: Severity| {
        Json::Num(r.findings.iter().filter(|f| f.vuln.severity == sev).count() as f64)
    };
    let summary = obj(vec![
        ("packages", Json::Num(r.packages.len() as f64)),
        (
            "checked",
            Json::Num((r.packages.len() - r.unchecked.len()) as f64),
        ),
        ("unchecked", Json::Num(r.unchecked.len() as f64)),
        ("vulnerabilities", Json::Num(r.findings.len() as f64)),
        (
            "vulnerable_packages",
            Json::Num(r.vulnerable_packages() as f64),
        ),
        (
            "malicious_packages",
            Json::Num(r.malicious_packages().len() as f64),
        ),
        ("critical", count(Severity::Critical)),
        ("high", count(Severity::High)),
        ("medium", count(Severity::Medium)),
        ("low", count(Severity::Low)),
        ("unknown", count(Severity::Unknown)),
        ("from_cache", Json::Num(r.from_cache as f64)),
        ("fresh", Json::Num(r.fresh as f64)),
        ("install_scripts", Json::Num(r.install_scripts.len() as f64)),
        ("offline", Json::Bool(r.offline)),
        ("osv_unavailable", Json::Bool(r.osv_unavailable)),
        (
            "stale_cache_age_secs",
            r.stale_cache_age
                .map(|a| Json::Num(a as f64))
                .unwrap_or(Json::Null),
        ),
    ]);
    obj(vec![
        // Версия схемы JSON (как у `secrets`), не версия jetscan.
        ("version", Json::Num(1.0)),
        ("root", s(&r.root.display().to_string())),
        ("lockfiles", Json::Arr(lockfiles)),
        ("findings", Json::Arr(findings)),
        ("unchecked", Json::Arr(unchecked)),
        ("warnings", arr(&r.warnings)),
        ("fix_plan", fix_json(r)),
        (
            "suspicious_names",
            Json::Arr(
                r.typosquats
                    .iter()
                    .map(|(p, s)| {
                        obj(vec![
                            ("ecosystem", Json::Str(p.ecosystem.osv_name().to_string())),
                            ("package", Json::Str(p.name.clone())),
                            ("version", Json::Str(p.version.clone())),
                            ("looks_like", Json::Str(s.looks_like.clone())),
                            ("reason", Json::Str(s.reason.to_string())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "install_scripts",
            Json::Arr(r.install_scripts.iter().map(script_json).collect()),
        ),
        ("summary", summary),
    ])
}

fn script_json(s: &InstallScript) -> Json {
    obj(vec![
        ("lockfile", Json::Str(s.lockfile.clone())),
        ("package", Json::Str(s.name.clone())),
        ("version", Json::Str(s.version.clone())),
        ("dev", Json::Bool(s.dev)),
        (
            "commands",
            Json::Arr(
                s.commands
                    .iter()
                    .map(|(h, c)| {
                        obj(vec![
                            ("hook", Json::Str(h.clone())),
                            ("command", Json::Str(c.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "flags",
            Json::Arr(s.flags.iter().map(|f| Json::Str(f.to_string())).collect()),
        ),
    ])
}

/// `--fix`: план исправления — команды и правки манифестов (ничего не запускаем).
pub fn render_fix(r: &DepsReport) -> String {
    let plan = super::fix::plan(r);
    if plan.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "\n{} {}\n",
        ui::bold("Fix plan"),
        ui::dim("(nothing is run or edited — review and apply yourself)")
    );
    let mut lockfile = "";
    for s in &plan {
        if s.lockfile != lockfile {
            lockfile = &s.lockfile;
            out.push_str(&format!("  {}\n", ui::bold(&ui::sanitize_line(lockfile))));
        }
        let what = if s.to.is_empty() {
            format!(
                "{} {}",
                ui::sanitize_line(&s.package),
                ui::sanitize_line(&s.from)
            )
        } else {
            format!(
                "{} {} → {}",
                ui::sanitize_line(&s.package),
                ui::sanitize_line(&s.from),
                ui::sanitize_line(&s.to)
            )
        };
        out.push_str(&format!("    {}\n", ui::dim(&what)));
        if let Some(cmd) = &s.command {
            out.push_str(&format!("      $ {}\n", ui::cyan(cmd)));
        }
        if let Some(edit) = &s.edit {
            out.push_str(&format!("      edit {}\n", ui::cyan(edit)));
        }
        if let Some(note) = s.note {
            out.push_str(&format!("      {}\n", ui::yellow(note)));
        }
    }
    out
}

fn fix_json(r: &DepsReport) -> Json {
    Json::Arr(
        super::fix::plan(r)
            .into_iter()
            .map(|s| {
                obj(vec![
                    ("lockfile", Json::Str(s.lockfile)),
                    ("package", Json::Str(s.package)),
                    ("from", Json::Str(s.from)),
                    ("to", Json::Str(s.to)),
                    ("command", s.command.map(Json::Str).unwrap_or(Json::Null)),
                    ("edit", s.edit.map(Json::Str).unwrap_or(Json::Null)),
                    (
                        "note",
                        s.note
                            .map(|n| Json::Str(n.to_string()))
                            .unwrap_or(Json::Null),
                    ),
                ])
            })
            .collect(),
    )
}
