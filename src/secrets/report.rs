//! Отчёт по секретам (T1.5 + T1.8): текст для человека и `--json` для CI.
//! Всё, что пришло с диска или из git (пути, коммиты, ошибки git), — untrusted:
//! только через `ui::sanitize_line`. Сырой секрет сюда не попадает по построению
//! (`Finding` хранит только маску и отпечаток).

use super::history::HistoryError;
use super::machine::{MachineReport, Spot, SpotKind};
use super::scan::{HistoryOutcome, IGNORE_FILE, INLINE_IGNORE, ScanReport};
use super::{Confidence, Finding, Liveness, Location, Tracking};
use crate::json::{self, Json};
use crate::ui;
use std::collections::HashMap;
use std::path::Path;

/// Секции находок в файлах по git-статусу, в порядке важности.
const FILE_SECTIONS: &[(Tracking, &str, &str)] = &[
    (
        Tracking::Tracked,
        "Committed to git",
        "(already in the repository — every clone has it)",
    ),
    (
        Tracking::Untracked,
        "Not ignored by git",
        "(one `git add .` away from a leak)",
    ),
    (Tracking::Unknown, "In files", ""),
    (Tracking::Ignored, "Local only", ""),
];

fn section_head(title: &str, note: &str) -> String {
    if note.is_empty() {
        format!(
            "
{}
",
            ui::bold(title)
        )
    } else {
        format!(
            "
{} {}
",
            ui::bold(title),
            ui::dim(note)
        )
    }
}

pub fn render_text(r: &ScanReport) -> String {
    let mut out = String::new();
    let root = ui::sanitize_line(&r.root.display().to_string());
    out.push_str(&format!(
        "\n{} {}\n",
        ui::bold("jetscan secrets"),
        ui::dim(&root)
    ));

    // Секции по git-статусу (T1.10): сначала то, что уже утекло, в конце — локальное.
    for (tracking, title, note) in FILE_SECTIONS {
        let group: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| f.tracking == *tracking)
            .collect();
        if group.is_empty() || *tracking == Tracking::Ignored {
            continue;
        }
        out.push_str(&section_head(title, note));
        for f in group {
            out.push_str(&finding_lines(f));
        }
    }
    if !r.history_findings.is_empty() {
        out.push_str(&format!(
            "\n{} {}\n",
            ui::bold("Only in git history"),
            ui::dim("(deleted from files, still in commits)")
        ));
        for f in &r.history_findings {
            out.push_str(&finding_lines(f));
        }
    }
    let local: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.tracking == Tracking::Ignored)
        .collect();
    if !local.is_empty() {
        out.push_str(&section_head(
            "Local only",
            "(in .gitignore — not a leak, listed for completeness)",
        ));
        for f in &local {
            out.push_str(&ui::dim(&finding_lines(f)));
        }
    }

    // --- сводка ---
    out.push('\n');
    let w = &r.walk;
    let mut skipped = Vec::new();
    for (n, what) in [
        (w.skipped_binary, "binary"),
        (w.skipped_large, "large"),
        (w.skipped_unreadable, "unreadable"),
    ] {
        if n > 0 {
            skipped.push(format!("{n} {what}"));
        }
    }
    let mut scanned = format!("Scanned {}", ui::plural(w.files_scanned, "file", "files"));
    if !skipped.is_empty() {
        scanned.push_str(&format!(" (skipped {})", skipped.join(", ")));
    }
    match &r.history {
        HistoryOutcome::Scanned(s) => scanned.push_str(&format!(
            " and {} of git history",
            ui::plural(s.commits, "commit", "commits")
        )),
        HistoryOutcome::Disabled => {}
        HistoryOutcome::Failed(_) => {}
    }
    out.push_str(&format!("{}\n", ui::dim(&scanned)));
    if let HistoryOutcome::Failed(e) = &r.history {
        out.push_str(&format!(
            "{}\n",
            ui::yellow(&format!("! {}", history_warning(e)))
        ));
    }
    if r.ignored > 0 {
        out.push_str(&format!(
            "{}\n",
            ui::dim(&format!("{} suppressed by {IGNORE_FILE}", r.ignored))
        ));
    }

    let actionable = r.actionable();
    let count = |t: Tracking| r.findings.iter().filter(|f| f.tracking == t).count();
    let (committed, untracked, local_n) = (
        count(Tracking::Tracked),
        count(Tracking::Untracked),
        count(Tracking::Ignored),
    );
    if actionable == 0 {
        let history_note = if matches!(r.history, HistoryOutcome::Failed(_)) {
            " (git history was NOT checked)"
        } else {
            ""
        };
        let clean = if local_n > 0 {
            format!(
                "No leaked secrets{history_note} — {} only in .gitignored files",
                ui::plural(local_n, "local secret", "local secrets")
            )
        } else if history_note.is_empty() {
            "No secrets found".to_string()
        } else {
            format!("No secrets found in files{history_note}")
        };
        out.push_str(&format!("\n{}\n", ui::bold_green(&format!("✓ {clean}"))));
        return out;
    }

    let (high, medium, low) = by_confidence(r);
    let mut head = format!("✗ Found {}", ui::plural(actionable, "secret", "secrets"));
    let mut parts = Vec::new();
    for (n, label) in [(high, "high"), (medium, "medium"), (low, "low")] {
        if n > 0 {
            parts.push(format!("{n} {label}"));
        }
    }
    head.push_str(&format!(" ({})", parts.join(", ")));
    let mut where_ = Vec::new();
    if committed > 0 {
        where_.push(format!("{committed} committed"));
    }
    if untracked > 0 {
        where_.push(format!("{untracked} not ignored"));
    }
    if !r.history_findings.is_empty() {
        where_.push(format!("{} only in git history", r.history_findings.len()));
    }
    if !where_.is_empty() {
        head.push_str(&format!(" — {}", where_.join(", ")));
    }
    out.push_str(&format!("\n{}\n", ui::bold(&ui::red(&head))));
    if local_n > 0 {
        out.push_str(&format!(
            "{}\n",
            ui::dim(&format!(
                "+ {} in .gitignored files (not counted)",
                ui::plural(local_n, "local secret", "local secrets")
            ))
        ));
    }

    let live = r
        .all_findings()
        .filter(|f| f.is_actionable() && f.verified == Some(Liveness::Live))
        .count();
    if live > 0 {
        out.push_str(&format!(
            "{}\n",
            ui::bold(&ui::red(&format!(
                "! {live} verified LIVE right now (--verify) — rotate these first"
            )))
        ));
    }

    out.push_str(&format!("\n{}\n", ui::bold("What to do")));
    if actionable > untracked {
        out.push_str(&hint(
            "Rotate every key above (revoke and reissue). Deleting it from the code is not enough —",
        ));
        out.push_str(&hint(
            "  anyone who cloned the repo or saw a CI log still has it.",
        ));
    }
    if untracked > 0 {
        out.push_str(&hint(
            "Not-ignored files are one `git add .` away from a leak: add them to .gitignore",
        ));
        out.push_str(&hint("  or move the secrets out of the project folder."));
    }
    if !r.history_findings.is_empty() {
        out.push_str(&hint(
            "History-only secrets are still public in every clone: rotate first, then rewrite",
        ));
        out.push_str(&hint(
            "  history (git filter-repo / BFG) if the repo is shared, and force-push.",
        ));
    }
    out.push_str(&hint(&format!(
        "False positive? Add its fingerprint to {IGNORE_FILE}, or put `{INLINE_IGNORE}` on the line."
    )));
    out
}

fn finding_lines(f: &Finding) -> String {
    finding_lines_as(f, None)
}

/// `file_display` — показать вместо пути файла (для мест вроде `~/.npmrc`).
fn finding_lines_as(f: &Finding, file_display: Option<&str>) -> String {
    let place = match &f.location {
        Location::File { path } => format!(
            "{}:{}:{}",
            ui::sanitize_line(
                &file_display
                    .map(str::to_string)
                    .unwrap_or_else(|| path.to_string_lossy().replace('\\', "/"))
            ),
            f.line,
            f.col
        ),
        Location::Git { commit, path } => format!(
            "{} {}:{}",
            ui::yellow(&ui::sanitize_line(short(commit))),
            ui::sanitize_line(path),
            f.line
        ),
    };
    let conf = match f.rule.confidence {
        Confidence::High => ui::red("high"),
        Confidence::Medium => ui::yellow("medium"),
        Confidence::Low => ui::dim("low"),
    };
    format!(
        "  {} {}  {} [{}]{}\n      {}  {}\n",
        ui::red("✗"),
        place,
        ui::bold(f.rule.name),
        conf,
        verified_tag(f),
        ui::cyan(&ui::sanitize_line(&f.masked)),
        ui::dim(&format!("fp {}", f.fingerprint))
    )
}

/// Итог `--verify` в строке находки. Пусто — не проверялся.
fn verified_tag(f: &Finding) -> String {
    match &f.verified {
        Some(Liveness::Live) => format!("  {}", ui::bold(&ui::red("LIVE — works right now"))),
        Some(Liveness::Revoked) => format!("  {}", ui::dim("revoked")),
        Some(Liveness::Unknown(why)) => {
            format!(
                "  {}",
                ui::dim(&format!("verify: {}", ui::sanitize_line(why)))
            )
        }
        None => String::new(),
    }
}

/// Как `finding_lines`, но с git-статусом в конце первой строки — для машинного отчёта,
/// где нет отдельных секций «Committed / Not ignored».
fn finding_lines_tagged(f: &Finding) -> String {
    let tag = match (&f.location, f.tracking) {
        (Location::Git { .. }, _) => ui::yellow("· only in history"),
        (_, Tracking::Tracked) => ui::red("· committed"),
        (_, Tracking::Untracked) => ui::yellow("· not ignored"),
        _ => String::new(),
    };
    let base = finding_lines(f);
    if tag.is_empty() {
        return base;
    }
    match base.split_once('\n') {
        Some((first, rest)) => format!("{first}  {tag}\n{rest}"),
        None => base,
    }
}

/// Строка подсказки; начинающаяся с двух пробелов — продолжение предыдущей (без стрелки).
fn hint(text: &str) -> String {
    match text.strip_prefix("  ") {
        Some(rest) => format!("    {rest}\n"),
        None => format!("  {} {}\n", ui::dim("→"), text),
    }
}

fn short(commit: &str) -> &str {
    commit.get(..10).unwrap_or(commit)
}

fn by_confidence(r: &ScanReport) -> (usize, usize, usize) {
    let mut c = (0, 0, 0);
    for f in r.all_findings().filter(|f| f.is_actionable()) {
        match f.rule.confidence {
            Confidence::High => c.0 += 1,
            Confidence::Medium => c.1 += 1,
            Confidence::Low => c.2 += 1,
        }
    }
    c
}

pub(crate) fn history_warning(e: &HistoryError) -> String {
    match e {
        HistoryError::GitNotFound => {
            "git not found in PATH — git history was not scanned".to_string()
        }
        HistoryError::NotARepo => "not a git repository — git history was not scanned".to_string(),
        HistoryError::Git(msg) => format!(
            "git history was not scanned: {}",
            ui::sanitize_line(msg.lines().next().unwrap_or(""))
        ),
    }
}

// --- JSON ---

fn obj(entries: Vec<(&str, Json)>) -> Json {
    Json::Obj(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<HashMap<_, _>>(),
    )
}

fn num(n: usize) -> Json {
    Json::Num(n as f64)
}

fn finding_json(f: &Finding) -> Json {
    let mut e = vec![
        ("rule", Json::Str(f.rule.id.to_string())),
        ("name", Json::Str(f.rule.name.to_string())),
        (
            "confidence",
            Json::Str(f.rule.confidence.label().to_string()),
        ),
        ("line", num(f.line)),
        ("col", num(f.col)),
        ("masked", Json::Str(f.masked.clone())),
        ("fingerprint", Json::Str(f.fingerprint.clone())),
        ("git", Json::Str(f.tracking.label().to_string())),
        (
            "verified",
            f.verified
                .as_ref()
                .map(|v| Json::Str(v.label().to_string()))
                .unwrap_or(Json::Null),
        ),
    ];
    match &f.location {
        Location::File { path } => {
            e.push(("source", Json::Str("file".into())));
            e.push(("path", Json::Str(path.to_string_lossy().replace('\\', "/"))));
        }
        Location::Git { commit, path } => {
            e.push(("source", Json::Str("history".into())));
            e.push(("path", Json::Str(path.clone())));
            e.push(("commit", Json::Str(commit.clone())));
        }
    }
    obj(e)
}

pub fn render_json(r: &ScanReport) -> String {
    json::stringify_pretty(&to_json(r))
}

/// JSON-документ скана — для `render_json` и сводного отчёта (`jetscan scan`).
pub fn to_json(r: &ScanReport) -> Json {
    let (high, medium, low) = by_confidence(r);
    let history = match &r.history {
        HistoryOutcome::Disabled => obj(vec![("status", Json::Str("disabled".into()))]),
        HistoryOutcome::Scanned(s) => obj(vec![
            ("status", Json::Str("scanned".into())),
            ("commits", num(s.commits)),
        ]),
        HistoryOutcome::Failed(e) => obj(vec![
            ("status", Json::Str("failed".into())),
            ("message", Json::Str(history_warning(e))),
        ]),
    };
    let w = &r.walk;
    obj(vec![
        ("version", num(1)),
        ("root", Json::Str(r.root.display().to_string())),
        (
            "summary",
            obj(vec![
                ("files_scanned", num(w.files_scanned)),
                ("skipped_binary", num(w.skipped_binary)),
                ("skipped_large", num(w.skipped_large)),
                ("skipped_unreadable", num(w.skipped_unreadable)),
                ("findings", num(r.total())),
                ("high", num(high)),
                ("medium", num(medium)),
                ("low", num(low)),
                ("history_only", num(r.history_findings.len())),
                ("actionable", num(r.actionable())),
                (
                    "committed",
                    num(r
                        .findings
                        .iter()
                        .filter(|f| f.tracking == Tracking::Tracked)
                        .count()),
                ),
                (
                    "untracked",
                    num(r
                        .findings
                        .iter()
                        .filter(|f| f.tracking == Tracking::Untracked)
                        .count()),
                ),
                (
                    "local_ignored",
                    num(r
                        .findings
                        .iter()
                        .filter(|f| f.tracking == Tracking::Ignored)
                        .count()),
                ),
                ("ignored", num(r.ignored)),
            ]),
        ),
        ("history", history),
        (
            "findings",
            Json::Arr(r.all_findings().map(finding_json).collect()),
        ),
    ])
}

// --- pre-commit (T3.2) ---

/// Отчёт `jetscan secrets --staged`: только то, что уйдёт в коммит. Коротко — его читают
/// в момент `git commit`.
pub fn render_staged_text(r: &ScanReport) -> String {
    let mut out = String::new();
    let n = r.actionable();
    if n == 0 {
        let mut msg = format!(
            "✓ jetscan: no secrets in staged changes ({})",
            ui::plural(r.walk.files_scanned, "file", "files")
        );
        if r.ignored > 0 {
            msg.push_str(&format!(", {} suppressed", r.ignored));
        }
        out.push_str(&format!("{}\n", ui::green(&msg)));
        return out;
    }
    out.push_str(&format!(
        "\n{} {}\n",
        ui::bold("jetscan pre-commit"),
        ui::dim("(staged changes)")
    ));
    for f in r.findings.iter().filter(|f| f.is_actionable()) {
        out.push_str(&finding_lines(f));
    }
    out.push_str(&format!(
        "\n{}\n",
        ui::bold(&ui::red(&format!(
            "✗ Commit blocked: {} in staged changes",
            ui::plural(n, "secret", "secrets")
        )))
    ));
    out.push_str(&hint(
        "Remove it from the file (use an env variable or a secret store), then `git add` again.",
    ));
    out.push_str(&hint(
        "  Not committed yet — no need to rotate, unless it was already pushed or shared.",
    ));
    out.push_str(&hint(
        "False positive? Put `jetscan:ignore` on the line or its fingerprint in .jetscanignore.",
    ));
    out.push_str(&hint("Skip the check once: git commit --no-verify"));
    out
}

// --- скан машины (T1.12) ---

/// Сколько находок на репозиторий показывать в машинном отчёте; остальное — `jetscan secrets <repo>`.
const MACHINE_PER_REPO: usize = 10;

fn tilde(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rel) => format!("~/{}", rel.to_string_lossy().replace('\\', "/")),
        Err(_) => p.display().to_string(),
    }
}

pub fn render_machine_text(m: &MachineReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "\n{} {}\n",
        ui::bold("jetscan machine"),
        ui::dim(&ui::sanitize_line(&m.home.display().to_string()))
    ));

    for (kind, title, note) in [
        (
            SpotKind::CredentialStore,
            "Credential stores",
            "(plaintext files on disk)",
        ),
        (
            SpotKind::ShellHistory,
            "Shell history",
            "(secrets typed or pasted into a terminal)",
        ),
    ] {
        let with: Vec<&Spot> = m
            .spots
            .iter()
            .filter(|s| s.kind == kind && s.report.total() > 0)
            .collect();
        if with.is_empty() {
            continue;
        }
        out.push_str(&format!("\n{} {}\n", ui::bold(title), ui::dim(note)));
        for s in with {
            for f in s.report.all_findings() {
                out.push_str(&finding_lines_as(f, Some(&s.display)));
            }
        }
    }

    // Репозитории: только то, что может утечь; локальное (.gitignore) — одной строкой.
    let dirty: Vec<&ScanReport> = m.repos.iter().filter(|r| r.actionable() > 0).collect();
    if !dirty.is_empty() {
        out.push_str(&format!("\n{}\n", ui::bold("Repositories")));
        for r in &dirty {
            let name = ui::sanitize_line(&tilde(&m.home, &r.root));
            let n = r.actionable();
            let mut head = format!("{name} — {}", ui::plural(n, "secret", "secrets"));
            let local = r.total() - n;
            if local > 0 {
                head.push_str(&format!(" (+{local} local in .gitignore)"));
            }
            out.push_str(&format!("  {}\n", ui::bold(&head)));
            for f in r
                .all_findings()
                .filter(|f| f.is_actionable())
                .take(MACHINE_PER_REPO)
            {
                out.push_str(&indent(&finding_lines_tagged(f)));
            }
            if n > MACHINE_PER_REPO {
                out.push_str(&format!(
                    "    {}\n",
                    ui::dim(&format!(
                        "… and {} more — run `jetscan secrets {}`",
                        n - MACHINE_PER_REPO,
                        crate::combined::shell_arg(&name)
                    ))
                ));
            }
        }
    }

    // --- сводка ---
    let files: usize = m.repos.iter().map(|r| r.walk.files_scanned).sum();
    let commits: usize = m
        .repos
        .iter()
        .map(|r| match &r.history {
            HistoryOutcome::Scanned(s) => s.commits,
            _ => 0,
        })
        .sum();
    let history_failed: Vec<String> = m
        .repos
        .iter()
        .filter(|r| matches!(r.history, HistoryOutcome::Failed(_)))
        .map(|r| ui::sanitize_line(&tilde(&m.home, &r.root)))
        .collect();
    let stores = m
        .spots
        .iter()
        .filter(|s| s.kind == SpotKind::CredentialStore)
        .count();
    let shells = m.spots.len() - stores;
    out.push('\n');
    out.push_str(&format!(
        "{}\n",
        ui::dim(&format!(
            "Scanned {}, {} and {} ({} files, {} commits)",
            ui::plural(stores, "credential file", "credential files"),
            ui::plural(shells, "shell history", "shell histories"),
            ui::plural(m.repos.len(), "repository", "repositories"),
            files,
            commits
        ))
    ));
    if !history_failed.is_empty() {
        let mut names = history_failed
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if history_failed.len() > 3 {
            names.push_str(&format!(" and {} more", history_failed.len() - 3));
        }
        out.push_str(&format!(
            "{}\n",
            ui::yellow(&format!(
                "! git history was not scanned in {}: {names} (broken or not a git repo?)",
                ui::plural(history_failed.len(), "repository", "repositories")
            ))
        ));
    }

    let total = m.actionable();
    let local = m.total() - total;
    let local_note = if local > 0 {
        format!(
            "{} in .gitignored project files (not counted)",
            ui::plural(local, "local secret", "local secrets")
        )
    } else {
        String::new()
    };
    if total == 0 {
        let msg = if local > 0 {
            format!("✓ No leaked secrets on this machine — {local_note}")
        } else {
            "✓ No secrets found on this machine".to_string()
        };
        out.push_str(&format!("\n{}\n", ui::bold_green(&msg)));
        return out;
    }
    let sum_kind = |k: SpotKind| -> usize {
        m.spots
            .iter()
            .filter(|s| s.kind == k)
            .map(|s| s.report.total())
            .sum()
    };
    let in_stores = sum_kind(SpotKind::CredentialStore);
    let in_shell = sum_kind(SpotKind::ShellHistory);
    let in_repos: usize = dirty.iter().map(|r| r.actionable()).sum();
    let mut parts = Vec::new();
    if in_stores > 0 {
        parts.push(format!("{in_stores} in credential stores"));
    }
    if in_shell > 0 {
        parts.push(format!("{in_shell} in shell history"));
    }
    if in_repos > 0 {
        parts.push(format!(
            "{in_repos} in {} of {} repositories",
            dirty.len(),
            m.repos.len()
        ));
    }
    out.push_str(&format!(
        "\n{}\n",
        ui::bold(&ui::red(&format!(
            "✗ Found {}: {}",
            ui::plural(total, "secret", "secrets"),
            parts.join(", ")
        )))
    ));
    if local > 0 {
        out.push_str(&format!("{}\n", ui::dim(&format!("+ {local_note}"))));
    }

    out.push_str(&format!("\n{}\n", ui::bold("What to do")));
    if in_shell > 0 {
        out.push_str(&hint(
            "Shell history: rotate the key, then delete that line from the history file.",
        ));
        out.push_str(&hint(
            "  Next time set secrets from a file or a prompt, not as a command argument.",
        ));
    }
    if in_stores > 0 {
        out.push_str(&hint(
            "Credential stores keep tokens in plaintext: any program you run can read them.",
        ));
        out.push_str(&hint(
            "  Prefer the OS keychain (git: `credential.helper manager`), use short-lived tokens.",
        ));
    }
    if in_repos > 0 {
        out.push_str(&hint(
            "Repositories: rotate every key; run `jetscan secrets <repo>` for details.",
        ));
    }
    out
}

fn indent(block: &str) -> String {
    block.lines().map(|l| format!("  {l}\n")).collect()
}

pub fn render_machine_json(m: &MachineReport) -> String {
    json::stringify_pretty(&machine_to_json(m))
}

pub fn machine_to_json(m: &MachineReport) -> Json {
    let spots = m
        .spots
        .iter()
        .map(|s| {
            obj(vec![
                ("path", Json::Str(s.display.clone())),
                (
                    "kind",
                    Json::Str(
                        match s.kind {
                            SpotKind::CredentialStore => "credential-store",
                            SpotKind::ShellHistory => "shell-history",
                        }
                        .into(),
                    ),
                ),
                (
                    "findings",
                    Json::Arr(s.report.all_findings().map(finding_json).collect()),
                ),
            ])
        })
        .collect();
    let repos = m
        .repos
        .iter()
        .map(|r| {
            let history = match &r.history {
                HistoryOutcome::Disabled => Json::Str("disabled".into()),
                HistoryOutcome::Scanned(_) => Json::Str("scanned".into()),
                HistoryOutcome::Failed(_) => Json::Str("failed".into()),
            };
            obj(vec![
                ("path", Json::Str(tilde(&m.home, &r.root))),
                ("files_scanned", num(r.walk.files_scanned)),
                ("history", history),
                (
                    "findings",
                    Json::Arr(r.all_findings().map(finding_json).collect()),
                ),
            ])
        })
        .collect();
    obj(vec![
        ("version", num(1)),
        ("mode", Json::Str("machine".into())),
        ("home", Json::Str(m.home.display().to_string())),
        (
            "summary",
            obj(vec![
                ("findings", num(m.total())),
                ("actionable", num(m.actionable())),
                ("repositories", num(m.repos.len())),
                (
                    "repositories_with_findings",
                    num(m.repos.iter().filter(|r| r.total() > 0).count()),
                ),
                ("unreadable_dirs", num(m.unreadable_dirs)),
            ]),
        ),
        ("spots", Json::Arr(spots)),
        ("repositories", Json::Arr(repos)),
    ])
}

#[cfg(test)]
mod machine_tests {
    use super::*;
    use crate::secrets::history::HistoryStats;
    use crate::secrets::walk::WalkStats;
    use crate::secrets::{Hit, RuleInfo};
    use std::path::PathBuf;

    fn secret() -> String {
        format!("{}{}", "ghp_", "Zq8".repeat(12))
    }

    fn rep(root: &str, n: usize) -> ScanReport {
        let hit = Hit {
            rule: RuleInfo {
                id: "github-token",
                name: "GitHub Token",
                confidence: Confidence::High,
            },
            line: 2,
            col: 5,
            secret: secret(),
        };
        ScanReport {
            root: PathBuf::from(root),
            findings: (0..n)
                .map(|i| {
                    Finding::new(
                        &hit,
                        Location::File {
                            path: PathBuf::from(format!("f{i}.js")),
                        },
                    )
                })
                .collect(),
            history_findings: vec![],
            walk: WalkStats {
                files_scanned: 5,
                ..WalkStats::default()
            },
            history: HistoryOutcome::Scanned(HistoryStats {
                commits: 7,
                lines: 0,
            }),
            ignored: 0,
        }
    }

    fn machine() -> MachineReport {
        let home = PathBuf::from("/home/u");
        MachineReport {
            home: home.clone(),
            spots: vec![
                Spot {
                    kind: SpotKind::ShellHistory,
                    display: "~/.bash_history".into(),
                    report: rep("/home/u/.bash_history", 1),
                },
                Spot {
                    kind: SpotKind::CredentialStore,
                    display: "~/.npmrc".into(),
                    report: rep("/home/u/.npmrc", 0),
                },
            ],
            repos: vec![rep("/home/u/code/big", 12), rep("/home/u/code/clean", 0)],
            unreadable_dirs: 0,
        }
    }

    #[test]
    fn machine_text_summarizes_and_caps_per_repo() {
        let t = render_machine_text(&machine());
        assert!(t.contains("~/.bash_history:2:5"));
        assert!(t.contains("~/code/big — 12 secrets"));
        assert!(t.contains("… and 2 more — run `jetscan secrets ~/code/big`"));
        assert!(!t.contains("~/code/clean"));
        assert!(t.contains(
            "Scanned 1 credential file, 1 shell history and 2 repositories (10 files, 14 commits)"
        ));
        assert!(t.contains("Found 13 secrets: 1 in shell history, 12 in 1 of 2 repositories"));
        assert!(t.contains("delete that line from the history file"));
        assert!(!t.contains(&secret()));
    }

    #[test]
    fn machine_json_parses_and_has_no_raw_secret() {
        let j = render_machine_json(&machine());
        assert!(!j.contains(&secret()));
        let v = json::parse(&j).unwrap();
        assert_eq!(v.get("mode").and_then(Json::as_str), Some("machine"));
        assert_eq!(
            v.get("summary")
                .and_then(|s| s.get("findings"))
                .and_then(Json::as_f64),
            Some(13.0)
        );
        assert_eq!(j, render_machine_json(&machine()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::history::HistoryStats;
    use crate::secrets::walk::WalkStats;
    use crate::secrets::{Hit, RuleInfo};
    use std::path::PathBuf;

    const RULE: RuleInfo = RuleInfo {
        id: "github-token",
        name: "GitHub Token",
        confidence: Confidence::High,
    };

    fn secret() -> String {
        format!("{}{}", "ghp_", "Zq8".repeat(12))
    }

    fn report(path: &str) -> ScanReport {
        let hit = Hit {
            rule: RULE,
            line: 3,
            col: 7,
            secret: secret(),
        };
        ScanReport {
            root: PathBuf::from("proj"),
            findings: vec![Finding::new(
                &hit,
                Location::File {
                    path: PathBuf::from(path),
                },
            )],
            history_findings: vec![Finding::new(
                &hit,
                Location::Git {
                    commit: "0123456789abcdef0123456789abcdef01234567".into(),
                    path: "old.js".into(),
                },
            )],
            walk: WalkStats {
                files_scanned: 12,
                ..WalkStats::default()
            },
            history: HistoryOutcome::Scanned(HistoryStats {
                commits: 40,
                lines: 0,
            }),
            ignored: 0,
        }
    }

    #[test]
    fn text_report_has_summary_and_never_the_raw_secret() {
        let t = render_text(&report("src/a.js"));
        assert!(t.contains("src/a.js:3:7"));
        assert!(t.contains("0123456789 old.js:3"));
        assert!(t.contains("Found 2 secrets (2 high) — 1 only in git history"));
        assert!(t.contains("Scanned 12 files and 40 commits"));
        assert!(t.contains("Rotate every key"));
        assert!(!t.contains(&secret()));
    }

    #[test]
    fn hostile_file_name_cannot_forge_report_lines() {
        let t = render_text(&report("evil\n\n✓ No secrets found\x1b[2J\u{202e}.js"));
        assert!(!t.contains("\n✓ No secrets found"));
        assert!(!t.contains("\x1b[2J"));
        assert!(!t.contains('\u{202e}'));
    }

    #[test]
    fn clean_report_says_when_history_was_not_checked() {
        let mut r = report("a");
        r.findings.clear();
        r.history_findings.clear();
        r.history = HistoryOutcome::Failed(HistoryError::GitNotFound);
        let t = render_text(&r);
        assert!(t.contains("git history was NOT checked"));
        assert!(t.contains("git not found"));
    }

    #[test]
    fn json_report_is_parseable_and_has_no_raw_secret() {
        let j = render_json(&report("src/a.js"));
        assert!(!j.contains(&secret()));
        let v = json::parse(&j).unwrap();
        assert_eq!(v.get("version").and_then(Json::as_f64), Some(1.0));
        let findings = v.get("findings").and_then(Json::as_array).unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(
            findings[1].get("source").and_then(Json::as_str),
            Some("history")
        );
        assert_eq!(
            v.get("summary")
                .and_then(|s| s.get("history_only"))
                .and_then(Json::as_f64),
            Some(1.0)
        );
        // Детерминизм: одинаковый ввод → байт-в-байт одинаковый вывод.
        assert_eq!(j, render_json(&report("src/a.js")));
    }
}
