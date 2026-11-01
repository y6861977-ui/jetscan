//! Движок поиска секретов (T1.4 + T1.8): склеивает обход файлов, git-историю,
//! правила и спецфайлы в один детерминированный отчёт.

use super::history::{self, HistoryError, HistoryStats};
use super::walk::{self, DEFAULT_SKIP_DIRS, WalkOptions, WalkStats};
use super::{Finding, Hit, Location, gitstatus, rules, scan_line, special, verify};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

/// Маркер на строке, который отключает находки на ней.
pub const INLINE_IGNORE: &str = "jetscan:ignore";
/// Файл игнор-листа в корне сканирования.
pub const IGNORE_FILE: &str = ".jetscanignore";

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub walk: WalkOptions,
    /// Сканировать ли git-историю (по умолчанию — да).
    pub history: bool,
    /// `--verify`: спросить у провайдера, рабочий ли ключ (T4.1). Сеть; по умолчанию — нет.
    pub verify: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            walk: WalkOptions::default(),
            history: true,
            verify: false,
        }
    }
}

/// Что стало с историей.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryOutcome {
    /// Не запрашивали (`--no-history`) или корень — файл.
    Disabled,
    Scanned(HistoryStats),
    Failed(HistoryError),
}

#[derive(Clone, Debug)]
pub struct ScanReport {
    pub root: PathBuf,
    /// Находки в текущих файлах, отсортированы (путь, строка, колонка, правило).
    pub findings: Vec<Finding>,
    /// Секреты, которых уже нет в файлах, но которые живут в истории.
    /// По одному на отпечаток — коммит, где секрет появился впервые.
    pub history_findings: Vec<Finding>,
    pub walk: WalkStats,
    pub history: HistoryOutcome,
    /// Сколько находок подавлено `.jetscanignore` / `jetscan:ignore`.
    pub ignored: usize,
}

impl ScanReport {
    pub fn total(&self) -> usize {
        self.findings.len() + self.history_findings.len()
    }

    pub fn all_findings(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().chain(self.history_findings.iter())
    }

    /// Находки, ведущие к утечке (всё, кроме файлов в `.gitignore`). Это считает `--exit-code`.
    pub fn actionable(&self) -> usize {
        self.all_findings().filter(|f| f.is_actionable()).count()
    }
}

pub fn scan(root: &Path, opts: &ScanOptions) -> Result<ScanReport, String> {
    scan_with(root, opts, &verify::Curl)
}

/// `scan` с подставляемым транспортом для `--verify` (в тестах — фейк, без сети).
pub fn scan_with(
    root: &Path,
    opts: &ScanOptions,
    transport: &dyn verify::Transport,
) -> Result<ScanReport, String> {
    // Сырые секреты для `--verify`: только при флаге, только в памяти, по одному на отпечаток.
    let mut raw: BTreeMap<String, (&'static str, String)> = BTreeMap::new();
    let mut keep_raw = |f: &Finding, hit: &Hit| {
        if opts.verify {
            raw.entry(f.fingerprint.clone())
                .or_insert_with(|| (hit.rule.id, hit.secret.clone()));
        }
    };
    let meta = fs::metadata(root).map_err(|e| format!("cannot read '{}': {e}", root.display()))?;
    let ignore = IgnoreList::load(root, meta.is_dir());
    let mut ignored = 0;
    // Отпечатки, заглушенные в файлах, — чтобы тот же секрет из истории не считать дважды.
    let mut ignored_fps: std::collections::HashSet<String> = std::collections::HashSet::new();

    // --- текущие файлы ---
    let mut by_key: HashMap<(PathBuf, usize, String), Finding> = HashMap::new();
    // История читается в фоне, пока идут текущие файлы: это отдельные процессы git.
    let (walk_stats, history_hits) = std::thread::scope(|scope| {
        let history = (opts.history && meta.is_dir())
            .then(|| scope.spawn(|| git_hits(root, GitSource::History)));
        let walk_stats = walk::walk(root, &opts.walk, &mut |path, text| {
            let rel = relative(root, path, meta.is_dir());
            let rel_str = slash_path(&rel);
            let mut hits: Vec<Hit> = scan_text_with_ignores(text);
            widen_private_keys(&mut hits, text);
            if special::is_special(path) {
                hits.extend(
                    special::scan(path, text)
                        .into_iter()
                        .filter(|h| !line_has_inline_ignore(text, h.line)),
                );
            }
            for hit in hits {
                let finding = Finding::new(&hit, Location::File { path: rel.clone() });
                if ignore.matches(&rel_str, &finding) {
                    ignored += 1;
                    ignored_fps.insert(finding.fingerprint.clone());
                    continue;
                }
                keep_raw(&finding, &hit);
                insert_best(
                    &mut by_key,
                    (rel.clone(), finding.line, finding.fingerprint.clone()),
                    finding,
                );
            }
        });
        let history = history.map(|h| h.join().unwrap_or_else(|p| std::panic::resume_unwind(p)));
        (walk_stats, history)
    });
    let mut findings: Vec<Finding> = by_key.into_values().collect();
    findings.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    if meta.is_dir() {
        mark_tracking(root, &mut findings);
    }

    // --- git-история ---
    let mut history_findings = Vec::new();
    let history = if let Some((ready, result, _)) = history_hits {
        let mut first_seen: HashMap<String, Finding> = HashMap::new();
        for (hit, commit, path) in ready {
            let finding = Finding::new(
                &hit,
                Location::Git {
                    commit,
                    path: path.clone(),
                },
            );
            if ignore.matches(&path, &finding) {
                // Один секрет во многих коммитах — одна заглушённая находка.
                if ignored_fps.insert(finding.fingerprint.clone()) {
                    ignored += 1;
                }
                continue;
            }
            keep_raw(&finding, &hit);
            // git log идёт от новых к старым: перезапись оставляет самый ранний коммит,
            // но при равном отпечатке предпочитаем более уверенное правило.
            let keep_new = first_seen
                .get(&finding.fingerprint)
                .is_none_or(|old| finding.rule.confidence >= old.rule.confidence);
            if keep_new {
                first_seen.insert(finding.fingerprint.clone(), finding);
            }
        }
        match result {
            Ok(stats) => {
                let in_files: std::collections::HashSet<&str> =
                    findings.iter().map(|f| f.fingerprint.as_str()).collect();
                history_findings = first_seen
                    .into_values()
                    .filter(|f| !in_files.contains(f.fingerprint.as_str()))
                    .collect();
                history_findings.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
                HistoryOutcome::Scanned(stats)
            }
            Err(e) => HistoryOutcome::Failed(e),
        }
    } else {
        HistoryOutcome::Disabled
    };

    if opts.verify && !raw.is_empty() {
        let live = verify::check(&raw, transport);
        for f in findings.iter_mut().chain(history_findings.iter_mut()) {
            f.verified = live.get(&f.fingerprint).cloned();
        }
    }
    drop(raw); // сырые секреты дальше не живут

    Ok(ScanReport {
        root: root.to_path_buf(),
        findings,
        history_findings,
        walk: walk_stats,
        history,
        ignored,
    })
}

/// Git-статус каждого файла с находкой (T1.10). Не репозиторий / нет git — `Unknown`.
fn mark_tracking(root: &Path, findings: &mut [Finding]) {
    let path_of = |f: &Finding| match &f.location {
        Location::File { path } => Some(slash_path(path)),
        Location::Git { .. } => None,
    };
    let mut paths: Vec<String> = findings.iter().filter_map(path_of).collect();
    paths.sort();
    paths.dedup();
    let Some(status) = gitstatus::classify(root, &paths) else {
        return;
    };
    for f in findings.iter_mut() {
        if let Some(t) = path_of(f).and_then(|p| status.get(&p).copied()) {
            f.tracking = t;
        }
    }
}

const PRIVATE_KEY_RULE: &str = "private-key";
/// Ограничители, чтобы битый PEM без `-----END` не тянул в память весь файл.
const PEM_MAX_LINES: usize = 200;
const PEM_MAX_LINE: usize = 16 * 1024;

/// Правило `private-key` видит только строку-заголовок, а заголовок одинаков у всех
/// RSA-ключей — значит, одинаков и отпечаток (ignore одного глушил бы все ключи, история
/// схлопывала бы разные). Поэтому секрет ключа = блок от `-----BEGIN` до `-----END`.
fn widen_private_keys(hits: &mut [Hit], text: &str) {
    if !hits.iter().any(|h| h.rule.id == PRIVATE_KEY_RULE) {
        return;
    }
    let lines: Vec<&str> = text.lines().collect();
    for h in hits.iter_mut().filter(|h| h.rule.id == PRIVATE_KEY_RULE) {
        let Some(first) = lines.get(h.line - 1) else {
            continue;
        };
        let start = first.char_indices().nth(h.col - 1).map_or(0, |(i, _)| i);
        let mut block: String = first[start..].chars().take(PEM_MAX_LINE).collect();
        if !block.contains("-----END") {
            for l in lines.iter().skip(h.line).take(PEM_MAX_LINES) {
                block.push('\n');
                block.extend(l.trim().chars().take(PEM_MAX_LINE));
                if l.contains("-----END") {
                    break;
                }
            }
        }
        h.secret = block;
    }
}

/// Откуда добавленные строки: вся история или индекс (staged).
#[derive(Clone, Copy)]
enum GitSource {
    History,
    Staged,
}

/// Срабатывания по добавленным строкам git (порядок — как отдаёт git) + итог git.
/// Общая часть истории (T1.8) и pre-commit (T3.2): правила, спецфайлы, PEM на много строк.
type GitHits = (
    Vec<(Hit, String, String)>,
    Result<HistoryStats, HistoryError>,
    usize, // сколько разных файлов прошло через git (для сводки pre-commit)
);

fn git_hits(root: &Path, source: GitSource) -> GitHits {
    match source {
        // Длинная история — параллельно; порядок срабатываний тот же, что у одного git.
        GitSource::History => match history::scan_parallel(root, GitLineScanner::default) {
            Ok((ready, stats)) => (ready, Ok(stats), 0),
            Err(e) => (Vec::new(), Err(e), 0),
        },
        GitSource::Staged => {
            let mut scanner = GitLineScanner::default();
            let mut ready = Vec::new();
            let mut paths: std::collections::HashSet<String> = std::collections::HashSet::new();
            let result = history::scan_staged(root, &mut |hl| {
                if !paths.contains(hl.path) {
                    paths.insert(hl.path.to_string());
                }
                scanner.scan_added(hl, &mut ready);
            });
            scanner.flush(&mut ready);
            (ready, result, paths.len())
        }
    }
}

/// Правила по добавленным строкам git: общая часть истории (T1.8) и pre-commit (T3.2).
#[derive(Default)]
struct GitLineScanner {
    /// Приватный ключ, чьё тело ещё дочитываем следующими строками того же коммита/файла.
    pending: Option<PendingKey>,
}

impl history::CommitVisitor for GitLineScanner {
    type Out = (Hit, String, String);

    fn line(&mut self, line: &history::HistoryLine, out: &mut Vec<Self::Out>) {
        self.scan_added(line, out);
    }

    fn end_commit(&mut self, out: &mut Vec<Self::Out>) {
        self.flush(out);
    }
}

impl GitLineScanner {
    fn flush(&mut self, ready: &mut Vec<(Hit, String, String)>) {
        if let Some(p) = self.pending.take() {
            ready.push(p.finish());
        }
    }

    fn scan_added(&mut self, hl: &history::HistoryLine, ready: &mut Vec<(Hit, String, String)>) {
        let pending = &mut self.pending;
        if let Some(p) = pending.as_mut() {
            if p.commit == hl.commit && p.path == hl.path && hl.line == p.next_line {
                p.push(hl.text);
                if p.done {
                    ready.push(pending.take().unwrap().finish());
                }
                return;
            }
            ready.push(pending.take().unwrap().finish());
        }
        if path_in_skipped_dir(hl.path) || hl.text.contains(INLINE_IGNORE) {
            return;
        }
        let mut hits = scan_line(rules::all(), hl.line, hl.text);
        // Спецфайлы построчные (.env, .npmrc, .pypirc, .git-credentials) работают и по строке.
        let as_path = Path::new(hl.path);
        if special::is_special(as_path) {
            hits.extend(special::scan(as_path, hl.text).into_iter().map(|mut h| {
                h.line = hl.line;
                h
            }));
        }
        for hit in hits {
            if hit.rule.id == PRIVATE_KEY_RULE && !hit.secret.contains("-----END") {
                let mut p = PendingKey {
                    hit,
                    commit: hl.commit.to_string(),
                    path: hl.path.to_string(),
                    next_line: hl.line + 1,
                    body_lines: 0,
                    done: false,
                };
                // Ключ одной строкой (`"-----BEGIN ...-----\nMIIE..."` в JSON) — тело тут же.
                let rest = &hl.text[hl.text.find("-----BEGIN").unwrap_or(0)..];
                p.hit.secret = rest.chars().take(PEM_MAX_LINE).collect();
                p.done = p.hit.secret.contains("-----END");
                if p.done {
                    ready.push(p.finish());
                } else {
                    *pending = Some(p);
                }
            } else {
                ready.push((hit, hl.commit.to_string(), hl.path.to_string()));
            }
        }
    }
}

/// Только то, что уйдёт в следующий коммит (`git diff --cached`) — для pre-commit (T3.2).
/// Пути — от корня репозитория; `.jetscanignore` и `jetscan:ignore` действуют.
/// Не репозиторий / нет git — ошибка: молча пропустить проверку перед коммитом нельзя.
pub fn scan_staged(root: &Path) -> Result<ScanReport, String> {
    let ignore = IgnoreList::load(root, true);
    let (ready, result, files) = git_hits(root, GitSource::Staged);
    result.map_err(|e| match e {
        HistoryError::GitNotFound => "git not found in PATH".to_string(),
        HistoryError::NotARepo => format!("'{}' is not a git repository", root.display()),
        HistoryError::Git(msg) => format!("git failed: {}", msg.lines().next().unwrap_or("")),
    })?;
    let mut ignored = 0;
    let mut by_key: HashMap<(PathBuf, usize, String), Finding> = HashMap::new();
    for (hit, _, path) in ready {
        let finding = Finding::new(
            &hit,
            Location::File {
                path: PathBuf::from(&path),
            },
        );
        if ignore.matches(&path, &finding) {
            ignored += 1;
            continue;
        }
        insert_best(
            &mut by_key,
            (
                PathBuf::from(&path),
                finding.line,
                finding.fingerprint.clone(),
            ),
            finding,
        );
    }
    let mut findings: Vec<Finding> = by_key.into_values().collect();
    findings.sort_by(|a, b| sort_key(a).cmp(&sort_key(b)));
    Ok(ScanReport {
        root: root.to_path_buf(),
        findings,
        history_findings: Vec::new(),
        walk: WalkStats {
            files_scanned: files,
            ..WalkStats::default()
        },
        history: HistoryOutcome::Disabled,
        ignored,
    })
}

/// Приватный ключ из истории: тело приходит следующими добавленными строками.
struct PendingKey {
    hit: Hit,
    commit: String,
    path: String,
    next_line: usize,
    body_lines: usize,
    done: bool,
}

impl PendingKey {
    fn push(&mut self, line: &str) {
        self.hit.secret.push('\n');
        self.hit
            .secret
            .extend(line.trim().chars().take(PEM_MAX_LINE));
        self.next_line += 1;
        self.body_lines += 1;
        self.done = line.contains("-----END") || self.body_lines >= PEM_MAX_LINES;
    }

    fn finish(self) -> (Hit, String, String) {
        (self.hit, self.commit, self.path)
    }
}

/// Общие правила по тексту, кроме строк с `jetscan:ignore`.
fn scan_text_with_ignores(text: &str) -> Vec<Hit> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.contains(INLINE_IGNORE))
        .flat_map(|(i, line)| scan_line(rules::all(), i + 1, line))
        .collect()
}

fn line_has_inline_ignore(text: &str, line_no: usize) -> bool {
    text.lines()
        .nth(line_no.saturating_sub(1))
        .is_some_and(|l| l.contains(INLINE_IGNORE))
}

/// Одно и то же место + один и тот же секрет от двух правил → оставляем более уверенное;
/// при равенстве — первое (провайдерские правила идут раньше спецфайлов).
fn insert_best<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Finding>, key: K, f: Finding) {
    match map.get(&key) {
        Some(old) if old.rule.confidence >= f.rule.confidence => {}
        _ => {
            map.insert(key, f);
        }
    }
}

fn sort_key(f: &Finding) -> (String, String, usize, usize, &'static str) {
    let (commit, path) = match &f.location {
        Location::File { path } => (String::new(), slash_path(path)),
        Location::Git { commit, path } => (commit.clone(), path.clone()),
    };
    (path, commit, f.line, f.col, f.rule.id)
}

fn relative(root: &Path, path: &Path, root_is_dir: bool) -> PathBuf {
    if root_is_dir {
        path.strip_prefix(root).unwrap_or(path).to_path_buf()
    } else {
        path.file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf())
    }
}

fn slash_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// История содержит и то, что обход файлов пропускает (закоммиченный `node_modules`).
/// Держим поведение одинаковым.
fn path_in_skipped_dir(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.pop(); // имя файла
    parts
        .iter()
        .any(|p| DEFAULT_SKIP_DIRS.iter().any(|s| p.eq_ignore_ascii_case(s)))
}

/// `.jetscanignore`: по строке на запись, `#` — комментарий.
///   `1a2b3c4d5e6f7a8b`     — отпечаток (16 hex) — конкретный секрет везде;
///   `rule:url-credentials` — всё правило;
///   `docs/`                — каталог (префикс пути);
///   `tests/fixture.env`    — конкретный файл.
#[derive(Default)]
struct IgnoreList {
    fingerprints: Vec<String>,
    rules: Vec<String>,
    paths: Vec<String>,
}

impl IgnoreList {
    fn load(root: &Path, root_is_dir: bool) -> IgnoreList {
        let mut list = IgnoreList::default();
        if !root_is_dir {
            return list;
        }
        let Ok(text) = fs::read_to_string(root.join(IGNORE_FILE)) else {
            return list;
        };
        for raw in text.lines() {
            let entry = raw.split('#').next().unwrap_or("").trim();
            if entry.is_empty() {
                continue;
            }
            if let Some(rule) = entry.strip_prefix("rule:") {
                list.rules.push(rule.trim().to_string());
            } else if entry.len() == 16 && entry.bytes().all(|b| b.is_ascii_hexdigit()) {
                list.fingerprints.push(entry.to_ascii_lowercase());
            } else {
                list.paths.push(
                    entry
                        .replace('\\', "/")
                        .trim_start_matches("./")
                        .to_string(),
                );
            }
        }
        list
    }

    fn matches(&self, rel_path: &str, f: &Finding) -> bool {
        self.fingerprints.contains(&f.fingerprint)
            || self.rules.iter().any(|r| r == f.rule.id)
            || self.paths.iter().any(|p| {
                if let Some(dir) = p.strip_suffix('/') {
                    rel_path == dir || rel_path.starts_with(&format!("{dir}/"))
                } else {
                    rel_path == p
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::fingerprint;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!(
                "jetscan-scan-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn write(&self, rel: &str, body: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn no_history() -> ScanOptions {
        ScanOptions {
            history: false,
            ..ScanOptions::default()
        }
    }

    fn aws() -> String {
        format!("{}{}", "AKIA", "Q7ZK2M4N8P3R5T6V")
    }

    #[test]
    fn finds_secrets_with_relative_paths_in_stable_order() {
        let t = Tmp::new("order");
        t.write("z.txt", &format!("key = {}\n", aws()));
        t.write("a/b.txt", &format!("\n\nx {}", aws()));
        let r = scan(&t.0, &no_history()).unwrap();
        let got: Vec<(String, usize)> = r
            .findings
            .iter()
            .map(|f| match &f.location {
                Location::File { path } => (slash_path(path), f.line),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(got, vec![("a/b.txt".into(), 3), ("z.txt".into(), 1)]);
        assert_eq!(r.walk.files_scanned, 2);
        assert!(r.findings.iter().all(|f| !f.masked.contains(&aws())));
    }

    #[test]
    fn provider_rule_wins_over_env_rule_on_same_value() {
        let t = Tmp::new("dedup");
        t.write(".env", &format!("AWS_ACCESS_KEY={}\n", aws()));
        let r = scan(&t.0, &no_history()).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule.id, "aws-access-key");
    }

    #[test]
    fn inline_and_file_ignores_suppress_findings() {
        let t = Tmp::new("ignore");
        t.write("a.txt", &format!("{} // jetscan:ignore\n", aws()));
        t.write(".env", "DB_PASSWORD=Tq9vL2mXw # jetscan:ignore\n");
        t.write("docs/x.md", &aws());
        t.write("b.txt", &aws());
        t.write("c.txt", &format!("https://u:{}@h", "Rz81kQ0pw"));
        t.write(
            IGNORE_FILE,
            &format!(
                "docs/\n{}  # b.txt\nrule:url-credentials\n",
                fingerprint(&aws())
            ),
        );
        let r = scan(&t.0, &no_history()).unwrap();
        assert_eq!(r.findings, vec![]);
        assert_eq!(r.ignored, 3);
    }

    #[test]
    fn missing_root_is_an_error_not_a_clean_result() {
        let t = Tmp::new("missing");
        assert!(scan(&t.0.join("nope"), &no_history()).is_err());
    }

    #[test]
    fn single_file_root_works() {
        let t = Tmp::new("file");
        t.write("one.txt", &aws());
        let r = scan(&t.0.join("one.txt"), &ScanOptions::default()).unwrap();
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.history, HistoryOutcome::Disabled);
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn secret_removed_from_files_is_reported_from_history() {
        let t = Tmp::new("history");
        if !git(&t.0, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        t.write("config.js", &format!("const t = '{gh}';\n"));
        assert!(git(&t.0, &["add", "."]));
        assert!(git(&t.0, &["commit", "-q", "-m", "add"]));
        t.write("config.js", "const t = process.env.GH_TOKEN;\n");
        assert!(git(&t.0, &["commit", "-qam", "remove"]));
        // Секрет, который всё ещё в файле, в history_findings не дублируется.
        t.write("live.txt", &aws());
        assert!(git(&t.0, &["add", "."]));
        assert!(git(&t.0, &["commit", "-q", "-m", "live"]));

        let r = scan(&t.0, &ScanOptions::default()).unwrap();
        assert!(matches!(r.history, HistoryOutcome::Scanned(ref s) if s.commits == 3));
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.history_findings.len(), 1);
        let h = &r.history_findings[0];
        assert_eq!(h.rule.id, "github-token");
        assert!(matches!(&h.location, Location::Git { path, .. } if path == "config.js"));

        // Заглушили по отпечатку: секрет был в двух коммитах (добавлен и в другом файле
        // ещё раз) — в счётчике одна находка, а не по строке на коммит.
        t.write("other.js", &format!("// '{gh}'\n"));
        assert!(git(&t.0, &["add", "."]));
        assert!(git(&t.0, &["commit", "-q", "-m", "again"]));
        t.write("other.js", "// gone\n");
        assert!(git(&t.0, &["commit", "-qam", "gone"]));
        t.write(IGNORE_FILE, &format!("{}\n", h.fingerprint));
        let r2 = scan(&t.0, &ScanOptions::default()).unwrap();
        assert!(r2.history_findings.is_empty());
        assert_eq!(r2.ignored, 1);
    }

    /// Транспорт, который запоминает всё, что пытались отправить.
    struct Spy(std::sync::Mutex<Vec<String>>);
    impl verify::Transport for Spy {
        fn send(&self, req: &verify::Request) -> Result<verify::Response, String> {
            self.0.lock().unwrap().push(req.url.clone());
            Ok(verify::Response {
                status: 200,
                body: String::new(),
            })
        }
    }

    #[test]
    fn verify_is_opt_in_and_nothing_leaves_without_a_provider() {
        let t = Tmp::new("verify");
        // private-key: адаптера нет и не будет (проверять нечем).
        // Собираем в рантайме: литерал PEM в исходнике jetscan нашёл бы сам у себя.
        let begin = format!("{}{}", "-----BEGIN RSA ", "PRIVATE KEY-----");
        let end = format!("{}{}", "-----END RSA ", "PRIVATE KEY-----");
        t.write("id_rsa", &format!("{begin}\nMIIEowIBAAKCAQEAzz\n{end}\n"));
        let spy = Spy(std::sync::Mutex::new(Vec::new()));
        // Без --verify сеть не трогаем вовсе.
        let r = scan_with(
            &t.0,
            &ScanOptions {
                history: false,
                ..ScanOptions::default()
            },
            &spy,
        )
        .unwrap();
        assert_eq!(r.findings.len(), 1);
        assert!(r.findings[0].verified.is_none());
        // С --verify, но без адаптера для правила — тоже ничего не уходит.
        let opts = ScanOptions {
            history: false,
            verify: true,
            ..ScanOptions::default()
        };
        let r = scan_with(&t.0, &opts, &spy).unwrap();
        assert!(r.findings[0].verified.is_none());
        assert!(spy.0.lock().unwrap().is_empty(), "no provider → no request");
    }

    #[test]
    fn staged_scan_sees_only_what_the_next_commit_adds() {
        let t = Tmp::new("staged");
        if !git(&t.0, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        // Закоммиченный секрет — не дело pre-commit (его покажет обычный скан).
        t.write("old.js", &format!("const a = '{gh}';\n"));
        assert!(git(&t.0, &["add", "."]));
        assert!(git(&t.0, &["commit", "-q", "-m", "old"]));
        // Не добавлен в индекс — тоже не уйдёт в коммит.
        t.write("unstaged.js", &aws());
        // В индексе: ключ AWS на 2-й строке и строка с jetscan:ignore.
        t.write(
            "new.py",
            &format!("x = 1\n{}\nk = '{gh}'  # jetscan:ignore\n", aws()),
        );
        assert!(git(&t.0, &["add", "new.py"]));

        let r = scan_staged(&t.0).unwrap();
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        let f = &r.findings[0];
        assert_eq!(f.rule.id, "aws-access-key");
        assert!(matches!(&f.location, Location::File { path } if path == Path::new("new.py")));
        assert_eq!(f.line, 2);
        assert_eq!(r.walk.files_scanned, 1);

        // Не репозиторий — ошибка, а не «чисто».
        let plain = Tmp::new("staged-plain");
        if !git(&plain.0, &["rev-parse", "--is-inside-work-tree"]) {
            assert!(scan_staged(&plain.0).is_err());
        }
    }
}

#[cfg(test)]
mod pem_tests {
    //! Ревью T1.6 (Claude): у всех RSA-ключей был один отпечаток — от заголовка.
    use super::*;

    fn pem(body: &str) -> String {
        format!(
            "{}\n{body}\n{}\n",
            concat!("-----BEGIN RSA ", "PRIVATE KEY-----"),
            concat!("-----END RSA ", "PRIVATE KEY-----")
        )
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("jetscan-pem-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn opts() -> ScanOptions {
        ScanOptions {
            history: false,
            ..ScanOptions::default()
        }
    }

    #[test]
    fn different_keys_get_different_fingerprints_and_ignore_is_per_key() {
        let d = tmp("files");
        fs::write(d.join("a.key"), pem("MIIEowIBAAKCAQEAaaaa")).unwrap();
        fs::write(d.join("b.key"), pem("MIIEpAIBAAKCAQEAbbbb")).unwrap();
        let r = scan(&d, &opts()).unwrap();
        assert_eq!(r.findings.len(), 2);
        assert_ne!(r.findings[0].fingerprint, r.findings[1].fingerprint);
        assert!(r.findings.iter().all(|f| f.line == 1 && f.col == 1));

        // Игнор одного ключа не глушит другой.
        fs::write(d.join(IGNORE_FILE), &r.findings[0].fingerprint).unwrap();
        let r2 = scan(&d, &opts()).unwrap();
        assert_eq!(r2.findings.len(), 1);
        assert_eq!(r2.ignored, 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn same_key_in_two_files_keeps_one_fingerprint() {
        let d = tmp("same");
        fs::write(d.join("a.key"), pem("MIIEowIBAAKCAQEAsame")).unwrap();
        fs::write(d.join("b.pem"), pem("MIIEowIBAAKCAQEAsame")).unwrap();
        let r = scan(&d, &opts()).unwrap();
        assert_eq!(r.findings[0].fingerprint, r.findings[1].fingerprint);
        let _ = fs::remove_dir_all(&d);
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn deleted_key_in_history_is_not_hidden_by_another_key_in_files() {
        let d = tmp("hist");
        if !git(&d, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        fs::write(d.join("old.key"), pem("MIIEowIBAAKCAQEAold1")).unwrap();
        assert!(git(&d, &["add", "."]));
        assert!(git(&d, &["commit", "-qm", "old"]));
        assert!(git(&d, &["rm", "-q", "old.key"]));
        assert!(git(&d, &["commit", "-qm", "rm"]));
        fs::write(d.join("new.key"), pem("MIIEowIBAAKCAQEAnew2")).unwrap();
        assert!(git(&d, &["add", "."]));
        assert!(git(&d, &["commit", "-qm", "new"]));

        let r = scan(&d, &ScanOptions::default()).unwrap();
        assert_eq!(r.findings.len(), 1, "new.key in files");
        assert_eq!(r.history_findings.len(), 1, "old.key only in history");
        assert!(
            matches!(&r.history_findings[0].location, Location::Git { path, .. } if path == "old.key")
        );
        let _ = fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod tracking_tests {
    //! T1.10: находка знает, в git ли её файл.
    use super::*;
    use crate::secrets::{Tracking, report};

    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn findings_are_split_by_git_status_and_local_ones_do_not_count() {
        let d = std::env::temp_dir().join(format!("jetscan-track-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("deploy")).unwrap();
        if !git(&d, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        // Как в реальном прогоне: настоящий ключ скопирован в закоммиченный example.
        let key = format!("{}{}", "sk_live_", "51HxQk2LmZp8Rt4Vw9Yb3Nc6");
        fs::write(d.join(".gitignore"), ".env\n").unwrap();
        fs::write(
            d.join("deploy/.env.production.example"),
            format!("STRIPE_SECRET={key}\n"),
        )
        .unwrap();
        assert!(git(&d, &["add", "."]));
        assert!(git(&d, &["commit", "-qm", "init"]));
        fs::write(
            d.join(".env"),
            format!("STRIPE_SECRET={key}\nDB_PASSWORD=Tq9vL2mXw\n"),
        )
        .unwrap();
        let aws = format!("{}{}", "AKIA", "Q7ZK2M4N8P3R5T6V");
        fs::write(d.join("notes.txt"), &aws).unwrap();

        let r = scan(&d, &ScanOptions::default()).unwrap();
        let by = |p: &str| -> Vec<Tracking> {
            r.findings
                .iter()
                .filter(|f| matches!(&f.location, Location::File { path } if slash_path(path) == p))
                .map(|f| f.tracking)
                .collect()
        };
        assert_eq!(
            by("deploy/.env.production.example"),
            vec![Tracking::Tracked]
        );
        assert_eq!(by("notes.txt"), vec![Tracking::Untracked]);
        assert!(by(".env").iter().all(|t| *t == Tracking::Ignored));
        assert_eq!(by(".env").len(), 2);
        assert_eq!(r.actionable(), 2, "committed + not ignored; .env is local");

        let t = report::render_text(&r);
        assert!(t.contains("Committed to git"));
        assert!(t.contains("Not ignored by git"));
        assert!(t.contains("Local only"));
        assert!(t.contains("Found 2 secrets"));
        assert!(t.contains("1 committed, 1 not ignored"));
        assert!(t.contains("+ 2 local secrets in .gitignored files (not counted)"));
        let j = report::render_json(&r);
        assert!(j.contains("\"git\": \"tracked\""));
        assert!(j.contains("\"local_ignored\": 2"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn only_local_secrets_is_reported_as_no_leak() {
        let d = std::env::temp_dir().join(format!("jetscan-track2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        if !git(&d, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        fs::write(d.join(".gitignore"), ".env\n").unwrap();
        fs::write(d.join(".env"), "DB_PASSWORD=Tq9vL2mXw\n").unwrap();
        let r = scan(&d, &ScanOptions::default()).unwrap();
        assert_eq!(r.actionable(), 0);
        let t = report::render_text(&r);
        assert!(t.contains("No leaked secrets — 1 local secret only in .gitignored files"));
        let _ = fs::remove_dir_all(&d);
    }
}
