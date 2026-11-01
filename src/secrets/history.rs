//! Добавленные строки из git-истории.
//!
//! БЕЗОПАСНОСТЬ (обязательно): сканируем, возможно, чужой репозиторий, а его
//! `.git/config` может запускать команды. Вызывать git только так:
//!   git --no-pager -c core.fsmonitor=false -c core.hooksPath=/dev/null -c log.showSignature=false
//!       -C <repo> log -p --all --no-color --no-ext-diff --no-textconv --unified=0 ...
//! (параллельно: `rev-list --all`, затем те же флаги с `--no-walk=unsorted --stdin`,
//! SHA коммитов — через stdin). Аргументы — через `Command::arg`, никакого шелла.
//! Вывод читать потоково.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread;

/// Одна добавленная (`+`) строка из коммита.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryLine<'a> {
    /// Полный SHA коммита.
    pub commit: &'a str,
    /// Путь файла в репозитории (как пишет git, через `/`).
    pub path: &'a str,
    /// Номер строки в новой версии файла (из `@@ ... +N,M @@`), с 1.
    pub line: usize,
    /// Текст строки без ведущего `+`.
    pub text: &'a str,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryStats {
    pub commits: usize,
    pub lines: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryError {
    /// `git` не найден в PATH.
    GitNotFound,
    /// Каталог не является git-репозиторием.
    NotARepo,
    /// git упал; текст stderr (будет санитайзиться при выводе).
    Git(String),
}

/// Аргументы `git log` после `log`: патчи без цвета/внешних diff/textconv, без контекста.
const LOG_ARGS: [&str; 9] = [
    "-p",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--unified=0",
    "--no-renames",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--format=commit %H",
];

/// Вызывает `visit` для каждой добавленной строки во всех коммитах (`--all`).
/// Один процесс git; эталонный порядок для [`scan_parallel`].
pub fn scan(
    repo: &Path,
    visit: &mut dyn FnMut(&HistoryLine),
) -> Result<HistoryStats, HistoryError> {
    let mut args = vec!["log", "--all"];
    args.extend(LOG_ARGS);
    run(repo, &args, None, b"", &mut |event| {
        if let Event::Line(line) = event {
            visit(line);
        }
        Ok(())
    })
}

/// Состояние одного рабочего потока [`scan_parallel`]: правила по строкам коммита.
pub trait CommitVisitor: Send {
    type Out: Send;
    /// Добавленная строка; результаты — в `out` (выход текущего коммита).
    fn line(&mut self, line: &HistoryLine, out: &mut Vec<Self::Out>);
    /// Коммит закончился: дописать то, что копилось по нескольким строкам.
    fn end_commit(&mut self, out: &mut Vec<Self::Out>);
}

/// Не меньше стольких коммитов на процесс git: на маленькой истории запуск
/// процессов дороже выигрыша.
const MIN_COMMITS_PER_JOB: usize = 256;
const MAX_JOBS: usize = 8;
/// Сколько готовых коммитов поток может держать впереди сборщика.
const AHEAD: usize = 512;

/// То же, что [`scan`], но быстрее на длинной истории: git однопоточный, а на curl/curl
/// (40 364 коммита) ~17 с из ~20 — это сам `git log -p` (tests/benchmark.md, B2).
/// Коммиты из `git rev-list --all` раздаются по кругу нескольким
/// `git log -p --no-walk=unsorted --stdin`, правила работают в их потоках, а выход
/// собирается строго в порядке `rev-list` — тот же порядок, что у [`scan`], поэтому
/// результат не зависит от числа потоков.
pub fn scan_parallel<V: CommitVisitor>(
    repo: &Path,
    make: impl Fn() -> V + Sync,
) -> Result<(Vec<V::Out>, HistoryStats), HistoryError> {
    let commits = commit_list(repo)?;
    let cpus = thread::available_parallelism().map_or(1, |n| n.get());
    let jobs = (commits.len() / MIN_COMMITS_PER_JOB).clamp(1, cpus.clamp(1, MAX_JOBS));
    scan_commits(repo, &commits, jobs, make)
}

fn scan_commits<V: CommitVisitor>(
    repo: &Path,
    commits: &[String],
    jobs: usize,
    make: impl Fn() -> V + Sync,
) -> Result<(Vec<V::Out>, HistoryStats), HistoryError> {
    if commits.is_empty() {
        return Ok((Vec::new(), HistoryStats::default()));
    }
    let jobs = jobs.clamp(1, commits.len());
    let mut args = vec!["log", "--no-walk=unsorted", "--stdin"];
    args.extend(LOG_ARGS);

    thread::scope(|scope| {
        let mut receivers = Vec::with_capacity(jobs);
        let mut workers = Vec::with_capacity(jobs);
        for job in 0..jobs {
            let (tx, rx) = sync_channel(AHEAD);
            let mut stdin = String::new();
            for sha in commits.iter().skip(job).step_by(jobs) {
                stdin.push_str(sha);
                stdin.push('\n');
            }
            let (visitor, args) = (make(), &args);
            workers.push(scope.spawn(move || shard(repo, args, stdin, visitor, tx)));
            receivers.push(rx);
        }

        let mut out = Vec::new();
        // Первый сбой сборки: (поток, порядок нарушен?). Остальные потоки тогда
        // прерываются (их канал закрыт), их ошибки — следствие, не причина.
        let mut broken = None;
        for (i, sha) in commits.iter().enumerate() {
            match receivers[i % jobs].recv() {
                Ok((got, items)) if got == *sha => out.extend(items),
                Ok(_) => {
                    broken = Some((i % jobs, true));
                    break;
                }
                Err(_) => {
                    broken = Some((i % jobs, false));
                    break;
                }
            }
        }
        drop(receivers);

        let results: Vec<_> = workers
            .into_iter()
            .map(|w| {
                w.join()
                    .unwrap_or_else(|_| Err(HistoryError::Git("history worker panicked".into())))
            })
            .collect();
        if let Some((job, out_of_order)) = broken {
            return Err(if out_of_order {
                HistoryError::Git("git log returned commits out of order".into())
            } else {
                match &results[job] {
                    Err(e) => e.clone(),
                    Ok(_) => {
                        HistoryError::Git("git log returned fewer commits than rev-list".into())
                    }
                }
            });
        }
        let mut stats = HistoryStats::default();
        for result in results {
            let s = result?;
            stats.commits += s.commits;
            stats.lines += s.lines;
        }
        Ok((out, stats))
    })
}

/// Все коммиты `--all` в порядке `git log --all`.
fn commit_list(repo: &Path) -> Result<Vec<String>, HistoryError> {
    let mut commits = Vec::new();
    let mut buffer = String::new();
    let mut collect = |reader: &mut dyn BufRead| -> io::Result<()> {
        loop {
            buffer.clear();
            if reader.read_line(&mut buffer)? == 0 {
                return Ok(());
            }
            let sha = buffer.trim_end();
            if is_object_id(sha) {
                commits.push(sha.to_string());
            }
        }
    };
    run_raw(repo, &["rev-list", "--all"], None, &mut collect)?;
    Ok(commits)
}

/// Один процесс `git log --no-walk`: его коммиты по одному уходят сборщику.
fn shard<V: CommitVisitor>(
    repo: &Path,
    args: &[&str],
    stdin: String,
    mut visitor: V,
    tx: SyncSender<(String, Vec<V::Out>)>,
) -> Result<HistoryStats, HistoryError> {
    let mut items = Vec::new();
    run(repo, args, Some(stdin), b"", &mut |event| match event {
        Event::Line(line) => {
            visitor.line(line, &mut items);
            Ok(())
        }
        Event::CommitEnd(sha) => {
            visitor.end_commit(&mut items);
            tx.send((sha.to_string(), std::mem::take(&mut items)))
                .map_err(|_| io::Error::other("history collector stopped"))
        }
    })
}

/// `commit` для staged-строк: их ещё нет ни в одном коммите (T3.2, pre-commit).
pub const STAGED: &str = "0000000000000000000000000000000000000000";

/// Добавленные строки из индекса (`git diff --cached`) — то, что уйдёт в следующий коммит.
/// Тот же разбор, что и для истории; `commit` у строк — [`STAGED`].
pub fn scan_staged(
    repo: &Path,
    visit: &mut dyn FnMut(&HistoryLine),
) -> Result<HistoryStats, HistoryError> {
    let args = [
        "diff",
        "--cached",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=0",
        "--no-renames",
        "--diff-filter=ACMR",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ];
    // У diff нет строк `commit`: подставляем одну, чтобы разбор был общим.
    let prefix = format!("commit {STAGED}\n");
    run(repo, &args, None, prefix.as_bytes(), &mut |event| {
        if let Event::Line(line) = event {
            visit(line);
        }
        Ok(())
    })
}

/// Что видит разбор вывода `git log -p`.
enum Event<'a, 'b> {
    Line(&'b HistoryLine<'a>),
    /// Все строки этого коммита уже отданы (приходит и для коммитов без строк).
    CommitEnd(&'a str),
}

/// git + разбор патчей; ошибка из `on_event` прерывает git.
fn run(
    repo: &Path,
    args: &[&str],
    stdin: Option<String>,
    prefix: &[u8],
    on_event: &mut dyn FnMut(Event) -> io::Result<()>,
) -> Result<HistoryStats, HistoryError> {
    let mut stats = HistoryStats::default();
    run_raw(repo, args, stdin, &mut |reader| {
        stats = parse_history(prefix.chain(reader), on_event)?;
        Ok(())
    })?;
    Ok(stats)
}

/// Запуск git по правилам безопасности из шапки; stdout читает `read`.
fn run_raw(
    repo: &Path,
    args: &[&str],
    stdin: Option<String>,
    read: &mut dyn FnMut(&mut dyn BufRead) -> io::Result<()>,
) -> Result<(), HistoryError> {
    let mut child = Command::new("git")
        .arg("--no-pager")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        // log.showSignature=true из конфига чужого репо запускает gpg.program — тоже команда.
        .arg("-c")
        .arg("log.showSignature=false")
        .arg("-c")
        .arg("core.quotePath=false")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                HistoryError::GitNotFound
            } else {
                HistoryError::Git(format!("failed to start git: {error}"))
            }
        })?;

    // Список коммитов пишет отдельный поток: git может начать писать stdout раньше,
    // чем дочитает stdin, а мы читаем stdout здесь.
    let stdin_thread = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => Some(thread::spawn(move || {
            // Ошибка записи = git уже завершился; его код и stderr скажут почему.
            let _ = pipe.write_all(data.as_bytes());
        })),
        _ => None,
    };
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");
    let stderr_thread = thread::spawn(move || drain_stderr(stderr));

    let parsed = read(&mut BufReader::new(stdout));
    if parsed.is_err() {
        let _ = child.kill();
    }
    if let Some(t) = stdin_thread {
        let _ = t.join();
    }
    let status = child
        .wait()
        .map_err(|error| HistoryError::Git(format!("failed to wait for git: {error}")))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| HistoryError::Git("failed to collect git stderr".to_string()))
        .and_then(|result| {
            result.map_err(|error| HistoryError::Git(format!("failed to read git stderr: {error}")))
        })?;

    parsed.map_err(|error| HistoryError::Git(format!("failed to read git history: {error}")))?;
    if status.success() {
        Ok(())
    } else if is_not_a_repo(&stderr) {
        Err(HistoryError::NotARepo)
    } else {
        let message = stderr.trim();
        Err(HistoryError::Git(if message.is_empty() {
            format!("git exited with status {status}")
        } else {
            message.to_string()
        }))
    }
}

fn parse_history(
    reader: impl BufRead,
    on_event: &mut dyn FnMut(Event) -> io::Result<()>,
) -> io::Result<HistoryStats> {
    let mut stats = HistoryStats::default();
    let mut commit = String::new();
    let mut path = String::new();
    let mut next_new_line = None::<usize>;
    let mut buffer = Vec::new();
    let mut reader = reader;

    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer)? == 0 {
            if !commit.is_empty() {
                on_event(Event::CommitEnd(&commit))?;
            }
            break;
        }
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
        }
        let line = String::from_utf8_lossy(&buffer);

        if let Some(line_number) = next_new_line.as_mut() {
            if let Some(text) = line.strip_prefix('+') {
                if !commit.is_empty() && !path.is_empty() {
                    on_event(Event::Line(&HistoryLine {
                        commit: &commit,
                        path: &path,
                        line: *line_number,
                        text,
                    }))?;
                    stats.lines += 1;
                }
                *line_number = line_number.saturating_add(1);
                continue;
            }
            if line.starts_with('-') || line.starts_with('\\') {
                continue;
            }
            if line.starts_with(' ') {
                *line_number = line_number.saturating_add(1);
                continue;
            }
            next_new_line = None;
        }

        if let Some(sha) = line.strip_prefix("commit ").filter(|sha| is_object_id(sha)) {
            if !commit.is_empty() {
                on_event(Event::CommitEnd(&commit))?;
            }
            commit.clear();
            commit.push_str(sha);
            path.clear();
            stats.commits += 1;
        } else if line.starts_with("diff --git ") {
            path.clear();
        } else if let Some(raw_path) = line.strip_prefix("+++ ") {
            path = parse_git_path(raw_path).unwrap_or_default();
        } else if let Some(line_number) = parse_hunk_new_start(&line) {
            next_new_line = Some(line_number);
        }
    }

    Ok(stats)
}

fn parse_hunk_new_start(line: &str) -> Option<usize> {
    if !line.starts_with("@@ ") {
        return None;
    }
    let range = line
        .split_ascii_whitespace()
        .find(|part| part.starts_with('+'))?;
    range[1..].split(',').next()?.parse().ok()
}

fn parse_git_path(raw: &str) -> Option<String> {
    let decoded = if raw.starts_with('"') {
        decode_git_quoted_path(raw)?
    } else {
        raw.to_string()
    };
    if decoded == "/dev/null" {
        return None;
    }
    decoded.strip_prefix("b/").map(str::to_string)
}

fn decode_git_quoted_path(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    if bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let mut decoded = Vec::new();
    let mut cursor = 1;
    while cursor + 1 < bytes.len() {
        if bytes[cursor] != b'\\' {
            decoded.push(bytes[cursor]);
            cursor += 1;
            continue;
        }
        cursor += 1;
        let escaped = *bytes.get(cursor)?;
        match escaped {
            b'a' => decoded.push(0x07),
            b'b' => decoded.push(0x08),
            b't' => decoded.push(b'\t'),
            b'n' => decoded.push(b'\n'),
            b'v' => decoded.push(0x0b),
            b'f' => decoded.push(0x0c),
            b'r' => decoded.push(b'\r'),
            b'"' | b'\\' => decoded.push(escaped),
            b'0'..=b'7' => {
                let mut value = u32::from(escaped - b'0');
                let mut digits = 1;
                while digits < 3
                    && cursor + 1 < bytes.len() - 1
                    && matches!(bytes[cursor + 1], b'0'..=b'7')
                {
                    cursor += 1;
                    value = value * 8 + u32::from(bytes[cursor] - b'0');
                    digits += 1;
                }
                decoded.push(u8::try_from(value).ok()?);
            }
            _ => decoded.push(escaped),
        }
        cursor += 1;
    }
    String::from_utf8(decoded)
        .or_else(|error| {
            Ok::<String, std::string::FromUtf8Error>(
                String::from_utf8_lossy(error.as_bytes()).into_owned(),
            )
        })
        .ok()
}

fn is_object_id(value: &str) -> bool {
    value.len() >= 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_not_a_repo(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("not a git repository") || lower.contains("cannot change to")
}

fn drain_stderr(mut stderr: impl Read) -> io::Result<String> {
    const MAX_CAPTURED: usize = 64 * 1024;
    let mut captured = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stderr.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURED.saturating_sub(captured.len());
        captured.extend_from_slice(&buffer[..read.min(remaining)]);
    }
    if captured.len() == MAX_CAPTURED {
        captured.extend_from_slice(b"\n[stderr truncated]");
    }
    Ok(String::from_utf8_lossy(&captured).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "jetscan-history-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary repository directory");
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_commits_paths_hunks_and_added_lines() {
        let log = concat!(
            "commit 1111111111111111111111111111111111111111\n",
            "diff --git a/src/a.txt b/src/a.txt\n",
            "--- a/src/a.txt\n",
            "+++ b/src/a.txt\n",
            "@@ -1 +1,2 @@\n",
            "-old\n",
            "+new\n",
            "+second\n",
            "@@ -5,0 +8 @@\n",
            "+eight\n",
            "commit 2222222222222222222222222222222222222222\n",
            "diff --git a/old.txt b/new.txt\n",
            "--- a/old.txt\n",
            "+++ \"b/dir/space\\040name.txt\"\n",
            "@@ -0,0 +3 @@\n",
            "++++ literal\n",
        );
        let mut seen = Vec::new();
        let mut ends = Vec::new();

        let stats = parse_history(log.as_bytes(), &mut |event| {
            match event {
                Event::Line(line) => seen.push((
                    line.commit.to_string(),
                    line.path.to_string(),
                    line.line,
                    line.text.to_string(),
                )),
                Event::CommitEnd(sha) => ends.push((sha.to_string(), seen.len())),
            }
            Ok(())
        })
        .unwrap();

        assert_eq!(
            stats,
            HistoryStats {
                commits: 2,
                lines: 4
            }
        );
        // Конец коммита — после всех его строк, в том числе для последнего.
        assert_eq!(ends, vec![("1".repeat(40), 3), ("2".repeat(40), 4)]);
        assert_eq!(
            seen,
            vec![
                (
                    "1111111111111111111111111111111111111111".to_string(),
                    "src/a.txt".to_string(),
                    1,
                    "new".to_string(),
                ),
                (
                    "1111111111111111111111111111111111111111".to_string(),
                    "src/a.txt".to_string(),
                    2,
                    "second".to_string(),
                ),
                (
                    "1111111111111111111111111111111111111111".to_string(),
                    "src/a.txt".to_string(),
                    8,
                    "eight".to_string(),
                ),
                (
                    "2222222222222222222222222222222222222222".to_string(),
                    "dir/space name.txt".to_string(),
                    3,
                    "+++ literal".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn non_repository_is_reported_without_panicking() {
        if !git_available() {
            eprintln!("skipping git history test: git is not available");
            return;
        }
        let temp = TempDir::new();

        let result = scan(temp.path(), &mut |_| {});

        assert_eq!(result, Err(HistoryError::NotARepo));
    }

    #[test]
    fn finds_a_secret_removed_by_a_later_commit() {
        if !git_available() {
            eprintln!("skipping git history test: git is not available");
            return;
        }
        let temp = TempDir::new();
        git(temp.path(), &["init"]);
        git(
            temp.path(),
            &["config", "user.email", "jetscan@example.test"],
        );
        git(temp.path(), &["config", "user.name", "jetscan test"]);
        let secret = format!("{}{}", "AKIA", "A1".repeat(8));
        fs::write(temp.path().join("secret.txt"), format!("{secret}\n"))
            .expect("write secret fixture");
        git(temp.path(), &["add", "secret.txt"]);
        git(temp.path(), &["commit", "-m", "add fixture"]);
        fs::write(temp.path().join("secret.txt"), "clean\n").expect("replace fixture");
        git(temp.path(), &["add", "secret.txt"]);
        git(temp.path(), &["commit", "-m", "remove fixture"]);
        let mut seen = Vec::new();

        let stats = scan(temp.path(), &mut |line| {
            seen.push((
                line.commit.to_string(),
                line.path.to_string(),
                line.line,
                line.text.to_string(),
            ));
        })
        .unwrap();

        assert_eq!(stats.commits, 2);
        let found = seen.iter().find(|(_, _, _, text)| text == &secret);
        let (commit, path, line, _) = found.expect("removed secret remains in history");
        assert_eq!(commit.len(), 40);
        assert_eq!(path, "secret.txt");
        assert_eq!(*line, 1);
    }

    /// Собирает строки так же, как правила: по коммиту, с отметкой конца коммита.
    struct Collect;
    impl CommitVisitor for Collect {
        type Out = String;
        fn line(&mut self, line: &HistoryLine, out: &mut Vec<String>) {
            out.push(format!(
                "{} {}:{} {}",
                line.commit, line.path, line.line, line.text
            ));
        }
        fn end_commit(&mut self, out: &mut Vec<String>) {
            out.push("end".into());
        }
    }

    #[test]
    fn parallel_scan_matches_the_single_git_order() {
        if !git_available() {
            eprintln!("skipping git history test: git is not available");
            return;
        }
        let temp = TempDir::new();
        let repo = temp.path();
        git(repo, &["init", "-q", "-b", "main"]);
        git(repo, &["config", "user.email", "jetscan@example.test"]);
        git(repo, &["config", "user.name", "jetscan test"]);
        let commit = |file: &str, text: &str, date: u32| {
            fs::write(repo.join(file), text).expect("write fixture");
            git(repo, &["add", "-A"]);
            let date = format!("2020-01-01T00:00:{date:02}Z");
            git_at(repo, &date, &["commit", "-q", "-m", file]);
        };
        commit("a.txt", "one\ntwo\n", 1);
        commit("b.txt", "-----BEGIN KEY-----\nbody\n-----END KEY-----\n", 2);
        git_at(
            repo,
            "2020-01-01T00:00:03Z",
            &["commit", "-q", "--allow-empty", "-m", "empty"],
        );
        git(repo, &["checkout", "-q", "-b", "side"]);
        commit("side.txt", "side\n", 4);
        git(repo, &["checkout", "-q", "main"]);
        for i in 5..12 {
            commit("a.txt", &format!("line {i}\n"), i);
        }
        git_at(
            repo,
            "2020-01-01T00:00:12Z",
            &["merge", "-q", "--no-ff", "-m", "merge", "side"],
        );
        commit("c.txt", "after merge\n", 13);

        let mut serial = Vec::new();
        let mut current = String::new();
        let serial_stats = scan(repo, &mut |line| {
            current = line.commit.to_string();
            serial.push(format!(
                "{} {}:{} {}",
                line.commit, line.path, line.line, line.text
            ));
        })
        .unwrap();
        assert_eq!(serial_stats.commits, 13);

        let commits = commit_list(repo).unwrap();
        assert_eq!(commits.len(), 13);
        for jobs in [1, 2, 3, 5, 13, 40] {
            let (out, stats) = scan_commits(repo, &commits, jobs, || Collect).unwrap();
            assert_eq!(stats, serial_stats, "jobs={jobs}");
            assert_eq!(
                out.iter().filter(|s| *s == "end").count(),
                13,
                "jobs={jobs}"
            );
            let lines: Vec<_> = out.into_iter().filter(|s| s != "end").collect();
            assert_eq!(lines, serial, "jobs={jobs}");
        }
        let (_, stats) = scan_parallel(repo, || Collect).unwrap();
        assert_eq!(stats, serial_stats);
    }

    #[test]
    fn parallel_scan_of_empty_and_missing_repositories() {
        if !git_available() {
            eprintln!("skipping git history test: git is not available");
            return;
        }
        let temp = TempDir::new();
        assert_eq!(
            scan_parallel(temp.path(), || Collect).map(|_| ()),
            Err(HistoryError::NotARepo)
        );
        git(temp.path(), &["init", "-q"]);
        let (out, stats) = scan_parallel(temp.path(), || Collect).unwrap();
        assert!(out.is_empty());
        assert_eq!(stats, HistoryStats::default());
    }

    fn git_at(repo: &Path, date: &str, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .output()
            .expect("run git test command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("run git test command");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
