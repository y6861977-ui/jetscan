//! Git-статус файлов с находками (T1.10): в git / не в git / в `.gitignore`.
//!
//! Два вызова на весь скан, пути — через stdin с NUL-разделителем (ни лимита
//! командной строки Windows, ни шелла, ни glob-магии в путях).
//! Те же защитные флаги, что в `history.rs`: репозиторий может быть чужим.

use super::Tracking;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Классифицирует `paths` (относительно `root`, через `/`).
/// `None` — не репозиторий или git недоступен: статус неизвестен, а не «чисто».
pub fn classify(root: &Path, paths: &[String]) -> Option<HashMap<String, Tracking>> {
    if paths.is_empty() {
        return Some(HashMap::new());
    }
    // Внутри ли рабочего дерева вообще.
    let inside = git(root, &["rev-parse", "--is-inside-work-tree"], None)?;
    if inside.0 != 0 || String::from_utf8_lossy(&inside.1).trim() != "true" {
        return None;
    }

    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_bytes());
        input.push(0);
    }

    // В индексе (tracked): весь список под root (ls-files печатает пути относительно
    // cwd = root) и пересечение. У ls-files нет --pathspec-from-file, а пути
    // аргументами упёрлись бы в лимит командной строки Windows.
    let (code, out) = git(root, &["ls-files", "-z", "--cached"], None)?;
    if code != 0 {
        return None;
    }
    let tracked: HashSet<String> = split_nul(&out).collect();

    // Игнорируемые. `--no-index`: смотреть только правила, даже если файл в индексе
    // (нам нужен ответ про .gitignore; tracked уже посчитан отдельно).
    // Код 1 = «ничего не игнорируется» — это не ошибка.
    let (code, out) = git(
        root,
        &["check-ignore", "-z", "--stdin", "--no-index"],
        Some(&input),
    )?;
    if code > 1 {
        return None;
    }
    let ignored: HashSet<String> = split_nul(&out).collect();

    Some(
        paths
            .iter()
            .map(|p| {
                let t = if tracked.contains(p) {
                    Tracking::Tracked
                } else if ignored.contains(p) {
                    Tracking::Ignored
                } else {
                    Tracking::Untracked
                };
                (p.clone(), t)
            })
            .collect(),
    )
}

fn split_nul(out: &[u8]) -> impl Iterator<Item = String> + '_ {
    out.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
}

/// Запуск git с защитой от конфигурации чужого репозитория. `None` — git не запустился.
fn git(root: &Path, args: &[&str], stdin: Option<&[u8]>) -> Option<(i32, Vec<u8>)> {
    let mut cmd = Command::new("git");
    cmd.arg("--no-pager")
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "core.quotePath=false"])
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        // Не GIT_LITERAL_PATHSPECS: check-ignore с ним падает («pathspec magic not supported»).
        // Pathspec'ов тут нет: ls-files без путей, check-ignore читает имена, а не маски
        // (тест с `app [1].js`).
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().ok()?;
    if let Some(data) = stdin {
        // Пишем в отдельном потоке: большой вывод git не должен заблокировать запись.
        let mut pipe = child.stdin.take()?;
        let data = data.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
        let out = child.wait_with_output().ok()?;
        let _ = writer.join();
        Some((out.status.code().unwrap_or(-1), out.stdout))
    } else {
        let out = child.wait_with_output().ok()?;
        Some((out.status.code().unwrap_or(-1), out.stdout))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("jetscan-gs-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn run(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
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
    fn classifies_tracked_untracked_and_ignored() {
        let d = tmp("cls");
        if !run(&d, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        fs::create_dir_all(d.join("deploy")).unwrap();
        fs::write(d.join(".gitignore"), ".env\nsecrets/\n").unwrap();
        fs::write(d.join("deploy/.env.example"), "x").unwrap();
        fs::write(d.join("app [1].js"), "x").unwrap(); // glob-символы в имени
        assert!(run(
            &d,
            &["add", ".gitignore", "deploy/.env.example", "app [1].js"]
        ));
        assert!(run(&d, &["commit", "-qm", "init"]));
        fs::write(d.join(".env"), "x").unwrap();
        fs::create_dir_all(d.join("secrets")).unwrap();
        fs::write(d.join("secrets/k.pem"), "x").unwrap();
        fs::write(d.join("new.txt"), "x").unwrap();
        // В индексе, но и под правилом .gitignore (добавлен через -f): это Tracked.
        fs::write(d.join("forced.env"), "x").unwrap();
        fs::write(d.join(".gitignore"), ".env\nsecrets/\nforced.env\n").unwrap();
        assert!(run(&d, &["add", "-f", "forced.env"]));

        let paths: Vec<String> = [
            "deploy/.env.example",
            "app [1].js",
            ".env",
            "secrets/k.pem",
            "new.txt",
            "forced.env",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let m = classify(&d, &paths).expect("is a repo");
        assert_eq!(m["deploy/.env.example"], Tracking::Tracked);
        assert_eq!(m["app [1].js"], Tracking::Tracked);
        assert_eq!(m[".env"], Tracking::Ignored);
        assert_eq!(m["secrets/k.pem"], Tracking::Ignored);
        assert_eq!(m["new.txt"], Tracking::Untracked);
        assert_eq!(m["forced.env"], Tracking::Tracked);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn not_a_repo_is_unknown_not_clean() {
        let d = tmp("norepo");
        // Временная папка может оказаться внутри чужого репо — тогда тест не о том.
        if Command::new("git")
            .arg("-C")
            .arg(&d)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("skipping: temp dir is inside a git repo");
            return;
        }
        assert_eq!(classify(&d, &["a.txt".to_string()]), None);
        let _ = fs::remove_dir_all(&d);
    }
}
