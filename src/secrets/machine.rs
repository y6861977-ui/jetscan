//! Скан всей машины (T1.12): известные места, где секреты лежат в открытом виде,
//! история терминала и все git-репозитории в домашней папке.
//! Всё локально; находки — те же `Finding` (маска + отпечаток).

use super::scan::{self, ScanOptions, ScanReport};
use super::walk::DEFAULT_SKIP_DIRS;
use std::fs;
use std::path::{Path, PathBuf};

/// Что это за место — от этого зависит текст совета в отчёте.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpotKind {
    /// Файл, где тулза хранит креды открытым текстом (`.git-credentials`, `.npmrc`...).
    CredentialStore,
    /// История команд терминала — сюда секреты попадают случайно.
    ShellHistory,
}

/// Одно известное место на диске.
#[derive(Clone, Debug)]
pub struct Spot {
    pub kind: SpotKind,
    /// Как показать в отчёте (`~/.npmrc`).
    pub display: String,
    pub report: ScanReport,
}

#[derive(Clone, Debug)]
pub struct MachineReport {
    pub home: PathBuf,
    pub spots: Vec<Spot>,
    /// Только репозитории; порядок — по пути.
    pub repos: Vec<ScanReport>,
    /// Каталоги, куда не смогли зайти при поиске репозиториев.
    pub unreadable_dirs: usize,
}

impl MachineReport {
    pub fn total(&self) -> usize {
        self.spots.iter().map(|s| s.report.total()).sum::<usize>()
            + self.repos.iter().map(ScanReport::total).sum::<usize>()
    }

    /// Без локальных секретов в `.gitignore` — это считает `--exit-code`.
    pub fn actionable(&self) -> usize {
        self.spots
            .iter()
            .map(|s| s.report.actionable())
            .sum::<usize>()
            + self.repos.iter().map(ScanReport::actionable).sum::<usize>()
    }
}

#[derive(Clone, Debug)]
pub struct MachineOptions {
    pub scan: ScanOptions,
    /// Насколько глубоко от домашней папки искать репозитории.
    pub max_depth: usize,
}

impl Default for MachineOptions {
    fn default() -> Self {
        MachineOptions {
            scan: ScanOptions::default(),
            max_depth: 6,
        }
    }
}

/// Файлы кредов и истории относительно домашней папки (через `/`).
const SPOTS: &[(&str, SpotKind)] = &[
    (".git-credentials", SpotKind::CredentialStore),
    (".npmrc", SpotKind::CredentialStore),
    (".pypirc", SpotKind::CredentialStore),
    (".docker/config.json", SpotKind::CredentialStore),
    (".aws/credentials", SpotKind::CredentialStore),
    (".config/gh/hosts.yml", SpotKind::CredentialStore),
    (
        "AppData/Roaming/GitHub CLI/hosts.yml",
        SpotKind::CredentialStore,
    ),
    (
        "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        SpotKind::ShellHistory,
    ),
    (".bash_history", SpotKind::ShellHistory),
    (".zsh_history", SpotKind::ShellHistory),
    (".python_history", SpotKind::ShellHistory),
    (".node_repl_history", SpotKind::ShellHistory),
];

/// Каталоги домашней папки, где своих репозиториев не бывает, а файлов — миллионы.
/// Сравнение без учёта регистра, по имени каталога на любой глубине.
const HOME_SKIP_DIRS: &[&str] = &[
    "AppData",
    "Library",
    ".cache",
    ".cargo",
    ".rustup",
    ".npm",
    ".nvm",
    ".pnpm-store",
    ".yarn",
    ".gradle",
    ".m2",
    ".nuget",
    ".vscode",
    ".vscode-server",
    ".local",
    "go",
    "scoop",
    "$Recycle.Bin",
];

/// Домашняя папка: `USERPROFILE` на Windows, `HOME` иначе.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn scan_machine(home: &Path, opts: &MachineOptions) -> Result<MachineReport, String> {
    if !home.is_dir() {
        return Err(format!("home folder '{}' not found", home.display()));
    }

    // Креды и история бывают больше лимита для исходников — им лимит повыше,
    // иначе большой ConsoleHost_history.txt молча пропустится.
    let mut spot_opts = opts.scan.clone();
    spot_opts.walk.max_file_bytes = spot_opts.walk.max_file_bytes.max(64 * 1024 * 1024);
    spot_opts.history = false;

    let mut spots = Vec::new();
    for (rel, kind) in SPOTS {
        let path = home.join(rel);
        if !path.is_file() {
            continue;
        }
        let report = scan::scan(&path, &spot_opts)?;
        spots.push(Spot {
            kind: *kind,
            display: format!("~/{rel}"),
            report,
        });
    }

    let (repo_paths, unreadable_dirs) = find_repos(home, opts.max_depth);
    let mut repos = Vec::new();
    for repo in repo_paths {
        // Один битый репозиторий не должен ронять скан всей машины.
        if let Ok(report) = scan::scan(&repo, &opts.scan) {
            repos.push(report);
        }
    }

    Ok(MachineReport {
        home: home.to_path_buf(),
        spots,
        repos,
        unreadable_dirs,
    })
}

/// Каталоги с `.git` внутри (каталог или файл — у worktree/submodule это файл).
/// В найденный репозиторий не спускаемся: его целиком сканирует `scan`.
/// Симлинки/junction не разыменовываем. Порядок детерминирован.
pub fn find_repos(root: &Path, max_depth: usize) -> (Vec<PathBuf>, usize) {
    let mut repos = Vec::new();
    let mut unreadable = 0;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        // Сам корень (домашняя папка как dotfiles-репо) — не репозиторий для скана:
        // иначе walk пойдёт по всему AppData.
        if depth > 0 && dir.join(".git").exists() {
            repos.push(dir);
            continue;
        }
        if depth >= max_depth {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            unreadable += 1;
            continue;
        };
        let mut children: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if !ft.is_dir() || ft.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if skip_dir(&name) {
                continue;
            }
            children.push(entry.path());
        }
        children.sort();
        // Стек — LIFO: кладём в обратном порядке, чтобы обходить по алфавиту.
        for child in children.into_iter().rev() {
            stack.push((child, depth + 1));
        }
    }
    repos.sort();
    (repos, unreadable)
}

fn skip_dir(name: &str) -> bool {
    HOME_SKIP_DIRS
        .iter()
        .chain(DEFAULT_SKIP_DIRS.iter())
        .any(|s| name.eq_ignore_ascii_case(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p =
                std::env::temp_dir().join(format!("jetscan-machine-{tag}-{}", std::process::id()));
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

    #[test]
    fn finds_repos_skips_noise_and_does_not_descend_into_repos() {
        let t = Tmp::new("repos");
        t.write("code/b/.git/HEAD", "ref: x");
        t.write("code/a/.git/HEAD", "ref: x");
        t.write("code/a/vendored/.git/HEAD", "ref: x"); // внутри репо — не отдельно
        t.write("code/wt/.git", "gitdir: ../a/.git/worktrees/wt"); // worktree: .git — файл
        t.write("AppData/Local/x/.git/HEAD", "ref: x");
        t.write("proj/node_modules/pkg/.git/HEAD", "ref: x");
        t.write("deep/1/2/3/4/5/6/7/.git/HEAD", "ref: x");
        let (repos, _) = find_repos(&t.0, 6);
        let rel: Vec<String> = repos
            .iter()
            .map(|p| {
                p.strip_prefix(&t.0)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(rel, vec!["code/a", "code/b", "code/wt"]);
    }

    #[test]
    fn scans_credential_stores_and_shell_history() {
        let t = Tmp::new("spots");
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        t.write(".git-credentials", &format!("https://me:{gh}@github.com\n"));
        t.write(
            "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
            &format!("cd x\n$env:GH_TOKEN=\"{gh}\"\n"),
        );
        t.write(".bash_history", "ls\ncd ..\n");
        let opts = MachineOptions {
            scan: ScanOptions {
                history: false,
                ..ScanOptions::default()
            },
            ..MachineOptions::default()
        };
        let r = scan_machine(&t.0, &opts).unwrap();
        let found: Vec<(&str, usize)> = r
            .spots
            .iter()
            .map(|s| (s.display.as_str(), s.report.total()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("~/.git-credentials", 1),
                (
                    "~/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                    1
                ),
                ("~/.bash_history", 0),
            ]
        );
        assert_eq!(r.total(), 2);
        assert!(r.spots[1].kind == SpotKind::ShellHistory);
    }

    #[test]
    fn large_shell_history_is_not_silently_skipped() {
        let t = Tmp::new("large");
        let gh = format!("{}{}", "ghp_", "Zq8".repeat(12));
        let mut body = "echo hello\n".repeat(200_000); // ~2.2 МБ > лимита 1 МБ
        body.push_str(&format!("export GH_TOKEN={gh}\n"));
        t.write(".bash_history", &body);
        let r = scan_machine(&t.0, &MachineOptions::default()).unwrap();
        assert_eq!(r.spots[0].report.total(), 1);
    }

    #[test]
    fn missing_home_is_an_error() {
        let t = Tmp::new("nohome");
        assert!(scan_machine(&t.0.join("nope"), &MachineOptions::default()).is_err());
    }
}
