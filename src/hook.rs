//! `jetscan hook install|uninstall` (T3.2): git pre-commit хук, который не даёт закоммитить
//! секрет. Секрет, пойманный до коммита, не надо ротировать — это дешевле всего.
//!
//! Правила:
//! - Чужой хук не трогаем никогда: уже есть `pre-commit` без нашей метки — ошибка с
//!   подсказкой, что дописать руками.
//! - Каталог хуков — от самого git (`rev-parse --git-path hooks`): учитывает
//!   `core.hooksPath` и worktree.
//! - Путь к jetscan экранируется для sh; если бинарник переедет — хук возьмёт `jetscan`
//!   из PATH, а не тихо пропустит проверку.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// По этой строке узнаём свой хук.
pub const MARKER: &str = "# jetscan pre-commit hook";

fn hooks_dir(repo: &Path) -> Result<PathBuf, String> {
    let out = Command::new("git")
        .args(["-c", "core.fsmonitor=false"])
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--git-path", "hooks"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "git not found in PATH".to_string())?;
    if !out.status.success() {
        return Err(format!("'{}' is not a git repository", repo.display()));
    }
    let rel = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if rel.is_empty() {
        return Err("git did not report a hooks directory".to_string());
    }
    let p = PathBuf::from(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    // `--git-path` отвечает относительно каталога, где запущен git (`-C repo`).
    Ok(if p.is_absolute() { p } else { repo.join(p) })
}

/// Строка в двойных кавычках для sh: экранируем `\ " $ \``.
fn sh_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        if matches!(c, '\\' | '"' | '$' | '`') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

pub fn script(exe: &Path) -> String {
    // Git for Windows запускает хуки через свой sh: прямые слэши работают везде.
    let exe = exe.to_string_lossy().replace('\\', "/");
    format!(
        "#!/bin/sh\n\
         {MARKER} — blocks commits that add secrets.\n\
         # Checks only staged changes, locally. Remove: jetscan hook uninstall\n\
         JETSCAN={}\n\
         [ -x \"$JETSCAN\" ] || JETSCAN=jetscan\n\
         exec \"$JETSCAN\" secrets --staged --exit-code\n",
        sh_quote(&exe)
    )
}

fn is_ours(path: &Path) -> bool {
    fs::read_to_string(path).is_ok_and(|t| t.contains(MARKER))
}

/// Ставит хук; возвращает путь к нему. Свой хук обновляет, чужой — не трогает.
pub fn install(repo: &Path, exe: &Path) -> Result<PathBuf, String> {
    let dir = hooks_dir(repo)?;
    let path = dir.join("pre-commit");
    if path.exists() && !is_ours(&path) {
        return Err(format!(
            "{} already exists and is not jetscan's — not touching it.\n  \
             Add this line to it yourself:  jetscan secrets --staged --exit-code || exit 1",
            path.display()
        ));
    }
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    fs::write(&path, script(exe)).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("cannot make {} executable: {e}", path.display()))?;
    }
    Ok(path)
}

/// Удаляет только свой хук. `Ok(None)` — хука не было.
pub fn uninstall(repo: &Path) -> Result<Option<PathBuf>, String> {
    let path = hooks_dir(repo)?.join("pre-commit");
    if !path.exists() {
        return Ok(None);
    }
    if !is_ours(&path) {
        return Err(format!(
            "{} is not jetscan's hook — not removing it",
            path.display()
        ));
    }
    fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_quotes_hostile_paths() {
        let s = script(Path::new("C:\\Users\\A \"B\"\\$x`y\\jetscan.exe"));
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains(MARKER));
        assert!(s.contains("JETSCAN=\"C:/Users/A \\\"B\\\"/\\$x\\`y/jetscan.exe\"\n"));
        assert!(s.contains("exec \"$JETSCAN\" secrets --staged --exit-code"));
    }

    fn git(dir: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    }

    #[test]
    fn installs_updates_and_never_touches_foreign_hooks() {
        let d = std::env::temp_dir().join(format!("jetscan-hook-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        if !git(&d, &["init", "-q"]) {
            eprintln!("skipping: git not available");
            return;
        }
        let exe = Path::new("/opt/jetscan");
        let p = install(&d, exe).unwrap();
        assert!(is_ours(&p));
        // Повторно — обновляет свой.
        assert_eq!(install(&d, exe).unwrap(), p);
        assert_eq!(uninstall(&d).unwrap(), Some(p.clone()));
        assert_eq!(uninstall(&d).unwrap(), None);
        // Чужой хук: ни установка, ни удаление его не трогают.
        fs::write(&p, "#!/bin/sh\nnpm test\n").unwrap();
        assert!(install(&d, exe).is_err());
        assert!(uninstall(&d).is_err());
        assert_eq!(fs::read_to_string(&p).unwrap(), "#!/bin/sh\nnpm test\n");
        let _ = fs::remove_dir_all(&d);
    }
}
