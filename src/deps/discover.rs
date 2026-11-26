//! Поиск lockfile'ов в проекте. Только имена файлов, без чтения содержимого.
//! Пропускаем те же шумные каталоги, что и поиск секретов (`node_modules`, `target`,
//! `vendor`, `.venv`...): lockfile'ы внутри них — чужие, не то, что установлено у нас.
//! Симлинки не разыменовываем. Порядок детерминирован.

use super::lockfiles::{self, Kind};
use crate::secrets::walk::DEFAULT_SKIP_DIRS;
use std::fs;
use std::path::{Path, PathBuf};

pub struct Found {
    pub path: PathBuf,
    /// Относительно корня скана, через `/`. Для одного файла — его имя.
    pub rel: String,
    pub kind: &'static Kind,
}

/// Глубина поиска: монорепо глубже не бывают, а бесконечный обход дорог.
const MAX_DEPTH: usize = 12;

pub fn find_lockfiles(root: &Path) -> Result<Vec<Found>, String> {
    let meta = fs::metadata(root).map_err(|e| format!("cannot read '{}': {e}", root.display()))?;
    if meta.is_file() {
        let name = root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let kind = lockfiles::kind_for(&name)
            .ok_or_else(|| format!("'{}' is not a lockfile jetscan knows", root.display()))?;
        return Ok(vec![Found {
            path: root.to_path_buf(),
            rel: name,
            kind,
        }]);
    }

    let mut out = Vec::new();
    let mut manifests: Vec<Found> = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let mut subdirs = Vec::new();
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                if depth < MAX_DEPTH
                    && !DEFAULT_SKIP_DIRS
                        .iter()
                        .any(|s| name.eq_ignore_ascii_case(s))
                {
                    subdirs.push(entry.path());
                }
            } else if ft.is_file()
                && let Some(kind) = lockfiles::kind_for(&name)
            {
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(Found { path, rel, kind });
            } else if ft.is_file() && name == "package.json" {
                let path = entry.path();
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                manifests.push(Found {
                    path,
                    rel,
                    kind: &lockfiles::PACKAGE_JSON,
                });
            }
        }
        for d in subdirs {
            stack.push((d, depth + 1));
        }
    }
    // A package.json counts only where no npm lockfile covers it (same folder or above: a
    // workspace root lockfile covers every package below it).
    let npm_dirs: Vec<String> = out
        .iter()
        .filter(|f| f.kind.ecosystem == lockfiles::PACKAGE_JSON.ecosystem)
        .map(|f| parent_dir(&f.rel))
        .collect();
    for m in manifests {
        let dir = parent_dir(&m.rel);
        let covered = npm_dirs
            .iter()
            .any(|d| d.is_empty() || dir == *d || dir.starts_with(&format!("{d}/")));
        if !covered {
            out.push(m);
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

fn parent_dir(rel: &str) -> String {
    rel.rsplit_once('/')
        .map_or(String::new(), |(d, _)| d.to_string())
}

#[cfg(test)]
mod tests {

    #[test]
    fn package_json_counts_only_where_no_npm_lockfile_covers_it() {
        let d = std::env::temp_dir().join(format!("jetscan-pkgjson-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for dir in ["", "app", "mono/packages/a", "py"] {
            fs::create_dir_all(d.join(dir)).unwrap();
        }
        fs::write(d.join("app/package.json"), "{}").unwrap();
        fs::write(d.join("mono/package-lock.json"), "{}").unwrap();
        fs::write(d.join("mono/package.json"), "{}").unwrap();
        fs::write(d.join("mono/packages/a/package.json"), "{}").unwrap();
        fs::write(d.join("py/requirements.txt"), "").unwrap();
        fs::write(d.join("py/package.json"), "{}").unwrap();
        let found: Vec<(String, &str)> = find_lockfiles(&d)
            .unwrap()
            .into_iter()
            .map(|f| (f.rel, f.kind.label))
            .collect();
        let _ = fs::remove_dir_all(&d);
        assert_eq!(
            found,
            vec![
                ("app/package.json".to_string(), "package.json"),
                ("mono/package-lock.json".to_string(), "package-lock.json"),
                ("py/package.json".to_string(), "package.json"),
                ("py/requirements.txt".to_string(), "requirements.txt"),
            ]
        );
    }

    use super::*;

    #[test]
    fn finds_lockfiles_and_skips_noise() {
        let d = std::env::temp_dir().join(format!("jetscan-discover-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for rel in [
            "package-lock.json",
            "web/yarn.lock",
            "api/requirements-dev.txt",
            "node_modules/x/package-lock.json",
            "target/Cargo.lock",
            "README.md",
        ] {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, "x").unwrap();
        }
        let found: Vec<(String, &str)> = find_lockfiles(&d)
            .unwrap()
            .into_iter()
            .map(|f| (f.rel, f.kind.label))
            .collect();
        assert_eq!(
            found,
            vec![
                ("api/requirements-dev.txt".to_string(), "requirements.txt"),
                ("package-lock.json".to_string(), "package-lock.json"),
                ("web/yarn.lock".to_string(), "yarn.lock"),
            ]
        );
        // Один файл — тоже можно; не lockfile — ошибка, а не «чисто».
        assert_eq!(
            find_lockfiles(&d.join("package-lock.json")).unwrap().len(),
            1
        );
        assert!(find_lockfiles(&d.join("README.md")).is_err());
        assert!(find_lockfiles(&d.join("nope")).is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
