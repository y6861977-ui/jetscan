//! Обход файлов проекта.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

/// Каталоги, в которые не заходим (сравнение по имени каталога, без учёта регистра).
pub const DEFAULT_SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    ".venv",
    "__pycache__",
];

#[derive(Clone, Debug)]
pub struct WalkOptions {
    /// Файлы больше — пропускаются (`skipped_large`).
    pub max_file_bytes: u64,
}

impl Default for WalkOptions {
    fn default() -> Self {
        WalkOptions {
            max_file_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub files_scanned: usize,
    pub skipped_binary: usize,
    pub skipped_large: usize,
    pub skipped_unreadable: usize,
    pub dirs_skipped: usize,
}

/// Обходит `root` (каталог или один файл) и вызывает `visit(путь, текст)` для каждого
/// текстового файла. Требования:
/// - симлинки не разыменовываются (ни файлы, ни каталоги);
/// - бинарник = NUL-байт в первых 8 КБ;
/// - невалидный UTF-8 декодируется с потерями (`from_utf8_lossy`), не пропускается;
/// - порядок детерминирован: записи каталога сортируются по имени;
/// - ошибки чтения не паникуют, а идут в `skipped_unreadable`.
pub fn walk(root: &Path, opts: &WalkOptions, visit: &mut dyn FnMut(&Path, &str)) -> WalkStats {
    let mut stats = WalkStats::default();
    walk_path(root, opts, visit, &mut stats);
    stats
}

fn walk_path(
    path: &Path,
    opts: &WalkOptions,
    visit: &mut dyn FnMut(&Path, &str),
    stats: &mut WalkStats,
) {
    // Корень пользователь указал сам — его разыменовываем (проект бывает подключён
    // симлинком/junction). Иначе скан молча ничего не находит = ложное «чисто».
    // Симлинки ВНУТРИ по-прежнему не разыменовываются (walk_dir).
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            stats.skipped_unreadable += 1;
            return;
        }
    };

    if metadata.is_dir() {
        let skipped = path
            .file_name()
            .map(|name| should_skip_dir(&name.to_string_lossy()))
            .unwrap_or(false);
        if skipped {
            stats.dirs_skipped += 1;
        } else {
            walk_dir(path, opts, visit, stats);
        }
    } else if metadata.is_file() {
        walk_file(path, metadata.len(), opts, visit, stats);
    }
}

fn walk_dir(
    path: &Path,
    opts: &WalkOptions,
    visit: &mut dyn FnMut(&Path, &str),
    stats: &mut WalkStats,
) {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => {
            stats.skipped_unreadable += 1;
            return;
        }
    };

    let mut children = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) => children.push(entry),
            Err(_) => stats.skipped_unreadable += 1,
        }
    }
    children.sort_by_key(|entry| entry.file_name());

    for entry in children {
        let path = entry.path();
        // Тип записи — из листинга каталога, без отдельного вызова на файл (T9.3, P3):
        // на Windows `symlink_metadata` открывает дескриптор на каждый файл (~19 мкс).
        // Как и `symlink_metadata`, `DirEntry::file_type` ссылки не разыменовывает:
        // симлинк и junction (reparse point «name surrogate») — `is_symlink()`.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                stats.skipped_unreadable += 1;
                continue;
            }
        };

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if should_skip_dir(&entry.file_name().to_string_lossy()) {
                stats.dirs_skipped += 1;
            } else {
                walk_dir(&path, opts, visit, stats);
            }
        } else if file_type.is_file() {
            let Some(len) = entry_len(&entry, &path, opts) else {
                stats.skipped_unreadable += 1;
                continue;
            };
            walk_file(&path, len, opts, visit, stats);
        }
    }
}

/// Размер файла. На Windows `DirEntry::metadata` берёт его из листинга каталога даром, но
/// там он может отставать у файла, в который сейчас пишут. Поэтому «слишком большой»
/// перепроверяем тем же `symlink_metadata`, что и раньше; слишком маленький безопасен —
/// `walk_file` читает не больше `max_file_bytes + 1` и проверяет длину прочитанного.
fn entry_len(entry: &fs::DirEntry, path: &Path, opts: &WalkOptions) -> Option<u64> {
    let len = entry.metadata().ok()?.len();
    if len <= opts.max_file_bytes {
        return Some(len);
    }
    fs::symlink_metadata(path)
        .ok()
        .map(|metadata| metadata.len())
}

fn should_skip_dir(name: &str) -> bool {
    DEFAULT_SKIP_DIRS
        .iter()
        .any(|skipped| name.eq_ignore_ascii_case(skipped))
}

fn walk_file(
    path: &Path,
    metadata_len: u64,
    opts: &WalkOptions,
    visit: &mut dyn FnMut(&Path, &str),
    stats: &mut WalkStats,
) {
    if metadata_len > opts.max_file_bytes {
        stats.skipped_large += 1;
        return;
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            stats.skipped_unreadable += 1;
            return;
        }
    };
    // Ёмкость по размеру из каталога: без перевыделений по ходу чтения.
    let mut bytes = Vec::with_capacity((metadata_len as usize).saturating_add(1));
    if file
        .take(opts.max_file_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        stats.skipped_unreadable += 1;
        return;
    }
    if (bytes.len() as u64) > opts.max_file_bytes {
        stats.skipped_large += 1;
        return;
    }
    if bytes.iter().take(8 * 1024).any(|&byte| byte == 0) {
        stats.skipped_binary += 1;
        return;
    }

    let text = String::from_utf8_lossy(&bytes);
    visit(path, &text);
    stats.files_scanned += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
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
                "jetscan-walk-{}-{nanos}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary directory");
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

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create test parent");
        }
        fs::write(path, bytes).expect("write test file");
    }

    fn relative_paths(root: &Path, opts: &WalkOptions) -> (Vec<PathBuf>, WalkStats) {
        let mut paths = Vec::new();
        let stats = walk(root, opts, &mut |path, _| {
            paths.push(path.strip_prefix(root).unwrap_or(path).to_path_buf());
        });
        (paths, stats)
    }

    #[test]
    fn skips_default_directories_case_insensitively() {
        let temp = TempDir::new();
        for name in DEFAULT_SKIP_DIRS {
            write(&temp.path().join(name).join("ignored.txt"), b"ignored");
        }
        write(
            &temp.path().join("TARGET").join("also-ignored.txt"),
            b"ignored",
        );
        write(&temp.path().join("src").join("kept.txt"), b"kept");

        let (paths, stats) = relative_paths(temp.path(), &WalkOptions::default());

        assert_eq!(paths, vec![PathBuf::from("src").join("kept.txt")]);
        assert_eq!(stats.files_scanned, 1);
        // `TARGET` is its own directory on a case-sensitive file system (Linux) and
        // the same one as `target` on Windows/macOS: count what was really created.
        let created = fs::read_dir(temp.path()).unwrap().count() - 1; // minus src
        assert_eq!(stats.dirs_skipped, created);
    }

    #[test]
    fn skips_binary_and_large_files() {
        let temp = TempDir::new();
        write(&temp.path().join("binary.dat"), b"text\0binary");
        write(&temp.path().join("large.txt"), b"12345678901234567");
        write(&temp.path().join("small.txt"), b"1234");
        let opts = WalkOptions { max_file_bytes: 16 };

        let (paths, stats) = relative_paths(temp.path(), &opts);

        assert_eq!(paths, vec![PathBuf::from("small.txt")]);
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.skipped_binary, 1);
        assert_eq!(stats.skipped_large, 1);
    }

    #[test]
    fn binary_check_is_limited_to_first_eight_kibibytes() {
        let temp = TempDir::new();
        let mut bytes = vec![b'a'; 8 * 1024];
        bytes.push(0);
        write(&temp.path().join("late-nul.txt"), &bytes);
        let mut contents = Vec::new();

        let stats = walk(temp.path(), &WalkOptions::default(), &mut |_, text| {
            contents.push(text.to_string());
        });

        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.skipped_binary, 0);
        assert_eq!(contents[0].as_bytes().last(), Some(&0));
    }

    #[test]
    fn visits_files_in_deterministic_sorted_order() {
        let temp = TempDir::new();
        write(&temp.path().join("z.txt"), b"z");
        write(&temp.path().join("a.txt"), b"a");
        write(&temp.path().join("m").join("b.txt"), b"b");
        write(&temp.path().join("m").join("a.txt"), b"a");

        let (first, stats) = relative_paths(temp.path(), &WalkOptions::default());
        let (second, _) = relative_paths(temp.path(), &WalkOptions::default());

        assert_eq!(first, second);
        assert_eq!(
            first,
            vec![
                PathBuf::from("a.txt"),
                PathBuf::from("m").join("a.txt"),
                PathBuf::from("m").join("b.txt"),
                PathBuf::from("z.txt"),
            ]
        );
        assert_eq!(stats.files_scanned, 4);
    }

    #[test]
    fn decodes_invalid_utf8_lossily() {
        let temp = TempDir::new();
        write(&temp.path().join("invalid.txt"), &[b'a', 0xff, b'b']);
        let mut text = String::new();

        let stats = walk(temp.path(), &WalkOptions::default(), &mut |_, contents| {
            text = contents.to_string();
        });

        assert_eq!(stats.files_scanned, 1);
        assert_eq!(text, "a\u{fffd}b");
    }

    #[test]
    fn missing_root_is_counted_as_unreadable() {
        let temp = TempDir::new();
        let missing = temp.path().join("missing");

        let stats = walk(&missing, &WalkOptions::default(), &mut |_, _| {
            panic!("missing path must not be visited")
        });

        assert_eq!(stats.skipped_unreadable, 1);
        assert_eq!(stats.files_scanned, 0);
    }

    #[test]
    fn skipped_directory_is_not_scanned_when_it_is_the_root() {
        let temp = TempDir::new();
        let root = temp.path().join("node_modules");
        write(&root.join("ignored.txt"), b"ignored");

        let stats = walk(&root, &WalkOptions::default(), &mut |_, _| {
            panic!("skipped root must not be visited")
        });

        assert_eq!(stats.dirs_skipped, 1);
        assert_eq!(stats.files_scanned, 0);
    }

    #[test]
    fn does_not_follow_directory_symlinks() {
        let temp = TempDir::new();
        write(&temp.path().join("kept.txt"), b"kept");
        let link = temp.path().join("loop");

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(temp.path(), &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(temp.path(), &link).is_ok();
        if !linked {
            eprintln!("skipping symlink assertion: OS denied symlink creation");
            return;
        }

        let (paths, stats) = relative_paths(temp.path(), &WalkOptions::default());

        assert_eq!(paths, vec![PathBuf::from("kept.txt")]);
        assert_eq!(stats.files_scanned, 1);
    }

    /// Windows junction (`mklink /J` needs no privileges, unlike symlinks).
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[test]
    fn does_not_follow_file_symlinks() {
        let temp = TempDir::new();
        write(&temp.path().join("real.txt"), b"real");
        let link = temp.path().join("link.txt");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(temp.path().join("real.txt"), &link).is_ok();
        #[cfg(windows)]
        let linked =
            std::os::windows::fs::symlink_file(temp.path().join("real.txt"), &link).is_ok();
        if !linked {
            eprintln!("skipping file symlink assertion: OS denied symlink creation");
            return;
        }
        let (paths, stats) = relative_paths(temp.path(), &WalkOptions::default());
        assert_eq!(paths, vec![PathBuf::from("real.txt")]);
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.skipped_unreadable, 0);
    }

    #[cfg(windows)]
    #[test]
    fn does_not_follow_junctions_but_scans_a_junction_root() {
        let temp = TempDir::new();
        write(&temp.path().join("real").join("a.txt"), b"a");
        // Junction inside the tree: to a sibling, and back to its own parent (a loop).
        let to_sibling = temp.path().join("j-sibling");
        let to_parent = temp.path().join("real").join("j-loop");
        assert!(
            junction(&to_sibling, &temp.path().join("real")),
            "mklink /J"
        );
        assert!(junction(&to_parent, temp.path()), "mklink /J");

        let (paths, stats) = relative_paths(temp.path(), &WalkOptions::default());
        assert_eq!(paths, vec![PathBuf::from("real").join("a.txt")]);
        assert_eq!(stats.files_scanned, 1);
        assert_eq!(stats.skipped_unreadable, 0);

        // A junction given as the root is followed, like a symlinked root.
        let stats = walk(&to_sibling, &WalkOptions::default(), &mut |_, _| {});
        assert_eq!(stats.files_scanned, 1);
    }

    #[test]
    fn entry_classification_matches_symlink_metadata() {
        // P3: the walk reads the entry type and size from the directory listing. They must
        // say exactly what `fs::symlink_metadata` (the previous per-entry call) says.
        let temp = TempDir::new();
        write(&temp.path().join("file.txt"), b"12345");
        write(&temp.path().join("dir").join("inner.txt"), b"x");
        write(&temp.path().join("empty.txt"), b"");
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(temp.path().join("dir"), temp.path().join("ld"));
            let _ =
                std::os::unix::fs::symlink(temp.path().join("file.txt"), temp.path().join("lf"));
            let _ = std::os::unix::fs::symlink(temp.path().join("gone"), temp.path().join("lx"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{symlink_dir, symlink_file};
            let _ = symlink_dir(temp.path().join("dir"), temp.path().join("ld"));
            let _ = symlink_file(temp.path().join("file.txt"), temp.path().join("lf"));
            let _ = symlink_file(temp.path().join("gone"), temp.path().join("lx"));
            assert!(junction(&temp.path().join("jd"), &temp.path().join("dir")));
        }
        let mut seen = 0;
        for entry in fs::read_dir(temp.path()).unwrap() {
            let entry = entry.unwrap();
            let from_listing = entry.file_type().unwrap();
            let from_call = fs::symlink_metadata(entry.path()).unwrap();
            let name = entry.file_name();
            assert_eq!(
                (
                    from_listing.is_symlink(),
                    from_listing.is_dir(),
                    from_listing.is_file()
                ),
                (
                    from_call.file_type().is_symlink(),
                    from_call.is_dir(),
                    from_call.is_file()
                ),
                "{name:?}"
            );
            if from_listing.is_file() {
                let opts = WalkOptions::default();
                assert_eq!(
                    entry_len(&entry, &entry.path(), &opts),
                    Some(from_call.len()),
                    "{name:?}"
                );
            }
            seen += 1;
        }
        assert!(seen >= 3);
    }

    #[test]
    fn large_file_size_is_confirmed_before_skipping() {
        let temp = TempDir::new();
        write(&temp.path().join("big.txt"), &[b'a'; 40]);
        let entry = fs::read_dir(temp.path()).unwrap().next().unwrap().unwrap();
        let opts = WalkOptions { max_file_bytes: 16 };
        assert_eq!(entry_len(&entry, &entry.path(), &opts), Some(40));
        let (_, stats) = relative_paths(temp.path(), &opts);
        assert_eq!(stats.skipped_large, 1);
    }
}

#[cfg(test)]
mod review_tests {
    //! Регрессия с ревью T1.1 (Claude): симлинк-корень не должен давать ложное «чисто».
    use super::*;

    #[test]
    fn symlinked_root_is_scanned() {
        let base = std::env::temp_dir().join(format!("jetscan-walk-root-{}", std::process::id()));
        let real = base.join("real");
        let link = base.join("link");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("a.txt"), b"a").unwrap();

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&real, &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&real, &link).is_ok();
        if linked {
            let stats = walk(&link, &WalkOptions::default(), &mut |_, _| {});
            assert_eq!(stats.files_scanned, 1);
        } else {
            eprintln!("skipping: OS denied symlink creation");
        }
        let _ = fs::remove_dir_all(&base);
    }
}
