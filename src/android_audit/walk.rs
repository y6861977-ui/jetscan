//! Ограниченный обход Android-проекта (те же гарантии, что у `web_audit::enumerate`):
//! только внутри корня (симлинки и junction не разыменовываются, каждый каталог канонизируется
//! и сверяется с корнем), детерминированный порядок, бюджеты размера/числа файлов/глубины.
//!
//! Обход в два шага: сначала список путей (по имени решаем, что это и нужно ли открывать), потом
//! чтение по требованию через [`Reader`] с общим бюджетом байт. Хранилища ключей (`*.jks`,
//! `*.keystore`, …) не открываются никогда — только имя и размер.
//!
//! Пропускаются каталоги сборки, кэшей и сгенерированного кода: `build`, `.gradle`, `.idea`,
//! `.cxx`, `.externalNativeBuild`, `generated`, `.kotlin`, `.git`, `node_modules`, `out`, ….

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const SKIP_DIRS: &[&str] = &[
    ".git",
    ".gradle",
    ".idea",
    ".cxx",
    ".externalNativeBuild",
    ".kotlin",
    ".fleet",
    ".vscode",
    "build",
    "generated",
    "intermediates",
    "captures",
    "node_modules",
    "out",
    "target",
    ".venv",
    "__pycache__",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Budgets {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: usize,
    pub max_depth: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_files: 40_000,
            max_depth: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// `*.gradle`, `*.gradle.kts` (в т. ч. `settings.gradle(.kts)`).
    Gradle,
    /// `*.versions.toml` (каталог версий).
    VersionCatalog,
    /// `*.properties`.
    Properties,
    /// `AndroidManifest.xml`.
    Manifest,
    /// Прочий `*.xml` (ресурсы, конфиги).
    Xml,
    Kotlin,
    Java,
    /// `*.json` (в т. ч. `google-services.json`).
    Json,
    /// Прочий текст, который ищут матчеры ключей (`*.yml`, `*.cfg`, спецфайлы ядра).
    OtherText,
    /// `*.jks`, `*.keystore`, `*.bks`, `*.p12`, `*.pfx` — не открывается.
    Keystore,
    /// `.gitignore` — только чтобы понять, что файл с секретом не уходит в git.
    GitIgnore,
}

impl FileKind {
    pub fn label(self) -> &'static str {
        match self {
            FileKind::Gradle => "gradle",
            FileKind::VersionCatalog => "version_catalog",
            FileKind::Properties => "properties",
            FileKind::Manifest => "manifest",
            FileKind::Xml => "xml",
            FileKind::Kotlin => "kotlin",
            FileKind::Java => "java",
            FileKind::Json => "json",
            FileKind::OtherText => "text",
            FileKind::Keystore => "keystore",
            FileKind::GitIgnore => "gitignore",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// От корня, через `/`.
    pub relative_path: String,
    pub kind: FileKind,
    pub len: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub files_listed: usize,
    pub files_read: usize,
    pub bytes_read: u64,
    pub skipped_large: usize,
    pub skipped_binary: usize,
    pub skipped_unreadable: usize,
    pub symlinks_skipped: usize,
    pub outside_root_skipped: usize,
    pub dirs_skipped: usize,
    pub depth_limited: usize,
    /// Упёрлись в общий бюджет байт или файлов — дальше не читали.
    pub budget_exhausted: bool,
    /// Каталоги, которые не удалось прочитать (что в них — неизвестно).
    pub dirs_unreadable: usize,
    /// Конкретные файлы, которые нужны были, но не прочитаны (велики/нечитаемы): по виду файла
    /// понятно, каким правилам их не хватило.
    pub skipped_files: Vec<(String, FileKind)>,
}

impl WalkStats {
    /// Обход неполный — проверки по нему не могут быть `completed`.
    pub fn incomplete(&self) -> bool {
        self.budget_exhausted
            || self.skipped_large > 0
            || self.skipped_unreadable > 0
            || self.outside_root_skipped > 0
            || self.depth_limited > 0
    }

    /// Неполнота, про которую не известно, каких файлов она касается (бюджет, глубина, каталоги).
    pub fn incomplete_everywhere(&self) -> bool {
        self.budget_exhausted
            || self.outside_root_skipped > 0
            || self.depth_limited > 0
            || self.dirs_unreadable > 0
    }
}

const TEXT_EXTENSIONS: &[&str] = &["yml", "yaml", "cfg", "conf", "ini", "env", "pro"];

fn classify(name: &str, relative: &str) -> Option<FileKind> {
    let lower = name.to_ascii_lowercase();
    if lower == "androidmanifest.xml" {
        return Some(FileKind::Manifest);
    }
    if lower == ".gitignore" {
        return Some(FileKind::GitIgnore);
    }
    if lower.ends_with(".gradle") || lower.ends_with(".gradle.kts") {
        return Some(FileKind::Gradle);
    }
    if lower.ends_with(".versions.toml") {
        return Some(FileKind::VersionCatalog);
    }
    let ext = lower.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    match ext {
        "properties" => return Some(FileKind::Properties),
        "xml" => return Some(FileKind::Xml),
        "kt" => return Some(FileKind::Kotlin),
        "java" => return Some(FileKind::Java),
        "json" => return Some(FileKind::Json),
        "jks" | "keystore" | "bks" | "p12" | "pfx" => return Some(FileKind::Keystore),
        _ => {}
    }
    if TEXT_EXTENSIONS.contains(&ext) || crate::secrets::special::is_special(Path::new(relative)) {
        return Some(FileKind::OtherText);
    }
    None
}

/// Список файлов проекта. Ошибка — только если корень не каталог или его нельзя канонизировать.
pub fn list(root: &Path, budgets: &Budgets) -> Result<(PathBuf, Vec<Entry>, WalkStats), String> {
    let canonical =
        fs::canonicalize(root).map_err(|e| format!("cannot open {}: {e}", root.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    let mut walker = Walker {
        root: canonical.clone(),
        budgets,
        stats: WalkStats::default(),
        entries: Vec::new(),
    };
    walker.dir(&canonical, "", 0);
    walker.stats.files_listed = walker.entries.len();
    Ok((canonical, walker.entries, walker.stats))
}

struct Walker<'a> {
    root: PathBuf,
    budgets: &'a Budgets,
    stats: WalkStats,
    entries: Vec<Entry>,
}

impl Walker<'_> {
    fn dir(&mut self, path: &Path, relative: &str, depth: usize) {
        if self.stats.budget_exhausted {
            return;
        }
        if depth > self.budgets.max_depth {
            self.stats.depth_limited += 1;
            return;
        }
        match fs::canonicalize(path) {
            Ok(canonical) if canonical.starts_with(&self.root) => {}
            Ok(_) => {
                self.stats.outside_root_skipped += 1;
                return;
            }
            Err(_) => {
                self.stats.skipped_unreadable += 1;
                self.stats.dirs_unreadable += 1;
                return;
            }
        }
        let Ok(entries) = fs::read_dir(path) else {
            self.stats.skipped_unreadable += 1;
            self.stats.dirs_unreadable += 1;
            return;
        };
        let mut children: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => children.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )),
                Err(_) => {
                    self.stats.skipped_unreadable += 1;
                    self.stats.dirs_unreadable += 1;
                }
            }
        }
        children.sort();
        for (name, child) in children {
            if self.stats.budget_exhausted {
                return;
            }
            let child_relative = if relative.is_empty() {
                name.clone()
            } else {
                format!("{relative}/{name}")
            };
            let Ok(meta) = fs::symlink_metadata(&child) else {
                self.stats.skipped_unreadable += 1;
                self.stats.dirs_unreadable += 1;
                continue;
            };
            if meta.file_type().is_symlink() {
                self.stats.symlinks_skipped += 1;
            } else if meta.is_dir() {
                if SKIP_DIRS.iter().any(|d| name.eq_ignore_ascii_case(d)) {
                    self.stats.dirs_skipped += 1;
                } else {
                    self.dir(&child, &child_relative, depth + 1);
                }
            } else if meta.is_file() {
                let Some(kind) = classify(&name, &child_relative) else {
                    continue;
                };
                if self.entries.len() >= self.budgets.max_files {
                    self.stats.budget_exhausted = true;
                    return;
                }
                self.entries.push(Entry {
                    relative_path: child_relative,
                    kind,
                    len: meta.len(),
                });
            }
        }
    }
}

/// Чтение файлов из списка с общим бюджетом байт.
pub struct Reader<'a> {
    root: PathBuf,
    budgets: &'a Budgets,
    pub stats: WalkStats,
}

impl<'a> Reader<'a> {
    pub fn new(root: PathBuf, budgets: &'a Budgets, stats: WalkStats) -> Reader<'a> {
        Reader {
            root,
            budgets,
            stats,
        }
    }

    fn skip(&mut self, entry: &Entry, large: bool) {
        if large {
            self.stats.skipped_large += 1;
        } else {
            self.stats.skipped_unreadable += 1;
        }
        if self.stats.skipped_files.len() < 1000 {
            self.stats
                .skipped_files
                .push((entry.relative_path.clone(), entry.kind));
        }
    }

    /// Текст файла: BOM снят, невалидный UTF-8 — с потерями. `None` — не прочитан (причина
    /// учтена в статистике): велик, двоичный, нечитаем, бюджет исчерпан.
    pub fn read(&mut self, entry: &Entry) -> Option<String> {
        if entry.kind == FileKind::Keystore {
            return None;
        }
        if entry.len > self.budgets.max_file_bytes {
            self.skip(entry, true);
            return None;
        }
        if self.stats.bytes_read.saturating_add(entry.len) > self.budgets.max_total_bytes {
            self.stats.budget_exhausted = true;
            return None;
        }
        let path = entry
            .relative_path
            .split('/')
            .fold(self.root.clone(), |p, part| p.join(part));
        // Защита в глубину: файл не стал симлинком между обходом и чтением.
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            _ => {
                self.skip(entry, false);
                return None;
            }
        }
        let mut bytes = Vec::new();
        let read = File::open(&path).and_then(|file| {
            file.take(self.budgets.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        });
        if read.is_err() {
            self.skip(entry, false);
            return None;
        }
        if bytes.len() as u64 > self.budgets.max_file_bytes {
            self.skip(entry, true);
            return None;
        }
        if bytes.iter().take(8 * 1024).any(|&b| b == 0) {
            self.stats.skipped_binary += 1;
            return None;
        }
        self.stats.files_read += 1;
        self.stats.bytes_read += bytes.len() as u64;
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        Some(match text.strip_prefix('\u{feff}') {
            Some(rest) => rest.to_string(),
            None => text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::TempProject;

    #[test]
    fn classifies_and_skips_build_dirs() {
        let t = TempProject::new();
        for (path, text) in [
            ("settings.gradle.kts", ""),
            ("app/build.gradle", ""),
            ("app/src/main/AndroidManifest.xml", "<manifest/>"),
            ("app/src/main/res/values/strings.xml", "<resources/>"),
            ("app/src/main/java/A.java", ""),
            ("app/src/main/kotlin/B.kt", ""),
            ("app/google-services.json", "{}"),
            ("gradle/libs.versions.toml", ""),
            ("gradle.properties", ""),
            ("release.jks", "binary"),
            ("app/build/generated/C.java", ""),
            (".gradle/x.properties", ""),
            ("app/build/intermediates/AndroidManifest.xml", ""),
            ("README.md", ""),
            ("image.png", ""),
            ("fastlane/metadata.yml", ""),
        ] {
            t.write(path, text);
        }
        let (_, entries, stats) = list(t.path(), &Budgets::default()).unwrap();
        let got: Vec<(&str, FileKind)> = entries
            .iter()
            .map(|e| (e.relative_path.as_str(), e.kind))
            .collect();
        assert_eq!(
            got,
            vec![
                ("app/build.gradle", FileKind::Gradle),
                ("app/google-services.json", FileKind::Json),
                ("app/src/main/AndroidManifest.xml", FileKind::Manifest),
                ("app/src/main/java/A.java", FileKind::Java),
                ("app/src/main/kotlin/B.kt", FileKind::Kotlin),
                ("app/src/main/res/values/strings.xml", FileKind::Xml),
                ("fastlane/metadata.yml", FileKind::OtherText),
                ("gradle/libs.versions.toml", FileKind::VersionCatalog),
                ("gradle.properties", FileKind::Properties),
                ("release.jks", FileKind::Keystore),
                ("settings.gradle.kts", FileKind::Gradle),
            ]
        );
        assert_eq!(stats.dirs_skipped, 2);
        assert!(!stats.incomplete());
    }

    #[test]
    fn reader_budgets_binary_and_keystores() {
        let t = TempProject::new();
        t.write("a.kt", &"a".repeat(100));
        t.write_bytes("b.kt", b"x\0y");
        t.write("c.kt", &"c".repeat(2000));
        t.write("d.jks", "secret-bytes");
        let budgets = Budgets {
            max_file_bytes: 1024,
            ..Budgets::default()
        };
        let (root, entries, stats) = list(t.path(), &budgets).unwrap();
        let mut reader = Reader::new(root, &budgets, stats);
        let texts: Vec<Option<String>> = entries.iter().map(|e| reader.read(e)).collect();
        assert_eq!(texts[0].as_deref().map(str::len), Some(100));
        assert!(texts[1].is_none() && texts[2].is_none() && texts[3].is_none());
        assert_eq!(reader.stats.skipped_binary, 1);
        assert_eq!(reader.stats.skipped_large, 1);
        assert!(reader.stats.incomplete());
        let tiny = Budgets {
            max_total_bytes: 50,
            ..Budgets::default()
        };
        let mut reader = Reader::new(t.path().to_path_buf(), &tiny, WalkStats::default());
        assert!(reader.read(&entries[0]).is_none());
        assert!(reader.stats.budget_exhausted);
    }

    #[test]
    fn file_count_budget_and_missing_root() {
        let t = TempProject::new();
        for i in 0..5 {
            t.write(&format!("f{i}.kt"), "x");
        }
        let budgets = Budgets {
            max_files: 3,
            ..Budgets::default()
        };
        let (_, entries, stats) = list(t.path(), &budgets).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(stats.budget_exhausted);
        assert!(list(&t.path().join("nope"), &Budgets::default()).is_err());
    }
}
