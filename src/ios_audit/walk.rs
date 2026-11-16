//! Ограниченный обход iOS-проекта. Гарантии и бюджеты — те же, что у `android_audit::walk`
//! (типы `Budgets` и `WalkStats` оттуда же): только внутри корня (симлинки и junction не
//! разыменовываются, каждый каталог канонизируется и сверяется с корнем), детерминированный
//! порядок, лимиты размера/числа файлов/глубины. Своё здесь — только классификация файлов iOS.
//!
//! Пропускаются сторонний и сгенерированный код: `Pods`, `Carthage/Build`, `Carthage/Checkouts`,
//! `DerivedData`, `build`, `.build`, `.swiftpm`, `SourcePackages`, `xcuserdata`, `vendor/bundle`,
//! бандлы `*.xcassets`, `*.framework`, `*.xcframework`, `*.app`, `*.dSYM`, `*.xcarchive`.
//!
//! Файлы подписи (`*.p12`, `*.p8`, `*.mobileprovision`, `*.cer`, …) не читаются целиком никогда:
//! только размер и первые байты заголовка ([`Reader::header`]), содержимое не выводится.

pub use crate::android_audit::walk::{Budgets, WalkStats};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "Pods",
    "DerivedData",
    "build",
    ".build",
    ".swiftpm",
    "SourcePackages",
    "xcuserdata",
    "node_modules",
    ".idea",
    ".vscode",
    ".gradle",
    ".bundle",
];

const SKIP_DIR_SUFFIXES: &[&str] = &[
    ".xcassets",
    ".framework",
    ".xcframework",
    ".app",
    ".dsym",
    ".xcarchive",
    ".appex",
];

/// Каталог не обходим: сторонний/сгенерированный код. `parent` — имя родителя.
fn skip_dir(name: &str, parent: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SKIP_DIRS.iter().any(|d| name.eq_ignore_ascii_case(d))
        || SKIP_DIR_SUFFIXES.iter().any(|s| lower.ends_with(s))
        || (parent.eq_ignore_ascii_case("carthage")
            && (name.eq_ignore_ascii_case("build") || name.eq_ignore_ascii_case("checkouts")))
        || (parent.eq_ignore_ascii_case("vendor") && name.eq_ignore_ascii_case("bundle"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// `*.xcodeproj/project.pbxproj`.
    Pbxproj,
    /// `*.plist` (Info.plist, GoogleService-Info.plist, …).
    Plist,
    /// `*.entitlements`.
    Entitlements,
    /// `*.xcconfig`.
    XcConfig,
    Swift,
    /// `*.m`, `*.mm`, `*.h`.
    ObjC,
    /// Прочий текст для матчеров ключей ядра (`*.json`, `*.yml`, `.env`, `Fastfile`, `*.rb`, …).
    OtherText,
    /// `*.p12`, `*.pfx`: PKCS#12 (сертификат + закрытый ключ).
    Pkcs12,
    /// `*.p8`: закрытый ключ (App Store Connect API, APNs).
    P8,
    /// `*.mobileprovision`, `*.provisionprofile`.
    Provision,
    /// `*.cer`, `*.der`, `*.crt`: обычно только сертификат (публичный).
    Cert,
    /// `*.keychain`, `*.keychain-db`.
    Keychain,
    /// `.gitignore`.
    GitIgnore,
}

impl FileKind {
    pub fn is_signing(self) -> bool {
        matches!(
            self,
            FileKind::Pkcs12
                | FileKind::P8
                | FileKind::Provision
                | FileKind::Cert
                | FileKind::Keychain
        )
    }

    pub fn is_code(self) -> bool {
        matches!(self, FileKind::Swift | FileKind::ObjC)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// От корня, через `/`.
    pub relative_path: String,
    pub kind: FileKind,
    pub len: u64,
}

impl Entry {
    pub fn name(&self) -> &str {
        self.relative_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.relative_path)
    }
}

const TEXT_EXTENSIONS: &[&str] = &[
    "json",
    "yml",
    "yaml",
    "rb",
    "sh",
    "cfg",
    "conf",
    "ini",
    "env",
    "properties",
    "toml",
    "pem",
    "key",
    "txt",
];

const TEXT_NAMES: &[&str] = &[
    "fastfile",
    "appfile",
    "matchfile",
    "gymfile",
    "snapfile",
    "deliverfile",
    "pluginfile",
    "podfile",
    "cartfile",
    "gemfile",
    "brewfile",
];

fn classify(name: &str, relative: &str) -> Option<FileKind> {
    let lower = name.to_ascii_lowercase();
    if lower == "project.pbxproj" {
        let parent = relative.rsplit('/').nth(1).unwrap_or("");
        return parent
            .to_ascii_lowercase()
            .ends_with(".xcodeproj")
            .then_some(FileKind::Pbxproj);
    }
    if lower == ".gitignore" {
        return Some(FileKind::GitIgnore);
    }
    let ext = lower.rsplit_once('.').map(|(_, ext)| ext).unwrap_or("");
    let kind = match ext {
        "plist" => FileKind::Plist,
        "entitlements" => FileKind::Entitlements,
        "xcconfig" => FileKind::XcConfig,
        "swift" => FileKind::Swift,
        "m" | "mm" | "h" => FileKind::ObjC,
        "p12" | "pfx" => FileKind::Pkcs12,
        "p8" => FileKind::P8,
        "mobileprovision" | "provisionprofile" => FileKind::Provision,
        "cer" | "der" | "crt" => FileKind::Cert,
        "keychain" | "keychain-db" => FileKind::Keychain,
        // `.txt` — только как заметки рядом с ключами (`secrets.txt`), не любой текст.
        "txt" if !lower.contains("secret") && !lower.contains("key") => return None,
        e if TEXT_EXTENSIONS.contains(&e) => FileKind::OtherText,
        _ if TEXT_NAMES.contains(&lower.as_str()) => FileKind::OtherText,
        _ if crate::secrets::special::is_special(Path::new(relative)) => FileKind::OtherText,
        _ => return None,
    };
    Some(kind)
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
    walker.dir(&canonical, "", "", 0);
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
    fn dir(&mut self, path: &Path, relative: &str, own_name: &str, depth: usize) {
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
                if skip_dir(&name, own_name) {
                    self.stats.dirs_skipped += 1;
                } else {
                    self.dir(&child, &child_relative, &name, depth + 1);
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

/// Сколько байт заголовка файла подписи читаем (тип ключа/шифрования, не содержимое).
pub const HEADER_BYTES: usize = 64;

/// Что вернуло чтение файла.
#[derive(Debug, PartialEq, Eq)]
pub enum Content {
    Text(String),
    /// Двоичный plist (`bplist00`) — не разбирается.
    BinaryPlist,
    /// Не прочитан (причина учтена в статистике).
    Skipped,
}

/// Чтение файлов из списка с общим бюджетом байт.
pub struct Reader<'a> {
    root: PathBuf,
    budgets: &'a Budgets,
    pub stats: WalkStats,
    /// Пропущенные файлы с их видом (каким правилам их не хватило).
    pub skipped: Vec<(String, FileKind)>,
}

impl<'a> Reader<'a> {
    pub fn new(root: PathBuf, budgets: &'a Budgets, stats: WalkStats) -> Reader<'a> {
        Reader {
            root,
            budgets,
            stats,
            skipped: Vec::new(),
        }
    }

    fn path_of(&self, entry: &Entry) -> PathBuf {
        entry
            .relative_path
            .split('/')
            .fold(self.root.clone(), |p, part| p.join(part))
    }

    fn skip(&mut self, entry: &Entry, large: bool) {
        if large {
            self.stats.skipped_large += 1;
        } else {
            self.stats.skipped_unreadable += 1;
        }
        if self.skipped.len() < 1000 {
            self.skipped.push((entry.relative_path.clone(), entry.kind));
        }
    }

    /// Предел размера для файла: `project.pbxproj` больших приложений бывает в несколько МиБ,
    /// поэтому для него — не меньше 16 МиБ (остальным — `--max-size`).
    pub fn limit_for(&self, entry: &Entry) -> u64 {
        if entry.kind == FileKind::Pbxproj {
            self.budgets.max_file_bytes.max(16 * 1024 * 1024)
        } else {
            self.budgets.max_file_bytes
        }
    }

    /// Текст файла: BOM снят, невалидный UTF-8 — с потерями. Файлы подписи не читаются.
    pub fn read(&mut self, entry: &Entry) -> Content {
        if entry.kind.is_signing() {
            return Content::Skipped;
        }
        let limit = self.limit_for(entry);
        if entry.len > limit {
            self.skip(entry, true);
            return Content::Skipped;
        }
        if self.stats.bytes_read.saturating_add(entry.len) > self.budgets.max_total_bytes {
            self.stats.budget_exhausted = true;
            return Content::Skipped;
        }
        let path = self.path_of(entry);
        // Защита в глубину: файл не стал симлинком между обходом и чтением.
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            _ => {
                self.skip(entry, false);
                return Content::Skipped;
            }
        }
        let mut bytes = Vec::new();
        let read = File::open(&path)
            .and_then(|file| file.take(limit.saturating_add(1)).read_to_end(&mut bytes));
        if read.is_err() {
            self.skip(entry, false);
            return Content::Skipped;
        }
        if bytes.len() as u64 > limit {
            self.skip(entry, true);
            return Content::Skipped;
        }
        if matches!(entry.kind, FileKind::Plist | FileKind::Entitlements)
            && bytes.starts_with(b"bplist")
        {
            self.stats.files_read += 1;
            self.stats.bytes_read += bytes.len() as u64;
            return Content::BinaryPlist;
        }
        if bytes.iter().take(8 * 1024).any(|&b| b == 0) {
            self.stats.skipped_binary += 1;
            return Content::Skipped;
        }
        self.stats.files_read += 1;
        self.stats.bytes_read += bytes.len() as u64;
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        Content::Text(match text.strip_prefix('\u{feff}') {
            Some(rest) => rest.to_string(),
            None => text,
        })
    }

    /// Первые [`HEADER_BYTES`] байт файла подписи (тип, а не содержимое). `None` — не прочитан.
    pub fn header(&mut self, entry: &Entry) -> Option<Vec<u8>> {
        let path = self.path_of(entry);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() => {}
            _ => return None,
        }
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|file| file.take(HEADER_BYTES as u64).read_to_end(&mut bytes))
            .ok()?;
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::TempProject;

    #[test]
    fn classifies_and_skips_third_party_dirs() {
        let t = TempProject::new();
        for (path, text) in [
            ("App.xcodeproj/project.pbxproj", "{}"),
            ("App.xcodeproj/xcuserdata/u.xcuserdatad/x.plist", ""),
            ("App/Info.plist", "<plist/>"),
            ("App/App.entitlements", "<plist/>"),
            ("App/AppDelegate.swift", ""),
            ("App/Legacy.m", ""),
            ("App/Legacy.h", ""),
            ("Config/Release.xcconfig", ""),
            ("Pods/Alamofire/Source/A.swift", ""),
            ("Carthage/Build/x.json", ""),
            ("Carthage/Checkouts/Lib/A.swift", ""),
            ("App/Assets.xcassets/Contents.json", "{}"),
            ("fastlane/Fastfile", ""),
            ("certs/dist.p12", "x"),
            ("certs/AuthKey_ABC.p8", "x"),
            ("certs/App.mobileprovision", "x"),
            ("App/pin.cer", "x"),
            ("README.md", ""),
            ("notes.txt", ""),
            ("project.pbxproj", "{}"),
            (".build/checkouts/A.swift", ""),
            ("Package.swift", ""),
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
                ("App/App.entitlements", FileKind::Entitlements),
                ("App/AppDelegate.swift", FileKind::Swift),
                ("App/Info.plist", FileKind::Plist),
                ("App/Legacy.h", FileKind::ObjC),
                ("App/Legacy.m", FileKind::ObjC),
                ("App/pin.cer", FileKind::Cert),
                ("App.xcodeproj/project.pbxproj", FileKind::Pbxproj),
                ("Config/Release.xcconfig", FileKind::XcConfig),
                ("Package.swift", FileKind::Swift),
                ("certs/App.mobileprovision", FileKind::Provision),
                ("certs/AuthKey_ABC.p8", FileKind::P8),
                ("certs/dist.p12", FileKind::Pkcs12),
                ("fastlane/Fastfile", FileKind::OtherText),
            ]
        );
        // Pods, Carthage/Build, Carthage/Checkouts, xcuserdata, .xcassets, .build.
        assert_eq!(stats.dirs_skipped, 6);
        assert!(!stats.incomplete());
    }

    #[test]
    fn reader_budgets_binary_plists_and_signing_files() {
        let t = TempProject::new();
        t.write("a.swift", &"a".repeat(100));
        t.write_bytes("b.swift", b"x\0y");
        t.write("c.swift", &"c".repeat(2000));
        t.write_bytes("d.plist", b"bplist00\0\x01\x02");
        t.write("e.p12", "secret-bytes");
        let budgets = Budgets {
            max_file_bytes: 1024,
            ..Budgets::default()
        };
        let (root, entries, stats) = list(t.path(), &budgets).unwrap();
        let mut reader = Reader::new(root, &budgets, stats);
        let got: Vec<Content> = entries.iter().map(|e| reader.read(e)).collect();
        assert!(matches!(&got[0], Content::Text(s) if s.len() == 100));
        assert_eq!(got[1], Content::Skipped);
        assert_eq!(got[2], Content::Skipped);
        assert_eq!(got[3], Content::BinaryPlist);
        assert_eq!(got[4], Content::Skipped);
        assert_eq!(reader.stats.skipped_binary, 1);
        assert_eq!(reader.stats.skipped_large, 1);
        assert_eq!(
            reader.skipped,
            vec![("c.swift".to_string(), FileKind::Swift)]
        );
        assert_eq!(reader.header(&entries[4]).unwrap(), b"secret-bytes");
        let tiny = Budgets {
            max_total_bytes: 50,
            ..Budgets::default()
        };
        let mut reader = Reader::new(t.path().to_path_buf(), &tiny, WalkStats::default());
        assert_eq!(reader.read(&entries[0]), Content::Skipped);
        assert!(reader.stats.budget_exhausted);
    }

    #[test]
    fn pbxproj_gets_a_larger_size_limit() {
        let budgets = Budgets {
            max_file_bytes: 1024,
            ..Budgets::default()
        };
        let reader = Reader::new(PathBuf::from("."), &budgets, WalkStats::default());
        let e = |kind| Entry {
            relative_path: "x".into(),
            kind,
            len: 0,
        };
        assert_eq!(reader.limit_for(&e(FileKind::Pbxproj)), 16 * 1024 * 1024);
        assert_eq!(reader.limit_for(&e(FileKind::Swift)), 1024);
    }
}
