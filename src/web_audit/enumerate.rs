//! CL-WEB-02: ограниченный обход исходников веб-проекта.
//!
//! Гарантии:
//! - читаем только внутри корня: симлинки (и junction на Windows) не разыменовываются, а каждый
//!   каталог дополнительно канонизируется и сверяется с канонизированным корнем;
//! - бюджеты: размер файла, суммарный объём, число файлов, глубина. Исчерпали — останавливаемся
//!   и честно помечаем результат неполным (`budget_exhausted`), а не «чисто»;
//! - файл читается только после фильтра по имени (картинки и прочее не открываем);
//! - порядок детерминирован (сортировка по имени);
//! - бинарник (NUL в первых 8 КБ) пропускается, невалидный UTF-8 декодируется с потерями.
//!
//! `.gitignore` не применяем: переменные из `.env.local` вшиваются в бандл при сборке независимо
//! от git, а сгенерированные каталоги (`.next`, `dist`, ...) пропускаются по имени.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Каталоги сборки, зависимостей и кэшей. Сравнение по имени без учёта регистра.
pub const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".netlify",
    ".turbo",
    ".cache",
    ".parcel-cache",
    ".output",
    ".yarn",
    ".pnpm-store",
    "out",
    "dist",
    "build",
    "coverage",
    "storybook-static",
    "target",
    "vendor",
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
            max_total_bytes: 64 * 1024 * 1024,
            max_files: 20_000,
            max_depth: 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind {
    /// JS/TS/JSX/TSX (`.js .jsx .ts .tsx .mjs .cjs .mts .cts`), кроме `.d.ts`.
    Script,
    /// `.html`/`.htm` — отдаётся браузеру как есть (Vite `index.html`, `public/*.html`).
    Html,
    /// `.env`, `.env.local`, `.env.production`, ... (не `.example`/`.sample`/`.template`).
    Env,
    /// SQL-схема базы для WEB-RLS-009 (`supabase/**/*.sql`, `prisma/migrations/**/migration.sql`,
    /// `drizzle/**/*.sql`). Прочие `.sql` не читаем.
    Sql,
    /// `supabase/config.toml` — открытые через Data API схемы.
    SupabaseConfig,
    /// `*.rules` — правила Firestore / Cloud Storage (WEB-FIREBASE-010; не-Firebase отсеивается по тексту).
    FirebaseRules,
    /// `*.rules.json` — правила Realtime Database.
    FirebaseDatabaseRules,
    /// `firebase.json` — какие файлы правил подключены.
    FirebaseConfig,
}

#[derive(Clone, Debug)]
pub struct SourceFile {
    /// От корня, через `/`.
    pub relative_path: String,
    pub kind: FileKind,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnumStats {
    pub files_read: usize,
    pub bytes_read: u64,
    pub skipped_large: usize,
    pub skipped_binary: usize,
    pub skipped_unreadable: usize,
    /// Vue/Svelte/Astro SFC: синтаксис не поддержан — не «проверено», а «не проверялось».
    pub skipped_unsupported: usize,
    pub symlinks_skipped: usize,
    /// Каталог, канонический путь которого вне корня (junction/bind mount и т. п.).
    pub outside_root_skipped: usize,
    pub dirs_skipped: usize,
    pub depth_limited: usize,
    /// Упёрлись в общий бюджет байт или файлов — дальше не читали.
    pub budget_exhausted: bool,
}

impl EnumStats {
    /// Обход неполный — проверки по нему не могут быть `completed`.
    pub fn incomplete(&self) -> bool {
        self.budget_exhausted
            || self.skipped_large > 0
            || self.skipped_unreadable > 0
            || self.outside_root_skipped > 0
            || self.depth_limited > 0
    }
}

/// Какого вида файл — по имени и пути от корня. `None` — не наш (не открываем).
/// `Err(())` — наш, но не поддержан.
fn classify(name: &str, relative: &str) -> Option<Result<FileKind, ()>> {
    let lower = name.to_ascii_lowercase();
    if crate::web_audit::rules::rls::sql_group(relative).is_some() {
        return Some(Ok(FileKind::Sql));
    }
    if crate::web_audit::rules::rls::is_supabase_config(relative) {
        return Some(Ok(FileKind::SupabaseConfig));
    }
    if lower == "firebase.json" {
        return Some(Ok(FileKind::FirebaseConfig));
    }
    if lower.ends_with(".rules.json") {
        return Some(Ok(FileKind::FirebaseDatabaseRules));
    }
    if lower.ends_with(".rules") {
        return Some(Ok(FileKind::FirebaseRules));
    }
    if lower == ".env" {
        return Some(Ok(FileKind::Env));
    }
    if let Some(suffix) = lower.strip_prefix(".env.") {
        let template = ["example", "sample", "template", "dist", "defaults"]
            .iter()
            .any(|t| suffix == *t || suffix.ends_with(&format!(".{t}")));
        return (!template).then_some(Ok(FileKind::Env));
    }
    let ext = lower.rsplit_once('.').map(|(_, ext)| ext)?;
    match ext {
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" => {
            let declaration = [".d.ts", ".d.mts", ".d.cts"]
                .iter()
                .any(|d| lower.ends_with(d));
            (!declaration).then_some(Ok(FileKind::Script))
        }
        "html" | "htm" => Some(Ok(FileKind::Html)),
        "vue" | "svelte" | "astro" => Some(Err(())),
        _ => None,
    }
}

/// Обходит `root` (каталог) и отдаёт каждый подходящий файл в `visit`.
/// Ошибка — только если корень не каталог или его нельзя канонизировать.
pub fn enumerate(
    root: &Path,
    budgets: &Budgets,
    visit: &mut dyn FnMut(SourceFile),
) -> Result<EnumStats, String> {
    let canonical_root =
        fs::canonicalize(root).map_err(|e| format!("cannot open {}: {e}", root.display()))?;
    if !canonical_root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }
    let mut walker = Walker {
        root: canonical_root.clone(),
        budgets,
        stats: EnumStats::default(),
        visit,
    };
    walker.dir(&canonical_root, "", 0);
    Ok(walker.stats)
}

struct Walker<'a> {
    root: PathBuf,
    budgets: &'a Budgets,
    stats: EnumStats,
    visit: &'a mut dyn FnMut(SourceFile),
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
        // Защита в глубину: даже если ОС сообщила «не симлинк», каталог обязан лежать в корне.
        match fs::canonicalize(path) {
            Ok(canonical) if canonical.starts_with(&self.root) => {}
            Ok(_) => {
                self.stats.outside_root_skipped += 1;
                return;
            }
            Err(_) => {
                self.stats.skipped_unreadable += 1;
                return;
            }
        }
        let Ok(entries) = fs::read_dir(path) else {
            self.stats.skipped_unreadable += 1;
            return;
        };
        let mut children: Vec<(String, PathBuf)> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => children.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    entry.path(),
                )),
                Err(_) => self.stats.skipped_unreadable += 1,
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
                self.file(&child, &name, child_relative, meta.len());
            }
        }
    }

    fn file(&mut self, path: &Path, name: &str, relative: String, len: u64) {
        let kind = match classify(name, &relative) {
            None => return,
            Some(Err(())) => {
                self.stats.skipped_unsupported += 1;
                return;
            }
            Some(Ok(kind)) => kind,
        };
        if len > self.budgets.max_file_bytes {
            self.stats.skipped_large += 1;
            return;
        }
        if self.stats.files_read >= self.budgets.max_files
            || self.stats.bytes_read.saturating_add(len) > self.budgets.max_total_bytes
        {
            self.stats.budget_exhausted = true;
            return;
        }
        let mut bytes = Vec::new();
        let read = File::open(path).and_then(|file| {
            file.take(self.budgets.max_file_bytes.saturating_add(1))
                .read_to_end(&mut bytes)
        });
        if read.is_err() {
            self.stats.skipped_unreadable += 1;
            return;
        }
        // Файл мог вырасти между stat и чтением.
        if bytes.len() as u64 > self.budgets.max_file_bytes {
            self.stats.skipped_large += 1;
            return;
        }
        if bytes.iter().take(8 * 1024).any(|&b| b == 0) {
            self.stats.skipped_binary += 1;
            return;
        }
        self.stats.files_read += 1;
        self.stats.bytes_read += bytes.len() as u64;
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        let text = match text.strip_prefix('\u{feff}') {
            Some(rest) => rest.to_string(),
            None => text,
        };
        (self.visit)(SourceFile {
            relative_path: relative,
            kind,
            text,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::TempProject;

    fn collect(root: &Path, budgets: &Budgets) -> (Vec<(String, FileKind)>, EnumStats) {
        let mut files = Vec::new();
        let stats = enumerate(root, budgets, &mut |f| {
            files.push((f.relative_path, f.kind))
        })
        .expect("enumerate");
        (files, stats)
    }

    fn paths(files: &[(String, FileKind)]) -> Vec<&str> {
        files.iter().map(|(p, _)| p.as_str()).collect()
    }

    #[test]
    fn picks_sources_env_and_html_in_sorted_order() {
        let t = TempProject::new();
        t.write("src/b.tsx", "b");
        t.write("src/a.ts", "a");
        t.write("src/types.d.ts", "declare const x: number;");
        t.write("index.html", "<div></div>");
        t.write(".env.local", "A=1");
        t.write(".env.example", "A=");
        t.write(".env.production.sample", "A=");
        t.write("logo.png", "png");
        t.write("README.md", "md");
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert_eq!(
            paths(&files),
            vec![".env.local", "index.html", "src/a.ts", "src/b.tsx"]
        );
        assert_eq!(files[0].1, FileKind::Env);
        assert_eq!(files[1].1, FileKind::Html);
        assert!(!stats.incomplete());
    }

    #[test]
    fn sql_schema_and_supabase_config_only_in_known_places() {
        let t = TempProject::new();
        t.write("supabase/migrations/1_init.sql", "create table a (id int);");
        t.write("supabase/config.toml", "[api]");
        t.write("supabase/tests/a.test.sql", "select 1;");
        t.write("db/dump.sql", "select 1;");
        t.write("config.toml", "x");
        t.write("firebase.json", "{}");
        t.write("firestore.rules", "service cloud.firestore {}");
        t.write("database.rules.json", "{}");
        let (files, _) = collect(t.path(), &Budgets::default());
        assert_eq!(
            files,
            vec![
                (
                    "database.rules.json".to_string(),
                    FileKind::FirebaseDatabaseRules
                ),
                ("firebase.json".to_string(), FileKind::FirebaseConfig),
                ("firestore.rules".to_string(), FileKind::FirebaseRules),
                ("supabase/config.toml".to_string(), FileKind::SupabaseConfig),
                ("supabase/migrations/1_init.sql".to_string(), FileKind::Sql),
            ]
        );
    }

    #[test]
    fn skips_build_and_dependency_dirs() {
        let t = TempProject::new();
        for dir in [
            "node_modules/x",
            ".next/static",
            "dist",
            "out",
            "coverage",
            ".git",
        ] {
            t.write(&format!("{dir}/a.js"), "a");
        }
        t.write("app/page.tsx", "p");
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert_eq!(paths(&files), vec!["app/page.tsx"]);
        assert_eq!(stats.dirs_skipped, 6);
    }

    #[test]
    fn unsupported_sfc_counted_not_silent() {
        let t = TempProject::new();
        t.write("src/App.vue", "<template></template>");
        t.write("src/Card.svelte", "<script></script>");
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert!(files.is_empty());
        assert_eq!(stats.skipped_unsupported, 2);
    }

    #[test]
    fn per_file_budget_and_binary() {
        let t = TempProject::new();
        t.write("big.js", &"a".repeat(2048));
        t.write_bytes("bin.js", b"abc\0def");
        t.write("ok.js", "ok");
        let budgets = Budgets {
            max_file_bytes: 1024,
            ..Budgets::default()
        };
        let (files, stats) = collect(t.path(), &budgets);
        assert_eq!(paths(&files), vec!["ok.js"]);
        assert_eq!(stats.skipped_large, 1);
        assert_eq!(stats.skipped_binary, 1);
        assert!(stats.incomplete());
    }

    #[test]
    fn total_budget_stops_and_marks_incomplete() {
        let t = TempProject::new();
        for i in 0..10 {
            t.write(&format!("f{i}.js"), &"x".repeat(100));
        }
        let budgets = Budgets {
            max_total_bytes: 350,
            ..Budgets::default()
        };
        let (files, stats) = collect(t.path(), &budgets);
        assert_eq!(files.len(), 3);
        assert!(stats.budget_exhausted);
        assert!(stats.incomplete());

        let budgets = Budgets {
            max_files: 2,
            ..Budgets::default()
        };
        let (files, stats) = collect(t.path(), &budgets);
        assert_eq!(files.len(), 2);
        assert!(stats.budget_exhausted);
    }

    #[test]
    fn depth_budget() {
        let t = TempProject::new();
        t.write("a/b/c/d.js", "d");
        t.write("a/top.js", "t");
        let budgets = Budgets {
            max_depth: 2,
            ..Budgets::default()
        };
        let (files, stats) = collect(t.path(), &budgets);
        assert_eq!(paths(&files), vec!["a/top.js"]);
        assert_eq!(stats.depth_limited, 1);
    }

    #[test]
    fn invalid_utf8_is_lossy_and_bom_stripped() {
        let t = TempProject::new();
        t.write_bytes("a.js", b"\xef\xbb\xbfconst a = '\xff';");
        let mut texts = Vec::new();
        enumerate(t.path(), &Budgets::default(), &mut |f| texts.push(f.text)).unwrap();
        assert_eq!(texts, vec!["const a = '\u{fffd}';".to_string()]);
    }

    #[test]
    fn missing_root_or_file_root_is_an_error() {
        let t = TempProject::new();
        assert!(enumerate(&t.path().join("nope"), &Budgets::default(), &mut |_| {}).is_err());
        t.write("a.js", "a");
        assert!(enumerate(&t.path().join("a.js"), &Budgets::default(), &mut |_| {}).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let t = TempProject::new();
        let outside = TempProject::new();
        outside.write("secret.js", "s");
        t.write("app/a.js", "a");
        std::os::unix::fs::symlink(outside.path(), t.path().join("app/linked")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.js"), t.path().join("b.js"))
            .unwrap();
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert_eq!(paths(&files), vec!["app/a.js"]);
        assert_eq!(stats.symlinks_skipped, 2);
    }

    #[cfg(windows)]
    #[test]
    fn symlinks_are_not_followed() {
        // Создание симлинка на Windows требует прав/режима разработчика; без них тест
        // проверяет только то, что обход не падает. С правами — что ссылка пропущена.
        let t = TempProject::new();
        let outside = TempProject::new();
        outside.write("secret.js", "s");
        t.write("app/a.js", "a");
        let linked = std::os::windows::fs::symlink_dir(outside.path(), t.path().join("app/linked"));
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert_eq!(paths(&files), vec!["app/a.js"]);
        if linked.is_ok() {
            assert_eq!(stats.symlinks_skipped, 1);
        }
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_not_followed() {
        // Junction создаётся без прав администратора — проверяем по-настоящему.
        let t = TempProject::new();
        let outside = TempProject::new();
        outside.write("secret.js", "s");
        t.write("app/a.js", "a");
        let junction = t.path().join("app").join("junction");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .output()
            .is_ok_and(|o| o.status.success());
        assert!(made, "mklink /J failed");
        assert!(junction.join("secret.js").exists());
        let (files, stats) = collect(t.path(), &Budgets::default());
        assert_eq!(paths(&files), vec!["app/a.js"]);
        assert_eq!(stats.symlinks_skipped + stats.outside_root_skipped, 1);
    }
}
