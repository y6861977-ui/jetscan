//! Происхождение файла: попадёт ли он в браузерный бандл.
//!
//! Это вывод по правилам фреймворка, а не по графу импортов: файл с `"use client"`
//! станет клиентским, ЕСЛИ его импортируют; мёртвый файл в бандл не попадёт. Поэтому даже
//! «клиентский» вывод ведёт максимум к `potential`, а модуль без явной границы — к `needs_review`.

use super::enumerate::FileKind;
use super::framework::{FrameworkInfo, FrameworkKind};
use super::lexer::{Class, Lexed};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Попадёт в браузер по правилам фреймворка. Причина — для отчёта.
    Client(&'static str),
    /// Только сервер / Node (route handler, `"use server"`, `server-only`, конфиг сборки).
    Server(&'static str),
    /// Граница не видна: обычный модуль, который может импортировать и клиент, и сервер.
    Shared,
    /// Тесты, моки, stories — в продакшен-бандл не входят.
    Test,
}

impl Reach {
    pub fn label(self) -> &'static str {
        match self {
            Reach::Client(_) => "client",
            Reach::Server(_) => "server",
            Reach::Shared => "shared",
            Reach::Test => "test",
        }
    }
}

const SCRIPT_EXTS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];

/// Имя файла без расширения скрипта (`page.tsx` → `page`, `next.config.mjs` → `next.config`).
fn stem(name: &str) -> &str {
    match name.rsplit_once('.') {
        Some((stem, ext)) if SCRIPT_EXTS.contains(&ext) => stem,
        _ => name,
    }
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let name = segments.last().copied().unwrap_or("");
    segments[..segments.len().saturating_sub(1)]
        .iter()
        .any(|s| {
            matches!(
                *s,
                "__tests__" | "__mocks__" | "test" | "tests" | "e2e" | "cypress" | "playwright"
            )
        })
        || [".test.", ".spec.", ".stories.", ".story.", ".cy."]
            .iter()
            .any(|m| name.contains(m))
}

/// `dir` — префикс пути (`app`, `src/app`); возвращает остаток пути внутри него.
fn under<'a>(path: &'a str, dir: &str) -> Option<&'a str> {
    path.strip_prefix(dir)?.strip_prefix('/')
}

/// Специальные файлы App Router: без `"use client"` это Server Components / серверный код.
const APP_SERVER_FILES: &[&str] = &[
    "page",
    "layout",
    "template",
    "loading",
    "not-found",
    "default",
    "head",
    "opengraph-image",
    "twitter-image",
    "icon",
    "apple-icon",
    "sitemap",
    "robots",
    "manifest",
];

pub fn classify(
    path: &str,
    kind: FileKind,
    directives: &[String],
    imports: &[String],
    framework: &FrameworkInfo,
) -> Reach {
    if is_test_path(path) {
        return Reach::Test;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    let public = path.starts_with("public/");
    if kind == FileKind::Html {
        return if public {
            Reach::Client("public/ is served to the browser as-is")
        } else if framework.kind == FrameworkKind::ViteReact && path == "index.html" {
            Reach::Client("Vite index.html is served to the browser")
        } else {
            Reach::Shared
        };
    }
    if directives.iter().any(|d| d == "use server") {
        return Reach::Server("'use server' directive");
    }
    if imports.iter().any(|m| m == "server-only") {
        return Reach::Server("imports server-only");
    }
    if directives.iter().any(|d| d == "use client") {
        return Reach::Client("'use client' directive");
    }
    if public {
        return Reach::Client("public/ is served to the browser as-is");
    }
    let stem = stem(name);
    // `next.config` исполняется в Node, но его `env: {...}` Next.js вшивает в клиентский бандл —
    // поэтому это не «сервер», а «смотреть глазами».
    if stem == "next.config" {
        return Reach::Shared;
    }
    // Прочие конфиги инструментов (`vite.config`, `tailwind.config`, ...) исполняются в Node.
    if stem.ends_with(".config") || stem.ends_with(".config.base") {
        return Reach::Server("tool configuration runs in Node");
    }
    match framework.kind {
        FrameworkKind::NextJs => {
            let root_level = !path.contains('/')
                || path
                    .strip_prefix("src/")
                    .is_some_and(|rest| !rest.contains('/'));
            if root_level && matches!(stem, "middleware" | "instrumentation") {
                return Reach::Server("Next.js middleware/instrumentation runs on the server");
            }
            // Next.js 16 переименовал middleware в proxy (полевой тест 2026-11-12, W5).
            if root_level
                && stem == "proxy"
                && super::framework::next_major(framework).is_none_or(|m| m >= 16)
            {
                return Reach::Server("Next.js 16 proxy (formerly middleware) runs on the server");
            }
            for dir in &framework.app_dirs {
                if under(path, dir).is_some() {
                    if stem == "route" {
                        return Reach::Server("App Router route handler");
                    }
                    if APP_SERVER_FILES.contains(&stem) {
                        return Reach::Server("App Router Server Component (no 'use client')");
                    }
                    return Reach::Shared;
                }
            }
            for dir in &framework.pages_dirs {
                if let Some(rest) = under(path, dir) {
                    if rest.starts_with("api/") {
                        return Reach::Server("Pages Router API route");
                    }
                    if stem == "_document" {
                        return Reach::Server("pages/_document renders on the server only");
                    }
                    return Reach::Client("Pages Router page is bundled for the browser");
                }
            }
            Reach::Shared
        }
        FrameworkKind::ViteReact => {
            // Клиентский корень — каталог модуля-входа из index.html (W1: бывает и корень проекта).
            let entry = framework.vite_entry_dir.as_deref().unwrap_or("src");
            let rest = if entry.is_empty() {
                Some(path)
            } else {
                under(path, entry)
            };
            match rest {
                Some(rest)
                    if !rest
                        .split('/')
                        .any(|s| matches!(s, "server" | "api" | "scripts")) =>
                {
                    if entry.is_empty() {
                        Reach::Client("Vite client source (entry module at the project root)")
                    } else {
                        Reach::Client(
                            "Vite client source (directory of the index.html entry module)",
                        )
                    }
                }
                _ => Reach::Shared,
            }
        }
        FrameworkKind::Generic | FrameworkKind::Unsupported => Reach::Shared,
    }
}

/// Байтовые диапазоны `getServerSideProps` / `getStaticProps` / `getStaticPaths` в странице
/// Pages Router: Next.js вырезает их из клиентского бандла.
///
/// Без парсера: от имени функции идём по коду, считая `()` и `{}`. Диапазон кончается,
/// когда закрылось тело (первая `{` вне скобок) или встретился `;`/`export` на нулевой
/// глубине. Ошибка в сторону «короче» даёт лишнюю находку, а не пропуск.
pub fn server_ranges(text: &str, lexed: &Lexed) -> Vec<(usize, usize)> {
    let b = text.as_bytes();
    let mut ranges = Vec::new();
    for name in ["getServerSideProps", "getStaticProps", "getStaticPaths"] {
        for start in super::lexer::code_occurrences(text, lexed, name) {
            let after = start + name.len();
            if b.get(after)
                .is_some_and(|&c| c.is_ascii_alphanumeric() || c == b'_')
            {
                continue;
            }
            // Объявление, а не вызов/упоминание: перед именем `function` или `const`/`let`/`var`.
            let before = text[..start].trim_end();
            let declared = ["function", "const", "let", "var", "function*"]
                .iter()
                .any(|kw| before.ends_with(kw));
            if !declared {
                continue;
            }
            let mut parens = 0usize;
            let mut braces = 0usize;
            let mut body = false;
            let mut end = b.len();
            let mut i = after;
            while i < b.len() {
                if lexed.class_at(i) != Class::Code {
                    i += 1;
                    continue;
                }
                match b[i] {
                    b'(' => parens += 1,
                    b')' => parens = parens.saturating_sub(1),
                    b'{' => {
                        if parens == 0 && braces == 0 {
                            body = true;
                        }
                        braces += 1;
                    }
                    b'}' => {
                        braces = braces.saturating_sub(1);
                        if body && braces == 0 && parens == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    b';' if parens == 0 && braces == 0 => {
                        end = i + 1;
                        break;
                    }
                    b'e' if parens == 0
                        && braces == 0
                        && text[i..].starts_with("export")
                        && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) =>
                    {
                        end = i;
                        break;
                    }
                    _ => {}
                }
                i += 1;
            }
            ranges.push((start, end));
        }
    }
    ranges.sort();
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::framework::Manifest;
    use crate::web_audit::lexer::lex;

    fn fw(kind: FrameworkKind, app: &[&str], pages: &[&str]) -> FrameworkInfo {
        FrameworkInfo {
            kind,
            manifest: Manifest::Found,
            unsupported: None,
            version: None,
            app_dirs: app.iter().map(|s| s.to_string()).collect(),
            pages_dirs: pages.iter().map(|s| s.to_string()).collect(),
            uses_supabase: false,
            uses_firebase: false,
            vite_entry_dir: None,
            notes: vec![],
        }
    }

    fn reach(path: &str, text: &str, framework: &FrameworkInfo) -> Reach {
        let lexed = lex(text);
        classify(
            path,
            FileKind::Script,
            &super::super::lexer::directives(text, &lexed),
            &super::super::lexer::imports(text, &lexed),
            framework,
        )
    }

    #[test]
    fn next_app_router_boundaries() {
        let f = fw(FrameworkKind::NextJs, &["app"], &[]);
        assert!(matches!(
            reach("app/page.tsx", "export default 1", &f),
            Reach::Server(_)
        ));
        assert!(matches!(
            reach("app/api/x/route.ts", "", &f),
            Reach::Server(_)
        ));
        assert!(matches!(
            reach("app/c.tsx", "'use client'\nexport const a = 1", &f),
            Reach::Client(_)
        ));
        assert!(matches!(
            reach("app/page.tsx", "\"use client\";\nexport default 1", &f),
            Reach::Client(_)
        ));
        assert_eq!(
            reach("app/ui/button.tsx", "export const b = 1", &f),
            Reach::Shared
        );
        assert!(matches!(
            reach(
                "app/actions.ts",
                "'use server'\nexport async function a() {}",
                &f
            ),
            Reach::Server(_)
        ));
        assert!(matches!(
            reach("lib/db.ts", "import 'server-only'\nexport const db = 1", &f),
            Reach::Server(_)
        ));
        assert!(matches!(reach("middleware.ts", "", &f), Reach::Server(_)));
        // `env` в next.config попадает в бандл — не сервер.
        assert_eq!(reach("next.config.mjs", "", &f), Reach::Shared);
        assert!(matches!(
            reach("tailwind.config.ts", "", &f),
            Reach::Server(_)
        ));
        assert_eq!(reach("lib/util.ts", "", &f), Reach::Shared);
        // `"use client"` не в прологе — не директива.
        assert_eq!(
            reach("app/ui/x.tsx", "const s = 1;\n'use client'", &f),
            Reach::Shared
        );
    }

    #[test]
    fn server_only_beats_use_client() {
        let f = fw(FrameworkKind::NextJs, &["app"], &[]);
        assert!(matches!(
            reach("app/x.tsx", "'use client'\nimport 'server-only'", &f),
            Reach::Server(_)
        ));
    }

    #[test]
    fn next_pages_router_boundaries() {
        let f = fw(FrameworkKind::NextJs, &[], &["pages"]);
        assert!(matches!(reach("pages/index.tsx", "", &f), Reach::Client(_)));
        assert!(matches!(
            reach("pages/api/pay.ts", "", &f),
            Reach::Server(_)
        ));
        assert!(matches!(
            reach("pages/_document.tsx", "", &f),
            Reach::Server(_)
        ));
    }

    #[test]
    fn vite_and_generic() {
        let f = fw(FrameworkKind::ViteReact, &[], &[]);
        assert!(matches!(reach("src/App.tsx", "", &f), Reach::Client(_)));
        assert!(matches!(reach("vite.config.ts", "", &f), Reach::Server(_)));
        assert_eq!(reach("src/server/db.ts", "", &f), Reach::Shared);
        assert_eq!(reach("server/index.ts", "", &f), Reach::Shared);
        let g = fw(FrameworkKind::Generic, &[], &[]);
        assert_eq!(reach("src/App.tsx", "", &g), Reach::Shared);
        assert!(matches!(reach("public/sdk.js", "", &g), Reach::Client(_)));
    }

    #[test]
    fn tests_and_stories_are_excluded() {
        let f = fw(FrameworkKind::ViteReact, &[], &[]);
        assert_eq!(reach("src/App.test.tsx", "", &f), Reach::Test);
        assert_eq!(reach("src/__tests__/a.ts", "", &f), Reach::Test);
        assert_eq!(reach("src/Button.stories.tsx", "", &f), Reach::Test);
        assert!(matches!(reach("src/contest.tsx", "", &f), Reach::Client(_)));
    }

    fn covered(text: &str, needle: &str) -> bool {
        let lexed = lex(text);
        let at = text.find(needle).unwrap();
        server_ranges(text, &lexed)
            .iter()
            .any(|&(s, e)| s <= at && at < e)
    }

    #[test]
    fn get_server_side_props_function_body() {
        let text = "export default function P() { return KEY_CLIENT }\n\
                    export async function getServerSideProps({ params }) {\n\
                      const k = KEY_SERVER;\n  if (a) { b() }\n  return { props: {} };\n}\n\
                    const after = KEY_AFTER;";
        assert!(covered(text, "KEY_SERVER"));
        assert!(!covered(text, "KEY_CLIENT"));
        assert!(!covered(text, "KEY_AFTER"));
    }

    #[test]
    fn get_static_props_arrow_and_satisfies() {
        let text =
            "export const getStaticProps = async (ctx) => {\n  return KEY_A;\n};\nconst x = KEY_B;";
        assert!(covered(text, "KEY_A"));
        assert!(!covered(text, "KEY_B"));
        let text = "export const getStaticProps = (async () => ({ props: { k: KEY_A } })) satisfies G\nexport default function P() { return KEY_B }";
        assert!(covered(text, "KEY_A"));
        assert!(!covered(text, "KEY_B"));
    }

    #[test]
    fn mention_is_not_a_server_range() {
        let text = "// getServerSideProps is not used here\nconst a = KEY_A; getServerSideProps();";
        assert!(!covered(text, "KEY_A"));
    }
}
