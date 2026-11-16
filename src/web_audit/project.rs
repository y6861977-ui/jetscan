//! Небольшая модель проекта для правил, которым нужен соседний файл: кто что импортирует и где
//! это лежит. Не граф вызовов и не парсер — только `import … from "…"` и разрешение пути модуля
//! (относительные пути, алиасы `paths` из `tsconfig.json`/`jsconfig.json`, по умолчанию `@/` и `~/`
//! → корень и `src/`). Внешние пакеты не разрешаются (их кода в проекте нет).
//!
//! Используется: WEB-AUTH-004 (обёртки и делегирование — полевой тест 2026-11-12, паттерны 1–2),
//! WEB-XSS-003 (функция-санитайзер, определённая в проекте), WEB-SUPABASE-005/WEB-SECRET-001
//! (кто импортирует модуль без границы клиент/сервер).

use super::lexer::{self, Class, Lexed, plain_string};
use super::provenance::Reach;
use crate::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;

/// `import { imported as local } from "specifier"`; `imported` = `default` / `*` для таких импортов.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportBinding {
    pub local: String,
    pub imported: String,
    pub specifier: String,
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// Статические импорты файла с именами. Динамические `import()`, `require`, реэкспорт — нет.
pub fn import_bindings(text: &str, lexed: &Lexed) -> Vec<ImportBinding> {
    let mut out = Vec::new();
    for at in lexer::code_occurrences(text, lexed, "import") {
        let after = at + "import".len();
        let next = text[after..].chars().next();
        if next.is_some_and(|c| is_ident(c) || c == '(' || c == '.') {
            continue;
        }
        // Ищем `from "<spec>"` не дальше 2000 байт и до `;` в коде.
        let window_end = (after + 2000).min(text.len());
        let mut from_at = None;
        let mut i = after;
        while i < window_end {
            if lexed.class_at(i) == Class::Code {
                let b = text.as_bytes()[i];
                if b == b';' {
                    break;
                }
                if text[i..].starts_with("from")
                    && !text[..i].ends_with(|c: char| is_ident(c))
                    && !text[i + 4..].starts_with(|c: char| is_ident(c))
                {
                    from_at = Some(i);
                    break;
                }
            } else if lexed.class_at(i) == Class::Str
                && from_at.is_none()
                && i == skip_ws(text, after)
            {
                break; // `import "side-effect"` — без привязок
            }
            i += 1;
        }
        let Some(from_at) = from_at else {
            continue;
        };
        let spec_at = skip_ws(text, from_at + 4);
        let Some(literal) = lexed.literal_at(spec_at).filter(|l| l.start == spec_at) else {
            continue;
        };
        let Some(specifier) = plain_string(text, literal) else {
            continue;
        };
        let clause = text[after..from_at].trim();
        let clause = clause.strip_prefix("type ").unwrap_or(clause);
        parse_clause(clause, &specifier, &mut out);
    }
    out
}

fn skip_ws(text: &str, mut at: usize) -> usize {
    let b = text.as_bytes();
    while at < b.len() && b[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

fn parse_clause(clause: &str, specifier: &str, out: &mut Vec<ImportBinding>) {
    let mut push = |local: &str, imported: &str| {
        let local = local.trim();
        if !local.is_empty()
            && local.chars().next().is_some_and(is_ident_start)
            && local.chars().all(is_ident)
        {
            out.push(ImportBinding {
                local: local.to_string(),
                imported: imported.trim().to_string(),
                specifier: specifier.to_string(),
            });
        }
    };
    let (head, braces) = match clause.find('{') {
        Some(open) => {
            let close = clause[open..].find('}').map_or(clause.len(), |c| open + c);
            (&clause[..open], Some(&clause[open + 1..close]))
        }
        None => (clause, None),
    };
    for part in head.split(',') {
        let part = part.trim();
        if let Some(ns) = part.strip_prefix("* as ") {
            push(ns, "*");
        } else if !part.is_empty() {
            push(part, "default");
        }
    }
    if let Some(inner) = braces {
        for item in inner.split(',') {
            let item = item.trim();
            let item = item.strip_prefix("type ").unwrap_or(item);
            match item.split_once(" as ") {
                Some((imported, local)) => push(local, imported),
                None => push(item, item),
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct FileFacts {
    pub reach: Reach,
    pub auth_signal: bool,
    pub sanitizer: bool,
    pub imports: Vec<ImportBinding>,
}

#[derive(Clone, Debug, Default)]
pub struct Project {
    pub files: BTreeMap<String, FileFacts>,
    /// (префикс алиаса, каталоги-цели от корня) — из `paths`, плюс `@/`, `~/` по умолчанию.
    aliases: Vec<(String, Vec<String>)>,
    /// `baseUrl` (от корня), если задан: тогда `lib/x` ищется как путь от него.
    base_url: Option<String>,
}

const EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

impl Project {
    pub fn new(root: &Path) -> Project {
        let mut project = Project::default();
        for name in ["tsconfig.json", "jsconfig.json"] {
            if let Some((aliases, base)) = read_paths(&root.join(name)) {
                project.aliases = aliases;
                project.base_url = base;
                break;
            }
        }
        for prefix in ["@/", "~/"] {
            if !project.aliases.iter().any(|(p, _)| p == prefix) {
                project
                    .aliases
                    .push((prefix.to_string(), vec![String::new(), "src/".to_string()]));
            }
        }
        project
    }

    pub fn add(&mut self, path: &str, facts: FileFacts) {
        self.files.insert(path.to_string(), facts);
    }

    fn existing(&self, base: &str) -> Option<String> {
        if self.files.contains_key(base) {
            return Some(base.to_string());
        }
        for ext in EXTENSIONS {
            let candidate = format!("{base}.{ext}");
            if self.files.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        for ext in EXTENSIONS {
            let candidate = format!("{base}/index.{ext}");
            if self.files.contains_key(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    /// Путь файла проекта, на который указывает `specifier` из файла `from`; `None` — внешний пакет
    /// или не найден.
    pub fn resolve(&self, from: &str, specifier: &str) -> Option<String> {
        if specifier.starts_with("./") || specifier.starts_with("../") {
            let dir = from.rsplit_once('/').map_or("", |(d, _)| d);
            return self.existing(&normalize(&format!("{dir}/{specifier}"))?);
        }
        for (prefix, targets) in &self.aliases {
            if let Some(rest) = specifier.strip_prefix(prefix.as_str()) {
                for target in targets {
                    if let Some(found) =
                        normalize(&format!("{target}{rest}")).and_then(|p| self.existing(&p))
                    {
                        return Some(found);
                    }
                }
            }
        }
        let base = self.base_url.as_deref()?;
        let joined = if base.is_empty() {
            specifier.to_string()
        } else {
            format!("{base}/{specifier}")
        };
        normalize(&joined).and_then(|p| self.existing(&p))
    }

    /// Привязка импорта `local` в файле `from` (если есть).
    pub fn binding<'a>(&'a self, from: &str, local: &str) -> Option<&'a ImportBinding> {
        self.files
            .get(from)?
            .imports
            .iter()
            .find(|b| b.local == local)
    }

    /// Файлы проекта, которые импортируют `path`.
    pub fn importers(&self, path: &str) -> Vec<(&str, Reach)> {
        self.files
            .iter()
            .filter(|(from, facts)| {
                from.as_str() != path
                    && facts
                        .imports
                        .iter()
                        .any(|b| self.resolve(from, &b.specifier).as_deref() == Some(path))
            })
            .map(|(from, facts)| (from.as_str(), facts.reach))
            .collect()
    }
}

/// `a/./b/../c` → `a/c`; выход выше корня — `None`.
fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// `compilerOptions.paths` и `baseUrl` из tsconfig/jsconfig (комментарии и висячие запятые
/// допускаются, как у TypeScript). Ошибка разбора — `None` (остаются алиасы по умолчанию).
#[allow(clippy::type_complexity)]
fn read_paths(path: &Path) -> Option<(Vec<(String, Vec<String>)>, Option<String>)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > 256 * 1024 {
        return None;
    }
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(256 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    let lexed = lexer::lex(&text);
    let stripped = lexer::strip_comments(&text, &lexed);
    let cleaned = drop_trailing_commas(&stripped, &lexer::lex(&stripped));
    let parsed = json::parse(&cleaned).ok()?;
    let options = parsed.get("compilerOptions")?;
    let base = options
        .get("baseUrl")
        .and_then(|b| b.as_str())
        .and_then(|b| normalize(b.trim_start_matches("./")));
    let mut aliases = Vec::new();
    if let Some(paths) = options.get("paths").and_then(|p| p.as_object()) {
        let mut keys: Vec<&String> = paths.keys().collect();
        keys.sort();
        for key in keys {
            let Some(prefix) = key.strip_suffix('*') else {
                continue;
            };
            let targets: Vec<String> = paths[key]
                .as_array()
                .unwrap_or(&[])
                .iter()
                .filter_map(|t| t.as_str()?.strip_suffix('*').map(str::to_string))
                .filter_map(|t| {
                    let joined = match &base {
                        Some(b) if !b.is_empty() => format!("{b}/{t}"),
                        _ => t,
                    };
                    let mut n = normalize(joined.trim_start_matches("./"))?;
                    if !n.is_empty() {
                        n.push('/');
                    }
                    Some(n)
                })
                .collect();
            if !targets.is_empty() {
                aliases.push((prefix.to_string(), targets));
            }
        }
    }
    Some((aliases, base))
}

fn drop_trailing_commas(text: &str, lexed: &Lexed) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    for (i, c) in text.char_indices() {
        if c == ',' && lexed.class_at(i) == Class::Code {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if matches!(b.get(j), Some(b'}' | b']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::TempProject;

    fn bindings(text: &str) -> Vec<(String, String, String)> {
        import_bindings(text, &lexer::lex(text))
            .into_iter()
            .map(|b| (b.local, b.imported, b.specifier))
            .collect()
    }

    #[test]
    fn parses_import_clauses() {
        let b = bindings(
            "import React, { useState as useS, type FC } from 'react';\n\
             import * as ns from \"./ns\";\nimport \"./side\";\nimport type { T } from './t';\n\
             const x = await import('./dyn'); import.meta.env;\nimport def from '@/lib/def'",
        );
        assert_eq!(
            b,
            vec![
                ("React".into(), "default".into(), "react".into()),
                ("useS".into(), "useState".into(), "react".into()),
                ("FC".into(), "FC".into(), "react".into()),
                ("ns".into(), "*".into(), "./ns".into()),
                ("T".into(), "T".into(), "./t".into()),
                ("def".into(), "default".into(), "@/lib/def".into()),
            ]
        );
    }

    fn facts() -> FileFacts {
        FileFacts {
            reach: Reach::Shared,
            auth_signal: false,
            sanitizer: false,
            imports: vec![],
        }
    }

    #[test]
    fn resolves_relative_alias_and_tsconfig_paths() {
        let t = TempProject::new();
        t.write(
            "tsconfig.json",
            "{ // comment\n \"compilerOptions\": { \"baseUrl\": \".\", \"paths\": { \"#lib/*\": [\"./src/lib/*\",], }, }, }",
        );
        let mut p = Project::new(t.path());
        for f in [
            "app/api/x/route.ts",
            "lib/cron/with-cron.ts",
            "src/lib/a/index.tsx",
            "app/util.js",
        ] {
            p.add(f, facts());
        }
        assert_eq!(
            p.resolve("app/api/x/route.ts", "../../util").as_deref(),
            Some("app/util.js")
        );
        assert_eq!(
            p.resolve("app/api/x/route.ts", "@/lib/cron/with-cron")
                .as_deref(),
            Some("lib/cron/with-cron.ts")
        );
        assert_eq!(
            p.resolve("app/api/x/route.ts", "#lib/a").as_deref(),
            Some("src/lib/a/index.tsx")
        );
        assert_eq!(
            p.resolve("app/api/x/route.ts", "lib/cron/with-cron")
                .as_deref(),
            Some("lib/cron/with-cron.ts")
        );
        assert_eq!(p.resolve("app/api/x/route.ts", "next/server"), None);
        assert_eq!(p.resolve("app/x.ts", "../../../etc/passwd"), None);
    }

    #[test]
    fn importers_are_listed() {
        let t = TempProject::new();
        let mut p = Project::new(t.path());
        p.add("utils/admin.ts", facts());
        let mut server = facts();
        server.reach = Reach::Server("route");
        server.imports = vec![ImportBinding {
            local: "admin".into(),
            imported: "admin".into(),
            specifier: "@/utils/admin".into(),
        }];
        p.add("app/api/route.ts", server);
        assert_eq!(p.importers("utils/admin.ts").len(), 1);
    }
}
