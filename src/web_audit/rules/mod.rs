//! Правила Web Source Audit. Каждое правило получает уже разобранный файл (`FileContext`)
//! и добавляет находки; ни одно не читает файлы само и не ходит в сеть.

pub mod auth;
pub mod cors;
pub mod debug;
pub mod env;
pub mod firebase;
pub mod rls;
pub mod secret;
pub mod supabase;
pub mod xss;

use super::enumerate::FileKind;
use super::framework::FrameworkInfo;
use super::lexer::{self, Class, Lexed, Literal};
use super::location::LineIndex;
use super::provenance::{self, Reach};
use crate::secrets::scan::INLINE_IGNORE;

/// Разобранный исходный файл — общий вход для всех правил.
pub struct FileContext<'a> {
    pub path: &'a str,
    pub kind: FileKind,
    pub text: &'a str,
    pub lexed: Lexed,
    /// Текст без комментариев (символ → пробел): строки и колонки совпадают с `text`.
    pub stripped: String,
    pub index: LineIndex,
    pub reach: Reach,
    /// Директивы пролога (`"use client"`, `"use server"`, ...).
    pub directives: Vec<String>,
    /// Куски клиентского файла, которые фреймворк вырезает из бандла (`getServerSideProps`).
    pub server_ranges: Vec<(usize, usize)>,
    pub framework: &'a FrameworkInfo,
}

impl<'a> FileContext<'a> {
    pub fn new(
        path: &'a str,
        kind: FileKind,
        text: &'a str,
        framework: &'a FrameworkInfo,
    ) -> FileContext<'a> {
        let lexed = if kind == FileKind::Script {
            lexer::lex(text)
        } else {
            // HTML отдаётся браузеру целиком, вместе с `<!-- -->`: размечать нечего.
            Lexed {
                classes: vec![Class::Code; text.len()],
                literals: Vec::<Literal>::new(),
                recovered: 0,
            }
        };
        let stripped = if kind == FileKind::Script {
            lexer::strip_comments(text, &lexed)
        } else {
            text.to_string()
        };
        let (directives, imports) = if kind == FileKind::Script {
            (
                lexer::directives(text, &lexed),
                lexer::imports(text, &lexed),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let reach = provenance::classify(path, kind, &directives, &imports, framework);
        let pages_page = matches!(reach, Reach::Client(_))
            && framework
                .pages_dirs
                .iter()
                .any(|dir| path.starts_with(&format!("{dir}/")));
        let server_ranges = if pages_page {
            provenance::server_ranges(text, &lexed)
        } else {
            Vec::new()
        };
        FileContext {
            path,
            kind,
            text,
            stripped,
            index: LineIndex::new(text),
            lexed,
            reach,
            directives,
            server_ranges,
            framework,
        }
    }

    pub fn in_server_range(&self, byte: usize) -> bool {
        self.server_ranges
            .iter()
            .any(|&(start, end)| start <= byte && byte < end)
    }

    /// На строке `line` (с 1) стоит `jetscan:ignore` (в любом месте, и в комментарии тоже).
    pub fn line_ignored(&self, line: usize) -> bool {
        self.index
            .line_range(self.text, line)
            .is_some_and(|(s, e)| self.text[s..e].contains(INLINE_IGNORE))
    }
}

/// Сколько срабатываний одного правила в одном файле разбираем. Дальше — стоп и `partial`:
/// разбор срабатывания стоит O(длина строки), и минифицированная строка на мегабайт, набитая
/// ключеподобными токенами, иначе дала бы квадратичное время. Настоящему файлу 200 хватает.
pub const MAX_HITS_PER_FILE: usize = 200;

/// Счётчики, которые правила отдают движку.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleStats {
    /// Находки, подавленные `jetscan:ignore`.
    pub ignored_inline: usize,
    /// (правило, файл), где упёрлись в `MAX_HITS_PER_FILE` — проверка правила не полная.
    pub capped: Vec<(&'static str, String)>,
}

impl RuleStats {
    /// Отмечает, если срабатываний было больше лимита.
    pub fn note_cap(&mut self, rule: &'static str, path: &str, total: usize) {
        if total > MAX_HITS_PER_FILE {
            self.capped.push((rule, path.to_string()));
        }
    }
}
