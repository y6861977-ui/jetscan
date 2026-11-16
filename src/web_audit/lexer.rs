//! Консервативный токенайзер JS/TS/JSX — не парсер (ADR-001).
//!
//! Размечает каждый байт: код, комментарий, строка, шаблонная строка, регулярное выражение.
//! Этого хватает, чтобы: не искать ключи в комментариях; отличать упоминание в строке от
//! ссылки в коде (`process.env.X`); прочитать директивы (`"use client"`) и импорты.
//!
//! Где синтаксис неоднозначен без парсера — выбираем вариант, при котором меньше теряем:
//! - строка в кавычках не может пересечь перевод строки: апостроф в JSX-тексте (`Don't`)
//!   «съедает» максимум остаток строки, а не весь файл (считается в `recovered`);
//! - `/` — регулярка, только если перед ней не значение (по последнему значимому токену);
//!   регулярка тоже не пересекает перевод строки, иначе это деление;
//! - `//` внутри JSX-текста (`<a>https://x</a>`) будет принят за комментарий — известное
//!   ограничение, ключ после него на той же строке не увидим.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Code,
    Comment,
    Str,
    Template,
    Regex,
}

/// Непрерывный кусок литерала (строка целиком с кавычками; кусок шаблонной строки между
/// `${...}`; регулярка). Байтовые границы, `end` не включительно.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Literal {
    pub start: usize,
    pub end: usize,
    pub kind: Class,
}

#[derive(Clone, Debug)]
pub struct Lexed {
    /// Класс каждого байта исходного текста.
    pub classes: Vec<Class>,
    /// Литералы по возрастанию `start`.
    pub literals: Vec<Literal>,
    /// Сколько раз пришлось восстанавливаться (незакрытая строка/комментарий/шаблон).
    pub recovered: usize,
}

impl Lexed {
    pub fn class_at(&self, byte: usize) -> Class {
        self.classes.get(byte).copied().unwrap_or(Class::Code)
    }

    /// Литерал, содержащий байт `byte`.
    pub fn literal_at(&self, byte: usize) -> Option<&Literal> {
        let index = self.literals.partition_point(|l| l.start <= byte);
        let literal = self.literals.get(index.checked_sub(1)?)?;
        (byte < literal.end).then_some(literal)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Prev {
    Start,
    Punct,
    Value,
    Word(usize, usize),
}

const REGEX_AFTER_WORDS: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

pub fn lex(text: &str) -> Lexed {
    let b = text.as_bytes();
    let n = b.len();
    let mut classes = vec![Class::Code; n];
    let mut literals = Vec::new();
    let mut recovered = 0;
    // Глубина `{` внутри каждого открытого `${ ... }`.
    let mut templates: Vec<usize> = Vec::new();
    let mut prev = Prev::Start;
    let mut i = 0;

    let mark = |classes: &mut Vec<Class>, from: usize, to: usize, class: Class| {
        for c in &mut classes[from..to] {
            *c = class;
        }
    };

    // Кусок шаблонной строки от `from` (на обратной кавычке или на `}` после `${`).
    // Возвращает, где продолжать, и открыт ли новый `${`.
    let template_chunk = |from: usize, recovered: &mut usize| -> (usize, bool) {
        let mut j = from + 1;
        while j < n {
            match b[j] {
                b'\\' => j += 2,
                b'`' => return (j + 1, false),
                b'$' if b.get(j + 1) == Some(&b'{') => return (j + 2, true),
                _ => j += 1,
            }
        }
        *recovered += 1;
        (n, false)
    };

    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == b'/' && next == Some(b'/') || (i == 0 && c == b'#' && next == Some(b'!')) {
            let end = text[i..].find('\n').map_or(n, |p| i + p);
            mark(&mut classes, i, end, Class::Comment);
            i = end;
            continue;
        }
        if c == b'/' && next == Some(b'*') {
            let end = match text[i + 2..].find("*/") {
                Some(p) => i + 2 + p + 2,
                None => {
                    recovered += 1;
                    n
                }
            };
            mark(&mut classes, i, end, Class::Comment);
            i = end;
            continue;
        }
        if c == b'"' || c == b'\'' {
            let mut j = i + 1;
            let mut closed = false;
            while j < n {
                match b[j] {
                    b'\\' => j += 2,
                    b'\n' => break,
                    q if q == c => {
                        j += 1;
                        closed = true;
                        break;
                    }
                    _ => j += 1,
                }
            }
            let j = j.min(n);
            if !closed {
                recovered += 1;
            }
            mark(&mut classes, i, j, Class::Str);
            literals.push(Literal {
                start: i,
                end: j,
                kind: Class::Str,
            });
            prev = Prev::Value;
            i = j;
            continue;
        }
        if c == b'`' || (c == b'}' && templates.last() == Some(&0)) {
            if c == b'}' {
                templates.pop();
            }
            let (end, opened) = template_chunk(i, &mut recovered);
            let end = end.min(n);
            mark(&mut classes, i, end, Class::Template);
            literals.push(Literal {
                start: i,
                end,
                kind: Class::Template,
            });
            if opened {
                templates.push(0);
                prev = Prev::Punct;
            } else {
                prev = Prev::Value;
            }
            i = end;
            continue;
        }
        if c == b'/'
            && regex_allowed(text, prev)
            && let Some(end) = regex_end(b, i)
        {
            mark(&mut classes, i, end, Class::Regex);
            literals.push(Literal {
                start: i,
                end,
                kind: Class::Regex,
            });
            prev = Prev::Value;
            i = end;
            continue;
        }
        match c {
            b'{' => {
                if let Some(depth) = templates.last_mut() {
                    *depth += 1;
                }
                prev = Prev::Punct;
                i += 1;
            }
            b'}' => {
                if let Some(depth) = templates.last_mut() {
                    *depth -= 1;
                }
                prev = Prev::Punct;
                i += 1;
            }
            b')' | b']' => {
                prev = Prev::Value;
                i += 1;
            }
            c if c.is_ascii_whitespace() => i += 1,
            c if c.is_ascii_digit() => {
                while i < n && (is_ident_byte(b[i]) || b[i] == b'.') {
                    i += 1;
                }
                prev = Prev::Value;
            }
            c if is_ident_byte(c) => {
                let start = i;
                while i < n && is_ident_byte(b[i]) {
                    i += 1;
                }
                prev = Prev::Word(start, i);
            }
            _ => {
                prev = Prev::Punct;
                i += 1;
            }
        }
    }
    if !templates.is_empty() {
        recovered += 1;
    }
    Lexed {
        classes,
        literals,
        recovered,
    }
}

fn regex_allowed(text: &str, prev: Prev) -> bool {
    match prev {
        Prev::Start | Prev::Punct => true,
        Prev::Value => false,
        Prev::Word(start, end) => REGEX_AFTER_WORDS.contains(&&text[start..end]),
    }
}

/// Конец регулярки, начинающейся с `/` в `start`, или `None`, если до перевода строки
/// закрывающего `/` нет (значит, это было деление).
fn regex_end(b: &[u8], start: usize) -> Option<usize> {
    let mut j = start + 1;
    let mut in_class = false;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'\n' | b'\r' => return None,
            b'[' => {
                in_class = true;
                j += 1;
            }
            b']' => {
                in_class = false;
                j += 1;
            }
            b'/' if !in_class => {
                j += 1;
                while j < b.len() && b[j].is_ascii_alphabetic() {
                    j += 1;
                }
                return Some(j);
            }
            _ => j += 1,
        }
    }
    None
}

/// Текст, где каждый символ комментария заменён одним пробелом (переводы строк сохранены).
/// Колонки в символах и номера строк совпадают с исходником.
pub fn strip_comments(text: &str, lexed: &Lexed) -> String {
    text.char_indices()
        .map(|(i, c)| {
            if lexed.class_at(i) == Class::Comment && c != '\n' && c != '\r' {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// Содержимое строкового литерала без кавычек, если это простая строка без экранирования.
pub fn plain_string(text: &str, literal: &Literal) -> Option<String> {
    if literal.kind != Class::Str || literal.end < literal.start + 2 {
        return None;
    }
    let inner = &text[literal.start + 1..literal.end - 1];
    (!inner.contains('\\')).then(|| inner.to_string())
}

/// Байт, где кончается пробел/комментарий после `from` (первый значимый байт или `len`).
fn skip_trivia(text: &str, lexed: &Lexed, mut from: usize) -> usize {
    let b = text.as_bytes();
    while from < b.len()
        && (b[from].is_ascii_whitespace() || lexed.class_at(from) == Class::Comment)
    {
        from += 1;
    }
    from
}

/// Директивы пролога файла (`"use client"`, `'use server'`, `"use strict"`): строки-инструкции
/// до первого другого оператора. Директива в середине файла директивой не является.
pub fn directives(text: &str, lexed: &Lexed) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = skip_trivia(text, lexed, 0);
    while let Some(literal) = lexed.literal_at(i) {
        if literal.start != i || literal.kind != Class::Str {
            break;
        }
        let Some(value) = plain_string(text, literal) else {
            break;
        };
        // После директивы на той же строке — только `;`, комментарий или конец строки.
        let mut j = literal.end;
        while j < b.len() && (b[j] == b' ' || b[j] == b'\t' || lexed.class_at(j) == Class::Comment)
        {
            if b[j] == b'\n' {
                break;
            }
            j += 1;
        }
        match b.get(j) {
            None | Some(b';') | Some(b'\n') | Some(b'\r') => {}
            _ => break,
        }
        out.push(value);
        i = skip_trivia(text, lexed, if b.get(j) == Some(&b';') { j + 1 } else { j });
    }
    out
}

/// Предыдущее значимое слово кода перед байтом `before` (пропуская пробелы и комментарии)
/// и байт, с которого оно начинается.
fn word_before<'a>(text: &'a str, lexed: &Lexed, before: usize) -> Option<(&'a str, usize)> {
    let b = text.as_bytes();
    let mut j = before;
    while j > 0 && (b[j - 1].is_ascii_whitespace() || lexed.class_at(j - 1) == Class::Comment) {
        j -= 1;
    }
    let end = j;
    while j > 0 && is_ident_byte(b[j - 1]) && lexed.class_at(j - 1) == Class::Code {
        j -= 1;
    }
    (j < end).then(|| (&text[j..end], j))
}

fn punct_before(text: &str, lexed: &Lexed, before: usize) -> Option<(u8, usize)> {
    let b = text.as_bytes();
    let mut j = before;
    while j > 0 && (b[j - 1].is_ascii_whitespace() || lexed.class_at(j - 1) == Class::Comment) {
        j -= 1;
    }
    (j > 0 && lexed.class_at(j - 1) == Class::Code).then(|| (b[j - 1], j - 1))
}

/// Модули, которые файл импортирует: `import x from "m"`, `import "m"`, `export * from "m"`,
/// `require("m")`, `import("m")`. Только простые строки (без шаблонов и конкатенации).
pub fn imports(text: &str, lexed: &Lexed) -> Vec<String> {
    let mut out = Vec::new();
    for literal in &lexed.literals {
        let Some(value) = plain_string(text, literal) else {
            continue;
        };
        let is_import = match word_before(text, lexed, literal.start) {
            Some(("import" | "from", _)) => true,
            _ => match punct_before(text, lexed, literal.start) {
                Some((b'(', paren)) => {
                    matches!(
                        word_before(text, lexed, paren),
                        Some(("require" | "import", _))
                    )
                }
                _ => false,
            },
        };
        if is_import {
            out.push(value);
        }
    }
    out
}

/// Начала вхождений `needle` в коде (не в строке/комментарии), с границей слова слева.
pub fn code_occurrences(text: &str, lexed: &Lexed, needle: &str) -> Vec<usize> {
    let b = text.as_bytes();
    text.match_indices(needle)
        .map(|(i, _)| i)
        .filter(|&i| {
            lexed.class_at(i) == Class::Code
                && (i == 0 || (!is_ident_byte(b[i - 1]) && b[i - 1] != b'.'))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes_of(text: &str) -> String {
        let lexed = lex(text);
        lexed
            .classes
            .iter()
            .map(|c| match c {
                Class::Code => '.',
                Class::Comment => 'c',
                Class::Str => 's',
                Class::Template => 't',
                Class::Regex => 'r',
            })
            .collect()
    }

    #[test]
    fn comments_strings_and_code() {
        assert_eq!(classes_of("a // b"), "..cccc");
        assert_eq!(classes_of("a /* b */ c"), "..ccccccc..");
        assert_eq!(classes_of(r#"x = "a//b";"#), "....ssssss.");
        assert_eq!(classes_of(r#"'it\'s' + 1"#), "sssssss....");
    }

    #[test]
    fn template_literal_with_nested_expression() {
        let text = "`a${ {b:1}.b }c` + d";
        let c = classes_of(text);
        assert_eq!(&c[..4], "tttt");
        assert_eq!(&c[4..13], ".........");
        assert_eq!(&c[13..16], "ttt");
        assert_eq!(&c[16..], "....");
        let lexed = lex(text);
        assert_eq!(lexed.recovered, 0);
        assert_eq!(lexed.literals.len(), 2);
    }

    #[test]
    fn nested_template_in_template() {
        let lexed = lex("`a${`b${c}`}d` // x");
        assert_eq!(lexed.recovered, 0);
        assert_eq!(lexed.class_at(lexed.classes.len() - 1), Class::Comment);
    }

    #[test]
    fn regex_vs_division() {
        assert_eq!(classes_of("a = /x\\/y[/]/g;"), "....rrrrrrrrrr.");
        assert_eq!(classes_of("a = b / c / d"), ".............");
        assert_eq!(classes_of("return /a/"), ".......rrr");
        // Регулярка с `//` внутри не комментарий.
        assert_eq!(classes_of("x(/\\/\\//)"), "..rrrrrr.");
    }

    #[test]
    fn unterminated_string_stops_at_newline() {
        let lexed = lex("<p>Don't</p>\nconst k = 1;");
        assert_eq!(lexed.recovered, 1);
        let second_line = "<p>Don't</p>\n".len();
        assert_eq!(lexed.class_at(second_line), Class::Code);
    }

    #[test]
    fn unterminated_block_comment_is_recovered() {
        let lexed = lex("a /* never closed");
        assert_eq!(lexed.recovered, 1);
        assert_eq!(lexed.class_at(5), Class::Comment);
    }

    #[test]
    fn strip_comments_keeps_columns_with_unicode() {
        let text = "a /* привет */ b\n// ключ\nc";
        let stripped = strip_comments(text, &lex(text));
        assert_eq!(stripped.lines().count(), 3);
        let first: Vec<char> = stripped.lines().next().unwrap().chars().collect();
        let original: Vec<char> = text.lines().next().unwrap().chars().collect();
        assert_eq!(first.len(), original.len());
        assert_eq!(first.last(), Some(&'b'));
        assert!(!stripped.contains("ключ"));
    }

    #[test]
    fn directives_only_in_prologue() {
        let t = "// header\n'use client';\n\"use strict\"\nimport x from 'y';";
        assert_eq!(directives(t, &lex(t)), vec!["use client", "use strict"]);
        let t = "import x from 'y';\n'use client';";
        assert!(directives(t, &lex(t)).is_empty());
        let t = "'use client'.length;";
        assert!(directives(t, &lex(t)).is_empty());
        let t = "/* a */ \"use server\" // trailing\nexport async function f() {}";
        assert_eq!(directives(t, &lex(t)), vec!["use server"]);
    }

    #[test]
    fn imports_and_requires() {
        let t = "import 'server-only';\nimport a from \"a\";\nexport * from './b';\nconst c = require('c');\nconst d = await import(\"d\");\nconst s = 'not-import';";
        assert_eq!(
            imports(t, &lex(t)),
            vec!["server-only", "a", "./b", "c", "d"]
        );
    }

    #[test]
    fn code_occurrences_skip_strings_comments_and_members() {
        let t = "process.env.A; 'process.env.B'; // process.env.C\nx.process.env.D";
        let found = code_occurrences(t, &lex(t), "process.env.");
        assert_eq!(found, vec![0]);
    }

    #[test]
    fn literal_at_finds_enclosing_literal() {
        let t = "a = 'xyz' + `t`";
        let lexed = lex(t);
        assert_eq!(lexed.literal_at(5).map(|l| l.start), Some(4));
        assert!(lexed.literal_at(2).is_none());
        assert_eq!(lexed.literal_at(13).map(|l| l.kind), Some(Class::Template));
    }
}
