//! Консервативный токенайзер SQL (PostgreSQL) для WEB-RLS-009. Не парсер: режет текст на токены
//! и операторы по `;` верхнего уровня, а смысл операторов разбирает `rules::rls`.
//!
//! Что понимает: `--` и вложенные `/* */` комментарии, строки `'…'` (с `''`), `E'…'` (с `\`),
//! идентификаторы в кавычках `"…"` (с `""`), долларовые строки `$$…$$` / `$tag$…$tag$`,
//! параметры `$1`, мета-команды psql (`\connect …` в начале строки), тела `BEGIN ATOMIC … END`.
//! Незакрытая строка/комментарий — токен до конца файла и флаг `unterminated`: остаток файла
//! не анализируется, и это видно в отчёте (не «чисто»).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Слово: ключевое слово или идентификатор без кавычек.
    Word,
    /// `"Идентификатор"`.
    Quoted,
    /// `'строка'`, `E'строка'`.
    Str,
    /// `$$тело$$`.
    Dollar,
    /// Число или `$1`.
    Num,
    /// Один символ пунктуации: `( ) , ; . [ ]`.
    Punct,
    /// Оператор: подряд идущие `+-*/<>=~!@#%^&|`?:`.
    Op,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Statement {
    pub tokens: Vec<Token>,
}

#[derive(Clone, Debug, Default)]
pub struct SqlFile {
    pub statements: Vec<Statement>,
    /// Строка, комментарий или долларовое тело не закрыты до конца файла.
    pub unterminated: bool,
}

/// Нормализованное значение токена: слово — в нижнем регистре, `"Имя"` — как есть без кавычек,
/// строка — содержимое без кавычек (экранирование `''` снято), остальное — текст как есть.
pub fn value(text: &str, t: &Token) -> String {
    let raw = &text[t.start..t.end];
    match t.kind {
        Kind::Word => raw.to_ascii_lowercase(),
        Kind::Quoted => raw
            .strip_prefix('"')
            .map(|s| s.strip_suffix('"').unwrap_or(s))
            .unwrap_or(raw)
            .replace("\"\"", "\""),
        Kind::Str => {
            let s = raw.strip_prefix(['E', 'e']).unwrap_or(raw);
            let s = s.strip_prefix('\'').unwrap_or(s);
            let s = s.strip_suffix('\'').unwrap_or(s);
            s.replace("''", "'")
        }
        _ => raw.to_string(),
    }
}

fn is_op(b: u8) -> bool {
    b"+-*/<>=~!@#%^&|`?:".contains(&b)
}

fn is_word_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_word(b: u8) -> bool {
    is_word_start(b) || b.is_ascii_digit() || b == b'$'
}

/// Тег долларовой строки на `at` (`$$` или `$tag$`), если он там есть.
fn dollar_tag(b: &[u8], at: usize) -> Option<usize> {
    let mut i = at + 1;
    if b.get(i) == Some(&b'$') {
        return Some(2);
    }
    if !b.get(i).copied().is_some_and(is_word_start) {
        return None;
    }
    while i < b.len() && (is_word_start(b[i]) || b[i].is_ascii_digit()) {
        i += 1;
    }
    (b.get(i) == Some(&b'$')).then_some(i + 1 - at)
}

/// Токены всего текста. Второе значение — найдено ли незакрытое.
pub fn tokenize(text: &str) -> (Vec<Token>, bool) {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut unterminated = false;
    let mut i = 0;
    let mut line_start = true;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line_start = true;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let at_line_start = line_start;
        line_start = false;
        // Мета-команда psql (`\connect db`, `\restrict …` в pg_dump) — до конца строки.
        if c == b'\\' && at_line_start {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'-' && b.get(i + 1) == Some(&b'-') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if depth > 0 {
                unterminated = true;
            }
            continue;
        }
        let start = i;
        let escape_string =
            (c == b'E' || c == b'e') && b.get(i + 1) == Some(&b'\'') && !prev_is_word(b, i);
        if c == b'\'' || escape_string {
            i += if escape_string { 2 } else { 1 };
            let mut closed = false;
            while i < b.len() {
                if escape_string && b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    closed = true;
                    break;
                }
                i += 1;
            }
            i = i.min(b.len());
            unterminated |= !closed;
            out.push(Token {
                kind: Kind::Str,
                start,
                end: i,
            });
            continue;
        }
        if c == b'"' {
            i += 1;
            let mut closed = false;
            while i < b.len() {
                if b[i] == b'"' {
                    if b.get(i + 1) == Some(&b'"') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    closed = true;
                    break;
                }
                i += 1;
            }
            unterminated |= !closed;
            out.push(Token {
                kind: Kind::Quoted,
                start,
                end: i,
            });
            continue;
        }
        if c == b'$' {
            if b.get(i + 1).is_some_and(u8::is_ascii_digit) {
                i += 1;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(Token {
                    kind: Kind::Num,
                    start,
                    end: i,
                });
                continue;
            }
            if let Some(len) = dollar_tag(b, i) {
                let tag = &text[i..i + len];
                let body = i + len;
                let end = match text[body..].find(tag) {
                    Some(pos) => body + pos + len,
                    None => {
                        unterminated = true;
                        b.len()
                    }
                };
                out.push(Token {
                    kind: Kind::Dollar,
                    start,
                    end,
                });
                i = end;
                continue;
            }
        }
        if is_word_start(c) {
            while i < b.len() && is_word(b[i]) {
                i += 1;
            }
            // Многобайтный символ: не резать посередине.
            while i < b.len() && !text.is_char_boundary(i) {
                i += 1;
            }
            out.push(Token {
                kind: Kind::Word,
                start,
                end: i,
            });
            continue;
        }
        if c.is_ascii_digit() {
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'.' || b[i] == b'_') {
                i += 1;
            }
            out.push(Token {
                kind: Kind::Num,
                start,
                end: i,
            });
            continue;
        }
        if is_op(c) {
            while i < b.len() && is_op(b[i]) {
                // `--` / `/*` внутри оператора — начало комментария.
                if (b[i] == b'-' && b.get(i + 1) == Some(&b'-'))
                    || (b[i] == b'/' && b.get(i + 1) == Some(&b'*'))
                {
                    break;
                }
                i += 1;
            }
            if i == start {
                i += 1;
            }
            out.push(Token {
                kind: Kind::Op,
                start,
                end: i,
            });
            continue;
        }
        // Пунктуация и всё прочее — по одному символу (с учётом UTF-8).
        i += 1;
        while i < b.len() && !text.is_char_boundary(i) {
            i += 1;
        }
        out.push(Token {
            kind: Kind::Punct,
            start,
            end: i,
        });
    }
    (out, unterminated)
}

fn prev_is_word(b: &[u8], i: usize) -> bool {
    i > 0 && is_word(b[i - 1])
}

fn is_word_eq(text: &str, t: &Token, word: &str) -> bool {
    t.kind == Kind::Word && text[t.start..t.end].eq_ignore_ascii_case(word)
}

/// Текст в операторы. Пустые операторы (`;;`) отбрасываются.
pub fn parse(text: &str) -> SqlFile {
    let (tokens, unterminated) = tokenize(text);
    let mut statements = Vec::new();
    let mut current = Statement::default();
    // Тело `BEGIN ATOMIC … END` (SQL-стандартное тело функции) содержит `;`.
    let mut atomic = false;
    for t in tokens {
        if t.kind == Kind::Punct && &text[t.start..t.end] == ";" && !atomic {
            if !current.tokens.is_empty() {
                statements.push(std::mem::take(&mut current));
            }
            continue;
        }
        if t.kind == Kind::Word {
            let n = current.tokens.len();
            if is_word_eq(text, &t, "atomic")
                && n > 0
                && is_word_eq(text, &current.tokens[n - 1], "begin")
            {
                atomic = true;
            } else if atomic && is_word_eq(text, &t, "end") {
                atomic = false;
            }
        }
        if !(t.kind == Kind::Punct && &text[t.start..t.end] == ";") {
            current.tokens.push(t);
        }
    }
    if !current.tokens.is_empty() {
        statements.push(current);
    }
    SqlFile {
        statements,
        unterminated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<Vec<String>> {
        parse(text)
            .statements
            .iter()
            .map(|s| s.tokens.iter().map(|t| value(text, t)).collect())
            .collect()
    }

    #[test]
    fn splits_statements_and_skips_comments() {
        let sql = "-- head; not a split\ncreate table a (id int); /* x; /* nested; */ y; */\nALTER TABLE \"A\" enable row level security;;";
        assert_eq!(
            words(sql),
            vec![
                vec!["create", "table", "a", "(", "id", "int", ")"],
                vec!["alter", "table", "A", "enable", "row", "level", "security"],
            ]
        );
    }

    #[test]
    fn strings_and_dollar_bodies_keep_semicolons() {
        let sql = "insert into t values ('a;b', E'c\\'d;', 'it''s');\n\
                   create function f() returns int as $body$ select 1; $body$ language sql;\n\
                   do $$ begin perform 1; end $$;";
        let w = words(sql);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0][5], "a;b");
        assert_eq!(w[0][9], "it's");
        assert!(w[1].iter().any(|t| t == "$body$ select 1; $body$"));
        assert_eq!(w[2][0], "do");
    }

    #[test]
    fn params_operators_and_psql_meta() {
        let sql = "\\connect postgres\nselect $1::text, a<>b, x->>'k' from t;";
        let w = words(sql);
        assert_eq!(w.len(), 1);
        assert_eq!(&w[0][..4], &["select", "$1", "::", "text"]);
        assert!(w[0].contains(&"<>".to_string()));
        assert!(w[0].contains(&"->>".to_string()));
    }

    #[test]
    fn begin_atomic_body_is_one_statement() {
        let sql = "create function f() returns int language sql begin atomic select 1; select 2; end; select 3;";
        assert_eq!(words(sql).len(), 2);
    }

    #[test]
    fn unterminated_is_flagged() {
        assert!(parse("select 'abc").unterminated);
        assert!(parse("do $$ begin").unterminated);
        assert!(parse("/* open").unterminated);
        assert!(!parse("select 'a''b';").unterminated);
    }

    #[test]
    fn identifiers_with_e_are_not_escape_strings() {
        // `type'x'` — слово `type` и строка, а не E-строка.
        let w = words("select date'2020-01-01', e'a\\'b';");
        assert_eq!(w[0][1], "date");
        assert_eq!(w[0][2], "2020-01-01");
        assert_eq!(w[0][4], "a\\'b");
    }
}
