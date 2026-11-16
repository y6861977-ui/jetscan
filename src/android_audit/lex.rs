//! Консервативный токенайзер Kotlin / Java / Groovy (Gradle-скрипты и исходники приложения).
//!
//! Что умеет: идентификаторы (в т. ч. Kotlin `` `в кавычках` ``), числа, строки `"…"` и тройные
//! `"""…"""` (Kotlin raw, Groovy, Java text block), `'…'` (символ в Kotlin/Java, строка в Groovy,
//! `'''…'''` в Groovy), шаблоны `$имя` и `${…}` (Kotlin, Groovy; в Java их нет), комментарии `//`,
//! `/* */` (в Kotlin — вложенные), shebang. Переводы строк — отдельные токены: в Gradle они
//! разделяют операторы.
//!
//! Чего не умеет и не притворяется: Groovy slashy-строки `/…/` (читаются как операторы деления),
//! вывод типов, разбор выражений. Незакрытая строка/комментарий не ломает разбор: токен
//! заканчивается концом строки/файла, а `Lexed::unterminated` считает такие случаи.
//! Рекурсии нет; время линейно по длине текста.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Kotlin,
    Java,
    Groovy,
}

impl Lang {
    fn templates(self) -> bool {
        self != Lang::Java
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ident,
    /// Строковый литерал; `text` — значение с раскрытыми escape-последовательностями.
    Str,
    /// Символьный литерал Kotlin/Java.
    Char,
    Num,
    Punct,
    Newline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    /// Байтовый диапазон в исходном тексте (для строк — вместе с кавычками).
    pub start: usize,
    pub end: usize,
    /// Ident/Num/Punct — как в тексте; Str/Char — значение (шаблоны оставлены как написаны).
    pub text: String,
    /// Str: байтовые диапазоны выражений шаблонов в исходном тексте (`name` у `$name`,
    /// содержимое `${…}` без скобок). Непусто — значение не литерал.
    pub templates: Vec<(usize, usize)>,
}

impl Token {
    pub fn is(&self, kind: Kind, text: &str) -> bool {
        self.kind == kind && self.text == text
    }

    pub fn is_punct(&self, text: &str) -> bool {
        self.is(Kind::Punct, text)
    }

    pub fn is_ident(&self, text: &str) -> bool {
        self.is(Kind::Ident, text)
    }

    /// Строка без шаблонов — известное на момент чтения значение.
    pub fn literal_str(&self) -> Option<&str> {
        (self.kind == Kind::Str && self.templates.is_empty()).then_some(self.text.as_str())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lexed {
    pub tokens: Vec<Token>,
    /// Байтовые диапазоны комментариев.
    pub comments: Vec<(usize, usize)>,
    /// Сколько строк/комментариев не закрыто (разметка рядом приблизительна).
    pub unterminated: usize,
}

impl Lexed {
    /// Токены без переводов строк (для правил по коду, где строки не важны).
    pub fn significant(&self) -> Vec<&Token> {
        self.tokens
            .iter()
            .filter(|t| t.kind != Kind::Newline)
            .collect()
    }
}

const TWO_CHAR: &[&str] = &[
    "->", "==", "!=", "+=", "-=", "?:", "?.", "::", "&&", "||", "<=", ">=", "..", "!!",
];

fn ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    lang: Lang,
    out: Lexed,
}

pub fn lex(text: &str, lang: Lang) -> Lexed {
    let mut lexer = Lexer {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        lang,
        out: Lexed::default(),
    };
    lexer.run();
    lexer.out
}

impl Lexer<'_> {
    fn at(&self, offset: usize) -> u8 {
        self.bytes.get(self.pos + offset).copied().unwrap_or(0)
    }

    fn push(&mut self, kind: Kind, start: usize, text: String, templates: Vec<(usize, usize)>) {
        self.out.tokens.push(Token {
            kind,
            start,
            end: self.pos,
            text,
            templates,
        });
    }

    fn run(&mut self) {
        if self.bytes.starts_with(b"#!") {
            let end = self.line_end(0);
            self.out.comments.push((0, end));
            self.pos = end;
        }
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            let start = self.pos;
            match b {
                b'\n' => {
                    self.pos += 1;
                    self.push(Kind::Newline, start, "\n".to_string(), Vec::new());
                }
                b' ' | b'\t' | b'\r' | 0x0c => self.pos += 1,
                b'/' if self.at(1) == b'/' => {
                    let end = self.line_end(self.pos);
                    self.out.comments.push((start, end));
                    self.pos = end;
                }
                b'/' if self.at(1) == b'*' => self.block_comment(),
                b'"' => self.double_quoted(),
                b'\'' => self.single_quoted(),
                b'`' if self.lang == Lang::Kotlin => {
                    self.pos += 1;
                    let close = self.bytes[self.pos..]
                        .iter()
                        .position(|&c| c == b'`' || c == b'\n');
                    match close {
                        Some(n) if self.bytes[self.pos + n] == b'`' => {
                            let name = self.text[self.pos..self.pos + n].to_string();
                            self.pos += n + 1;
                            self.push(Kind::Ident, start, name, Vec::new());
                        }
                        _ => self.push(Kind::Punct, start, "`".to_string(), Vec::new()),
                    }
                }
                b'0'..=b'9' => {
                    self.pos += 1;
                    while self.pos < self.bytes.len() {
                        let c = self.bytes[self.pos];
                        if c.is_ascii_alphanumeric() || c == b'_' {
                            self.pos += 1;
                        } else if c == b'.' && self.at(1).is_ascii_digit() {
                            self.pos += 2;
                        } else {
                            break;
                        }
                    }
                    let text = self.text[start..self.pos].to_string();
                    self.push(Kind::Num, start, text, Vec::new());
                }
                c if ident_start(c) => {
                    while self.pos < self.bytes.len() && ident_continue(self.bytes[self.pos]) {
                        self.pos += 1;
                    }
                    let text = self.text[start..self.pos].to_string();
                    self.push(Kind::Ident, start, text, Vec::new());
                }
                _ => {
                    let two = self.text.get(self.pos..self.pos + 2).unwrap_or("");
                    let punct = if TWO_CHAR.contains(&two) {
                        self.pos += 2;
                        two.to_string()
                    } else {
                        self.pos += 1;
                        (b as char).to_string()
                    };
                    self.push(Kind::Punct, start, punct, Vec::new());
                }
            }
        }
    }

    fn line_end(&self, from: usize) -> usize {
        self.bytes[from..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(self.bytes.len(), |n| from + n)
    }

    fn block_comment(&mut self) {
        let start = self.pos;
        self.pos += 2;
        let mut depth = 1usize;
        while self.pos < self.bytes.len() {
            if self.at(0) == b'*' && self.at(1) == b'/' {
                self.pos += 2;
                depth -= 1;
                if depth == 0 {
                    self.out.comments.push((start, self.pos));
                    return;
                }
            } else if self.lang == Lang::Kotlin && self.at(0) == b'/' && self.at(1) == b'*' {
                self.pos += 2;
                depth += 1;
            } else {
                self.pos += 1;
            }
        }
        self.out.unterminated += 1;
        self.out.comments.push((start, self.pos));
    }

    /// Escape-последовательность после `\` (позиция на `\`). Возвращает символ значения.
    fn escape(&mut self) -> Option<char> {
        self.pos += 1;
        let c = self.at(0);
        let value = match c {
            b'n' => '\n',
            b't' => '\t',
            b'r' => '\r',
            b'b' => '\u{8}',
            b'0' => '\0',
            b'u' => {
                let hex = self.text.get(self.pos + 1..self.pos + 5).unwrap_or("");
                if hex.len() == 4 && hex.bytes().all(|h| h.is_ascii_hexdigit()) {
                    self.pos += 5;
                    return u32::from_str_radix(hex, 16).ok().and_then(char::from_u32);
                }
                'u'
            }
            0 => return None,
            _ => {
                // Любой другой символ (в т. ч. многобайтовый) — как есть.
                let ch = self.text[self.pos..].chars().next()?;
                self.pos += ch.len_utf8();
                return Some(ch);
            }
        };
        self.pos += 1;
        Some(value)
    }

    /// Шаблон `$name` / `${…}` внутри строки (позиция на `$`). `true` — шаблон был.
    fn template(&mut self, value: &mut String, spans: &mut Vec<(usize, usize)>) -> bool {
        if !self.lang.templates() {
            return false;
        }
        let next = self.at(1);
        if next == b'{' {
            let open = self.pos;
            let inner_start = self.pos + 2;
            let mut i = inner_start;
            let mut depth = 1usize;
            while i < self.bytes.len() {
                match self.bytes[i] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    b'"' | b'\'' => {
                        let quote = self.bytes[i];
                        i += 1;
                        while i < self.bytes.len()
                            && self.bytes[i] != quote
                            && self.bytes[i] != b'\n'
                        {
                            if self.bytes[i] == b'\\' {
                                i += 1;
                            }
                            i += 1;
                        }
                    }
                    b'\n' if self.lang == Lang::Groovy => break,
                    _ => {}
                }
                i += 1;
            }
            let end = i.min(self.bytes.len());
            spans.push((inner_start, end));
            let close = (end + 1).min(self.bytes.len());
            value.push_str(&self.text[open..close]);
            self.pos = close;
            true
        } else if ident_start(next) && next < 0x80 {
            let name_start = self.pos + 1;
            let mut i = name_start;
            while i < self.bytes.len() && ident_continue(self.bytes[i]) && self.bytes[i] < 0x80 {
                i += 1;
            }
            spans.push((name_start, i));
            value.push_str(&self.text[self.pos..i]);
            self.pos = i;
            true
        } else {
            false
        }
    }

    fn double_quoted(&mut self) {
        let start = self.pos;
        let triple = self.text[self.pos..].starts_with("\"\"\"");
        let mut value = String::new();
        let mut spans = Vec::new();
        if triple {
            self.pos += 3;
            loop {
                if self.pos >= self.bytes.len() {
                    self.out.unterminated += 1;
                    break;
                }
                if self.text[self.pos..].starts_with("\"\"\"") {
                    // `""""` в конце: лишние кавычки — часть значения.
                    let mut run = 0;
                    while self.at(run) == b'"' {
                        run += 1;
                    }
                    for _ in 0..run - 3 {
                        value.push('"');
                    }
                    self.pos += run;
                    break;
                }
                let c = self.at(0);
                if c == b'$' && self.template(&mut value, &mut spans) {
                    continue;
                }
                // Kotlin raw: escape нет; Groovy/Java: есть.
                if c == b'\\' && self.lang != Lang::Kotlin {
                    if let Some(ch) = self.escape() {
                        value.push(ch);
                    }
                    continue;
                }
                let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
                value.push(ch);
                self.pos += ch.len_utf8().max(1);
            }
        } else {
            self.pos += 1;
            loop {
                let c = self.at(0);
                if self.pos >= self.bytes.len() || c == b'\n' {
                    self.out.unterminated += 1;
                    break;
                }
                if c == b'"' {
                    self.pos += 1;
                    break;
                }
                if c == b'\\' {
                    if let Some(ch) = self.escape() {
                        value.push(ch);
                    }
                    continue;
                }
                if c == b'$' && self.template(&mut value, &mut spans) {
                    continue;
                }
                let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
                value.push(ch);
                self.pos += ch.len_utf8().max(1);
            }
        }
        self.push(Kind::Str, start, value, spans);
    }

    fn single_quoted(&mut self) {
        let start = self.pos;
        if self.lang == Lang::Groovy && self.text[self.pos..].starts_with("'''") {
            self.pos += 3;
            let mut value = String::new();
            loop {
                if self.pos >= self.bytes.len() {
                    self.out.unterminated += 1;
                    break;
                }
                if self.text[self.pos..].starts_with("'''") {
                    self.pos += 3;
                    break;
                }
                if self.at(0) == b'\\' {
                    if let Some(ch) = self.escape() {
                        value.push(ch);
                    }
                    continue;
                }
                let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
                value.push(ch);
                self.pos += ch.len_utf8().max(1);
            }
            self.push(Kind::Str, start, value, Vec::new());
            return;
        }
        self.pos += 1;
        let mut value = String::new();
        loop {
            let c = self.at(0);
            if self.pos >= self.bytes.len() || c == b'\n' {
                self.out.unterminated += 1;
                break;
            }
            if c == b'\'' {
                self.pos += 1;
                break;
            }
            if c == b'\\' {
                if let Some(ch) = self.escape() {
                    value.push(ch);
                }
                continue;
            }
            let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
            value.push(ch);
            self.pos += ch.len_utf8().max(1);
        }
        let kind = if self.lang == Lang::Groovy {
            Kind::Str
        } else {
            Kind::Char
        };
        self.push(kind, start, value, Vec::new());
    }
}

/// Какие байты текста — код (не комментарий и не литерал): для фрагментов и поиска по коду.
pub fn is_in_comment(lexed: &Lexed, byte: usize) -> bool {
    lexed
        .comments
        .iter()
        .any(|&(start, end)| byte >= start && byte < end)
}

/// Идентификаторы внутри выражений шаблонов строки (`"token=$token"`, `"${user.password}"`).
pub fn template_idents(text: &str, token: &Token, lang: Lang) -> Vec<Token> {
    let mut out = Vec::new();
    for &(start, end) in &token.templates {
        let Some(inner) = text.get(start..end) else {
            continue;
        };
        for mut t in lex(inner, lang).tokens {
            t.start += start;
            t.end += start;
            out.push(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str, lang: Lang) -> Vec<(Kind, String)> {
        lex(text, lang)
            .tokens
            .into_iter()
            .map(|t| (t.kind, t.text))
            .collect()
    }

    #[test]
    fn idents_numbers_punct_and_newlines() {
        let toks = kinds("a.b = 34\nc += 1.5f ?: x?.y", Lang::Kotlin);
        let texts: Vec<&str> = toks.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            texts,
            vec![
                "a", ".", "b", "=", "34", "\n", "c", "+=", "1.5f", "?:", "x", "?.", "y"
            ]
        );
        assert_eq!(toks[5].0, Kind::Newline);
        assert_eq!(toks[4].0, Kind::Num);
    }

    #[test]
    fn comments_are_not_tokens_and_kotlin_nests() {
        let l = lex("a /* x /* y */ z */ b // c\nd", Lang::Kotlin);
        let texts: Vec<&str> = l.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, vec!["a", "b", "\n", "d"]);
        assert_eq!(l.comments.len(), 2);
        // В Java вложенности нет: `z */` — код.
        let l = lex("a /* x /* y */ z */ b", Lang::Java);
        let texts: Vec<&str> = l.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, vec!["a", "z", "*", "/", "b"]);
    }

    #[test]
    fn strings_escapes_and_templates() {
        let text = r#"x("a\"b\n", "t=$token ${u.password}", 'q')"#;
        let l = lex(text, Lang::Kotlin);
        let strs: Vec<&Token> = l.tokens.iter().filter(|t| t.kind == Kind::Str).collect();
        assert_eq!(strs[0].text, "a\"b\n");
        assert!(strs[0].templates.is_empty());
        assert_eq!(strs[1].templates.len(), 2);
        let inner = template_idents(text, strs[1], Lang::Kotlin);
        let names: Vec<&str> = inner
            .iter()
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(names, vec!["token", "u", "password"]);
        assert_eq!(&text[inner[0].start..inner[0].end], "token");
        let ch = l.tokens.iter().find(|t| t.kind == Kind::Char).unwrap();
        assert_eq!(ch.text, "q");
    }

    #[test]
    fn java_has_no_templates_and_groovy_single_quotes_are_strings() {
        let l = lex(r#"s = "$notATemplate""#, Lang::Java);
        assert!(l.tokens[2].templates.is_empty());
        assert_eq!(l.tokens[2].text, "$notATemplate");
        let l = lex("storePassword 'abc'", Lang::Groovy);
        assert_eq!(l.tokens[1].literal_str(), Some("abc"));
        let l = lex("x = '''multi\nline'''", Lang::Groovy);
        assert_eq!(l.tokens[2].literal_str(), Some("multi\nline"));
    }

    #[test]
    fn raw_strings_keep_backslashes_in_kotlin() {
        let l = lex("val r = \"\"\"a\\nb\"\"\"\"", Lang::Kotlin);
        assert_eq!(l.tokens[3].text, "a\\nb\"");
        let l = lex("String t = \"\"\"\n  a\\tb\"\"\";", Lang::Java);
        assert_eq!(l.tokens[3].text, "\n  a\tb");
    }

    #[test]
    fn unterminated_literals_are_counted_and_recover_at_line_end() {
        let l = lex("a = \"open\nb = 1", Lang::Kotlin);
        assert_eq!(l.unterminated, 1);
        let texts: Vec<&str> = l.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(texts, vec!["a", "=", "open", "\n", "b", "=", "1"]);
        let l = lex("a /* never closed", Lang::Kotlin);
        assert_eq!(l.unterminated, 1);
        assert_eq!(l.tokens.len(), 1);
    }

    #[test]
    fn backtick_idents_and_unicode() {
        let l = lex("fun `my test`() { val имя = 1 }", Lang::Kotlin);
        assert_eq!(l.tokens[1].text, "my test");
        assert!(l.tokens.iter().any(|t| t.is_ident("имя")));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for text in [
            "\"\\",
            "\"\\u12",
            "'",
            "\"${",
            "\"${\"",
            "\"\"\"$",
            "`",
            "/*/",
            "\u{feff}é\"é\\é",
        ] {
            for lang in [Lang::Kotlin, Lang::Java, Lang::Groovy] {
                let _ = lex(text, lang);
            }
        }
    }
}
