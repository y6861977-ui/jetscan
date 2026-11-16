//! Консервативный токенайзер Swift / Objective-C (не парсер).
//!
//! Swift: идентификаторы (в т. ч. `` `в кавычках` `` и `$0`), числа, строки `"…"`, многострочные
//! `"""…"""`, raw-строки `#"…"#` / `##"…"##` (и многострочные), интерполяция `\(…)` / `\#(…)` (диапазоны
//! выражений сохраняются), комментарии `//` и вложенные `/* */`, директивы `#if/#elseif/#else/#endif`.
//! Objective-C: `@"…"`, `"…"`, `'c'`, комментарии без вложенности, строки препроцессора
//! (`#if`, `#ifdef`, `#import`, `#define`, … до конца строки с учётом `\`-переноса).
//!
//! Для каждого токена считается «только в debug-сборке»: внутри ветки `#if DEBUG` / `#ifdef DEBUG` (или
//! `#else` у `#if !DEBUG`). Других условий компиляции не вычисляем.
//!
//! Чего не умеет и не притворяется: regex-литералы Swift 5.7 (`/…/`, `#/…/#` читаются как операторы),
//! макросы препроцессора (тело `#define` пропускается), вывод типов. Незакрытая строка/комментарий не
//! ломает разбор: токен заканчивается концом строки/файла, а `Lexed::unterminated` считает такие случаи.
//! Рекурсии нет; время линейно по длине текста.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Swift,
    ObjC,
}

impl Lang {
    pub fn label(self) -> &'static str {
        match self {
            Lang::Swift => "swift",
            Lang::ObjC => "objc",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ident,
    /// Строковый литерал; `text` — значение (escape раскрыты, интерполяция оставлена как написана).
    Str,
    Char,
    Num,
    Punct,
    /// Строка директивы (`#if DEBUG`, `#import <X/X.h>`); `text` — без комментариев.
    Directive,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    /// Байтовый диапазон в исходнике (для строк — вместе с кавычками).
    pub start: usize,
    pub end: usize,
    pub text: String,
    /// Str: байтовые диапазоны выражений интерполяции `\(…)`. Непусто — значение не литерал.
    pub interps: Vec<(usize, usize)>,
    /// Токен в ветке, которая компилируется только в debug (`#if DEBUG`).
    pub debug: bool,
}

impl Token {
    pub fn is_punct(&self, text: &str) -> bool {
        self.kind == Kind::Punct && self.text == text
    }

    pub fn is_ident(&self, text: &str) -> bool {
        self.kind == Kind::Ident && self.text == text
    }

    /// Строка без интерполяции.
    pub fn literal_str(&self) -> Option<&str> {
        (self.kind == Kind::Str && self.interps.is_empty()).then_some(self.text.as_str())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lexed {
    pub tokens: Vec<Token>,
    /// Байтовые диапазоны комментариев.
    pub comments: Vec<(usize, usize)>,
    pub unterminated: usize,
}

const PUNCT3: &[&str] = &["...", "..<", "===", "!=="];
const PUNCT2: &[&str] = &[
    "->", "==", "!=", "&&", "||", "<=", ">=", "??", "?.", "+=", "-=", "*=", "/=", "::", "<<", ">>",
];

fn ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$' || b >= 0x80
}

fn ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80
}

const DIRECTIVES: &[&str] = &[
    "if",
    "elseif",
    "else",
    "endif",
    "ifdef",
    "ifndef",
    "elif",
    "import",
    "include",
    "define",
    "undef",
    "pragma",
    "error",
    "warning",
    "line",
    "sourceLocation",
];

struct Lexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    lang: Lang,
    out: Lexed,
    /// Начало строки: только пробелы с начала строки до `pos`.
    line_start: bool,
}

pub fn lex(text: &str, lang: Lang) -> Lexed {
    let mut lexer = Lexer {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        lang,
        out: Lexed::default(),
        line_start: true,
    };
    lexer.run();
    let mut out = lexer.out;
    mark_debug(&mut out.tokens);
    out
}

impl Lexer<'_> {
    fn at(&self, offset: usize) -> u8 {
        self.bytes.get(self.pos + offset).copied().unwrap_or(0)
    }

    fn push(&mut self, kind: Kind, start: usize, text: String, interps: Vec<(usize, usize)>) {
        self.out.tokens.push(Token {
            kind,
            start,
            end: self.pos,
            text,
            interps,
            debug: false,
        });
    }

    fn line_end(&self, from: usize) -> usize {
        self.bytes[from..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(self.bytes.len(), |n| from + n)
    }

    fn run(&mut self) {
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            let start = self.pos;
            let at_line_start = self.line_start;
            self.line_start = false;
            match b {
                b'\n' => {
                    self.pos += 1;
                    self.line_start = true;
                }
                b' ' | b'\t' | b'\r' | 0x0c => {
                    self.pos += 1;
                    self.line_start = at_line_start;
                }
                b'/' if self.at(1) == b'/' => {
                    let end = self.line_end(self.pos);
                    self.out.comments.push((start, end));
                    self.pos = end;
                }
                b'/' if self.at(1) == b'*' => {
                    self.block_comment();
                    self.line_start = at_line_start;
                }
                b'#' if at_line_start && self.directive() => {}
                b'#' if self.lang == Lang::Swift && matches!(self.at(1), b'#' | b'"') => {
                    let mut hashes = 0;
                    while self.at(hashes) == b'#' {
                        hashes += 1;
                    }
                    if self.at(hashes) == b'"' {
                        self.pos += hashes;
                        self.string(start, hashes);
                    } else {
                        self.pos += 1;
                        self.push(Kind::Punct, start, "#".to_string(), Vec::new());
                    }
                }
                b'#' if ident_start(self.at(1)) => {
                    self.pos += 1;
                    while self.pos < self.bytes.len() && ident_continue(self.bytes[self.pos]) {
                        self.pos += 1;
                    }
                    let text = self.text[start..self.pos].to_string();
                    self.push(Kind::Ident, start, text, Vec::new());
                }
                b'"' => self.string(start, 0),
                b'@' if self.lang == Lang::ObjC && self.at(1) == b'"' => {
                    self.pos += 1;
                    self.string(start, 0);
                }
                b'\'' if self.lang == Lang::ObjC => self.char_literal(),
                b'`' if self.lang == Lang::Swift => {
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
                    let rest = &self.text[self.pos..];
                    let punct = PUNCT3
                        .iter()
                        .chain(PUNCT2.iter())
                        .find(|p| rest.starts_with(**p))
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| {
                            rest.chars().next().map(String::from).unwrap_or_default()
                        });
                    self.pos += punct.len().max(1);
                    self.push(Kind::Punct, start, punct, Vec::new());
                }
            }
        }
    }

    /// `#word …` в начале строки. `true` — это директива, строка поглощена.
    fn directive(&mut self) -> bool {
        let mut k = self.pos + 1;
        while k < self.bytes.len() && matches!(self.bytes[k], b' ' | b'\t') {
            k += 1;
        }
        let word_start = k;
        while k < self.bytes.len() && self.bytes[k].is_ascii_alphabetic() {
            k += 1;
        }
        let word = &self.text[word_start..k];
        if !DIRECTIVES.contains(&word) {
            return false;
        }
        // В Swift `#warning("…")` / `#error("…")` — тоже директивы, но их строки — код: пропускаем строку.
        let start = self.pos;
        let mut end = self.line_end(start);
        if self.lang == Lang::ObjC {
            loop {
                let line = self.text[start..end].trim_end_matches('\r');
                if line.ends_with('\\') && end < self.bytes.len() {
                    end = self.line_end(end + 1);
                } else {
                    break;
                }
            }
        }
        // Комментарий в строке директивы — комментарий.
        let line = &self.text[start..end];
        let text = match line.find("//") {
            Some(c) => {
                self.out.comments.push((start + c, end));
                &line[..c]
            }
            None => line,
        };
        let text = match text.find("/*") {
            Some(c) => &text[..c],
            None => text,
        };
        let text = text.trim().to_string();
        self.pos = end;
        self.push(Kind::Directive, start, text, Vec::new());
        true
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
            } else if self.lang == Lang::Swift && self.at(0) == b'/' && self.at(1) == b'*' {
                self.pos += 2;
                depth += 1;
            } else {
                self.pos += 1;
            }
        }
        self.out.unterminated += 1;
        self.out.comments.push((start, self.pos));
    }

    /// Escape после `\` (позиция на символе после `\`). Возвращает символ значения.
    fn escape(&mut self, value: &mut String) {
        let c = self.at(0);
        match c {
            b'n' => value.push('\n'),
            b't' => value.push('\t'),
            b'r' => value.push('\r'),
            b'0' => value.push('\0'),
            b'u' if self.at(1) == b'{' => {
                let close = self.text[self.pos..].find('}').filter(|&n| n <= 10);
                if let Some(n) = close {
                    let hex = &self.text[self.pos + 2..self.pos + n];
                    if let Some(ch) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
                        value.push(ch);
                    }
                    self.pos += n + 1;
                    return;
                }
                value.push('u');
            }
            0 => return,
            _ => {
                let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
                value.push(ch);
                self.pos += ch.len_utf8();
                return;
            }
        }
        self.pos += 1;
    }

    /// Интерполяция `(…)` (позиция на `(`): до парной `)`, учитывая вложенные строки.
    fn interpolation(
        &mut self,
        value: &mut String,
        spans: &mut Vec<(usize, usize)>,
        multiline: bool,
    ) {
        let open = self.pos;
        let inner = self.pos + 1;
        let mut i = inner;
        let mut depth = 1usize;
        while i < self.bytes.len() {
            match self.bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                b'"' => {
                    i += 1;
                    while i < self.bytes.len() && self.bytes[i] != b'"' && self.bytes[i] != b'\n' {
                        if self.bytes[i] == b'\\' {
                            i += 1;
                        }
                        i += 1;
                    }
                }
                b'\n' if !multiline => break,
                _ => {}
            }
            i += 1;
        }
        let end = i.min(self.bytes.len());
        spans.push((inner, end));
        let close = (end + 1).min(self.bytes.len());
        value.push('\\');
        value.push_str(&self.text[open..close]);
        self.pos = close;
    }

    /// Строка: позиция на первой `"`; `hashes` — число `#` raw-строки Swift (уже пропущены).
    fn string(&mut self, start: usize, hashes: usize) {
        let swift = self.lang == Lang::Swift;
        let multiline = swift && self.text[self.pos..].starts_with("\"\"\"");
        self.pos += if multiline { 3 } else { 1 };
        let closing: String = format!(
            "{}{}",
            if multiline { "\"\"\"" } else { "\"" },
            "#".repeat(hashes)
        );
        let escape_seq: String = format!("\\{}", "#".repeat(hashes));
        let mut value = String::new();
        let mut spans = Vec::new();
        loop {
            if self.pos >= self.bytes.len() {
                self.out.unterminated += 1;
                break;
            }
            let c = self.at(0);
            if c == b'\n' && !multiline {
                self.out.unterminated += 1;
                break;
            }
            if self.text[self.pos..].starts_with(&closing) {
                self.pos += closing.len();
                break;
            }
            if c == b'\\' && self.text[self.pos..].starts_with(&escape_seq) {
                self.pos += escape_seq.len();
                if swift && self.at(0) == b'(' {
                    self.interpolation(&mut value, &mut spans, multiline);
                } else {
                    self.escape(&mut value);
                }
                continue;
            }
            let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
            value.push(ch);
            self.pos += ch.len_utf8().max(1);
        }
        self.push(Kind::Str, start, value, spans);
    }

    fn char_literal(&mut self) {
        let start = self.pos;
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
                self.pos += 1;
                self.escape(&mut value);
                continue;
            }
            let ch = self.text[self.pos..].chars().next().unwrap_or('\0');
            value.push(ch);
            self.pos += ch.len_utf8().max(1);
        }
        self.push(Kind::Char, start, value, Vec::new());
    }
}

/// Условие директивы: `Some(true)` — ветка только для debug (`DEBUG`, `DEBUG && X`, `defined(DEBUG)`),
/// `Some(false)` — ветка только не-debug (`!DEBUG`), `None` — не знаем.
fn debug_condition(cond: &str) -> Option<bool> {
    let compact: String = cond.chars().filter(|c| !c.is_whitespace()).collect();
    let compact = compact
        .replace("defined(DEBUG)", "DEBUG")
        .replace("(DEBUG)", "DEBUG");
    if compact.contains("||") {
        return None;
    }
    let mentions = |s: &str, at: usize| {
        let before = s[..at].chars().last();
        let after = s[at + 5..].chars().next();
        !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
    };
    let mut result = None;
    for (at, _) in compact.match_indices("DEBUG") {
        if !mentions(&compact, at) {
            continue;
        }
        let negated = compact[..at].ends_with('!');
        // `DEBUG == 0` / `DEBUG=0` — как `!DEBUG`.
        let zero = compact[at + 5..].starts_with("==0");
        result = Some(!(negated || zero));
    }
    result
}

/// Отмечает токены веток `#if DEBUG`. Стек кадров: (ветка debug-only, `#else` debug-only).
fn mark_debug(tokens: &mut [Token]) {
    let mut stack: Vec<(bool, bool)> = Vec::new();
    for t in tokens.iter_mut() {
        if t.kind == Kind::Directive {
            let body = t.text.trim_start_matches('#').trim_start();
            let (word, rest) = body
                .split_once(|c: char| c.is_whitespace() || c == '(' || c == '!')
                .map_or((body, ""), |(w, _)| (w, &body[w.len()..]));
            match word {
                "if" => {
                    let c = debug_condition(rest);
                    stack.push((c == Some(true), c == Some(false)));
                }
                "ifdef" => {
                    let d = rest.trim() == "DEBUG";
                    stack.push((d, false));
                }
                "ifndef" => {
                    let d = rest.trim() == "DEBUG";
                    stack.push((false, d));
                }
                "elseif" | "elif" => {
                    if let Some(top) = stack.last_mut() {
                        *top = (debug_condition(rest) == Some(true), false);
                    }
                }
                "else" => {
                    if let Some(top) = stack.last_mut() {
                        *top = (top.1, false);
                    }
                }
                "endif" => {
                    stack.pop();
                }
                _ => {}
            }
            continue;
        }
        t.debug = stack.iter().any(|(d, _)| *d);
    }
}

/// Идентификаторы внутри интерполяции строки (`"token=\(token)"`).
pub fn interp_idents(text: &str, token: &Token, lang: Lang) -> Vec<Token> {
    let mut out = Vec::new();
    for &(start, end) in &token.interps {
        let Some(inner) = text.get(start..end) else {
            continue;
        };
        for mut t in lex(inner, lang).tokens {
            t.start += start;
            t.end += start;
            t.debug = token.debug;
            out.push(t);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(text: &str, lang: Lang) -> Vec<String> {
        lex(text, lang).tokens.into_iter().map(|t| t.text).collect()
    }

    #[test]
    fn swift_tokens_and_comments() {
        let l = lex(
            "let a = b?.c ?? 1.5 /* x /* y */ z */ // c\nf(x...)",
            Lang::Swift,
        );
        let t: Vec<&str> = l.tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(
            t,
            vec![
                "let", "a", "=", "b", "?.", "c", "??", "1.5", "f", "(", "x", "...", ")"
            ]
        );
        assert_eq!(l.comments.len(), 2);
    }

    #[test]
    fn swift_strings_interpolation_and_raw() {
        let text = r##"print("t=\(token) \(user.password)", "a\"b\n", #"raw \(x) "q""#, #"r=\#(secret)"#)"##;
        let l = lex(text, Lang::Swift);
        let strs: Vec<&Token> = l.tokens.iter().filter(|t| t.kind == Kind::Str).collect();
        assert_eq!(strs.len(), 4);
        assert_eq!(strs[0].interps.len(), 2);
        let names: Vec<String> = interp_idents(text, strs[0], Lang::Swift)
            .into_iter()
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| t.text)
            .collect();
        assert_eq!(names, vec!["token", "user", "password"]);
        assert_eq!(strs[1].literal_str(), Some("a\"b\n"));
        assert_eq!(strs[2].literal_str(), Some("raw \\(x) \"q\""));
        assert_eq!(strs[3].interps.len(), 1);
        assert_eq!(&text[strs[3].interps[0].0..strs[3].interps[0].1], "secret");
    }

    #[test]
    fn swift_multiline_strings() {
        let text = "let s = \"\"\"\n  line \"one\"\n  \\(name)\n  \"\"\"\nlet t = 1";
        let l = lex(text, Lang::Swift);
        let s = l.tokens.iter().find(|t| t.kind == Kind::Str).unwrap();
        assert!(s.text.contains("line \"one\""));
        assert_eq!(s.interps.len(), 1);
        assert!(l.tokens.iter().any(|t| t.is_ident("t")));
        assert_eq!(l.unterminated, 0);
    }

    #[test]
    fn objc_strings_chars_and_directives() {
        let text = "#import <Foundation/Foundation.h>\n#define LOG(x) NSLog(x) \\\n  more\nNSString *s = @\"a\\\"b\"; char c = 'x';\n[d setObject:s forKey:@\"token\"];";
        let l = lex(text, Lang::ObjC);
        let kinds: Vec<Kind> = l.tokens.iter().map(|t| t.kind).collect();
        assert_eq!(kinds[0], Kind::Directive);
        assert_eq!(kinds[1], Kind::Directive);
        assert!(!l.tokens.iter().any(|t| t.is_ident("more")));
        let strs: Vec<&str> = l
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Str)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(strs, vec!["a\"b", "token"]);
        assert!(
            l.tokens
                .iter()
                .any(|t| t.kind == Kind::Char && t.text == "x")
        );
    }

    #[test]
    fn debug_regions() {
        let text = "a\n#if DEBUG\nb\n#else\nc\n#endif\n#if !DEBUG\nd\n#else\ne\n#endif\n#if DEBUG || BETA\nf\n#endif\n#if os(iOS)\n #if DEBUG\n g\n #endif\nh\n#endif";
        let l = lex(text, Lang::Swift);
        let debug: Vec<(&str, bool)> = l
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| (t.text.as_str(), t.debug))
            .collect();
        assert_eq!(
            debug,
            vec![
                ("a", false),
                ("b", true),
                ("c", false),
                ("d", false),
                ("e", true),
                ("f", false),
                ("g", true),
                ("h", false)
            ]
        );
        let objc = lex(
            "#ifdef DEBUG\nx\n#endif\n#ifndef DEBUG\ny\n#else\nz\n#endif\n#if defined(DEBUG) && DEBUG\nw\n#endif",
            Lang::ObjC,
        );
        let debug: Vec<bool> = objc
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| t.debug)
            .collect();
        assert_eq!(debug, vec![true, false, true, true]);
    }

    #[test]
    fn swift_hash_keywords_are_idents() {
        let t = texts("if #available(iOS 15, *) { x = #selector(f) }", Lang::Swift);
        assert!(t.contains(&"#available".to_string()));
        assert!(t.contains(&"#selector".to_string()));
    }

    #[test]
    fn unterminated_and_hostile_input() {
        let l = lex("let a = \"open\nlet b = 1", Lang::Swift);
        assert_eq!(l.unterminated, 1);
        assert!(l.tokens.iter().any(|t| t.is_ident("b")));
        for text in [
            "\"\\",
            "\"\\u{",
            "\"\\(",
            "\"\"\"",
            "#\"",
            "##",
            "#",
            "`",
            "/*/",
            "@\"",
            "'",
            "\u{feff}é\"é\\é",
            "#if",
            "#if DEBUG",
            "#endif\n#endif",
            "\"\\(\"",
            "#\"\\#(",
        ] {
            for lang in [Lang::Swift, Lang::ObjC] {
                let _ = lex(text, lang);
            }
        }
    }
}
