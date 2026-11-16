//! Property lists: XML (`<plist>…</plist>`, через текстовый XML-читатель `android_audit::xml` — без
//! DTD и внешних сущностей вообще) и старый ASCII-формат OpenStep (`{ key = value; list = (a, b); }`,
//! в нём записан `project.pbxproj`). Двоичный plist (`bplist00`) не разбирается: читатель файлов
//! отдаёт его отдельным видом, а правила становятся `partial` с путём (решение: исходные Info.plist и
//! .entitlements в проектах почти всегда XML, а свой разбор двоичного формата — лишняя поверхность).
//!
//! У каждого значения и ключа — строка и колонка в исходнике. Ошибка синтаксиса — `Err` с позицией
//! (правила по файлу — `partial`, не «чисто»). Глубина и число узлов ограничены.

use crate::android_audit::xml::{self, XmlElement};
use crate::web_audit::location::LineIndex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Bool(bool),
    /// `<integer>`, `<real>`, `<date>` — как написано.
    Scalar(String),
    /// `<data>` / `<…hex…>`: содержимое не храним.
    Data,
    Array(Vec<Node>),
    Dict(Vec<(Key, Node)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    pub line: u32,
    pub column: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub value: Value,
    pub line: u32,
    pub column: u32,
}

impl Node {
    pub fn get(&self, key: &str) -> Option<&Node> {
        self.entry(key).map(|(_, n)| n)
    }

    pub fn entry(&self, key: &str) -> Option<(&Key, &Node)> {
        match &self.value {
            Value::Dict(entries) => entries
                .iter()
                .find(|(k, _)| k.name == key)
                .map(|(k, n)| (k, n)),
            _ => None,
        }
    }

    pub fn entries(&self) -> &[(Key, Node)] {
        match &self.value {
            Value::Dict(entries) => entries,
            _ => &[],
        }
    }

    pub fn items(&self) -> &[Node] {
        match &self.value {
            Value::Array(items) => items,
            _ => &[],
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// `<true/>`/`<false/>`; строка `YES`/`NO`/`true`/`false`/`1`/`0` (так пишут в ASCII-plist и
    /// иногда в XML) — тоже. Иное — `None`.
    pub fn as_bool(&self) -> Option<bool> {
        match &self.value {
            Value::Bool(b) => Some(*b),
            Value::Str(s) | Value::Scalar(s) => match s.trim().to_ascii_lowercase().as_str() {
                "yes" | "true" | "1" => Some(true),
                "no" | "false" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlistError {
    pub line: u32,
    pub column: u32,
    pub what: String,
}

impl PlistError {
    pub fn describe(&self) -> String {
        format!(
            "property list is malformed at {}:{}: {}",
            self.line, self.column, self.what
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plist {
    pub root: Node,
    /// Замечания разбора (пропущенный DOCTYPE, нераскрытые сущности).
    pub issues: Vec<String>,
}

/// Разбор по первому значимому символу: `<` — XML, иначе ASCII.
pub fn parse(text: &str) -> Result<Plist, PlistError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim_start().starts_with('<') {
        parse_xml(text)
    } else {
        parse_ascii(text)
    }
}

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 4_000_000;

fn parse_xml(text: &str) -> Result<Plist, PlistError> {
    let doc = xml::parse(text, 0, &xml::Limits::default()).map_err(|e| PlistError {
        line: e.line,
        column: e.column,
        what: e.what,
    })?;
    let root = if doc.root.local == "plist" {
        doc.root.children.first().ok_or(PlistError {
            line: doc.root.pos.line,
            column: doc.root.pos.column,
            what: "<plist> is empty".to_string(),
        })?
    } else {
        &doc.root
    };
    let root = convert(root, 0)?;
    Ok(Plist {
        root,
        issues: doc.issues,
    })
}

fn convert(e: &XmlElement, depth: usize) -> Result<Node, PlistError> {
    let err = |what: &str| PlistError {
        line: e.pos.line,
        column: e.pos.column,
        what: what.to_string(),
    };
    if depth > MAX_DEPTH {
        return Err(err("nesting is too deep"));
    }
    let value = match e.local.as_str() {
        "string" => Value::Str(e.text.clone()),
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "integer" | "real" | "date" => Value::Scalar(e.text.trim().to_string()),
        "data" => Value::Data,
        "array" => Value::Array(
            e.children
                .iter()
                .map(|c| convert(c, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        "dict" => {
            let mut entries = Vec::new();
            let mut it = e.children.iter();
            while let Some(k) = it.next() {
                if k.local != "key" {
                    return Err(PlistError {
                        line: k.pos.line,
                        column: k.pos.column,
                        what: format!(
                            "expected <key> in <dict>, found <{}>",
                            crate::ui::sanitize_line(&k.local)
                        ),
                    });
                }
                let v = it.next().ok_or(PlistError {
                    line: k.pos.line,
                    column: k.pos.column,
                    what: "<key> without a value".to_string(),
                })?;
                entries.push((
                    Key {
                        name: k.text.clone(),
                        line: k.pos.line,
                        column: k.pos.column,
                    },
                    convert(v, depth + 1)?,
                ));
            }
            Value::Dict(entries)
        }
        other => {
            return Err(err(&format!(
                "unknown property list element <{}>",
                crate::ui::sanitize_line(other)
            )));
        }
    };
    Ok(Node {
        value,
        line: e.pos.line,
        column: e.pos.column,
    })
}

struct Ascii<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    index: LineIndex,
    nodes: usize,
}

fn bare_byte(b: u8) -> bool {
    !(b.is_ascii_whitespace() || b"{}()=;,\"'<>".contains(&b))
}

fn parse_ascii(text: &str) -> Result<Plist, PlistError> {
    let mut p = Ascii {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        index: LineIndex::new(text),
        nodes: 0,
    };
    p.skip()?;
    let root = p.value(0)?;
    p.skip()?;
    if p.pos < p.bytes.len() {
        return Err(p.error(p.pos, "text after the root value"));
    }
    Ok(Plist {
        root,
        issues: Vec::new(),
    })
}

impl Ascii<'_> {
    fn at(&self, byte: usize) -> (u32, u32) {
        self.index.line_col(self.text, byte).unwrap_or((1, 1))
    }

    fn error(&self, byte: usize, what: &str) -> PlistError {
        let (line, column) = self.at(byte.min(self.text.len()));
        PlistError {
            line,
            column,
            what: what.to_string(),
        }
    }

    /// Пробелы и комментарии `//`, `/* */`.
    fn skip(&mut self) -> Result<(), PlistError> {
        loop {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
                self.pos += 1;
            }
            if self.text[self.pos..].starts_with("//") {
                self.pos = self.text[self.pos..]
                    .find('\n')
                    .map_or(self.bytes.len(), |n| self.pos + n);
            } else if self.text[self.pos..].starts_with("/*") {
                let start = self.pos;
                let end = self.text[self.pos + 2..]
                    .find("*/")
                    .ok_or_else(|| self.error(start, "unterminated comment"))?;
                self.pos += 2 + end + 2;
            } else {
                return Ok(());
            }
        }
    }

    fn expect(&mut self, b: u8, what: &str) -> Result<(), PlistError> {
        self.skip()?;
        if self.bytes.get(self.pos) == Some(&b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error(self.pos, what))
        }
    }

    fn string(&mut self) -> Result<String, PlistError> {
        let start = self.pos;
        match self.bytes.get(self.pos) {
            Some(&q @ (b'"' | b'\'')) => {
                self.pos += 1;
                let mut out = String::new();
                loop {
                    let Some(&c) = self.bytes.get(self.pos) else {
                        return Err(self.error(start, "unterminated string"));
                    };
                    if c == q {
                        self.pos += 1;
                        return Ok(out);
                    }
                    if c == b'\\' {
                        self.pos += 1;
                        let e = self.bytes.get(self.pos).copied().unwrap_or(0);
                        match e {
                            b'n' => out.push('\n'),
                            b't' => out.push('\t'),
                            b'r' => out.push('\r'),
                            b'U' | b'u' => {
                                let hex = self.text.get(self.pos + 1..self.pos + 5).unwrap_or("");
                                if hex.len() == 4 && hex.bytes().all(|h| h.is_ascii_hexdigit()) {
                                    if let Some(ch) =
                                        u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
                                    {
                                        out.push(ch);
                                    }
                                    self.pos += 5;
                                    continue;
                                }
                                out.push(e as char);
                            }
                            b'0'..=b'7' => {
                                let mut n = 0u32;
                                let mut k = 0;
                                while k < 3
                                    && matches!(self.bytes.get(self.pos + k), Some(b'0'..=b'7'))
                                {
                                    n = n * 8 + u32::from(self.bytes[self.pos + k] - b'0');
                                    k += 1;
                                }
                                if let Some(ch) = char::from_u32(n) {
                                    out.push(ch);
                                }
                                self.pos += k;
                                continue;
                            }
                            0 => return Err(self.error(start, "unterminated string")),
                            _ => {
                                let ch = self.text[self.pos..].chars().next().unwrap_or(' ');
                                out.push(ch);
                                self.pos += ch.len_utf8();
                                continue;
                            }
                        }
                        self.pos += 1;
                        continue;
                    }
                    let ch = self.text[self.pos..].chars().next().unwrap_or(' ');
                    out.push(ch);
                    self.pos += ch.len_utf8();
                }
            }
            Some(&b) if bare_byte(b) => {
                while self.pos < self.bytes.len()
                    && bare_byte(self.bytes[self.pos])
                    && !self.bytes[self.pos..].starts_with(b"/*")
                    && !self.bytes[self.pos..].starts_with(b"//")
                {
                    self.pos += 1;
                }
                Ok(self.text[start..self.pos].to_string())
            }
            _ => Err(self.error(self.pos, "expected a string")),
        }
    }

    fn value(&mut self, depth: usize) -> Result<Node, PlistError> {
        self.skip()?;
        let start = self.pos;
        if depth > MAX_DEPTH {
            return Err(self.error(start, "nesting is too deep"));
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(self.error(start, "too many values"));
        }
        let (line, column) = self.at(start);
        let value = match self.bytes.get(self.pos) {
            Some(b'{') => {
                self.pos += 1;
                let mut entries = Vec::new();
                loop {
                    self.skip()?;
                    if self.bytes.get(self.pos) == Some(&b'}') {
                        self.pos += 1;
                        break;
                    }
                    if self.pos >= self.bytes.len() {
                        return Err(self.error(start, "dictionary is never closed"));
                    }
                    let key_at = self.pos;
                    let (kl, kc) = self.at(key_at);
                    let name = self.string()?;
                    self.expect(b'=', "expected '=' after a dictionary key")?;
                    let v = self.value(depth + 1)?;
                    self.skip()?;
                    match self.bytes.get(self.pos) {
                        Some(b';') => self.pos += 1,
                        Some(b'}') => {}
                        _ => return Err(self.error(self.pos, "expected ';' after a value")),
                    }
                    entries.push((
                        Key {
                            name,
                            line: kl,
                            column: kc,
                        },
                        v,
                    ));
                }
                Value::Dict(entries)
            }
            Some(b'(') => {
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    self.skip()?;
                    if self.bytes.get(self.pos) == Some(&b')') {
                        self.pos += 1;
                        break;
                    }
                    if self.pos >= self.bytes.len() {
                        return Err(self.error(start, "array is never closed"));
                    }
                    items.push(self.value(depth + 1)?);
                    self.skip()?;
                    match self.bytes.get(self.pos) {
                        Some(b',') => self.pos += 1,
                        Some(b')') => {}
                        _ => return Err(self.error(self.pos, "expected ',' or ')' in an array")),
                    }
                }
                Value::Array(items)
            }
            Some(b'<') => {
                let end = self.text[self.pos..]
                    .find('>')
                    .ok_or_else(|| self.error(start, "unterminated data"))?;
                self.pos += end + 1;
                Value::Data
            }
            _ => Value::Str(self.string()?),
        };
        Ok(Node {
            value,
            line,
            column,
        })
    }
}

/// Все строки-листья с путём ключей (`NSAppTransportSecurity.NSExceptionDomains.x`) — для поиска
/// секретов по именам ключей. Без рекурсии.
pub fn string_leaves(root: &Node) -> Vec<(String, &Key, &Node)> {
    let mut out = Vec::new();
    let mut stack: Vec<(String, &Node)> = vec![(String::new(), root)];
    while let Some((path, node)) = stack.pop() {
        match &node.value {
            Value::Dict(entries) => {
                for (k, v) in entries.iter().rev() {
                    let p = if path.is_empty() {
                        k.name.clone()
                    } else {
                        format!("{path}.{}", k.name)
                    };
                    if let Value::Str(_) = v.value {
                        out.push((p, k, v));
                    } else {
                        stack.push((p, v));
                    }
                }
            }
            Value::Array(items) => {
                for v in items.iter().rev() {
                    stack.push((path.clone(), v));
                }
            }
            _ => {}
        }
    }
    out.sort_by_key(|(_, k, _)| (k.line, k.column));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_plist_with_positions() {
        let text = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>NSAppTransportSecurity</key>\n\t<dict>\n\t\t<key>NSAllowsArbitraryLoads</key>\n\t\t<true/>\n\t</dict>\n\t<key>CFBundleURLTypes</key>\n\t<array><dict><key>CFBundleURLSchemes</key><array><string>myapp</string></array></dict></array>\n\t<key>N</key><integer> 3 </integer>\n</dict>\n</plist>\n";
        let p = parse(text).unwrap();
        let ats = p.root.get("NSAppTransportSecurity").unwrap();
        let (k, v) = ats.entry("NSAllowsArbitraryLoads").unwrap();
        assert_eq!((k.line, k.column), (7, 3));
        assert_eq!(v.as_bool(), Some(true));
        let schemes = &p.root.get("CFBundleURLTypes").unwrap().items()[0];
        assert_eq!(
            schemes.get("CFBundleURLSchemes").unwrap().items()[0].as_str(),
            Some("myapp")
        );
        assert_eq!(
            p.root.get("N").unwrap().value,
            Value::Scalar("3".to_string())
        );
        // DOCTYPE пропущен и отмечен, ничего не загружалось.
        assert!(p.issues.iter().any(|i| i.contains("DOCTYPE")));
    }

    #[test]
    fn xml_plist_errors() {
        for (text, what) in [
            (
                "<plist><dict><string>x</string></dict></plist>",
                "expected <key>",
            ),
            (
                "<plist><dict><key>a</key></dict></plist>",
                "without a value",
            ),
            (
                "<plist><dict><key>a</key><weird/></dict></plist>",
                "unknown",
            ),
            ("<plist></plist>", "empty"),
            ("<plist><dict>", "never closed"),
        ] {
            let e = parse(text).unwrap_err();
            assert!(e.what.contains(what), "{text}: {}", e.what);
        }
    }

    #[test]
    fn ascii_plist_like_pbxproj() {
        let text = "// !$*UTF8*$!\n{\n\tarchiveVersion = 1;\n\tobjects = {\n/* Begin */\n\t\tA1B2 /* App */ = {isa = PBXNativeTarget; name = \"My App\"; buildPhases = (X1, X2, ); };\n\t\tC3 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_FILE = \"App/Info.plist\"; \"OTHER[sdk=iphoneos*]\" = \"-a\\n\\\"b\\\"\"; DEF = (\"$(inherited)\", \"DEBUG=1\"); }; name = Release; data = <0fbd 7774>;};\n\t};\n\trootObject = A1B2;\n}\n";
        let p = parse(text).unwrap();
        let objects = p.root.get("objects").unwrap();
        let target = objects.get("A1B2").unwrap();
        assert_eq!(target.get("name").unwrap().as_str(), Some("My App"));
        assert_eq!(target.get("buildPhases").unwrap().items().len(), 2);
        let (k, _) = objects.entry("A1B2").unwrap();
        assert_eq!((k.line, k.column), (6, 3));
        let settings = objects.get("C3").unwrap().get("buildSettings").unwrap();
        assert_eq!(
            settings.get("OTHER[sdk=iphoneos*]").unwrap().as_str(),
            Some("-a\n\"b\"")
        );
        assert_eq!(
            settings.get("DEF").unwrap().items()[1].as_str(),
            Some("DEBUG=1")
        );
        assert_eq!(
            objects.get("C3").unwrap().get("data").unwrap().value,
            Value::Data
        );
        assert_eq!(p.root.get("rootObject").unwrap().as_str(), Some("A1B2"));
    }

    #[test]
    fn ascii_plist_errors_and_hostile_input() {
        for text in [
            "{ a = ; }",
            "{ a b; }",
            "{ a = (b c); }",
            "{ a = \"x }",
            "{ /* x",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
        assert!(parse("{ a = b; }").is_ok() && parse("{ a = b }").is_ok());
        for text in [
            "",
            "{",
            "(",
            "<",
            "\"",
            "\\",
            "{ a = \"\\",
            "{ a = \"\\U12\" ; }",
            "é",
            "/",
        ] {
            let _ = parse(text);
        }
        let deep = "(".repeat(500) + &")".repeat(500);
        assert!(parse(&deep).unwrap_err().what.contains("deep"));
    }

    #[test]
    fn leaves_have_dotted_paths() {
        let p = parse("<plist><dict><key>A</key><dict><key>Secret</key><string>v</string></dict><key>B</key><string>w</string></dict></plist>").unwrap();
        let leaves: Vec<String> = string_leaves(&p.root)
            .into_iter()
            .map(|(p, _, _)| p)
            .collect();
        assert_eq!(leaves, vec!["A.Secret", "B"]);
    }

    #[test]
    fn booleans_from_strings() {
        let p = parse("{ a = YES; b = NO; c = maybe; }").unwrap();
        assert_eq!(p.root.get("a").unwrap().as_bool(), Some(true));
        assert_eq!(p.root.get("b").unwrap().as_bool(), Some(false));
        assert_eq!(p.root.get("c").unwrap().as_bool(), None);
    }
}
