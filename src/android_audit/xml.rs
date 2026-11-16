//! Консервативный читатель текстового XML (`AndroidManifest.xml`, `res/xml/*.xml`, `res/values/*.xml`).
//!
//! Поддержано: элементы, атрибуты в `"`/`'`, пространства имён (`xmlns`, `xmlns:p`, области
//! видимости), комментарии, CDATA, инструкции обработки (`<?xml …?>` пропускается), предопределённые
//! сущности (`&lt; &gt; &amp; &quot; &apos;`) и числовые (`&#N;`, `&#xN;`).
//!
//! Никогда: DTD и внешние/пользовательские сущности. `<!DOCTYPE …>` пропускается целиком (с
//! внутренним подмножеством `[…]`) и отмечается в `issues`; неизвестная `&name;` остаётся текстом
//! как есть и тоже отмечается. Ничего не загружается и не раскрывается — XXE и «billion laughs»
//! невозможны по построению.
//!
//! Ошибка синтаксиса (незакрытый тег, чужой закрывающий тег, `<` в значении) — `Err` с позицией:
//! правила по такому файлу становятся `partial`, а не «чисто». Глубина, число элементов и
//! атрибутов ограничены. Рекурсии нет (стек — вектор).

use crate::apk_audit::axml::{self, Value};
use crate::web_audit::location::LineIndex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Pos {
    /// Номер файла у вызывающего (для слияния манифестов из разных source set'ов).
    pub file: usize,
    pub line: u32,
    pub column: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlAttr {
    pub prefix: Option<String>,
    pub local: String,
    /// URI пространства имён; у атрибута без префикса — `None`.
    pub namespace: Option<String>,
    pub value: String,
    pub pos: Pos,
    /// Откуда взялось значение, если его подставили (плейсхолдер Gradle, `@bool/…`).
    pub note: Option<String>,
}

impl XmlAttr {
    /// `prefix:local` как в исходнике.
    pub fn qualified(&self) -> String {
        match &self.prefix {
            Some(p) => format!("{p}:{}", self.local),
            None => self.local.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlElement {
    pub prefix: Option<String>,
    pub local: String,
    pub namespace: Option<String>,
    pub attributes: Vec<XmlAttr>,
    pub children: Vec<XmlElement>,
    /// Прямой текст элемента (с раскрытыми сущностями и CDATA), не больше `Limits::max_text`.
    pub text: String,
    pub pos: Pos,
}

impl XmlElement {
    pub fn attr_ns(&self, namespace: &str, local: &str) -> Option<&XmlAttr> {
        self.attributes
            .iter()
            .find(|a| a.namespace.as_deref() == Some(namespace) && a.local == local)
    }

    pub fn android(&self, local: &str) -> Option<&XmlAttr> {
        self.attr_ns(axml::ANDROID_NS, local)
    }

    pub fn plain(&self, local: &str) -> Option<&XmlAttr> {
        self.attributes
            .iter()
            .find(|a| a.namespace.is_none() && a.prefix.is_none() && a.local == local)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlDoc {
    pub root: XmlElement,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_elements: usize,
    pub max_attributes: usize,
    pub max_text: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 256,
            max_elements: 100_000,
            max_attributes: 1000,
            max_text: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlError {
    pub line: u32,
    pub column: u32,
    pub what: String,
}

impl XmlError {
    pub fn describe(&self) -> String {
        format!(
            "XML is malformed at {}:{}: {}",
            self.line, self.column, self.what
        )
    }
}

pub const TOOLS_NS: &str = "http://schemas.android.com/tools";

struct Open {
    element: XmlElement,
    /// Объявленные этим элементом пространства имён (префикс `""` — по умолчанию).
    namespaces: Vec<(String, String)>,
    raw_name: String,
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    index: LineIndex,
    file: usize,
    limits: &'a Limits,
    issues: Vec<String>,
    elements: usize,
}

pub fn parse(text: &str, file: usize, limits: &Limits) -> Result<XmlDoc, XmlError> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut p = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
        index: LineIndex::new(text),
        file,
        limits,
        issues: Vec::new(),
        elements: 0,
    };
    p.document()
}

fn name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':') || b >= 0x80
}

fn split_name(raw: &str) -> (Option<String>, String) {
    match raw.split_once(':') {
        Some((p, l)) => (Some(p.to_string()), l.to_string()),
        None => (None, raw.to_string()),
    }
}

impl Parser<'_> {
    fn pos_of(&self, byte: usize) -> Pos {
        let (line, column) = self.index.line_col(self.text, byte).unwrap_or((0, 0));
        Pos {
            file: self.file,
            line,
            column,
        }
    }

    fn error(&self, byte: usize, what: &str) -> XmlError {
        let pos = self.pos_of(byte.min(self.text.len()));
        XmlError {
            line: pos.line,
            column: pos.column,
            what: what.to_string(),
        }
    }

    fn starts(&self, s: &str) -> bool {
        self.text[self.pos..].starts_with(s)
    }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn find(&self, needle: &str) -> Option<usize> {
        self.text[self.pos..].find(needle).map(|n| self.pos + n)
    }

    fn name(&mut self) -> Option<String> {
        let start = self.pos;
        while self.pos < self.bytes.len() && name_byte(self.bytes[self.pos]) {
            self.pos += 1;
        }
        (self.pos > start).then(|| self.text[start..self.pos].to_string())
    }

    /// Раскрывает сущности в `raw`. Неизвестные — как есть, с замечанием.
    fn decode(&mut self, raw: &str) -> String {
        if !raw.contains('&') {
            return raw.to_string();
        }
        let mut out = String::with_capacity(raw.len());
        let mut rest = raw;
        while let Some(amp) = rest.find('&') {
            out.push_str(&rest[..amp]);
            let after = &rest[amp + 1..];
            let Some(semi) = after.find(';').filter(|&n| n <= 12) else {
                out.push('&');
                rest = after;
                continue;
            };
            let name = &after[..semi];
            let decoded = match name {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => {
                    let number = if let Some(hex) =
                        name.strip_prefix("#x").or_else(|| name.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        name.strip_prefix('#').and_then(|d| d.parse().ok())
                    };
                    number.and_then(char::from_u32)
                }
            };
            match decoded {
                Some(c) => out.push(c),
                None => {
                    if self.issues.len() < 20 {
                        self.issues.push(format!(
                            "entity &{}; is not expanded (DTD entities are never loaded)",
                            crate::ui::sanitize_line(name)
                        ));
                    }
                    out.push('&');
                    out.push_str(name);
                    out.push(';');
                }
            }
            rest = &after[semi + 1..];
        }
        out.push_str(rest);
        out
    }

    fn document(&mut self) -> Result<XmlDoc, XmlError> {
        let mut stack: Vec<Open> = Vec::new();
        let mut root: Option<XmlElement> = None;
        loop {
            if self.pos >= self.bytes.len() {
                break;
            }
            if self.bytes[self.pos] != b'<' {
                let end = self.find("<").unwrap_or(self.text.len());
                let text = self.text;
                let raw = &text[self.pos..end];
                match stack.last_mut() {
                    Some(_) => {
                        let decoded = self.decode(raw);
                        let max = self.limits.max_text;
                        if let Some(open) = stack.last_mut()
                            && open.element.text.len() < max
                        {
                            open.element.text.push_str(&decoded);
                        }
                    }
                    None if raw.trim().is_empty() => {}
                    None => return Err(self.error(self.pos, "text outside the root element")),
                }
                self.pos = end;
                continue;
            }
            let start = self.pos;
            if self.starts("<!--") {
                let end = self
                    .text
                    .get(self.pos + 4..)
                    .and_then(|r| r.find("-->"))
                    .ok_or_else(|| self.error(start, "unterminated comment"))?;
                self.pos += 4 + end + 3;
            } else if self.starts("<![CDATA[") {
                let end = self
                    .find("]]>")
                    .ok_or_else(|| self.error(start, "unterminated CDATA"))?;
                let content = &self.text[self.pos + 9..end];
                let Some(open) = stack.last_mut() else {
                    return Err(self.error(start, "CDATA outside the root element"));
                };
                if open.element.text.len() < self.limits.max_text {
                    open.element.text.push_str(content);
                }
                self.pos = end + 3;
            } else if self.starts("<?") {
                let end = self
                    .find("?>")
                    .ok_or_else(|| self.error(start, "unterminated processing instruction"))?;
                self.pos = end + 2;
            } else if self.starts("<!DOCTYPE") || self.starts("<!doctype") {
                // Пропускаем целиком, учитывая внутреннее подмножество `[…]` и кавычки.
                let mut depth = 0i32;
                let mut quote = 0u8;
                self.pos += 2;
                loop {
                    let Some(&b) = self.bytes.get(self.pos) else {
                        return Err(self.error(start, "unterminated DOCTYPE"));
                    };
                    self.pos += 1;
                    if quote != 0 {
                        if b == quote {
                            quote = 0;
                        }
                        continue;
                    }
                    match b {
                        b'"' | b'\'' => quote = b,
                        b'[' => depth += 1,
                        b']' => depth -= 1,
                        b'>' if depth <= 0 => break,
                        _ => {}
                    }
                }
                self.issues.push(
                    "a DOCTYPE was ignored: DTDs and their entities are never loaded or expanded"
                        .to_string(),
                );
            } else if self.starts("</") {
                self.pos += 2;
                let name = self
                    .name()
                    .ok_or_else(|| self.error(start, "closing tag without a name"))?;
                self.skip_ws();
                if self.bytes.get(self.pos) != Some(&b'>') {
                    return Err(self.error(self.pos, "expected '>' in closing tag"));
                }
                self.pos += 1;
                let Some(open) = stack.pop() else {
                    return Err(self.error(start, "closing tag without an open element"));
                };
                if open.raw_name != name {
                    return Err(self.error(
                        start,
                        &format!(
                            "closing tag </{}> does not match <{}>",
                            crate::ui::sanitize_line(&name),
                            crate::ui::sanitize_line(&open.raw_name)
                        ),
                    ));
                }
                self.close(open, &mut stack, &mut root, start)?;
            } else {
                self.open_tag(&mut stack, &mut root)?;
            }
        }
        if let Some(open) = stack.last() {
            return Err(XmlError {
                line: open.element.pos.line,
                column: open.element.pos.column,
                what: format!(
                    "element <{}> is never closed",
                    crate::ui::sanitize_line(&open.raw_name)
                ),
            });
        }
        let root = root.ok_or_else(|| self.error(self.pos, "no root element"))?;
        Ok(XmlDoc {
            root,
            issues: std::mem::take(&mut self.issues),
        })
    }

    fn close(
        &mut self,
        open: Open,
        stack: &mut [Open],
        root: &mut Option<XmlElement>,
        at: usize,
    ) -> Result<(), XmlError> {
        match stack.last_mut() {
            Some(parent) => parent.element.children.push(open.element),
            None if root.is_none() => *root = Some(open.element),
            None => return Err(self.error(at, "more than one root element")),
        }
        Ok(())
    }

    fn open_tag(
        &mut self,
        stack: &mut Vec<Open>,
        root: &mut Option<XmlElement>,
    ) -> Result<(), XmlError> {
        let start = self.pos;
        self.pos += 1;
        let raw_name = self
            .name()
            .ok_or_else(|| self.error(start, "'<' is not followed by a tag name"))?;
        if root.is_some() && stack.is_empty() {
            return Err(self.error(start, "more than one root element"));
        }
        self.elements += 1;
        if self.elements > self.limits.max_elements {
            return Err(self.error(start, "too many elements"));
        }
        if stack.len() >= self.limits.max_depth {
            return Err(self.error(start, "nesting is too deep"));
        }
        let mut raw_attrs: Vec<(String, String, usize)> = Vec::new();
        let self_closing;
        loop {
            let had_ws = self
                .bytes
                .get(self.pos)
                .is_some_and(|b| b.is_ascii_whitespace());
            self.skip_ws();
            match self.bytes.get(self.pos) {
                None => return Err(self.error(start, "unterminated tag")),
                Some(b'>') => {
                    self.pos += 1;
                    self_closing = false;
                    break;
                }
                Some(b'/') if self.bytes.get(self.pos + 1) == Some(&b'>') => {
                    self.pos += 2;
                    self_closing = true;
                    break;
                }
                Some(_) if !had_ws => {
                    return Err(self.error(self.pos, "expected whitespace before an attribute"));
                }
                Some(_) => {}
            }
            let attr_start = self.pos;
            let name = self
                .name()
                .ok_or_else(|| self.error(attr_start, "invalid attribute name"))?;
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b'=') {
                return Err(self.error(self.pos, "expected '=' after an attribute name"));
            }
            self.pos += 1;
            self.skip_ws();
            let quote = match self.bytes.get(self.pos) {
                Some(&q @ (b'"' | b'\'')) => q,
                _ => return Err(self.error(self.pos, "attribute value is not quoted")),
            };
            self.pos += 1;
            let value_start = self.pos;
            let close = self.bytes[self.pos..]
                .iter()
                .position(|&b| b == quote)
                .ok_or_else(|| self.error(value_start, "unterminated attribute value"))?;
            let raw = &self.text[value_start..value_start + close];
            if raw.contains('<') {
                return Err(self.error(value_start, "'<' inside an attribute value"));
            }
            self.pos = value_start + close + 1;
            if raw_attrs.iter().any(|(n, _, _)| *n == name) {
                return Err(self.error(attr_start, "duplicate attribute"));
            }
            if raw_attrs.len() >= self.limits.max_attributes {
                return Err(self.error(attr_start, "too many attributes"));
            }
            let raw = raw.to_string();
            let value = self.decode(&raw);
            raw_attrs.push((name, value, attr_start));
        }
        // Пространства имён этого элемента.
        let mut namespaces = Vec::new();
        for (name, value, _) in &raw_attrs {
            if name == "xmlns" {
                namespaces.push((String::new(), value.clone()));
            } else if let Some(prefix) = name.strip_prefix("xmlns:") {
                namespaces.push((prefix.to_string(), value.clone()));
            }
        }
        let lookup = |prefix: &str, stack: &[Open], own: &[(String, String)]| -> Option<String> {
            if prefix == "xml" {
                return Some("http://www.w3.org/XML/1998/namespace".to_string());
            }
            own.iter()
                .chain(stack.iter().rev().flat_map(|o| o.namespaces.iter()))
                .find(|(p, _)| p == prefix)
                .map(|(_, uri)| uri.clone())
        };
        let (prefix, local) = split_name(&raw_name);
        let namespace = lookup(prefix.as_deref().unwrap_or(""), stack, &namespaces);
        if prefix.is_some() && namespace.is_none() {
            self.issues.push(format!(
                "prefix of <{}> is not declared",
                crate::ui::sanitize_line(&raw_name)
            ));
        }
        let mut attributes = Vec::new();
        for (name, value, at) in raw_attrs {
            if name == "xmlns" || name.starts_with("xmlns:") {
                continue;
            }
            let (prefix, local) = split_name(&name);
            let namespace = match &prefix {
                Some(p) => {
                    let ns = lookup(p, stack, &namespaces);
                    if ns.is_none() && self.issues.len() < 20 {
                        self.issues.push(format!(
                            "prefix of attribute {} is not declared",
                            crate::ui::sanitize_line(&name)
                        ));
                    }
                    ns
                }
                None => None,
            };
            attributes.push(XmlAttr {
                prefix,
                local,
                namespace,
                value,
                pos: self.pos_of(at),
                note: None,
            });
        }
        let element = XmlElement {
            prefix,
            local,
            namespace,
            attributes,
            children: Vec::new(),
            text: String::new(),
            pos: self.pos_of(start),
        };
        let open = Open {
            element,
            namespaces,
            raw_name,
        };
        if self_closing {
            self.close(open, stack, root, start)
        } else {
            stack.push(open);
            Ok(())
        }
    }
}

/// Модель для правил APK: тот же `axml::Document`, что даёт декодер бинарного XML.
/// Значения — строки (`Value::String`); `true`/`false` в любом регистре приводятся к нижнему,
/// как их принимает aapt2. Позиции элементов — строка исходника.
pub fn to_document(doc: &XmlDoc) -> axml::Document {
    fn convert(e: &XmlElement) -> axml::Element {
        axml::Element {
            namespace: e.namespace.clone(),
            name: e.local.clone(),
            line: e.pos.line,
            attributes: e
                .attributes
                .iter()
                .map(|a| {
                    let value = if a.value.eq_ignore_ascii_case("true") {
                        "true".to_string()
                    } else if a.value.eq_ignore_ascii_case("false") {
                        "false".to_string()
                    } else {
                        a.value.clone()
                    };
                    axml::Attribute {
                        namespace: a.namespace.clone(),
                        raw_name: a.local.clone(),
                        resource_id: None,
                        raw_value: None,
                        value: Value::String(value),
                    }
                })
                .collect(),
            // Глубина ограничена `Limits::max_depth`, поэтому рекурсия здесь безопасна.
            children: e.children.iter().map(convert).collect(),
        }
    }
    axml::Document {
        root: Some(convert(&doc.root)),
        namespaces: Vec::new(),
        issues: doc.issues.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: &str = "xmlns:android=\"http://schemas.android.com/apk/res/android\"";

    fn doc(text: &str) -> XmlDoc {
        parse(text, 0, &Limits::default()).expect("valid XML")
    }

    #[test]
    fn elements_attributes_namespaces_and_positions() {
        let d = doc(&format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<!-- c -->\n<manifest {NS} package=\"p\">\n  <application\n      android:debuggable='true' />\n</manifest>\n"
        ));
        assert_eq!(d.root.local, "manifest");
        assert_eq!(d.root.plain("package").unwrap().value, "p");
        let app = &d.root.children[0];
        assert_eq!((app.pos.line, app.pos.column), (4, 3));
        let attr = app.android("debuggable").unwrap();
        assert_eq!(attr.value, "true");
        assert_eq!((attr.pos.line, attr.pos.column), (5, 7));
        assert_eq!(attr.qualified(), "android:debuggable");
        assert!(d.issues.is_empty());
    }

    #[test]
    fn entities_cdata_and_text() {
        let d = doc(
            "<r a=\"x &amp; &lt;y&gt; &#65;&#x42; &quot;\"><s>a &amp; b<![CDATA[<raw>]]></s></r>",
        );
        assert_eq!(d.root.attributes[0].value, "x & <y> AB \"");
        assert_eq!(d.root.children[0].text, "a & b<raw>");
    }

    #[test]
    fn doctype_and_custom_entities_are_never_expanded() {
        let d = doc(
            "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\"> <!ENTITY lol \"lol\">]>\n<r a=\"&x;&lol;\">&x;</r>",
        );
        assert_eq!(d.root.attributes[0].value, "&x;&lol;");
        assert_eq!(d.root.text, "&x;");
        assert!(d.issues.iter().any(|i| i.contains("DOCTYPE was ignored")));
        assert!(d.issues.iter().any(|i| i.contains("&x; is not expanded")));
    }

    #[test]
    fn default_and_scoped_namespaces() {
        let d = doc(
            "<a xmlns=\"urn:d\" xmlns:t=\"urn:t\"><b t:x=\"1\" y=\"2\"><c xmlns:t=\"urn:t2\" t:z=\"3\"/></b></a>",
        );
        assert_eq!(d.root.namespace.as_deref(), Some("urn:d"));
        let b = &d.root.children[0];
        assert_eq!(b.attributes[0].namespace.as_deref(), Some("urn:t"));
        assert_eq!(b.attributes[1].namespace, None);
        assert_eq!(
            b.children[0].attributes[0].namespace.as_deref(),
            Some("urn:t2")
        );
        let d = doc("<a p:x=\"1\"/>");
        assert!(d.issues.iter().any(|i| i.contains("not declared")));
    }

    #[test]
    fn malformed_documents_are_errors_with_positions() {
        for (text, what) in [
            ("<a><b></a>", "does not match"),
            ("<a>", "never closed"),
            ("<a x=1/>", "not quoted"),
            ("<a x=\"1\" x=\"2\"/>", "duplicate"),
            ("<a x=\"<\"/>", "inside an attribute"),
            ("<a/><b/>", "more than one root"),
            ("text", "outside the root"),
            ("", "no root"),
            ("<a><!-- x </a>", "unterminated comment"),
            ("<a x=\"1\"y=\"2\"/>", "whitespace"),
            ("</a>", "without an open"),
        ] {
            let e = parse(text, 0, &Limits::default()).unwrap_err();
            assert!(e.what.contains(what), "{text}: {}", e.what);
            assert!(e.line >= 1, "{text}");
        }
    }

    #[test]
    fn limits_are_enforced() {
        let deep = "<a>".repeat(300) + &"</a>".repeat(300);
        assert!(
            parse(&deep, 0, &Limits::default())
                .unwrap_err()
                .what
                .contains("deep")
        );
        let many = format!("<r>{}</r>", "<e/>".repeat(20));
        let limits = Limits {
            max_elements: 10,
            ..Limits::default()
        };
        assert!(parse(&many, 0, &limits).unwrap_err().what.contains("many"));
    }

    #[test]
    fn converts_to_the_apk_manifest_model() {
        let d = doc(&format!(
            "<manifest {NS} package=\"p\"><uses-sdk android:minSdkVersion=\"21\" android:targetSdkVersion=\"34\"/>\
             <application android:allowBackup=\"TRUE\"><service android:name=\".S\" android:exported=\"true\"/></application></manifest>"
        ));
        let m = crate::apk_audit::manifest::from_document(&to_document(&d)).unwrap();
        assert_eq!((m.sdk.min, m.sdk.target), (21, 34));
        let app = m.application.unwrap();
        assert_eq!(app.allow_backup, crate::apk_audit::manifest::Flag::True);
        assert_eq!(app.components[0].name, ".S");
        assert_eq!(
            app.components[0].exported,
            crate::apk_audit::manifest::Flag::True
        );
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for text in [
            "<",
            "<a",
            "<a b",
            "<a b=",
            "<a b='",
            "<!",
            "<!DOCTYPE",
            "<![CDATA[",
            "<?",
            "<a>&",
            "<a>&#xFFFFFFFF;</a>",
            "<a>&#1114112;</a>",
            "<é é='é'>é</é>",
            "<a></a >",
        ] {
            let _ = parse(text, 0, &Limits::default());
        }
    }
}
