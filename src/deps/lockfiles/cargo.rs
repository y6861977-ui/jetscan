//! `Cargo.lock`: registry packages only; workspace/path/git packages are omitted.

use crate::deps::Dep;

pub fn parse(text: &str) -> Result<Vec<Dep>, String> {
    let doc = toml::parse(text).map_err(|e| format!("Cargo.lock: {e}"))?;
    let packages = toml::packages(&doc).map_err(|e| format!("Cargo.lock: {e}"))?;
    let mut out = Vec::new();
    for package in packages {
        let name = toml::required_string(package, "name")?;
        let version = toml::required_string(package, "version")?;
        let source = toml::optional_string(package, "source")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("Cargo.lock: invalid package name".into());
        }
        if version.is_empty() {
            return Err(format!("Cargo.lock: missing version for {name}"));
        }
        if !toml::exact_version(version) && !toml::constraint(version) {
            return Err(format!("Cargo.lock: invalid version for {name}"));
        }
        if let Some(source) = source
            && (source.starts_with("registry+") || source.starts_with("sparse+"))
            && toml::exact_version(version)
        {
            out.push(Dep {
                name: name.into(),
                version: version.into(),
            });
        }
    }
    Ok(out)
}

// Shared by the three TOML lockfile readers. Kept here because T2.2 owns only
// cargo.rs, gomod.rs and python.rs. This is a bounded parser for lockfile TOML,
// not a general TOML library: unsupported bare values fail explicitly.
pub(super) mod toml {
    use std::collections::{BTreeMap, BTreeSet};

    pub type Table = BTreeMap<String, Value>;

    #[derive(Debug)]
    pub enum Value {
        String(String),
        Scalar(String),
        Array(Vec<Value>),
        ArrayTable(Vec<Value>),
        Table(Table),
        InlineTable(Table),
    }

    impl Value {
        pub fn table(&self) -> Result<&Table, String> {
            match self {
                Self::Table(table) | Self::InlineTable(table) => Ok(table),
                _ => Err("expected a TOML table".into()),
            }
        }
    }

    pub fn optional_string<'a>(table: &'a Table, key: &str) -> Result<Option<&'a str>, String> {
        match table.get(key) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            _ => Err(format!("package {key} must be a string")),
        }
    }

    pub fn required_string<'a>(table: &'a Table, key: &str) -> Result<&'a str, String> {
        optional_string(table, key)?.ok_or_else(|| format!("package is missing {key}"))
    }

    pub fn packages(doc: &Table) -> Result<Vec<&Table>, String> {
        match doc.get("package") {
            Some(Value::Array(items) | Value::ArrayTable(items)) => {
                items.iter().map(Value::table).collect()
            }
            Some(_) => Err("package must be an array of tables".into()),
            // A generated empty lockfile may contain only its format metadata.
            None if matches!(doc.get("version"), Some(Value::Scalar(v)) if v.parse::<u64>().is_ok())
                || matches!(doc.get("metadata"), Some(Value::Table(_))) =>
            {
                Ok(Vec::new())
            }
            None => Err("no package array or lockfile metadata found".into()),
        }
    }

    pub fn exact_version(version: &str) -> bool {
        !version.is_empty()
            && version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_+!".contains(&b))
            && version
                .strip_prefix('v')
                .unwrap_or(version)
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_digit)
            && !version.contains("..")
            && !version.ends_with(['.', '-', '+', '_', '!'])
            && !version.split('.').any(|p| p == "x" || p == "X")
    }

    pub fn constraint(version: &str) -> bool {
        version.contains(['<', '>', '=', '^', '~', '*', ',', '|'])
            || version.split('.').any(|p| p == "x" || p == "X")
    }

    pub fn parse(text: &str) -> Result<Table, String> {
        let mut parser = Parser {
            text: text.strip_prefix('\u{feff}').unwrap_or(text),
            pos: 0,
        };
        let mut root = Table::new();
        let mut section = Vec::new();
        let mut declared = BTreeSet::new();
        while {
            parser.space(true);
            parser.peek().is_some()
        } {
            if parser.eat('[') {
                let array = parser.eat('[');
                section = parser.key()?;
                parser.expect(']')?;
                if array {
                    parser.expect(']')?;
                }
                parser.end_line()?;
                // [package.source] may occur once for EACH [[package]].
                let identity = table_identity(&root, &section);
                if !array && !declared.insert(identity) {
                    return parser.error("duplicate table header");
                }
                let (last, parents) = section.split_last().ok_or("empty table name")?;
                let parent = descend(&mut root, parents)?;
                if array {
                    let value = parent
                        .entry(last.clone())
                        .or_insert_with(|| Value::ArrayTable(Vec::new()));
                    match value {
                        Value::ArrayTable(items) => items.push(Value::Table(Table::new())),
                        _ => return parser.error("array table conflicts with an existing value"),
                    }
                } else {
                    if parent
                        .get(last)
                        .is_some_and(|v| !matches!(v, Value::Table(_)))
                    {
                        return parser.error("table header conflicts with an existing value");
                    }
                    descend(&mut root, &section)?;
                }
            } else {
                let key = parser.key()?;
                parser.expect('=')?;
                let value = parser.value(section.len() + key.len())?;
                parser.end_line()?;
                insert(descend(&mut root, &section)?, &key, value)?;
            }
        }
        Ok(root)
    }

    fn table_identity(root: &Table, path: &[String]) -> Vec<(String, usize)> {
        let mut table = Some(root);
        path.iter()
            .map(|key| {
                let value = table.and_then(|t| t.get(key));
                let (next, index) = match value {
                    Some(Value::Table(t)) => (Some(t), 0),
                    Some(Value::ArrayTable(items)) => {
                        (items.last().and_then(|v| v.table().ok()), items.len())
                    }
                    _ => (None, 0),
                };
                table = next;
                (key.clone(), index)
            })
            .collect()
    }

    fn descend<'a>(table: &'a mut Table, path: &[String]) -> Result<&'a mut Table, String> {
        let mut table = table;
        for key in path {
            let value = table
                .entry(key.clone())
                .or_insert_with(|| Value::Table(Table::new()));
            table = match value {
                Value::Table(t) => t,
                Value::ArrayTable(items) => match items.last_mut() {
                    Some(Value::Table(t)) => t,
                    _ => return Err("table path does not refer to a table".into()),
                },
                _ => return Err("table conflicts with an existing value".into()),
            };
        }
        Ok(table)
    }

    fn insert(table: &mut Table, key: &[String], value: Value) -> Result<(), String> {
        let (last, parents) = key.split_last().ok_or("empty TOML key")?;
        let parent = descend(table, parents)?;
        if parent.insert(last.clone(), value).is_some() {
            return Err(format!("duplicate TOML key: {last}"));
        }
        Ok(())
    }

    struct Parser<'a> {
        text: &'a str,
        pos: usize,
    }

    impl Parser<'_> {
        fn peek(&self) -> Option<char> {
            self.text[self.pos..].chars().next()
        }
        fn bump(&mut self) -> Option<char> {
            let c = self.peek()?;
            self.pos += c.len_utf8();
            Some(c)
        }
        fn eat(&mut self, c: char) -> bool {
            if self.peek() == Some(c) {
                self.bump();
                true
            } else {
                false
            }
        }
        fn expect(&mut self, c: char) -> Result<(), String> {
            if self.eat(c) {
                Ok(())
            } else {
                self.error(&format!("expected '{c}'"))
            }
        }
        fn error<T>(&self, reason: &str) -> Result<T, String> {
            let line = self.text[..self.pos]
                .bytes()
                .filter(|&b| b == b'\n')
                .count()
                + 1;
            Err(format!("line {line}: {reason}"))
        }
        fn space(&mut self, newline: bool) {
            loop {
                while self
                    .peek()
                    .is_some_and(|c| c == ' ' || c == '\t' || (newline && (c == '\r' || c == '\n')))
                {
                    self.bump();
                }
                if newline && self.eat('#') {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                } else {
                    break;
                }
            }
        }
        fn end_line(&mut self) -> Result<(), String> {
            self.space(false);
            if self.eat('#') {
                while self.peek().is_some_and(|c| c != '\n') {
                    self.bump();
                }
            }
            self.eat('\r');
            if self.peek().is_none() || self.eat('\n') {
                Ok(())
            } else {
                self.error("unexpected text after value/header")
            }
        }
        fn key(&mut self) -> Result<Vec<String>, String> {
            let mut keys = Vec::new();
            loop {
                self.space(false);
                let key = if matches!(self.peek(), Some('"' | '\'')) {
                    if self.text[self.pos..].starts_with("\"\"\"")
                        || self.text[self.pos..].starts_with("'''")
                    {
                        return self.error("multiline strings cannot be TOML keys");
                    }
                    self.string()?
                } else {
                    let start = self.pos;
                    while self
                        .peek()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        self.bump();
                    }
                    if self.pos == start {
                        return self.error("expected TOML key");
                    }
                    self.text[start..self.pos].to_string()
                };
                keys.push(key);
                if keys.len() > 64 {
                    return self.error("table path is too deep");
                }
                self.space(false);
                if !self.eat('.') {
                    break;
                }
            }
            Ok(keys)
        }
        fn string(&mut self) -> Result<String, String> {
            let quote = self.bump().ok_or("missing string")?;
            let delimiter = if quote == '"' { "\"\"\"" } else { "'''" };
            let multi = self.text[self.pos..].starts_with(&delimiter[..2]);
            if multi {
                self.pos += 2;
                if self.text[self.pos..].starts_with("\r\n") {
                    self.pos += 2;
                } else {
                    self.eat('\n');
                }
            }
            let mut out = String::new();
            loop {
                if multi && self.text[self.pos..].starts_with(delimiter) {
                    self.pos += 3;
                    for _ in 0..2 {
                        if self.eat(quote) {
                            out.push(quote);
                        }
                    }
                    return Ok(out);
                }
                let c = self
                    .bump()
                    .ok_or_else(|| "unterminated TOML string".to_string())?;
                if !multi && c == quote {
                    return Ok(out);
                }
                if c == '\\' && quote == '"' {
                    if multi && self.peek().is_some_and(char::is_whitespace) {
                        self.space(false);
                        self.eat('\r');
                        self.expect('\n')?;
                        while self.peek().is_some_and(char::is_whitespace) {
                            self.bump();
                        }
                        continue;
                    }
                    let escape = self.bump().ok_or("unfinished string escape")?;
                    out.push(match escape {
                        'b' => '\u{0008}',
                        't' => '\t',
                        'n' => '\n',
                        'f' => '\u{000c}',
                        'r' => '\r',
                        '"' => '"',
                        '\\' => '\\',
                        'u' | 'U' => {
                            let mut code = 0;
                            for _ in 0..if escape == 'u' { 4 } else { 8 } {
                                let digit = self
                                    .bump()
                                    .and_then(|c| c.to_digit(16))
                                    .ok_or("invalid Unicode escape")?;
                                code = code * 16 + digit;
                            }
                            char::from_u32(code).ok_or("invalid Unicode scalar")?
                        }
                        _ => return self.error("invalid string escape"),
                    });
                } else {
                    if c.is_control() && c != '\t' && !(multi && (c == '\r' || c == '\n')) {
                        return self.error("control character or newline in string");
                    }
                    out.push(c);
                }
            }
        }
        fn value(&mut self, depth: usize) -> Result<Value, String> {
            if depth >= 64 {
                return self.error("TOML nesting is too deep");
            }
            self.space(false);
            match self.peek() {
                Some('"' | '\'') => Ok(Value::String(self.string()?)),
                Some('[') => {
                    self.bump();
                    let mut values = Vec::new();
                    loop {
                        self.space(true);
                        if self.eat(']') {
                            return Ok(Value::Array(values));
                        }
                        values.push(self.value(depth + 1)?);
                        self.space(true);
                        if self.eat(']') {
                            return Ok(Value::Array(values));
                        }
                        self.expect(',')?;
                    }
                }
                Some('{') => {
                    self.bump();
                    let mut table = Table::new();
                    self.space(false);
                    if self.eat('}') {
                        return Ok(Value::InlineTable(table));
                    }
                    loop {
                        let key = self.key()?;
                        self.expect('=')?;
                        let value = self.value(depth + key.len())?;
                        insert(&mut table, &key, value)?;
                        self.space(false);
                        if self.eat('}') {
                            return Ok(Value::InlineTable(table));
                        }
                        self.expect(',')?;
                    }
                }
                _ => {
                    let start = self.pos;
                    while self
                        .peek()
                        .is_some_and(|c| !c.is_whitespace() && !",]}#".contains(c))
                    {
                        self.bump();
                    }
                    let s = &self.text[start..self.pos];
                    // Lockfile metadata needs booleans and decimal numbers only.
                    let numeric = s.strip_prefix(['+', '-']).unwrap_or(s);
                    if s == "true"
                        || s == "false"
                        || (!numeric.is_empty()
                            && (numeric == "0" || !numeric.starts_with('0'))
                            && numeric.bytes().all(|b| b.is_ascii_digit())
                            && numeric.parse::<u64>().is_ok())
                    {
                        Ok(Value::Scalar(s.into()))
                    } else {
                        self.error("invalid or unsupported TOML value")
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_packages_and_multiline_dependencies() {
        let text = r#"# Generated by Cargo
version = 4
[[package]]
name = "my-app"
version = "0.1.0"
dependencies = ["serde", "unicode-ident"]
[[package]]
name = "serde"
version = "1.0.219"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "example checksum"
dependencies = [
    "serde_derive", # comment
]
[[package]]
name = 'unicode-ident'
version = '1.0.18'
source = 'sparse+https://index.crates.io/'
[[package]]
name = "git-dep"
version = "1.0.0"
source = "git+https://example.invalid/repo#revision"
[[package]]
name = "ranged"
version = ">=1.0"
source = "registry+https://example.invalid/index"
"#;
        assert_eq!(
            parse(text).unwrap(),
            vec![
                Dep {
                    name: "serde".into(),
                    version: "1.0.219".into()
                },
                Dep {
                    name: "unicode-ident".into(),
                    version: "1.0.18".into()
                },
            ]
        );
    }

    #[test]
    fn legacy_metadata_bom_and_quoted_keys() {
        let text = "\u{feff}[[package]]\r\n'name' = 'a'\r\nversion='1.0.0-beta.1+build'\r\nsource='registry+mirror'\r\n[metadata]\r\n'checksum a 1.0.0 (registry+mirror)'='hash'\r\n";
        assert_eq!(parse(text).unwrap()[0].version, "1.0.0-beta.1+build");
        assert!(parse("version = 4\npackage = []").unwrap().is_empty());
    }

    #[test]
    fn malformed_files_fail_including_ignored_fields() {
        for text in [
            "",
            "garbage",
            "foo = 1",
            "[[package]",
            "[[package]]\nname='a'",
            "[[package]]\nversion='1.0'",
            "[[package]]\nname=42\nversion='1.0'",
            "[[package]]\nname='a'\nversion='1.0'\nsource=42",
            "[[package]]\nname='a'\nversion='1.0'\nname='b'",
            "[[package]]\nname='a'\nversion='1.0'\ndependencies=[",
            "[[package]]\nname='a'\nversion='1.0'\ndependencies=['x' 'y']",
            "[[package]]\nname='a'\nversion='1.0'\nchecksum='unterminated",
            "[[package]]\nname='a'\nversion='1.0' trailing",
            "package = [42]",
            "[[package]]\nname='a'\nversion=''",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn bounded_toml_and_unicode_escapes() {
        assert!(toml::parse(&format!("x = {}0{}", "[".repeat(100), "]".repeat(100))).is_err());
        assert!(toml::parse("x = \"\\uD800\"").is_err());
        assert!(toml::parse("x = \"\\UFFFFFFFF\"").is_err());
        assert!(toml::parse("x = 'текст'").is_ok());
        assert!(toml::parse("[x]\na=1\n[x]\nb=2").is_err());
    }

    #[test]
    fn invalid_table_redefinitions_and_versions_are_errors() {
        for text in [
            "package=[]\n[[package]]\nname='a'\nversion='1.0'",
            "[[package]]\nname='a'\nversion='1.0'\n[package]\nsource='registry+mirror'",
            "[[package]]\nname='a'\nversion='garbage'",
            "[[package]]\nname='a'\nversion='1.0'\nx={}\nx.y=1",
            "[[package]]\nname='a'\nversion='1.0'\nx={a=1}\n[package.x]\nb=2",
            "version=04",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }
}
