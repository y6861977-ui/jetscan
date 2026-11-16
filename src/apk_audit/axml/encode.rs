//! ТОЛЬКО ДЛЯ ТЕСТОВ: кодировщик AXML из наших исходных `AndroidManifest.xml`.
//!
//! Это запасной путь, пока нет `aapt2` (решение интегратора 2026-11-12). Риск: кодер и декодер
//! пишет один автор и может ошибиться одинаково. Поэтому кодер повторяет то, что делает aapt2,
//! только в проверяемых местах: строки атрибутов `android:*` с resource id идут в пуле первыми
//! (по возрастанию id) и описаны картой ресурсов; атрибуты элемента отсортированы по id;
//! `true/false` и числа типизируются по схеме известных атрибутов, остальное — строка с raw-значением.
//! Когда появятся фикстуры от aapt2 (`aapt2.axml` рядом с исходником), они проверяются тем же тестом.
//!
//! Парсер XML здесь — минимальный, для наших же фикстур: элементы, атрибуты, `xmlns:`,
//! самозакрывающиеся теги, комментарии, `<?xml ?>`, сущности `&amp; &lt; &gt; &quot; &apos;`.

use super::{ANDROID_NS, KNOWN_ANDROID_ATTRS};

#[derive(Clone, Debug)]
pub struct XmlAttr {
    pub prefix: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct XmlElement {
    pub name: String,
    pub attrs: Vec<XmlAttr>,
    pub children: Vec<XmlElement>,
    pub line: u32,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Разбирает наш фикстурный XML. Паника — ошибка фикстуры, а не входа пользователя.
pub fn parse_xml(text: &str) -> (Vec<(String, String)>, XmlElement) {
    let mut namespaces = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root = None;
    let mut rest = text;
    let line_of = |rest: &str| (text[..text.len() - rest.len()].matches('\n').count() + 1) as u32;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt..];
        if rest.starts_with("<?") {
            rest = &rest[rest.find("?>").expect("unclosed <?") + 2..];
        } else if rest.starts_with("<!--") {
            rest = &rest[rest.find("-->").expect("unclosed comment") + 3..];
        } else if let Some(tail) = rest.strip_prefix("</") {
            let gt = tail.find('>').expect("unclosed end tag");
            let done = stack.pop().expect("end tag without start");
            assert_eq!(done.name, tail[..gt].trim(), "mismatched end tag");
            match stack.last_mut() {
                Some(parent) => parent.children.push(done),
                None => root = Some(done),
            }
            rest = &tail[gt + 1..];
        } else {
            let line = line_of(rest);
            let gt = rest.find('>').expect("unclosed tag");
            let inner = &rest[1..gt];
            let (inner, self_closing) = match inner.strip_suffix('/') {
                Some(i) => (i, true),
                None => (inner, false),
            };
            let name_end = inner.find(char::is_whitespace).unwrap_or(inner.len());
            let mut element = XmlElement {
                name: inner[..name_end].to_string(),
                attrs: Vec::new(),
                children: Vec::new(),
                line,
            };
            let mut a = inner[name_end..].trim_start();
            while !a.is_empty() {
                let eq = a.find('=').expect("attribute without =");
                let key = a[..eq].trim();
                let after = a[eq + 1..].trim_start();
                let quote = after.chars().next().expect("attribute value");
                let close = after[1..].find(quote).expect("unclosed attribute value") + 1;
                let value = unescape(&after[1..close]);
                if let Some(prefix) = key.strip_prefix("xmlns:") {
                    namespaces.push((prefix.to_string(), value));
                } else {
                    let (prefix, name) = match key.split_once(':') {
                        Some((p, n)) => (Some(p.to_string()), n.to_string()),
                        None => (None, key.to_string()),
                    };
                    element.attrs.push(XmlAttr {
                        prefix,
                        name,
                        value,
                    });
                }
                a = after[close + 1..].trim_start();
            }
            rest = &rest[gt + 1..];
            if self_closing {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => root = Some(element),
                }
            } else {
                stack.push(element);
            }
        }
    }
    assert!(stack.is_empty(), "unclosed elements in fixture");
    (namespaces, root.expect("no root element"))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Пул строк в UTF-8 (иначе UTF-16).
    pub utf8: bool,
    /// Обнулить имена атрибутов `android:*` в пуле (как делают обфускаторы); имя — только по id.
    pub obfuscate_names: bool,
}

const BOOL_ATTRS: &[&str] = &[
    "debuggable",
    "exported",
    "allowBackup",
    "usesCleartextTraffic",
    "enabled",
    "grantUriPermissions",
];
const INT_ATTRS: &[&str] = &[
    "versionCode",
    "minSdkVersion",
    "targetSdkVersion",
    "maxSdkVersion",
];

fn android_id(name: &str) -> Option<u32> {
    KNOWN_ANDROID_ATTRS
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(id, _)| *id)
}

struct Pool {
    strings: Vec<String>,
}

impl Pool {
    fn index(&mut self, s: &str) -> u32 {
        if let Some(i) = self.strings.iter().position(|x| x == s) {
            return i as u32;
        }
        self.strings.push(s.to_string());
        (self.strings.len() - 1) as u32
    }
}

fn chunk(kind: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let header_size = 8 + header.len();
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&(header_size as u16).to_le_bytes());
    out.extend_from_slice(&((header_size + body.len()) as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(body);
    out
}

fn string_pool(strings: &[String], utf8: bool) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut data = Vec::new();
    for s in strings {
        offsets.extend_from_slice(&(data.len() as u32).to_le_bytes());
        if utf8 {
            let units = s.encode_utf16().count();
            let bytes = s.as_bytes();
            for len in [units, bytes.len()] {
                if len > 0x7f {
                    data.push(0x80 | (len >> 8) as u8);
                    data.push(len as u8);
                } else {
                    data.push(len as u8);
                }
            }
            data.extend_from_slice(bytes);
            data.push(0);
        } else {
            let units: Vec<u16> = s.encode_utf16().collect();
            data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                data.extend_from_slice(&u.to_le_bytes());
            }
            data.extend_from_slice(&[0, 0]);
        }
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let mut header = Vec::new();
    header.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // styles
    header.extend_from_slice(&(if utf8 { 0x100u32 } else { 0 }).to_le_bytes());
    header.extend_from_slice(&(28 + offsets.len() as u32).to_le_bytes()); // stringsStart
    header.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
    let mut body = offsets;
    body.extend(data);
    chunk(0x0001, &header, &body)
}

fn node(kind: u16, line: u32, ext: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&line.to_le_bytes());
    header.extend_from_slice(&u32::MAX.to_le_bytes()); // comment
    chunk(kind, &header, ext)
}

/// Кодирует фикстурный XML в AXML.
pub fn encode(text: &str, options: Options) -> Vec<u8> {
    let (namespaces, root) = parse_xml(text);
    let uri_of = |prefix: &str| -> String {
        namespaces
            .iter()
            .find(|(p, _)| p == prefix)
            .map(|(_, u)| u.clone())
            .unwrap_or_else(|| panic!("undeclared prefix {prefix}"))
    };

    // Пул: сначала имена android-атрибутов с id (по возрастанию id) — для карты ресурсов.
    let mut used_ids: Vec<(u32, &str)> = Vec::new();
    let mut walk = vec![&root];
    while let Some(e) = walk.pop() {
        for a in &e.attrs {
            if a.prefix.as_deref().map(&uri_of) == Some(ANDROID_NS.to_string())
                && let Some(id) = android_id(&a.name)
                && !used_ids.iter().any(|(i, _)| *i == id)
            {
                used_ids.push((
                    id,
                    KNOWN_ANDROID_ATTRS
                        .iter()
                        .find(|(i, _)| *i == id)
                        .unwrap()
                        .1,
                ));
            }
        }
        walk.extend(e.children.iter());
    }
    used_ids.sort();
    let mut pool = Pool {
        strings: used_ids
            .iter()
            .map(|(_, name)| {
                // Обфускаторы оставляют пустые имена: тогда имя восстанавливается только по id.
                if options.obfuscate_names {
                    String::new()
                } else {
                    name.to_string()
                }
            })
            .collect(),
    };
    let mut resource_map = Vec::new();
    for (id, _) in &used_ids {
        resource_map.extend_from_slice(&id.to_le_bytes());
    }

    let mut body = Vec::new();
    let mut ns_chunks = Vec::new();
    for (prefix, uri) in &namespaces {
        let mut ext = Vec::new();
        ext.extend_from_slice(&pool.index(prefix).to_le_bytes());
        ext.extend_from_slice(&pool.index(uri).to_le_bytes());
        ns_chunks.push(ext);
    }
    for ext in &ns_chunks {
        body.extend(node(0x0100, 1, ext));
    }

    enum Step<'a> {
        Open(&'a XmlElement),
        Close(&'a XmlElement),
    }
    let mut steps = vec![Step::Open(&root)];
    while let Some(step) = steps.pop() {
        match step {
            Step::Open(e) => {
                let mut attrs: Vec<(u32, Vec<u8>)> = Vec::new();
                for a in &e.attrs {
                    let uri = a.prefix.as_deref().map(&uri_of);
                    let is_android = uri.as_deref() == Some(ANDROID_NS);
                    let id = if is_android {
                        android_id(&a.name)
                    } else {
                        None
                    };
                    let name_index = match id {
                        Some(id) => used_ids.iter().position(|(i, _)| *i == id).unwrap() as u32,
                        None => pool.index(&a.name),
                    };
                    let ns_index = uri.as_deref().map_or(u32::MAX, |u| pool.index(u));
                    let (raw, data_type, data) =
                        if is_android && BOOL_ATTRS.contains(&a.name.as_str()) {
                            let v = match a.value.as_str() {
                                "true" => u32::MAX,
                                "false" => 0,
                                other => panic!("bad boolean {other}"),
                            };
                            (u32::MAX, 0x12u8, v)
                        } else if is_android && INT_ATTRS.contains(&a.name.as_str()) {
                            let v: i32 = a.value.parse().expect("integer attribute");
                            (u32::MAX, 0x10u8, v as u32)
                        } else {
                            let s = pool.index(&a.value);
                            (s, 0x03u8, s)
                        };
                    let mut bytes = Vec::new();
                    bytes.extend_from_slice(&ns_index.to_le_bytes());
                    bytes.extend_from_slice(&name_index.to_le_bytes());
                    bytes.extend_from_slice(&raw.to_le_bytes());
                    bytes.extend_from_slice(&8u16.to_le_bytes());
                    bytes.push(0);
                    bytes.push(data_type);
                    bytes.extend_from_slice(&data.to_le_bytes());
                    // Порядок как у aapt2: по resource id, атрибуты без id — после.
                    attrs.push((id.unwrap_or(u32::MAX), bytes));
                }
                attrs.sort_by_key(|(id, _)| *id);
                let mut ext = Vec::new();
                ext.extend_from_slice(&u32::MAX.to_le_bytes()); // ns элемента
                ext.extend_from_slice(&pool.index(&e.name).to_le_bytes());
                ext.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
                ext.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
                ext.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
                ext.extend_from_slice(&[0; 6]); // id/class/style index
                for (_, bytes) in attrs {
                    ext.extend(bytes);
                }
                body.extend(node(0x0102, e.line, &ext));
                steps.push(Step::Close(e));
                for child in e.children.iter().rev() {
                    steps.push(Step::Open(child));
                }
            }
            Step::Close(e) => {
                let mut ext = Vec::new();
                ext.extend_from_slice(&u32::MAX.to_le_bytes());
                ext.extend_from_slice(&pool.index(&e.name).to_le_bytes());
                body.extend(node(0x0103, e.line, &ext));
            }
        }
    }
    for ext in ns_chunks.iter().rev() {
        body.extend(node(0x0101, 1, ext));
    }

    let mut doc_body = string_pool(&pool.strings, options.utf8);
    doc_body.extend(chunk(0x0180, &[], &resource_map));
    doc_body.extend(body);
    chunk(0x0003, &[], &doc_body)
}
