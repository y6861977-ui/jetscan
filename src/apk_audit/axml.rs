//! Декодер бинарного XML Android (AXML): `AndroidManifest.xml` и `res/xml/*.xml` внутри APK.
//!
//! Формат — последовательность чанков `ResChunk_header { type: u16, headerSize: u16, size: u32 }`
//! (AOSP `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`):
//! `RES_XML_TYPE` (0x0003) → пул строк (0x0001), карта ресурсов (0x0180), начало/конец namespace
//! (0x0100/0x0101), начало/конец элемента (0x0102/0x0103), CDATA (0x0104).
//!
//! Защита от враждебного входа (CL-APK-01): каждое чтение — через `cursor` с проверкой границ;
//! размер чанка ≥ его заголовка и ≤ остатка родителя; индексы строк сверяются с размером пула;
//! глубина, число атрибутов, строк и элементов ограничены; рекурсии нет (стек — вектор).
//! Фатальное (не AXML, нет пула строк, сломанный заголовок) — `Err(AxmlError)`;
//! остальное (неизвестный чанк, несогласованный конец элемента, битый индекс) — `issues`.
//!
//! Имена атрибутов в пуле строк могут быть пустыми или обфусцированы — поэтому у атрибута есть
//! `resource_id` из карты ресурсов, а `Attribute::name()` подставляет известное имя `android:*`.

use super::cursor::{slice_at, u8_at, u16_at, u32_at};

const RES_XML_TYPE: u16 = 0x0003;
const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const UTF8_FLAG: u32 = 0x100;
const NO_INDEX: u32 = 0xffff_ffff;

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// Атрибуты `android:*`, нужные правилам. Идентификаторы сверены с AOSP
/// `frameworks/base/core/res/res/values/public-final.xml` (2026-11-12).
pub const KNOWN_ANDROID_ATTRS: &[(u32, &str)] = &[
    (0x0101_0001, "label"),
    (0x0101_0002, "icon"),
    (0x0101_0003, "name"),
    (0x0101_0006, "permission"),
    (0x0101_0007, "readPermission"),
    (0x0101_0008, "writePermission"),
    (0x0101_0009, "protectionLevel"),
    (0x0101_000e, "enabled"),
    (0x0101_000f, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_0011, "process"),
    (0x0101_0018, "authorities"),
    (0x0101_001b, "grantUriPermissions"),
    (0x0101_0027, "scheme"),
    (0x0101_0028, "host"),
    (0x0101_0202, "targetActivity"),
    (0x0101_020c, "minSdkVersion"),
    (0x0101_021b, "versionCode"),
    (0x0101_021c, "versionName"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_0271, "maxSdkVersion"),
    (0x0101_0280, "allowBackup"),
    (0x0101_04eb, "fullBackupContent"),
    (0x0101_04ec, "usesCleartextTraffic"),
    (0x0101_0527, "networkSecurityConfig"),
    (0x0101_063e, "dataExtractionRules"),
];

pub fn known_android_attr(id: u32) -> Option<&'static str> {
    KNOWN_ANDROID_ATTRS
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, name)| *name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_depth: usize,
    pub max_attributes: usize,
    pub max_strings: usize,
    pub max_elements: usize,
    /// Длина одной строки пула в символах/байтах.
    pub max_string_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 256,
            max_attributes: 1000,
            max_strings: 200_000,
            max_elements: 100_000,
            max_string_len: 64 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AxmlError {
    /// Первый чанк не `RES_XML_TYPE` (это текстовый XML или вообще не XML).
    NotAxml,
    /// Заголовок или чанк выходит за пределы данных.
    Truncated(&'static str),
    /// Нет пула строк перед первым узлом.
    MissingStringPool,
    /// Превышен лимит (глубина, атрибуты, строки, элементы).
    Limit(&'static str),
}

impl AxmlError {
    pub fn describe(&self) -> String {
        match self {
            AxmlError::NotAxml => "not a binary Android XML document".to_string(),
            AxmlError::Truncated(what) => format!("binary XML is truncated or malformed: {what}"),
            AxmlError::MissingStringPool => "binary XML has no string pool".to_string(),
            AxmlError::Limit(what) => format!("binary XML exceeds the {what} limit"),
        }
    }
}

/// Типизированное значение атрибута (`Res_value`).
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    String(String),
    Bool(bool),
    Int(i32),
    Hex(u32),
    /// Ссылка на ресурс (`@xml/…`, `@bool/…`): без `resources.arsc` не разрешается.
    Reference(u32),
    /// Ссылка на атрибут темы (`?attr/…`).
    AttributeRef(u32),
    Float(f32),
    Null,
    /// Прочие типы (размеры, цвета, ...) — как есть.
    Other {
        data_type: u8,
        data: u32,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Attribute {
    /// URI пространства имён (`http://schemas.android.com/apk/res/android`) или `None`.
    pub namespace: Option<String>,
    /// Имя из пула строк (может быть пустым у обфусцированных APK).
    pub raw_name: String,
    /// Идентификатор ресурса атрибута из карты ресурсов.
    pub resource_id: Option<u32>,
    /// Исходная строка значения, если aapt её сохранил.
    pub raw_value: Option<String>,
    pub value: Value,
}

impl Attribute {
    /// Имя для правил: для `android:*` с известным id — каноническое имя по id (устойчиво к
    /// обфускации пула строк), иначе — имя из пула.
    pub fn name(&self) -> &str {
        if self.namespace.as_deref() == Some(ANDROID_NS)
            && let Some(known) = self.resource_id.and_then(known_android_attr)
        {
            return known;
        }
        &self.raw_name
    }

    pub fn is_android(&self) -> bool {
        self.namespace.as_deref() == Some(ANDROID_NS)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Element {
    pub namespace: Option<String>,
    pub name: String,
    pub line: u32,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    /// Атрибут `android:<name>`.
    pub fn android(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.is_android() && a.name() == name)
    }

    /// Атрибут без пространства имён (`package`).
    pub fn plain(&self, name: &str) -> Option<&Attribute> {
        self.attributes
            .iter()
            .find(|a| a.namespace.is_none() && a.raw_name == name)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Document {
    pub root: Option<Element>,
    /// Объявленные пространства имён: (префикс, URI).
    pub namespaces: Vec<(String, String)>,
    pub issues: Vec<String>,
}

struct StringPool<'a> {
    data: &'a [u8],
    offsets_at: usize,
    strings_at: usize,
    count: usize,
    utf8: bool,
    max_len: usize,
}

impl StringPool<'_> {
    /// Строка `index` или `None` (нет такого индекса / битые данные).
    fn get(&self, index: u32) -> Option<String> {
        if index == NO_INDEX || index as usize >= self.count {
            return None;
        }
        let offset = u32_at(self.data, self.offsets_at + 4 * index as usize)? as usize;
        let at = self.strings_at.checked_add(offset)?;
        if self.utf8 {
            // Длина в UTF-16 (1–2 байта), затем длина в байтах (1–2 байта), байты, NUL.
            let (_, at) = utf8_len(self.data, at)?;
            let (len, at) = utf8_len(self.data, at)?;
            if len > self.max_len {
                return None;
            }
            let bytes = slice_at(self.data, at, len)?;
            Some(String::from_utf8_lossy(bytes).into_owned())
        } else {
            let first = u16_at(self.data, at)?;
            let (len, at) = if first & 0x8000 != 0 {
                let second = u16_at(self.data, at + 2)?;
                (
                    (usize::from(first & 0x7fff) << 16) | usize::from(second),
                    at + 4,
                )
            } else {
                (usize::from(first), at + 2)
            };
            if len > self.max_len {
                return None;
            }
            let bytes = slice_at(self.data, at, len.checked_mul(2)?)?;
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&units))
        }
    }
}

fn utf8_len(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = u8_at(data, at)?;
    if first & 0x80 != 0 {
        let second = u8_at(data, at + 1)?;
        Some((
            (usize::from(first & 0x7f) << 8) | usize::from(second),
            at + 2,
        ))
    } else {
        Some((usize::from(first), at + 1))
    }
}

fn value_of(data_type: u8, data: u32, pool: &StringPool) -> Value {
    match data_type {
        0x00 => Value::Null,
        0x01 => Value::Reference(data),
        0x02 => Value::AttributeRef(data),
        0x03 => pool.get(data).map_or(Value::Null, Value::String),
        0x04 => Value::Float(f32::from_bits(data)),
        0x10 => Value::Int(data as i32),
        0x11 => Value::Hex(data),
        0x12 => Value::Bool(data != 0),
        other => Value::Other {
            data_type: other,
            data,
        },
    }
}

pub fn decode(data: &[u8], limits: &Limits) -> Result<Document, AxmlError> {
    let doc_type = u16_at(data, 0).ok_or(AxmlError::Truncated("document header"))?;
    let header_size = u16_at(data, 2).ok_or(AxmlError::Truncated("document header"))?;
    let size = u32_at(data, 4).ok_or(AxmlError::Truncated("document header"))? as usize;
    if doc_type != RES_XML_TYPE || header_size < 8 {
        return Err(AxmlError::NotAxml);
    }
    let mut issues = Vec::new();
    let end = if size > data.len() {
        return Err(AxmlError::Truncated("document size exceeds the data"));
    } else {
        if size < data.len() {
            issues.push(format!(
                "{} trailing byte(s) after the document",
                data.len() - size
            ));
        }
        size
    };
    let data = &data[..end];

    let mut pool: Option<StringPool> = None;
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0usize;
    let mut unknown_chunks = 0usize;

    let mut at = usize::from(header_size);
    while at < end {
        let chunk_type = u16_at(data, at).ok_or(AxmlError::Truncated("chunk header"))?;
        let chunk_header =
            usize::from(u16_at(data, at + 2).ok_or(AxmlError::Truncated("chunk header"))?);
        let chunk_size = u32_at(data, at + 4).ok_or(AxmlError::Truncated("chunk header"))? as usize;
        if chunk_header < 8
            || chunk_size < chunk_header
            || at.checked_add(chunk_size).is_none_or(|e| e > end)
        {
            return Err(AxmlError::Truncated("chunk size"));
        }
        let chunk = &data[at..at + chunk_size];
        match chunk_type {
            RES_STRING_POOL_TYPE => {
                if pool.is_some() {
                    issues.push("more than one string pool; the first is used".to_string());
                } else {
                    let count =
                        u32_at(chunk, 8).ok_or(AxmlError::Truncated("string pool"))? as usize;
                    let flags = u32_at(chunk, 16).ok_or(AxmlError::Truncated("string pool"))?;
                    let strings_start =
                        u32_at(chunk, 20).ok_or(AxmlError::Truncated("string pool"))? as usize;
                    if count > limits.max_strings {
                        return Err(AxmlError::Limit("string count"));
                    }
                    let offsets_end = chunk_header
                        .checked_add(
                            count
                                .checked_mul(4)
                                .ok_or(AxmlError::Limit("string count"))?,
                        )
                        .filter(|&e| e <= chunk_size)
                        .ok_or(AxmlError::Truncated("string pool offsets"))?;
                    if count > 0 && (strings_start < offsets_end || strings_start > chunk_size) {
                        return Err(AxmlError::Truncated("string pool data"));
                    }
                    pool = Some(StringPool {
                        data: chunk,
                        offsets_at: chunk_header,
                        strings_at: strings_start,
                        count,
                        utf8: flags & UTF8_FLAG != 0,
                        max_len: limits.max_string_len,
                    });
                }
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                let ids = (chunk_size - chunk_header) / 4;
                if ids > limits.max_strings {
                    return Err(AxmlError::Limit("resource map"));
                }
                resource_ids = (0..ids)
                    .filter_map(|i| u32_at(chunk, chunk_header + 4 * i))
                    .collect();
            }
            RES_XML_START_NAMESPACE_TYPE | RES_XML_END_NAMESPACE_TYPE => {
                let pool = pool.as_ref().ok_or(AxmlError::MissingStringPool)?;
                if chunk_type == RES_XML_START_NAMESPACE_TYPE {
                    let prefix = u32_at(chunk, chunk_header).and_then(|i| pool.get(i));
                    let uri = u32_at(chunk, chunk_header + 4).and_then(|i| pool.get(i));
                    match (prefix, uri) {
                        (Some(p), Some(u)) => namespaces.push((p, u)),
                        _ => issues.push(format!(
                            "namespace declaration at byte {at} has bad string indexes"
                        )),
                    }
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool = pool.as_ref().ok_or(AxmlError::MissingStringPool)?;
                elements += 1;
                if elements > limits.max_elements {
                    return Err(AxmlError::Limit("element count"));
                }
                if stack.len() >= limits.max_depth {
                    return Err(AxmlError::Limit("nesting depth"));
                }
                let line = u32_at(chunk, 8).unwrap_or(0);
                let ext = chunk_header;
                let field =
                    |o: usize| u32_at(chunk, ext + o).ok_or(AxmlError::Truncated("element"));
                let field16 =
                    |o: usize| u16_at(chunk, ext + o).ok_or(AxmlError::Truncated("element"));
                let ns = field(0)?;
                let name = field(4)?;
                let attr_start = usize::from(field16(8)?);
                let attr_size = usize::from(field16(10)?);
                let attr_count = usize::from(field16(12)?);
                if attr_count > limits.max_attributes {
                    return Err(AxmlError::Limit("attribute count"));
                }
                if attr_count > 0 && attr_size < 20 {
                    return Err(AxmlError::Truncated("attribute size"));
                }
                let name = pool.get(name).unwrap_or_else(|| {
                    issues.push(format!("element at byte {at} has a bad name index"));
                    String::new()
                });
                let mut attributes = Vec::with_capacity(attr_count);
                for i in 0..attr_count {
                    let base = ext
                        .checked_add(attr_start)
                        .and_then(|b| b.checked_add(i * attr_size))
                        .ok_or(AxmlError::Truncated("attribute"))?;
                    let a =
                        |o: usize| u32_at(chunk, base + o).ok_or(AxmlError::Truncated("attribute"));
                    let (a_ns, a_name, a_raw) = (a(0)?, a(4)?, a(8)?);
                    let data_type =
                        u8_at(chunk, base + 15).ok_or(AxmlError::Truncated("attribute"))?;
                    let a_data = a(16)?;
                    let raw_name = pool.get(a_name).unwrap_or_default();
                    let resource_id = resource_ids.get(a_name as usize).copied();
                    attributes.push(Attribute {
                        namespace: pool.get(a_ns),
                        raw_name,
                        resource_id,
                        raw_value: pool.get(a_raw),
                        value: value_of(data_type, a_data, pool),
                    });
                }
                stack.push(Element {
                    namespace: pool.get(ns),
                    name,
                    line,
                    attributes,
                    children: Vec::new(),
                });
            }
            RES_XML_END_ELEMENT_TYPE => {
                let pool = pool.as_ref().ok_or(AxmlError::MissingStringPool)?;
                let name = u32_at(chunk, chunk_header + 4).and_then(|i| pool.get(i));
                match stack.pop() {
                    Some(element) => {
                        if name.as_deref() != Some(element.name.as_str()) {
                            issues.push(format!(
                                "end tag does not match <{}>",
                                crate::ui::sanitize_line(&element.name)
                            ));
                        }
                        match stack.last_mut() {
                            Some(parent) => parent.children.push(element),
                            None if root.is_none() => root = Some(element),
                            None => {
                                issues.push("more than one root element; extra ignored".to_string())
                            }
                        }
                    }
                    None => issues.push("end tag without a start tag".to_string()),
                }
            }
            RES_XML_CDATA_TYPE => {}
            _ => unknown_chunks += 1,
        }
        at += chunk_size;
    }
    if unknown_chunks > 0 {
        issues.push(format!("{unknown_chunks} unknown chunk(s) skipped"));
    }
    if !stack.is_empty() {
        issues.push(format!("{} element(s) not closed", stack.len()));
        // Незакрытые элементы всё равно сворачиваем в дерево, чтобы не терять данные.
        while let Some(element) = stack.pop() {
            match stack.last_mut() {
                Some(parent) => parent.children.push(element),
                None if root.is_none() => root = Some(element),
                None => {}
            }
        }
    }
    if pool.is_none() {
        return Err(AxmlError::MissingStringPool);
    }
    Ok(Document {
        root,
        namespaces,
        issues,
    })
}

/// Каноническое текстовое представление дерева — для тестов и сверки с `aapt2 dump xmltree`.
/// Атрибуты отсортированы по имени (порядок в файле у разных компиляторов разный).
pub fn dump(doc: &Document) -> String {
    let mut out = String::new();
    for (prefix, uri) in &doc.namespaces {
        out.push_str(&format!("N {prefix}={uri}\n"));
    }
    let prefix_of = |uri: &Option<String>| -> String {
        match uri {
            None => String::new(),
            Some(u) => doc
                .namespaces
                .iter()
                .find(|(_, known)| known == u)
                .map_or_else(|| format!("{{{u}}}"), |(p, _)| format!("{p}:")),
        }
    };
    let mut work: Vec<(&Element, usize)> = doc.root.iter().map(|e| (e, 0)).collect();
    while let Some((element, depth)) = work.pop() {
        let pad = "  ".repeat(depth);
        out.push_str(&format!(
            "{pad}E {}{}\n",
            prefix_of(&element.namespace),
            element.name
        ));
        let mut attrs: Vec<String> = element
            .attributes
            .iter()
            .map(|a| {
                let value = match &a.value {
                    Value::String(s) => format!("string {s:?}"),
                    Value::Bool(b) => format!("bool {b}"),
                    Value::Int(i) => format!("int {i}"),
                    Value::Hex(h) => format!("hex 0x{h:08x}"),
                    Value::Reference(r) => format!("ref @0x{r:08x}"),
                    Value::AttributeRef(r) => format!("attr ?0x{r:08x}"),
                    Value::Float(f) => format!("float {f}"),
                    Value::Null => "null".to_string(),
                    Value::Other { data_type, data } => {
                        format!("type 0x{data_type:02x} 0x{data:08x}")
                    }
                };
                format!(
                    "{pad}  A {}{} = {value}\n",
                    prefix_of(&a.namespace),
                    a.name()
                )
            })
            .collect();
        attrs.sort();
        out.extend(attrs);
        for child in element.children.iter().rev() {
            work.push((child, depth + 1));
        }
    }
    for issue in &doc.issues {
        out.push_str(&format!("! {issue}\n"));
    }
    out
}

#[cfg(test)]
pub(crate) mod encode;

#[cfg(test)]
mod tests;
