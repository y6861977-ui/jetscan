//! Чтение ZIP (APK) по центральному каталогу: stored + deflate, CRC-32, лимиты.
//!
//! Модель угроз (CL-APK-01): архив недоверенный. Поэтому:
//! - ничего не пишется на диск — записи читаются только в память, имена — лишь метки
//!   (zip-slip невозможен по построению; подозрительные имена всё равно отмечаются);
//! - центральный каталог — источник правды, локальные заголовки сверяются с ним; расхождение,
//!   выход за границы, перекрытие записей (класс «нерекурсивных zip-бомб») → запись «не доверяем»;
//! - лимиты (одобрены в ADR-001): архив ≤ 200 МиБ, записей ≤ 20 000, запись ≤ 32 МиБ,
//!   всего распаковано ≤ 256 МиБ, сжатие ≤ 1000:1. Проверяются ДО распаковки, а inflate
//!   останавливается на заявленном размере;
//! - ZIP64, многотомные архивы, шифрование, методы кроме 0/8 — честная ошибка, не тишина;
//! - подпись APK (v1/v2/v3) не проверяется; APK Signing Block между записями и каталогом
//!   допустим и не считается мусором.

use super::crc32::crc32;
use super::cursor::{slice_at, u16_at, u32_at};
use super::inflate::{InflateError, inflate};
use crate::ui;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_ZIP64_LOCATOR: u32 = 0x0706_4b50;
const EOCD_LEN: usize = 22;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;
const MAX_COMMENT: usize = 0xffff;

const FLAG_ENCRYPTED: u16 = 1;
const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_bytes: u64,
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_archive_bytes: 200 * 1024 * 1024,
            max_entries: 20_000,
            max_entry_bytes: 32 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_ratio: 1000,
        }
    }
}

/// Архив прочитать нельзя вообще.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZipError {
    TooLarge { size: u64, limit: u64 },
    NoEndOfCentralDirectory,
    MultiDisk,
    Zip64Unsupported,
    TooManyEntries { declared: u64, limit: usize },
    CentralDirectoryOutOfBounds,
    BadCentralDirectoryEntry { index: usize },
}

impl ZipError {
    pub fn describe(&self) -> String {
        match self {
            ZipError::TooLarge { size, limit } => {
                format!("archive is {size} bytes, over the {limit}-byte limit")
            }
            ZipError::NoEndOfCentralDirectory => {
                "no ZIP end-of-central-directory record (not a ZIP/APK or truncated)".to_string()
            }
            ZipError::MultiDisk => "multi-disk archives are not supported".to_string(),
            ZipError::Zip64Unsupported => "ZIP64 archives are not supported".to_string(),
            ZipError::TooManyEntries { declared, limit } => {
                format!("archive declares {declared} entries, over the limit of {limit}")
            }
            ZipError::CentralDirectoryOutOfBounds => {
                "central directory lies outside the file".to_string()
            }
            ZipError::BadCentralDirectoryEntry { index } => {
                format!("central directory entry #{index} is malformed")
            }
        }
    }
}

/// Одну запись прочитать нельзя (архив в целом читается).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryError {
    /// Запись не доверяем (локальный заголовок не совпал, перекрытие, выход за границы).
    Untrusted(&'static str),
    Encrypted,
    UnsupportedMethod(u16),
    TooLarge {
        declared: u64,
        limit: u64,
    },
    RatioExceeded {
        compressed: u64,
        declared: u64,
    },
    /// Общий бюджет распаковки исчерпан.
    BudgetExhausted,
    /// Распакованный размер не совпал с заявленным (больше — останавливаемся на заявленном).
    SizeMismatch {
        declared: u64,
    },
    Inflate(InflateError),
    CrcMismatch {
        expected: u32,
        actual: u32,
    },
}

impl EntryError {
    pub fn describe(&self) -> String {
        match self {
            EntryError::Untrusted(why) => format!("entry not trusted: {why}"),
            EntryError::Encrypted => "entry is encrypted".to_string(),
            EntryError::UnsupportedMethod(m) => format!("compression method {m} is not supported"),
            EntryError::TooLarge { declared, limit } => {
                format!("entry declares {declared} bytes, over the {limit}-byte limit")
            }
            EntryError::RatioExceeded {
                compressed,
                declared,
            } => format!("compression ratio too high ({compressed} -> {declared} bytes)"),
            EntryError::BudgetExhausted => "total decompression budget exhausted".to_string(),
            EntryError::SizeMismatch { declared } => {
                format!("data does not inflate to the declared {declared} bytes")
            }
            EntryError::Inflate(e) => format!("deflate error: {}", e.label()),
            EntryError::CrcMismatch { expected, actual } => {
                format!("CRC-32 mismatch (expected {expected:08x}, got {actual:08x})")
            }
        }
    }
}

/// Нефатальные наблюдения об архиве — для отчёта.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issue {
    /// После записи EOCD есть байты, не описанные полем комментария.
    TrailingData { bytes: u64 },
    /// Перед первой записью есть байты (самораспаковывающийся архив, полиглот).
    PrependedData { bytes: u64 },
    /// Одно имя у нескольких записей: разные инструменты могут взять разные.
    DuplicateName { name: String, count: usize },
    /// `../`, абсолютный путь, `\`, NUL, буква диска. Мы ничего не распаковываем, но это признак.
    SuspiciousName { name: String },
    /// Две записи делят байты.
    Overlap { first: String, second: String },
    /// Запись помечена недоверенной (причина в `Entry::untrusted`).
    UntrustedEntry { name: String, reason: &'static str },
    /// Центральный каталог длиннее/короче, чем заявлено в EOCD.
    CentralDirectorySizeMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Имя для отчёта: UTF-8 с потерями, управляющие символы вычищены.
    pub name: String,
    pub raw_name: Vec<u8>,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_offset: u64,
    data_offset: usize,
    pub untrusted: Option<&'static str>,
}

/// Общий бюджет распакованных байт на один анализ.
#[derive(Clone, Debug)]
pub struct Budget {
    pub remaining: u64,
}

impl Budget {
    pub fn new(limits: &Limits) -> Budget {
        Budget {
            remaining: limits.max_total_bytes,
        }
    }
}

#[derive(Debug)]
pub struct Archive<'a> {
    data: &'a [u8],
    pub entries: Vec<Entry>,
    pub issues: Vec<Issue>,
    limits: Limits,
}

/// Читает файл архива с проверкой размера ДО чтения. Симлинк не разыменовывается.
pub fn load(path: &Path, limits: &Limits) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("cannot open: {e}"))?;
    if meta.file_type().is_symlink() {
        return Err("path is a symlink; not followed".to_string());
    }
    if !meta.is_file() {
        return Err("not a regular file".to_string());
    }
    if meta.len() > limits.max_archive_bytes {
        return Err(ZipError::TooLarge {
            size: meta.len(),
            limit: limits.max_archive_bytes,
        }
        .describe());
    }
    let mut data = Vec::new();
    fs::File::open(path)
        .and_then(|f| f.take(limits.max_archive_bytes + 1).read_to_end(&mut data))
        .map_err(|e| format!("read error: {e}"))?;
    if data.len() as u64 > limits.max_archive_bytes {
        return Err("file grew past the size limit while reading".to_string());
    }
    Ok(data)
}

fn display_name(raw: &[u8]) -> String {
    ui::sanitize_line(&String::from_utf8_lossy(raw))
}

fn suspicious(raw: &[u8]) -> bool {
    let s = String::from_utf8_lossy(raw);
    s.starts_with('/')
        || s.starts_with('\\')
        || s.contains('\\')
        || s.contains('\0')
        || s.split('/').any(|seg| seg == "..")
        || s.as_bytes().get(1) == Some(&b':')
}

/// Ищет EOCD с конца. Возвращает (позиция, есть ли хвост после комментария).
fn find_eocd(data: &[u8]) -> Option<(usize, bool)> {
    if data.len() < EOCD_LEN {
        return None;
    }
    let lowest = data.len().saturating_sub(EOCD_LEN + MAX_COMMENT);
    let mut fallback = None;
    let mut pos = data.len() - EOCD_LEN;
    loop {
        // Подпись внутри комментария может стоять у самого конца — тогда это не EOCD, ищем дальше.
        if u32_at(data, pos) == Some(SIG_EOCD)
            && let Some(comment) = u16_at(data, pos + 20)
        {
            let end = pos + EOCD_LEN + usize::from(comment);
            if end == data.len() {
                return Some((pos, false));
            }
            if end < data.len() && fallback.is_none() {
                fallback = Some((pos, true));
            }
        }
        if pos == lowest {
            return fallback;
        }
        pos -= 1;
    }
}

impl<'a> Archive<'a> {
    pub fn parse(data: &'a [u8], limits: &Limits) -> Result<Archive<'a>, ZipError> {
        if data.len() as u64 > limits.max_archive_bytes {
            return Err(ZipError::TooLarge {
                size: data.len() as u64,
                limit: limits.max_archive_bytes,
            });
        }
        let (eocd, trailing) = find_eocd(data).ok_or(ZipError::NoEndOfCentralDirectory)?;
        let field16 = |o: usize| u16_at(data, eocd + o).ok_or(ZipError::NoEndOfCentralDirectory);
        let field32 = |o: usize| u32_at(data, eocd + o).ok_or(ZipError::NoEndOfCentralDirectory);
        let (disk, cd_disk) = (field16(4)?, field16(6)?);
        let (on_disk, total) = (field16(8)?, field16(10)?);
        let (cd_size, cd_offset) = (field32(12)?, field32(16)?);
        let zip64_locator = eocd >= 20 && u32_at(data, eocd - 20) == Some(SIG_ZIP64_LOCATOR);
        if zip64_locator || total == 0xffff || cd_size == u32::MAX || cd_offset == u32::MAX {
            return Err(ZipError::Zip64Unsupported);
        }
        if disk != 0 || cd_disk != 0 || on_disk != total {
            return Err(ZipError::MultiDisk);
        }
        if usize::from(total) > limits.max_entries {
            return Err(ZipError::TooManyEntries {
                declared: u64::from(total),
                limit: limits.max_entries,
            });
        }
        let cd_start = cd_offset as usize;
        let cd_end = cd_start
            .checked_add(cd_size as usize)
            .filter(|&end| end <= eocd)
            .ok_or(ZipError::CentralDirectoryOutOfBounds)?;

        let mut issues = Vec::new();
        if trailing {
            let end = eocd + EOCD_LEN + usize::from(field16(20)?);
            issues.push(Issue::TrailingData {
                bytes: (data.len() - end) as u64,
            });
        }

        let mut entries = Vec::with_capacity(usize::from(total));
        let mut p = cd_start;
        for index in 0..usize::from(total) {
            let bad = ZipError::BadCentralDirectoryEntry { index };
            if p + CENTRAL_LEN > cd_end || u32_at(data, p) != Some(SIG_CENTRAL) {
                return Err(bad);
            }
            let f16 = |o: usize| u16_at(data, p + o).ok_or(bad.clone());
            let f32 = |o: usize| u32_at(data, p + o).ok_or(bad.clone());
            let flags = f16(8)?;
            let method = f16(10)?;
            let crc = f32(16)?;
            let compressed = f32(20)?;
            let uncompressed = f32(24)?;
            let name_len = usize::from(f16(28)?);
            let extra_len = usize::from(f16(30)?);
            let comment_len = usize::from(f16(32)?);
            let local = f32(42)?;
            let raw_name = slice_at(data, p + CENTRAL_LEN, name_len)
                .ok_or(bad.clone())?
                .to_vec();
            let next = p + CENTRAL_LEN + name_len + extra_len + comment_len;
            if next > cd_end {
                return Err(bad);
            }
            p = next;
            if compressed == u32::MAX || uncompressed == u32::MAX || local == u32::MAX {
                return Err(ZipError::Zip64Unsupported);
            }
            let mut entry = Entry {
                name: display_name(&raw_name),
                raw_name,
                flags,
                method,
                crc32: crc,
                compressed_size: u64::from(compressed),
                uncompressed_size: u64::from(uncompressed),
                local_offset: u64::from(local),
                data_offset: 0,
                untrusted: None,
            };
            check_local_header(data, &mut entry, cd_start);
            entries.push(entry);
        }
        if p != cd_end {
            issues.push(Issue::CentralDirectorySizeMismatch);
        }

        // Перекрытия: [локальный заголовок, конец данных) у разных записей не пересекаются.
        let mut spans: Vec<(usize, usize, usize)> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.untrusted.is_none())
            .map(|(i, e)| {
                (
                    e.local_offset as usize,
                    e.data_offset + e.compressed_size as usize,
                    i,
                )
            })
            .collect();
        spans.sort();
        let mut overlapping = Vec::new();
        for pair in spans.windows(2) {
            if pair[1].0 < pair[0].1 {
                overlapping.push((pair[0].2, pair[1].2));
            }
        }
        for (a, b) in overlapping {
            issues.push(Issue::Overlap {
                first: entries[a].name.clone(),
                second: entries[b].name.clone(),
            });
            entries[a].untrusted = Some("shares bytes with another entry");
            entries[b].untrusted = Some("shares bytes with another entry");
        }
        if let Some(&(first, _, _)) = spans.first()
            && first > 0
        {
            issues.push(Issue::PrependedData {
                bytes: first as u64,
            });
        }

        let mut seen: HashMap<&[u8], usize> = HashMap::new();
        for e in &entries {
            *seen.entry(e.raw_name.as_slice()).or_default() += 1;
        }
        let mut dups: Vec<(&[u8], usize)> = seen.into_iter().filter(|(_, n)| *n > 1).collect();
        dups.sort();
        for (raw, count) in dups {
            issues.push(Issue::DuplicateName {
                name: display_name(raw),
                count,
            });
        }
        for e in &entries {
            if suspicious(&e.raw_name) {
                issues.push(Issue::SuspiciousName {
                    name: e.name.clone(),
                });
            }
            if let Some(reason) = e.untrusted {
                issues.push(Issue::UntrustedEntry {
                    name: e.name.clone(),
                    reason,
                });
            }
        }
        Ok(Archive {
            data,
            entries,
            issues,
            limits: limits.clone(),
        })
    }

    /// Первая запись с таким именем (в порядке центрального каталога).
    pub fn find(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.raw_name == name.as_bytes())
    }

    /// Сжатые байты записи (для тестов и диагностики); `None` — запись не доверяем.
    pub fn raw(&self, index: usize) -> Option<&'a [u8]> {
        let e = self.entries.get(index)?;
        if e.untrusted.is_some() {
            return None;
        }
        slice_at(self.data, e.data_offset, e.compressed_size as usize)
    }

    /// Распаковывает запись в память с проверкой лимитов, размера и CRC.
    pub fn read(&self, index: usize, budget: &mut Budget) -> Result<Vec<u8>, EntryError> {
        let e = self
            .entries
            .get(index)
            .ok_or(EntryError::Untrusted("no such entry"))?;
        if let Some(reason) = e.untrusted {
            return Err(EntryError::Untrusted(reason));
        }
        if e.flags & FLAG_ENCRYPTED != 0 {
            return Err(EntryError::Encrypted);
        }
        if e.method != 0 && e.method != 8 {
            return Err(EntryError::UnsupportedMethod(e.method));
        }
        if e.uncompressed_size > self.limits.max_entry_bytes {
            return Err(EntryError::TooLarge {
                declared: e.uncompressed_size,
                limit: self.limits.max_entry_bytes,
            });
        }
        let ratio_exceeded = match e.uncompressed_size.checked_div(e.compressed_size) {
            None => e.uncompressed_size > 0, // compressed_size == 0
            Some(ratio) => ratio > self.limits.max_ratio,
        };
        if e.method == 8 && ratio_exceeded {
            return Err(EntryError::RatioExceeded {
                compressed: e.compressed_size,
                declared: e.uncompressed_size,
            });
        }
        if budget.remaining < e.uncompressed_size {
            return Err(EntryError::BudgetExhausted);
        }
        budget.remaining -= e.uncompressed_size;
        let raw = self
            .raw(index)
            .ok_or(EntryError::Untrusted("data out of bounds"))?;
        let declared = e.uncompressed_size;
        let data = if e.method == 0 {
            if e.compressed_size != declared {
                return Err(EntryError::SizeMismatch { declared });
            }
            raw.to_vec()
        } else {
            match inflate(raw, declared as usize) {
                Ok(out) => out.data,
                Err(InflateError::OutputLimit) => {
                    return Err(EntryError::SizeMismatch { declared });
                }
                Err(err) => return Err(EntryError::Inflate(err)),
            }
        };
        if data.len() as u64 != declared {
            return Err(EntryError::SizeMismatch { declared });
        }
        let actual = crc32(&data);
        if actual != e.crc32 {
            return Err(EntryError::CrcMismatch {
                expected: e.crc32,
                actual,
            });
        }
        Ok(data)
    }
}

/// Сверяет локальный заголовок с центральным каталогом и вычисляет начало данных.
fn check_local_header(data: &[u8], e: &mut Entry, cd_start: usize) {
    let at = e.local_offset as usize;
    if u32_at(data, at) != Some(SIG_LOCAL) {
        e.untrusted = Some("local header missing");
        return;
    }
    let (Some(method), Some(crc), Some(compressed), Some(name_len), Some(extra_len)) = (
        u16_at(data, at + 8),
        u32_at(data, at + 14),
        u32_at(data, at + 18),
        u16_at(data, at + 26),
        u16_at(data, at + 28),
    ) else {
        e.untrusted = Some("local header truncated");
        return;
    };
    let name_len = usize::from(name_len);
    if slice_at(data, at + LOCAL_LEN, name_len) != Some(e.raw_name.as_slice()) {
        e.untrusted = Some("local header name differs from the central directory");
        return;
    }
    if method != e.method {
        e.untrusted = Some("local header method differs from the central directory");
        return;
    }
    if e.flags & FLAG_DATA_DESCRIPTOR == 0
        && (crc != e.crc32 || u64::from(compressed) != e.compressed_size)
    {
        e.untrusted = Some("local header sizes or CRC differ from the central directory");
        return;
    }
    let start = at + LOCAL_LEN + name_len + usize::from(extra_len);
    match start.checked_add(e.compressed_size as usize) {
        Some(end) if end <= cd_start => e.data_offset = start,
        _ => e.untrusted = Some("entry data runs past the central directory"),
    }
}

#[cfg(test)]
pub(crate) mod tests;
