//! Пул строк DEX (`classes*.dex`) — только строки, для APK-SECRET-006 (ADR-DEX одобрен 2026-11-12).
//!
//! Читаем `header_item`, `map_list` (для сверки) и `string_ids` → `string_data_item`
//! (`uleb128 utf16_size` + MUTF-8 до `0x00`). Байткод, классы, методы не разбираем — поэтому
//! строку нельзя привязать к классу или строке исходника, и мы этого не делаем.
//! Формат: AOSP «Dalvik Executable format», https://source.android.com/docs/core/runtime/dex-format
//!
//! Враждебный вход: все чтения — через `cursor` с проверкой границ; число строк ограничено ДО чтения;
//! смещения дедуплицируются, а суммарно декодированные байты ≤ размера области данных (иначе миллион
//! id на одну строку в мегабайт дал бы терабайт работы); длина строки, `uleb128` и поиск `0x00`
//! ограничены; битый MUTF-8 → `U+FFFD`; рекурсии нет. Версии кроме 035–039 (в т. ч. контейнер 041)
//! и обратный порядок байт — `Err`, правило становится `partial`.

use super::cursor::{u8_at, u32_at};

const HEADER_SIZE: usize = 0x70;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const MAX_MAP_ITEMS: usize = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_strings: usize,
    /// Длина одной строки в байтах MUTF-8.
    pub max_string_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_strings: 1_000_000,
            max_string_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DexError {
    NotDex,
    UnsupportedVersion(String),
    BigEndian,
    Truncated(&'static str),
    Limit(&'static str),
}

impl DexError {
    pub fn describe(&self) -> String {
        match self {
            DexError::NotDex => "not a DEX file".to_string(),
            DexError::UnsupportedVersion(v) => format!(
                "unsupported dex version {v} (only 035-039 are read; the 041 container format is not)"
            ),
            DexError::BigEndian => "big-endian DEX is not supported".to_string(),
            DexError::Truncated(what) => format!("DEX is truncated or malformed: {what}"),
            DexError::Limit(what) => format!("DEX exceeds the {what} limit"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexString {
    /// Наименьший индекс в `string_ids`, указывающий на эту строку.
    pub index: u32,
    /// Смещение `string_data_item` в файле.
    pub offset: u32,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DexStrings {
    pub version: String,
    /// По возрастанию индекса; одна запись на уникальное смещение.
    pub strings: Vec<DexString>,
    /// Нефатальное: несовпадение checksum/размера/map_list, битые строки.
    pub issues: Vec<String>,
    /// Строки пропущены (битые, слишком длинные, лимит) — проверка неполная.
    pub skipped: usize,
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 — максимальная длина блока без переполнения u32 (как в zlib).
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// `uleb128` не длиннее 5 байт; возвращает (значение, следующий байт).
fn uleb128(data: &[u8], mut at: usize) -> Option<(u32, usize)> {
    let mut value = 0u32;
    for i in 0..5 {
        let byte = u8_at(data, at)?;
        at += 1;
        let bits = u32::from(byte & 0x7f);
        if i == 4 && bits > 0x0f {
            return None;
        }
        value |= bits << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, at));
        }
    }
    None
}

/// MUTF-8 → код-юниты UTF-16. Битая последовательность → `U+FFFD` (возвращается флаг).
fn mutf8_units(bytes: &[u8]) -> (Vec<u16>, bool) {
    let mut units = Vec::with_capacity(bytes.len());
    let mut bad = false;
    let mut i = 0;
    let cont = |b: Option<&u8>| {
        b.filter(|b| *b & 0xc0 == 0x80)
            .map(|b| u16::from(*b & 0x3f))
    };
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 & 0x80 == 0 {
            units.push(u16::from(b0));
            i += 1;
        } else if b0 & 0xe0 == 0xc0 {
            match cont(bytes.get(i + 1)) {
                Some(c1) => {
                    units.push((u16::from(b0 & 0x1f) << 6) | c1);
                    i += 2;
                }
                None => {
                    units.push(0xfffd);
                    bad = true;
                    i += 1;
                }
            }
        } else if b0 & 0xf0 == 0xe0 {
            match (cont(bytes.get(i + 1)), cont(bytes.get(i + 2))) {
                (Some(c1), Some(c2)) => {
                    units.push((u16::from(b0 & 0x0f) << 12) | (c1 << 6) | c2);
                    i += 3;
                }
                _ => {
                    units.push(0xfffd);
                    bad = true;
                    i += 1;
                }
            }
        } else {
            units.push(0xfffd);
            bad = true;
            i += 1;
        }
    }
    (units, bad)
}

pub fn read_strings(data: &[u8], limits: &Limits) -> Result<DexStrings, DexError> {
    if data.len() < 8 || &data[..4] != b"dex\n" || data[7] != 0 {
        return Err(DexError::NotDex);
    }
    let version = String::from_utf8_lossy(&data[4..7]).into_owned();
    if !matches!(version.as_str(), "035" | "036" | "037" | "038" | "039") {
        return Err(DexError::UnsupportedVersion(crate::ui::sanitize_line(
            &version,
        )));
    }
    if data.len() < HEADER_SIZE {
        return Err(DexError::Truncated("header"));
    }
    let field = |o: usize| u32_at(data, o).ok_or(DexError::Truncated("header"));
    match field(40)? {
        ENDIAN_CONSTANT => {}
        REVERSE_ENDIAN_CONSTANT => return Err(DexError::BigEndian),
        _ => return Err(DexError::Truncated("endian tag")),
    }
    if field(36)? as usize != HEADER_SIZE {
        return Err(DexError::Truncated("header size"));
    }
    let mut issues = Vec::new();
    let file_size = field(32)? as usize;
    let end = if file_size == data.len() {
        data.len()
    } else {
        issues.push(format!(
            "header file_size {file_size} differs from the entry size {}",
            data.len()
        ));
        file_size.min(data.len())
    };
    if end < HEADER_SIZE {
        return Err(DexError::Truncated("file size"));
    }
    if adler32(&data[12..end]) != field(8)? {
        issues.push("checksum mismatch: the file was modified or is corrupt".to_string());
    }

    let ids_size = field(56)? as usize;
    let ids_off = field(60)? as usize;
    if ids_size > limits.max_strings {
        return Err(DexError::Limit("string count"));
    }
    if ids_size > 0
        && (ids_off < HEADER_SIZE || ids_off.checked_add(ids_size * 4).is_none_or(|e| e > end))
    {
        return Err(DexError::Truncated("string_ids"));
    }
    // Область данных: строки обязаны лежать в ней. Битая область — читаем по всему файлу, но отмечаем.
    let data_off = field(108)? as usize;
    let data_size = field(104)? as usize;
    let (region_start, region_end) = match data_off.checked_add(data_size) {
        Some(e) if data_off >= HEADER_SIZE && e <= end && data_size > 0 => (data_off, e),
        _ => {
            issues.push(
                "data section bounds are invalid; strings were read from the whole file"
                    .to_string(),
            );
            (HEADER_SIZE, end)
        }
    };
    check_map(
        data,
        field(52)? as usize,
        end,
        ids_size,
        ids_off,
        &mut issues,
    );

    let mut ids: Vec<(u32, u32)> = (0..ids_size)
        .filter_map(|i| Some((u32_at(data, ids_off + 4 * i)?, i as u32)))
        .collect();
    ids.sort();
    ids.dedup_by_key(|(offset, _)| *offset);
    let budget_total = region_end - region_start;
    let mut decoded = 0usize;
    let mut skipped = 0usize;
    let mut bad_mutf8 = 0usize;
    let mut strings = Vec::with_capacity(ids.len());
    for (offset, index) in ids {
        let at = offset as usize;
        if at < region_start || at >= region_end {
            skipped += 1;
            continue;
        }
        let Some((utf16_size, body)) = uleb128(data, at) else {
            skipped += 1;
            continue;
        };
        // MUTF-8: не больше 3 байт на код-юнит; ищем 0x00 только в этом окне.
        let window = (utf16_size as usize)
            .saturating_mul(3)
            .saturating_add(1)
            .min(limits.max_string_bytes + 1)
            .min(region_end - body.min(region_end));
        let Some(len) = data[body..body + window].iter().position(|&b| b == 0) else {
            skipped += 1;
            continue;
        };
        decoded += len;
        if decoded > budget_total {
            issues.push(
                "decoded string bytes exceed the data section; the rest was not read".to_string(),
            );
            skipped += 1;
            break;
        }
        let (units, bad) = mutf8_units(&data[body..body + len]);
        if bad || units.len() != utf16_size as usize {
            bad_mutf8 += 1;
        }
        strings.push(DexString {
            index,
            offset,
            value: String::from_utf16_lossy(&units),
        });
    }
    if bad_mutf8 > 0 {
        issues.push(format!(
            "{bad_mutf8} string(s) with invalid MUTF-8 or a wrong length were decoded lossily"
        ));
    }
    strings.sort_by_key(|s| s.index);
    Ok(DexStrings {
        version,
        strings,
        issues,
        skipped,
    })
}

fn check_map(
    data: &[u8],
    map_off: usize,
    end: usize,
    ids_size: usize,
    ids_off: usize,
    issues: &mut Vec<String>,
) {
    let Some(count) = u32_at(data, map_off).filter(|_| map_off >= HEADER_SIZE && map_off < end)
    else {
        issues.push("map_list is missing or out of bounds".to_string());
        return;
    };
    if count as usize > MAX_MAP_ITEMS {
        issues.push("map_list is implausibly large; not checked".to_string());
        return;
    }
    for i in 0..count as usize {
        let item = map_off + 4 + 12 * i;
        let (Some(head), Some(size), Some(offset)) = (
            u32_at(data, item),
            u32_at(data, item + 4),
            u32_at(data, item + 8),
        ) else {
            issues.push("map_list is truncated".to_string());
            return;
        };
        if head as u16 == TYPE_STRING_ID_ITEM {
            if size as usize != ids_size || (ids_size > 0 && offset as usize != ids_off) {
                issues.push("map_list disagrees with the header about string_ids".to_string());
            }
            return;
        }
    }
    if ids_size > 0 {
        issues.push("map_list has no string_ids entry".to_string());
    }
}

#[cfg(test)]
pub(crate) mod tests;
