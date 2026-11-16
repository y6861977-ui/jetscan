//! Тесты пула строк DEX. DEX собирается здесь вручную (вариант B ADR-DEX): минимальный корректный
//! файл без классов — заголовок, `string_ids`, `string_data`, `map_list`, верный Adler-32.
//! Риск — тот же, что у AXML до aapt2: сборщик и читатель пишет один автор. Поэтому ожидаемые
//! значения в тестах заданы явно (байты MUTF-8 — руками, по спецификации), а не сняты с читателя.
//! Когда появится `dexdump` (оракул), его вывод на настоящем DEX от d8 можно сверить тем же тестом.

use super::*;
use crate::apk_audit::inflate::tests::Rng;

/// MUTF-8: U+0000 → C0 80, вне BMP — суррогаты по 3 байта (CESU-8).
pub(crate) fn mutf8(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in s.encode_utf16() {
        match unit {
            0x0001..=0x007f => out.push(unit as u8),
            0x0000 | 0x0080..=0x07ff => {
                out.push(0xc0 | (unit >> 6) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
            _ => {
                out.push(0xe0 | (unit >> 12) as u8);
                out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
                out.push(0x80 | (unit & 0x3f) as u8);
            }
        }
    }
    out
}

fn uleb(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Сырые `string_data_item` (длина + байты), чтобы тесты могли подложить битые.
pub(crate) fn items(strings: &[&str]) -> Vec<Vec<u8>> {
    strings
        .iter()
        .map(|s| {
            let mut item = Vec::new();
            uleb(s.encode_utf16().count() as u32, &mut item);
            item.extend(mutf8(s));
            item.push(0);
            item
        })
        .collect()
}

/// Собирает DEX версии `version` из готовых `string_data_item`.
pub(crate) fn build_items(version: &[u8; 3], data_items: &[Vec<u8>]) -> Vec<u8> {
    let ids: Vec<usize> = (0..data_items.len()).collect();
    build_raw(version, data_items, &ids)
}

/// То же, но `string_ids[i]` указывает на `data_items[ids[i]]` (для алиасинга смещений).
pub(crate) fn build_raw(version: &[u8; 3], data_items: &[Vec<u8>], ids: &[usize]) -> Vec<u8> {
    let n = ids.len();
    let ids_off = HEADER_SIZE;
    let data_off = ids_off + 4 * n;
    let mut data = Vec::new();
    let mut offsets = Vec::new();
    for item in data_items {
        offsets.push((data_off + data.len()) as u32);
        data.extend_from_slice(item);
    }
    while data.len() % 4 != 0 {
        data.push(0);
    }
    let map_off = data_off + data.len();
    let map: [(u16, u32, u32); 4] = [
        (0x0000, 1, 0),
        (0x0001, n as u32, ids_off as u32),
        (0x2002, n as u32, data_off as u32),
        (0x1000, 1, map_off as u32),
    ];
    data.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (kind, size, off) in map {
        data.extend_from_slice(&kind.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&off.to_le_bytes());
    }
    let total = data_off + data.len();
    let mut out = vec![0u8; HEADER_SIZE];
    out[..4].copy_from_slice(b"dex\n");
    out[4..7].copy_from_slice(version);
    let put =
        |out: &mut Vec<u8>, at: usize, v: u32| out[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put(&mut out, 32, total as u32);
    put(&mut out, 36, HEADER_SIZE as u32);
    put(&mut out, 40, ENDIAN_CONSTANT);
    put(&mut out, 52, map_off as u32);
    put(&mut out, 56, n as u32);
    put(&mut out, 60, if n == 0 { 0 } else { ids_off as u32 });
    put(&mut out, 104, data.len() as u32);
    put(&mut out, 108, data_off as u32);
    for &item in ids {
        out.extend_from_slice(&offsets[item].to_le_bytes());
    }
    out.extend(data);
    fix_checksum(&mut out);
    out
}

pub(crate) fn build(strings: &[&str]) -> Vec<u8> {
    build_items(b"035", &items(strings))
}

pub(crate) fn fix_checksum(dex: &mut [u8]) {
    let sum = adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&sum.to_le_bytes());
}

fn values(d: &DexStrings) -> Vec<&str> {
    d.strings.iter().map(|s| s.value.as_str()).collect()
}

#[test]
fn adler32_known_vectors() {
    assert_eq!(adler32(b""), 1);
    assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    assert_eq!(adler32(&[0xff; 10_000]), adler32([0xff; 10_000].as_ref()));
}

#[test]
fn mutf8_bytes_follow_the_spec() {
    // Байты заданы руками, не кодировщиком.
    assert_eq!(mutf8("A"), [0x41]);
    assert_eq!(mutf8("\0"), [0xc0, 0x80]);
    assert_eq!(mutf8("é"), [0xc3, 0xa9]);
    assert_eq!(mutf8("€"), [0xe2, 0x82, 0xac]);
    // U+1F600 = суррогаты D83D DE00, каждый по 3 байта.
    assert_eq!(mutf8("😀"), [0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
    let (units, bad) = mutf8_units(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]);
    assert_eq!(String::from_utf16_lossy(&units), "😀");
    assert!(!bad);
}

#[test]
fn reads_strings_with_unicode_nul_and_empty() {
    let input = ["", "Ljava/lang/String;", "Привет", "a\0b", "😀 ok"];
    let d = read_strings(&build(&input), &Limits::default()).unwrap();
    assert_eq!(d.version, "035");
    assert_eq!(values(&d), input.to_vec());
    assert!(d.issues.is_empty(), "{:?}", d.issues);
    assert_eq!(d.skipped, 0);
    assert_eq!(d.strings[2].index, 2);
}

#[test]
fn versions_and_byte_order() {
    for v in [b"035", b"037", b"038", b"039"] {
        assert!(read_strings(&build_items(v, &items(&["x"])), &Limits::default()).is_ok());
    }
    assert_eq!(
        read_strings(&build_items(b"041", &items(&["x"])), &Limits::default()),
        Err(DexError::UnsupportedVersion("041".to_string()))
    );
    let mut be = build(&["x"]);
    be[40..44].copy_from_slice(&REVERSE_ENDIAN_CONSTANT.to_le_bytes());
    assert_eq!(
        read_strings(&be, &Limits::default()),
        Err(DexError::BigEndian)
    );
    assert_eq!(
        read_strings(b"PK\x03\x04 not dex", &Limits::default()),
        Err(DexError::NotDex)
    );
    assert_eq!(
        read_strings(&build(&["x"])[..0x40], &Limits::default()),
        Err(DexError::Truncated("header"))
    );
}

#[test]
fn huge_declared_pool_is_rejected_before_reading() {
    let mut d = build(&["x"]);
    d[56..60].copy_from_slice(&4_000_000_000u32.to_le_bytes());
    assert_eq!(
        read_strings(&d, &Limits::default()),
        Err(DexError::Limit("string count"))
    );
    let mut d = build(&["x"]);
    d[56..60].copy_from_slice(&100_000u32.to_le_bytes());
    assert_eq!(
        read_strings(&d, &Limits::default()),
        Err(DexError::Truncated("string_ids"))
    );
}

#[test]
fn many_ids_aliasing_one_big_string_are_decoded_once() {
    // 100 000 id → одна строка в 100 КБ: без дедупа это 10 ГБ декодирования.
    let big = "k".repeat(100_000);
    let d = build_raw(b"035", &items(&[&big, "tail"]), &vec![0; 100_000]);
    let started = std::time::Instant::now();
    let r = read_strings(&d, &Limits::default()).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(r.strings.len(), 1, "one unique offset, decoded once");
    assert_eq!(r.strings[0].index, 0);
    assert_eq!(r.strings[0].value.len(), 100_000);
}

#[test]
fn hostile_strings_are_skipped_or_lossy_not_fatal() {
    // Заявлено 3 код-юнита (≤ 9 байт MUTF-8), а 0x00 нет и в 40 байтах — окно поиска ограничено.
    let mut no_terminator = Vec::new();
    uleb(3, &mut no_terminator);
    no_terminator.extend(std::iter::repeat_n(b'z', 40));
    let bad_uleb = vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x01, b'a', 0];
    let bad_mutf8 = vec![3, 0xff, b'a', 0xc3, 0];
    let d = build_items(
        b"035",
        &[
            items(&["ok"])[0].clone(),
            no_terminator,
            bad_uleb,
            bad_mutf8,
        ],
    );
    let r = read_strings(&d, &Limits::default()).unwrap();
    assert_eq!(r.skipped, 2, "no terminator + bad uleb128");
    let v = values(&r);
    assert_eq!(v[0], "ok");
    assert!(v[1].contains('\u{fffd}'));
    assert!(r.issues.iter().any(|i| i.contains("MUTF-8")));
}

#[test]
fn integrity_problems_are_issues() {
    assert!(
        read_strings(&build(&["x"]), &Limits::default())
            .unwrap()
            .issues
            .is_empty()
    );
    let mut d = build(&["abc"]);
    let last = d.len() - 1;
    d[last] ^= 0x55;
    let r = read_strings(&d, &Limits::default()).unwrap();
    assert!(r.issues.iter().any(|i| i.contains("checksum")));
    // map_list врёт про string_ids.
    let mut d = build(&["a", "b"]);
    let map_off = u32_at(&d, 52).unwrap() as usize;
    d[map_off + 4 + 12 + 4..map_off + 4 + 12 + 8].copy_from_slice(&7u32.to_le_bytes());
    fix_checksum(&mut d);
    let r = read_strings(&d, &Limits::default()).unwrap();
    assert!(r.issues.iter().any(|i| i.contains("map_list disagrees")));
    // Хвост после file_size.
    let mut d = build(&["a"]);
    d.extend_from_slice(b"junk");
    let r = read_strings(&d, &Limits::default()).unwrap();
    assert!(r.issues.iter().any(|i| i.contains("file_size")));
    assert_eq!(values(&r), vec!["a"]);
    // Смещение строки вне области данных — строка пропущена.
    let mut d = build(&["a"]);
    d[HEADER_SIZE..HEADER_SIZE + 4].copy_from_slice(&8u32.to_le_bytes());
    fix_checksum(&mut d);
    assert_eq!(read_strings(&d, &Limits::default()).unwrap().skipped, 1);
}

#[test]
fn every_truncation_and_mutation_is_safe() {
    let seed = build(&[
        "Lcom/jetscan/Fixture;",
        "Привет",
        "a\0b",
        "😀",
        &"x".repeat(300),
    ]);
    for len in 0..seed.len() {
        let _ = read_strings(&seed[..len], &Limits::default());
    }
    let mut rng = Rng(0xdec0_de15_bad5_eed5);
    let started = std::time::Instant::now();
    for _ in 0..20_000 {
        let mut d = seed.clone();
        for _ in 0..=rng.below(6) {
            let at = rng.below(d.len());
            d[at] = rng.next() as u8;
        }
        if let Ok(r) = read_strings(&d, &Limits::default()) {
            // Испорченный заголовок может заявить больше id — но работа ограничена размером файла.
            let decoded: usize = r.strings.iter().map(|s| s.value.len()).sum();
            assert!(r.strings.len() <= d.len() / 4);
            assert!(decoded <= 3 * d.len());
        }
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}
