//! Тесты ZIP: обычные архивы, враждебные архивы (собираются в памяти), фикстуры двух
//! независимых упаковщиков (7-Zip и PowerShell `Compress-Archive`), мутационный тест.

use super::*;
use crate::apk_audit::inflate::tests::{Rng, fixed_block, fixed_bomb};
use std::path::PathBuf;

#[derive(Clone)]
pub(crate) struct Spec {
    pub name: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub payload: Vec<u8>,
    pub crc: u32,
    pub size: u32,
    /// Имя в локальном заголовке, если должно отличаться от каталога.
    pub local_name: Option<Vec<u8>>,
}

impl Spec {
    pub fn stored(name: &str, data: &[u8]) -> Spec {
        Spec {
            name: name.as_bytes().to_vec(),
            method: 0,
            flags: 0,
            payload: data.to_vec(),
            crc: crc32(data),
            size: data.len() as u32,
            local_name: None,
        }
    }

    pub fn deflated(name: &str, data: &[u8]) -> Spec {
        Spec {
            method: 8,
            payload: fixed_block(data, &[], true),
            ..Spec::stored(name, data)
        }
    }
}

fn local_header(s: &Spec) -> Vec<u8> {
    let name = s.local_name.as_ref().unwrap_or(&s.name);
    let (crc, csize, usize_) = if s.flags & FLAG_DATA_DESCRIPTOR != 0 {
        (0, 0, 0)
    } else {
        (s.crc, s.payload.len() as u32, s.size)
    };
    let mut out = Vec::new();
    out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&s.flags.to_le_bytes());
    out.extend_from_slice(&s.method.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // время, дата
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&csize.to_le_bytes());
    out.extend_from_slice(&usize_.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out
}

fn central(s: &Spec, offset: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&s.flags.to_le_bytes());
    out.extend_from_slice(&s.method.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&s.crc.to_le_bytes());
    out.extend_from_slice(&(s.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&s.size.to_le_bytes());
    out.extend_from_slice(&(s.name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 4]); // extra, comment
    out.extend_from_slice(&[0; 8]); // disk, internal, external
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&s.name);
    out
}

#[derive(Default)]
pub(crate) struct Builder {
    pub prefix: Vec<u8>,
    pub specs: Vec<Spec>,
    /// Записи только в каталоге, с явным смещением локального заголовка.
    pub cd_only: Vec<(Spec, u32)>,
    pub comment: Vec<u8>,
    pub trailing: Vec<u8>,
}

impl Builder {
    pub fn with(specs: Vec<Spec>) -> Builder {
        Builder {
            specs,
            ..Builder::default()
        }
    }

    /// Байты архива и смещения локальных заголовков.
    pub fn build(&self) -> (Vec<u8>, Vec<u32>) {
        let mut out = self.prefix.clone();
        let mut offsets = Vec::new();
        for s in &self.specs {
            offsets.push(out.len() as u32);
            out.extend(local_header(s));
            out.extend_from_slice(&s.payload);
        }
        let cd_start = out.len();
        for (s, &off) in self.specs.iter().zip(&offsets) {
            out.extend(central(s, off));
        }
        for (s, off) in &self.cd_only {
            out.extend(central(s, *off));
        }
        let count = (self.specs.len() + self.cd_only.len()) as u16;
        let cd_size = (out.len() - cd_start) as u32;
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&(cd_start as u32).to_le_bytes());
        out.extend_from_slice(&(self.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.comment);
        out.extend_from_slice(&self.trailing);
        (out, offsets)
    }
}

fn eocd_at(data: &[u8], comment_len: usize, trailing: usize) -> usize {
    data.len() - trailing - comment_len - EOCD_LEN
}

fn read_all(archive: &Archive) -> Vec<Result<Vec<u8>, EntryError>> {
    let mut budget = Budget::new(&Limits::default());
    (0..archive.entries.len())
        .map(|i| archive.read(i, &mut budget))
        .collect()
}

#[test]
fn stored_and_deflated_round_trip() {
    let (data, _) = Builder::with(vec![
        Spec::stored("a.txt", b"plain stored text"),
        Spec::deflated("dir/b.txt", b"fixed huffman text"),
        Spec::stored("empty", b""),
    ])
    .build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    assert!(archive.issues.is_empty(), "{:?}", archive.issues);
    assert_eq!(archive.find("dir/b.txt"), Some(1));
    assert_eq!(archive.find("missing"), None);
    let mut budget = Budget::new(&Limits::default());
    let before = budget.remaining;
    assert_eq!(archive.read(0, &mut budget).unwrap(), b"plain stored text");
    assert_eq!(archive.read(1, &mut budget).unwrap(), b"fixed huffman text");
    assert_eq!(archive.read(2, &mut budget).unwrap(), b"");
    assert_eq!(before - budget.remaining, 17 + 18);
}

#[test]
fn data_descriptor_entries_are_read_from_the_central_directory() {
    let mut s = Spec::deflated("dd.txt", b"data descriptor");
    s.flags = FLAG_DATA_DESCRIPTOR;
    let (data, _) = Builder::with(vec![s]).build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    assert_eq!(
        read_all(&archive)[0].as_deref(),
        Ok(&b"data descriptor"[..])
    );
}

#[test]
fn zip_bombs_stop_before_or_at_the_declared_size() {
    // Заявлено 100 байт, поток распаковывается в ~1 МБ → стоп на 100, ошибка размера.
    let bomb = fixed_bomb(4000);
    let mut lying = Spec::stored("lying.bin", b"");
    lying.method = 8;
    lying.payload = bomb.clone();
    lying.size = 100;
    // Заявлено 10 МБ из ~6.5 КБ — степень сжатия > 1000:1 (больше, чем вообще даёт deflate), не распаковываем.
    let mut ratio = lying.clone();
    ratio.name = b"ratio.bin".to_vec();
    ratio.size = 10_000_000;
    // Заявлено больше лимита записи.
    let mut huge = lying.clone();
    huge.name = b"huge.bin".to_vec();
    huge.size = 64 * 1024 * 1024;
    let (data, _) = Builder::with(vec![lying, ratio, huge]).build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    let results = read_all(&archive);
    assert_eq!(results[0], Err(EntryError::SizeMismatch { declared: 100 }));
    assert!(matches!(results[1], Err(EntryError::RatioExceeded { .. })));
    assert!(matches!(results[2], Err(EntryError::TooLarge { .. })));
}

#[test]
fn total_budget_is_shared_across_entries() {
    let (data, _) = Builder::with(vec![
        Spec::stored("one", &[b'x'; 100]),
        Spec::stored("two", &[b'y'; 100]),
    ])
    .build();
    let limits = Limits {
        max_total_bytes: 150,
        ..Limits::default()
    };
    let archive = Archive::parse(&data, &limits).unwrap();
    let mut budget = Budget::new(&limits);
    assert!(archive.read(0, &mut budget).is_ok());
    assert_eq!(
        archive.read(1, &mut budget),
        Err(EntryError::BudgetExhausted)
    );
}

#[test]
fn entry_count_limit_and_zip64_markers() {
    let (mut data, _) = Builder::with(vec![Spec::stored("a", b"a")]).build();
    let eocd = eocd_at(&data, 0, 0);
    data[eocd + 8..eocd + 12].copy_from_slice(&[0x21, 0x4e, 0x21, 0x4e]); // 20001
    assert!(matches!(
        Archive::parse(&data, &Limits::default()),
        Err(ZipError::TooManyEntries {
            declared: 20001,
            ..
        })
    ));
    data[eocd + 8..eocd + 12].copy_from_slice(&[0xff; 4]);
    assert_eq!(
        Archive::parse(&data, &Limits::default()).unwrap_err(),
        ZipError::Zip64Unsupported
    );
    // Локатор ZIP64 перед EOCD.
    let (data, _) = Builder::with(vec![Spec::stored("a", b"a")]).build();
    let eocd = eocd_at(&data, 0, 0);
    let mut with_locator = data[..eocd].to_vec();
    with_locator.extend_from_slice(&SIG_ZIP64_LOCATOR.to_le_bytes());
    with_locator.extend_from_slice(&[0; 16]);
    with_locator.extend_from_slice(&data[eocd..]);
    assert_eq!(
        Archive::parse(&with_locator, &Limits::default()).unwrap_err(),
        ZipError::Zip64Unsupported
    );
}

#[test]
fn overlapping_entries_are_untrusted() {
    // Запись B лежит внутри данных записи A — приём «нерекурсивной zip-бомбы».
    let inner = Spec::stored("inner.bin", b"shared bytes");
    let mut payload = local_header(&inner);
    payload.extend_from_slice(&inner.payload);
    let outer = Spec::stored("outer.bin", &payload);
    let mut builder = Builder::with(vec![outer]);
    let (probe, offsets) = builder.build();
    drop(probe);
    let inner_offset = offsets[0] + local_header(&builder.specs[0]).len() as u32;
    builder.cd_only.push((inner, inner_offset));
    let (data, _) = builder.build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    assert!(
        archive
            .issues
            .iter()
            .any(|i| matches!(i, Issue::Overlap { .. }))
    );
    let results = read_all(&archive);
    assert!(
        results
            .iter()
            .all(|r| matches!(r, Err(EntryError::Untrusted(_))))
    );
}

#[test]
fn duplicate_names_alias_the_same_bytes() {
    let manifest = Spec::stored("AndroidManifest.xml", b"first");
    let mut builder = Builder::with(vec![manifest.clone()]);
    builder.cd_only.push((manifest, 0));
    let (data, _) = builder.build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    assert!(archive.issues.contains(&Issue::DuplicateName {
        name: "AndroidManifest.xml".to_string(),
        count: 2
    }));
    assert_eq!(archive.find("AndroidManifest.xml"), Some(0));
    // Два каталожных имени на одни байты — перекрытие, обе не доверяем.
    assert!(read_all(&archive).iter().all(|r| r.is_err()));
}

#[test]
fn suspicious_names_are_reported_and_never_extracted() {
    let (data, _) = Builder::with(vec![
        Spec::stored("../../evil.so", b"x"),
        Spec::stored("/abs/path", b"x"),
        Spec::stored("C:\\win\\x", b"x"),
        Spec::stored("ok/fine.txt", b"x"),
        Spec::stored("bell\u{7}name", b"x"),
    ])
    .build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    let flagged: Vec<&str> = archive
        .issues
        .iter()
        .filter_map(|i| match i {
            Issue::SuspiciousName { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(flagged, vec!["../../evil.so", "/abs/path", "C:\\win\\x"]);
    // Имя в отчёте без управляющих символов.
    assert_eq!(archive.entries[4].name, "bellname");
}

#[test]
fn corrupted_crc_local_header_and_unsupported_entries() {
    let mut bad_crc = Spec::stored("crc.txt", b"payload");
    bad_crc.crc ^= 1;
    let mut renamed = Spec::stored("cd-name", b"payload");
    renamed.local_name = Some(b"local-name".to_vec());
    let mut encrypted = Spec::stored("enc", b"payload");
    encrypted.flags = FLAG_ENCRYPTED;
    let mut bzip2 = Spec::stored("bz2", b"payload");
    bzip2.method = 12;
    let mut stored_lie = Spec::stored("stored-lie", b"payload");
    stored_lie.size = 3;
    let (data, _) = Builder::with(vec![bad_crc, renamed, encrypted, bzip2, stored_lie]).build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    let r = read_all(&archive);
    assert!(matches!(r[0], Err(EntryError::CrcMismatch { .. })));
    assert!(matches!(r[1], Err(EntryError::Untrusted(_))));
    assert_eq!(r[2], Err(EntryError::Encrypted));
    assert_eq!(r[3], Err(EntryError::UnsupportedMethod(12)));
    assert_eq!(r[4], Err(EntryError::SizeMismatch { declared: 3 }));
    assert!(
        archive
            .issues
            .iter()
            .any(|i| matches!(i, Issue::UntrustedEntry { name, .. } if name == "cd-name"))
    );
}

#[test]
fn malformed_containers() {
    let limits = Limits::default();
    assert_eq!(
        Archive::parse(&[], &limits).unwrap_err(),
        ZipError::NoEndOfCentralDirectory
    );
    assert_eq!(
        Archive::parse(&[0x50; 4000], &limits).unwrap_err(),
        ZipError::NoEndOfCentralDirectory
    );
    let (data, _) = Builder::with(vec![Spec::stored("a", b"abc")]).build();
    // Обрезанный EOCD.
    assert_eq!(
        Archive::parse(&data[..data.len() - 5], &limits).unwrap_err(),
        ZipError::NoEndOfCentralDirectory
    );
    // Каталог «за краем».
    let mut far = data.clone();
    let eocd = eocd_at(&far, 0, 0);
    far[eocd + 16..eocd + 20].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
    assert_eq!(
        Archive::parse(&far, &limits).unwrap_err(),
        ZipError::CentralDirectoryOutOfBounds
    );
    // Многотомный.
    let mut multi = data.clone();
    multi[eocd + 4] = 1;
    assert_eq!(
        Archive::parse(&multi, &limits).unwrap_err(),
        ZipError::MultiDisk
    );
    // Испорченная подпись записи каталога.
    let mut cd = data.clone();
    let cd_start = u32_at(&cd, eocd + 16).unwrap() as usize;
    cd[cd_start] = 0;
    assert_eq!(
        Archive::parse(&cd, &limits).unwrap_err(),
        ZipError::BadCentralDirectoryEntry { index: 0 }
    );
    // Слишком большой архив — до разбора.
    let small = Limits {
        max_archive_bytes: 10,
        ..Limits::default()
    };
    assert!(matches!(
        Archive::parse(&data, &small),
        Err(ZipError::TooLarge { .. })
    ));
}

#[test]
fn prepended_trailing_and_comment() {
    let mut b = Builder::with(vec![Spec::stored("a", b"abc")]);
    b.comment = b"archive comment with PK\x05\x06 inside".to_vec();
    let (data, _) = b.build();
    let archive = Archive::parse(&data, &Limits::default()).unwrap();
    assert!(archive.issues.is_empty(), "{:?}", archive.issues);
    // Байты до первой записи и после EOCD — допустимы, но отмечаются.
    b.comment.clear();
    b.prefix = b"#!/bin/sh polyglot\n".to_vec();
    let (data, offsets) = b.build();
    assert_eq!(offsets[0], 19);
    let mut with_tail = data.clone();
    with_tail.extend_from_slice(b"tail bytes");
    let archive = Archive::parse(&with_tail, &Limits::default()).unwrap();
    assert!(archive.issues.contains(&Issue::PrependedData { bytes: 19 }));
    assert!(archive.issues.contains(&Issue::TrailingData { bytes: 10 }));
    assert_eq!(read_all(&archive)[0].as_deref(), Ok(&b"abc"[..]));
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("apk")
        .join("zip")
}

/// Архивы двух независимых упаковщиков: все записи совпадают с исходниками,
/// и вместе они покрывают stored, fixed и dynamic блоки.
#[test]
fn archives_from_7zip_and_powershell_match_sources() {
    let dir = fixture_dir();
    let mut blocks = crate::apk_audit::inflate::BlockStats::default();
    let mut checked = 0;
    for zip in ["7zip.zip", "powershell.zip"] {
        let data = load(&dir.join(zip), &Limits::default()).expect(zip);
        assert!(data.len() < 10 * 1024, "{zip} must stay small");
        let archive = Archive::parse(&data, &Limits::default()).expect(zip);
        // PowerShell 5.1 `Compress-Archive` пишет `\` как разделитель — реальный случай
        // «подозрительного» имени; 7-Zip пишет `/`.
        let expected_issues = if zip == "powershell.zip" {
            vec![Issue::SuspiciousName {
                name: "nested\\привет.txt".to_string(),
            }]
        } else {
            vec![]
        };
        assert_eq!(archive.issues, expected_issues, "{zip}");
        let mut names: Vec<String> = archive
            .entries
            .iter()
            .map(|e| e.name.replace('\\', "/"))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "binary.bin",
                "empty.txt",
                "hello.txt",
                "lorem.txt",
                "nested/привет.txt"
            ],
            "{zip}"
        );
        let mut budget = Budget::new(&Limits::default());
        for (i, entry) in archive.entries.iter().enumerate() {
            let source = dir.join("src").join(entry.name.replace('\\', "/"));
            let expected = fs::read(source).expect("source file");
            assert_eq!(
                archive.read(i, &mut budget).as_deref(),
                Ok(expected.as_slice()),
                "{zip}/{}",
                entry.name
            );
            if entry.method == 8 {
                let out = inflate(archive.raw(i).unwrap(), expected.len()).unwrap();
                blocks.stored += out.blocks.stored;
                blocks.fixed += out.blocks.fixed;
                blocks.dynamic += out.blocks.dynamic;
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 10);
    assert!(
        blocks.dynamic > 0,
        "fixtures must exercise dynamic Huffman blocks: {blocks:?}"
    );
}

#[test]
fn load_refuses_non_files_and_checks_size_first() {
    let dir = fixture_dir();
    assert!(load(&dir, &Limits::default()).is_err());
    assert!(load(&dir.join("missing.zip"), &Limits::default()).is_err());
    let tiny = Limits {
        max_archive_bytes: 16,
        ..Limits::default()
    };
    assert!(
        load(&dir.join("7zip.zip"), &tiny)
            .unwrap_err()
            .contains("limit")
    );
}

#[test]
fn mutated_archives_never_panic_or_hang() {
    let dir = fixture_dir();
    let mut seeds = vec![
        Builder::with(vec![
            Spec::stored("AndroidManifest.xml", b"<manifest/>"),
            Spec::deflated("res/a.txt", b"deflated seed"),
        ])
        .build()
        .0,
    ];
    for zip in ["7zip.zip", "powershell.zip"] {
        seeds.push(fs::read(dir.join(zip)).unwrap());
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let started = std::time::Instant::now();
    for i in 0..3000 {
        let mut data = seeds[i % seeds.len()].clone();
        for _ in 0..=rng.below(6) {
            let at = rng.below(data.len());
            data[at] = rng.next() as u8;
        }
        if rng.below(5) == 0 {
            data.truncate(rng.below(data.len() + 1));
        }
        if let Ok(archive) = Archive::parse(&data, &Limits::default()) {
            for result in read_all(&archive).into_iter().flatten() {
                assert!(result.len() as u64 <= Limits::default().max_entry_bytes);
            }
        }
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}
