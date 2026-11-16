//! Тесты декодера AXML: фикстуры (наш кодировщик сейчас, `aapt2.axml` — когда появится),
//! обфускация имён, враждебные входы, мутационный тест.

use super::encode::{Options, encode};
use super::*;
use crate::apk_audit::inflate::tests::Rng;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("apk")
        .join("axml")
}

fn cases() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(fixture_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    assert!(dirs.len() >= 2);
    dirs
}

const VARIANTS: [Options; 4] = [
    Options {
        utf8: false,
        obfuscate_names: false,
    },
    Options {
        utf8: true,
        obfuscate_names: false,
    },
    Options {
        utf8: false,
        obfuscate_names: true,
    },
    Options {
        utf8: true,
        obfuscate_names: true,
    },
];

/// Атрибуты, которые aapt2 добавляет в `<manifest>` сам; при сверке с `aapt2.axml` их не учитываем.
const AAPT2_INJECTED: &[&str] = &[
    "android:compileSdkVersion",
    "android:compileSdkVersionCodename",
    "platformBuildVersionCode",
    "platformBuildVersionName",
];

#[test]
fn fixtures_decode_to_expected_dump() {
    for dir in cases() {
        let source = fs::read_to_string(dir.join("AndroidManifest.xml")).unwrap();
        let expected = fs::read_to_string(dir.join("expected.txt")).unwrap();
        for options in VARIANTS {
            let bytes = encode(&source, options);
            let doc = decode(&bytes, &Limits::default()).unwrap();
            assert_eq!(dump(&doc), expected, "{} {options:?}", dir.display());
        }
        // Оракул aapt2 (одобрен 2026-11-12): обязателен для каждого случая, чтобы его пропажа
        // не превращалась в тихое «проверено только своим кодировщиком».
        let aapt2 = dir.join("aapt2.axml");
        assert!(aapt2.exists(), "missing aapt2 oracle for {}", dir.display());
        {
            let doc = decode(&fs::read(&aapt2).unwrap(), &Limits::default()).unwrap();
            assert!(
                doc.issues.is_empty(),
                "aapt2 output decoded with issues: {:?}",
                doc.issues
            );
            // aapt2 9.5.1 пишет атрибуты `compileSdkVersion*` и `platformBuildVersion*` в <manifest>.
            let injected = dump(&doc)
                .lines()
                .filter(|l| {
                    AAPT2_INJECTED
                        .iter()
                        .any(|a| l.trim_start().starts_with(&format!("A {a} ")))
                })
                .count();
            assert_eq!(injected, AAPT2_INJECTED.len(), "{}", dir.display());
            let filtered: String = dump(&doc)
                .lines()
                .filter(|l| {
                    !AAPT2_INJECTED
                        .iter()
                        .any(|a| l.trim_start().starts_with(&format!("A {a} ")))
                })
                .map(|l| format!("{l}\n"))
                .collect();
            assert_eq!(filtered, expected, "aapt2 oracle: {}", dir.display());
        }
    }
}

#[test]
fn obfuscated_attribute_names_resolve_by_resource_id() {
    let source =
        fs::read_to_string(fixture_root().join("debuggable-exported/AndroidManifest.xml")).unwrap();
    let doc = decode(
        &encode(
            &source,
            Options {
                utf8: false,
                obfuscate_names: true,
            },
        ),
        &Limits::default(),
    )
    .unwrap();
    let root = doc.root.as_ref().unwrap();
    let app = root
        .children
        .iter()
        .find(|e| e.name == "application")
        .unwrap();
    let debuggable = app.android("debuggable").unwrap();
    assert_eq!(debuggable.raw_name, "");
    assert_eq!(debuggable.resource_id, Some(0x0101_000f));
    assert_eq!(debuggable.value, Value::Bool(true));
    assert_eq!(
        root.plain("package").unwrap().value,
        Value::String("com.jetscan.fixture.debuggable".to_string())
    );
    let sdk = root.children.iter().find(|e| e.name == "uses-sdk").unwrap();
    assert_eq!(
        sdk.android("targetSdkVersion").unwrap().value,
        Value::Int(30)
    );
    assert_eq!(sdk.line, 7);
}

fn sample() -> Vec<u8> {
    let source = fs::read_to_string(fixture_root().join("hardened/AndroidManifest.xml")).unwrap();
    encode(&source, Options::default())
}

#[test]
fn rejects_non_axml_and_bad_headers() {
    let limits = Limits::default();
    assert_eq!(
        decode(b"<?xml version=\"1.0\"?><manifest/>", &limits),
        Err(AxmlError::NotAxml)
    );
    assert!(matches!(decode(&[], &limits), Err(AxmlError::Truncated(_))));
    let mut bytes = sample();
    // Документ «длиннее» данных.
    let too_long = bytes.len() as u32 + 1;
    bytes[4..8].copy_from_slice(&too_long.to_le_bytes());
    assert!(matches!(
        decode(&bytes, &limits),
        Err(AxmlError::Truncated(_))
    ));
    // Размер чанка меньше его заголовка.
    let mut bytes = sample();
    bytes[12..16].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        decode(&bytes, &limits),
        Err(AxmlError::Truncated(_))
    ));
    // Только заголовок документа, без пула строк.
    let header_only = [0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00];
    assert_eq!(
        decode(&header_only, &limits),
        Err(AxmlError::MissingStringPool)
    );
}

#[test]
fn every_truncation_is_handled() {
    let bytes = sample();
    for len in 0..bytes.len() {
        let _ = decode(&bytes[..len], &Limits::default());
    }
    // Хвост после документа — не ошибка, а замечание.
    let mut tail = bytes.clone();
    tail.extend_from_slice(b"junk");
    let doc = decode(&tail, &Limits::default()).unwrap();
    assert!(doc.issues.iter().any(|i| i.contains("trailing")));
}

#[test]
fn limits_stop_depth_attribute_and_string_bombs() {
    let ns = "xmlns:android=\"http://schemas.android.com/apk/res/android\"";
    let deep = format!(
        "<manifest {ns}>{}{}</manifest>",
        "<a>".repeat(300),
        "</a>".repeat(300)
    );
    assert_eq!(
        decode(&encode(&deep, Options::default()), &Limits::default()),
        Err(AxmlError::Limit("nesting depth"))
    );
    let attrs: String = (0..1001).map(|i| format!(" a{i}=\"v\"")).collect();
    let wide = format!("<manifest {ns}{attrs}/>");
    assert_eq!(
        decode(&encode(&wide, Options::default()), &Limits::default()),
        Err(AxmlError::Limit("attribute count"))
    );
    // Заявленное число строк больше лимита.
    let mut bytes = sample();
    bytes[16..20].copy_from_slice(&1_000_000u32.to_le_bytes());
    assert_eq!(
        decode(&bytes, &Limits::default()),
        Err(AxmlError::Limit("string count"))
    );
    let few = Limits {
        max_elements: 3,
        ..Limits::default()
    };
    assert_eq!(
        decode(&sample(), &few),
        Err(AxmlError::Limit("element count"))
    );
}

#[test]
fn structural_problems_become_issues_not_crashes() {
    let ns = "xmlns:android=\"http://schemas.android.com/apk/res/android\"";
    let bytes = encode(
        &format!("<manifest {ns}><application/></manifest>"),
        Options::default(),
    );
    let doc = decode(&bytes, &Limits::default()).unwrap();
    assert!(doc.issues.is_empty(), "{:?}", doc.issues);
    // Срезаем последние чанки (конец элементов и namespace) и правим размер документа:
    // остаются незакрытые элементы — дерево собирается, проблема записана.
    let mut cut = bytes.clone();
    let end_ns = 24; // node(16) + ext(8)
    let end_el = 24;
    cut.truncate(cut.len() - end_ns - 2 * end_el);
    let len = cut.len() as u32;
    cut[4..8].copy_from_slice(&len.to_le_bytes());
    let doc = decode(&cut, &Limits::default()).unwrap();
    assert_eq!(doc.root.as_ref().unwrap().name, "manifest");
    assert_eq!(doc.root.as_ref().unwrap().children.len(), 1);
    assert!(doc.issues.iter().any(|i| i.contains("not closed")));
    // Неизвестный чанк в середине — пропускается и отмечается.
    let mut extra = bytes.clone();
    let unknown = [0x77, 0x07, 0x08, 0x00, 0x0c, 0x00, 0x00, 0x00, 1, 2, 3, 4];
    let insert_at = extra.len() - end_ns;
    extra.splice(insert_at..insert_at, unknown);
    let len = extra.len() as u32;
    extra[4..8].copy_from_slice(&len.to_le_bytes());
    let doc = decode(&extra, &Limits::default()).unwrap();
    assert!(doc.issues.iter().any(|i| i.contains("unknown chunk")));
}

#[test]
fn bad_string_indexes_do_not_panic() {
    let mut bytes = sample();
    // Портим все u32-поля, похожие на индексы строк, после пула строк.
    let pool_size = u32_at(&bytes, 12).unwrap() as usize;
    let start = 8 + pool_size;
    for i in (start..bytes.len() - 3).step_by(4) {
        if u32_at(&bytes, i).is_some_and(|v| v < 64) {
            bytes[i..i + 4].copy_from_slice(&0x00ff_ff00u32.to_le_bytes());
        }
    }
    let _ = decode(&bytes, &Limits::default());
}

#[test]
fn mutated_documents_never_panic_or_hang() {
    let seeds: Vec<Vec<u8>> = cases()
        .iter()
        .flat_map(|dir| {
            let source = fs::read_to_string(dir.join("AndroidManifest.xml")).unwrap();
            VARIANTS
                .iter()
                .map(move |o| encode(&source, *o))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut rng = Rng(0x0dd_ba11_cafe_f00d);
    let started = std::time::Instant::now();
    for i in 0..20_000 {
        let mut data = seeds[i % seeds.len()].clone();
        for _ in 0..=rng.below(6) {
            let at = rng.below(data.len());
            data[at] = rng.next() as u8;
        }
        if rng.below(6) == 0 {
            data.truncate(rng.below(data.len() + 1));
        }
        if let Ok(doc) = decode(&data, &Limits::default()) {
            let _ = dump(&doc);
        }
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
}

#[test]
fn known_attribute_ids_are_unique() {
    let mut ids: Vec<u32> = KNOWN_ANDROID_ATTRS.iter().map(|(id, _)| *id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), KNOWN_ANDROID_ATTRS.len());
    assert_eq!(known_android_attr(0x0101_0010), Some("exported"));
    assert_eq!(known_android_attr(0x7f01_0000), None);
}

/// Сквозной путь APK-0 → APK-1: манифест, сжатый deflate в ZIP, читается и декодируется.
#[test]
fn manifest_inside_a_zip_round_trips() {
    use crate::apk_audit::zip::tests::{Builder, Spec};
    use crate::apk_audit::zip::{Archive, Budget, Limits as ZipLimits};
    let dir = fixture_root().join("debuggable-exported");
    let source = fs::read_to_string(dir.join("AndroidManifest.xml")).unwrap();
    let manifest = encode(&source, Options::default());
    let (apk, _) = Builder::with(vec![
        Spec::deflated("AndroidManifest.xml", &manifest),
        Spec::stored("resources.arsc", b"not parsed in APK-1"),
    ])
    .build();
    let archive = Archive::parse(&apk, &ZipLimits::default()).unwrap();
    let index = archive.find("AndroidManifest.xml").unwrap();
    let bytes = archive
        .read(index, &mut Budget::new(&ZipLimits::default()))
        .unwrap();
    let doc = decode(&bytes, &Limits::default()).unwrap();
    assert_eq!(
        dump(&doc),
        fs::read_to_string(dir.join("expected.txt")).unwrap()
    );
}
