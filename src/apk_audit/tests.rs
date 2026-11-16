//! Сквозные тесты APK Static Audit: правила на фикстурах `fixtures/apk/rules/*.xml`
//! (кодируются тестовым кодировщиком и упаковываются в APK в памяти).

use super::axml::encode::{Options, encode};
use super::scan::{ApkScanOptions, ApkScanResult, scan_bytes};
use super::types::{CheckStatus, Confidence, Severity};
use super::zip::tests::{Builder, Spec};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn fixture(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("apk")
        .join(path)
}

pub(crate) fn compiled(path: &str) -> Vec<u8> {
    encode(
        &fs::read_to_string(fixture(path)).unwrap(),
        Options::default(),
    )
}

pub(crate) fn apk(manifest: &str, extra: Vec<Spec>) -> Vec<u8> {
    let mut specs = vec![Spec::deflated("AndroidManifest.xml", &compiled(manifest))];
    specs.extend(extra);
    Builder::with(specs).build().0
}

pub(crate) fn scan(bytes: &[u8]) -> ApkScanResult {
    scan_bytes(bytes, &ApkScanOptions::default())
}

/// (компонент, severity, confidence) находок правила, отсортированы.
fn rows(result: &ApkScanResult, rule: &str) -> Vec<(String, Severity, Confidence)> {
    let mut rows: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == rule)
        .map(|f| {
            (
                f.location.component.clone().unwrap_or_default(),
                f.severity,
                f.confidence,
            )
        })
        .collect();
    rows.sort();
    rows
}

fn row(
    component: &str,
    severity: Severity,
    confidence: Confidence,
) -> (String, Severity, Confidence) {
    (component.to_string(), severity, confidence)
}

fn check<'a>(result: &'a ApkScanResult, id: &str) -> &'a super::types::RuleCheck {
    result
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"))
}

fn explanation<'a>(result: &'a ApkScanResult, rule: &str, component: &str) -> &'a str {
    &result
        .findings
        .iter()
        .find(|f| f.rule_id == rule && f.location.component.as_deref() == Some(component))
        .unwrap_or_else(|| panic!("no {rule} finding for {component}"))
        .explanation
}

use Confidence::{NeedsReview, Potential};
use Severity::{Critical, High, Info, Low, Medium};

#[test]
fn export_001_target_30() {
    let r = scan(&apk("rules/exports-30.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-EXPORT-001"),
        vec![
            row("provider .Notes", Medium, Potential),
            row("receiver .PushReceiver", Low, NeedsReview),
            row("service .OpenService", Medium, Potential),
            row("service .WeakService", Low, Potential),
        ]
    );
    assert!(
        explanation(&r, "APK-EXPORT-001", "provider .Notes")
            .contains("No permission guards write access")
    );
    assert!(
        explanation(&r, "APK-EXPORT-001", "service .WeakService")
            .contains("normal/dangerous protection")
    );
    assert!(
        !explanation(&r, "APK-EXPORT-001", "receiver .PushReceiver").contains("refuses to install")
    );
    for id in [
        "APK-EXPORT-001",
        "APK-DEBUG-002",
        "APK-NET-003",
        "APK-BACKUP-004",
        "APK-PERMS-005",
        "APK-SECRET-006",
    ] {
        assert_eq!(check(&r, id).status, CheckStatus::Completed, "{id}");
    }
    assert!(rows(&r, "APK-DEBUG-002").is_empty());
    assert!(rows(&r, "APK-BACKUP-004").is_empty());
    assert!(rows(&r, "APK-NET-003").is_empty());
    assert_eq!(
        r.apk.package.as_deref(),
        Some("com.jetscan.fixture.exports")
    );
    assert_eq!((r.apk.min_sdk, r.apk.target_sdk), (Some(23), Some(30)));
}

#[test]
fn perms_005() {
    let r = scan(&apk("rules/exports-30.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-PERMS-005"),
        vec![
            row("uses-permission", Info, NeedsReview),
            row(
                "uses-permission android.permission.SYSTEM_ALERT_WINDOW",
                Low,
                NeedsReview
            ),
        ]
    );
    assert!(explanation(&r, "APK-PERMS-005", "uses-permission").contains("CAMERA, READ_CONTACTS"));
    // Только INTERNET (normal) — нет находок.
    let r = scan(&apk("rules/legacy-16.xml", vec![]));
    assert!(rows(&r, "APK-PERMS-005").is_empty());
}

#[test]
fn target_sdk_16_defaults() {
    let r = scan(&apk("rules/legacy-16.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-EXPORT-001"),
        vec![
            row("provider .Notes", Medium, NeedsReview),
            row("receiver .PushReceiver", Low, NeedsReview)
        ]
    );
    assert!(explanation(&r, "APK-EXPORT-001", "provider .Notes").contains("targetSdk < 17"));
    assert_eq!(
        rows(&r, "APK-BACKUP-004"),
        vec![row("application", Medium, NeedsReview)]
    );
    let mut net = rows(&r, "APK-NET-003");
    net.dedup();
    assert_eq!(net, vec![row("application", Low, NeedsReview)]);
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.rule_id == "APK-NET-003")
            .count(),
        2,
        "cleartext default + user CA default"
    );
}

#[test]
fn target_sdk_34_defaults() {
    let r = scan(&apk("rules/modern-34.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-EXPORT-001"),
        vec![row("receiver .PushReceiver", Low, NeedsReview)]
    );
    assert!(
        explanation(&r, "APK-EXPORT-001", "receiver .PushReceiver").contains("refuses to install")
    );
    assert_eq!(
        rows(&r, "APK-BACKUP-004"),
        vec![row("application", Low, NeedsReview)]
    );
    assert!(explanation(&r, "APK-BACKUP-004", "application").contains("not analysed"));
    assert!(rows(&r, "APK-NET-003").is_empty());
    assert!(rows(&r, "APK-DEBUG-002").is_empty());
}

#[test]
fn debug_002_backup_and_cleartext() {
    let r = scan(&apk("rules/debug-30.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-DEBUG-002"),
        vec![row("application", High, Potential)]
    );
    assert_eq!(
        rows(&r, "APK-BACKUP-004"),
        vec![row("application", Medium, Potential)]
    );
    assert_eq!(
        rows(&r, "APK-NET-003"),
        vec![row("application", Medium, Potential)]
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.rule_id == "APK-DEBUG-002")
        .unwrap();
    assert_eq!(f.cwe_ids, vec!["CWE-489"]);
    assert!(
        r.findings
            .iter()
            .all(|f| f.confidence != Confidence::Confirmed)
    );
}

fn nsc(entry: &str, source: &str) -> Spec {
    Spec::deflated(entry, &compiled(source))
}

#[test]
fn net_003_network_security_config_found_without_arsc() {
    // Имя файла обфусцировано — config находится по корневому элементу.
    let layout = encode("<LinearLayout />", Options::default());
    let r = scan(&apk(
        "rules/nsc-app.xml",
        vec![
            Spec::deflated("res/layout/main.xml", &layout),
            nsc("res/Xq.xml", "rules/nsc-user-ca.xml"),
        ],
    ));
    assert_eq!(r.apk.network_configs, vec!["res/Xq.xml".to_string()]);
    assert_eq!(
        rows(&r, "APK-NET-003"),
        vec![
            row(
                "base-config cleartextTrafficPermitted=true",
                Medium,
                Potential
            ),
            row(
                "domain-config cleartextTrafficPermitted=true",
                Low,
                NeedsReview
            ),
            row("trust-anchors certificates src=user", Medium, Potential),
        ]
    );
    // usesCleartextTraffic="true" перекрыт config (minSdk 24) — отдельной находки нет.
    assert!(
        r.findings
            .iter()
            .all(|f| f.location.component.as_deref() != Some("application"))
    );
    let f = r
        .findings
        .iter()
        .find(|f| f.title.contains("user-installed"))
        .unwrap();
    assert_eq!(f.location.archive_entry.as_deref(), Some("res/Xq.xml"));
    assert_eq!(f.cwe_ids, vec!["CWE-295"]);
    assert_eq!(check(&r, "APK-NET-003").status, CheckStatus::Completed);
}

#[test]
fn net_003_strict_config_and_debug_overrides() {
    let strict = scan(&apk(
        "rules/nsc-app.xml",
        vec![nsc(
            "res/xml/network_security_config.xml",
            "rules/nsc-strict.xml",
        )],
    ));
    assert!(rows(&strict, "APK-NET-003").is_empty());
    // Та же строгая конфигурация, но приложение debuggable — debug-overrides в силе.
    let source = fs::read_to_string(fixture("rules/nsc-app.xml"))
        .unwrap()
        .replace(
            "android:allowBackup=\"false\"",
            "android:allowBackup=\"false\" android:debuggable=\"true\"",
        );
    let mut specs = vec![Spec::deflated(
        "AndroidManifest.xml",
        &encode(&source, Options::default()),
    )];
    specs.push(nsc(
        "res/xml/network_security_config.xml",
        "rules/nsc-strict.xml",
    ));
    let r = scan(&Builder::with(specs).build().0);
    assert_eq!(
        rows(&r, "APK-NET-003"),
        vec![row("debug-overrides certificates src=user", Low, Potential)]
    );
}

#[test]
fn net_003_missing_config_is_partial() {
    let r = scan(&apk("rules/nsc-app.xml", vec![]));
    let c = check(&r, "APK-NET-003");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .contains("references a network security config")
    );
    assert!(!r.completed());
}

#[test]
fn secret_006_text_axml_and_out_of_scope_entries() {
    let stripe = crate::web_audit::testutil::stripe_secret();
    let github = crate::web_audit::testutil::github_token();
    let google = format!("{}{}", "AIza", crate::web_audit::testutil::body(35));
    let keys_xml = encode(
        &format!("<resources><item name=\"gh\" value=\"{github}\" /></resources>"),
        Options::default(),
    );
    let bytes = apk(
        "rules/exports-30.xml",
        vec![
            Spec::stored(
                "assets/config.json",
                format!("{{\n  \"maps\": \"{google}\",\n  \"stripe\": \"{stripe}\"\n}}\n")
                    .as_bytes(),
            ),
            Spec::stored(
                "assets/placeholder.txt",
                format!(
                    "STRIPE_KEY={}\n",
                    crate::web_audit::testutil::stripe_placeholder()
                )
                .as_bytes(),
            ),
            Spec::deflated("res/xml/keys.xml", &keys_xml),
            Spec::stored("classes.dex", stripe.as_bytes()),
            Spec::stored("lib/arm64-v8a/libnative.so", stripe.as_bytes()),
            Spec::stored("META-INF/MANIFEST.MF", stripe.as_bytes()),
        ],
    );
    let r = scan(&bytes);
    let mut found: Vec<(String, Option<u32>, Severity)> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APK-SECRET-006")
        .map(|f| {
            (
                f.location.archive_entry.clone().unwrap(),
                f.location.line,
                f.severity,
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            ("assets/config.json".to_string(), Some(2), Info),
            ("assets/config.json".to_string(), Some(3), Critical),
            ("res/xml/keys.xml".to_string(), None, Critical),
        ]
    );
    let axml_hit = r
        .findings
        .iter()
        .find(|f| f.location.archive_entry.as_deref() == Some("res/xml/keys.xml"))
        .unwrap();
    assert_eq!(
        axml_hit.location.component.as_deref(),
        Some("resources/item@value")
    );
    let dump = format!("{r:?}");
    for raw in [&stripe, &github, &google] {
        assert!(!dump.contains(raw.as_str()), "raw value leaked");
    }
    // .so и META-INF — вне рамок; classes.dex теперь читается, но здесь это не DEX → partial.
    assert!(
        r.limitations
            .iter()
            .any(|l| l.contains("binary entr(ies)") && l.starts_with("2 "))
    );
    let c = check(&r, "APK-SECRET-006");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .contains("classes.dex: not a DEX file")
    );
}

#[test]
fn broken_inputs_are_errors_not_clean() {
    // Не ZIP.
    let r = scan(b"definitely not an apk");
    assert_eq!(check(&r, "apk.archive").status, CheckStatus::Error);
    assert_eq!(check(&r, "APK-EXPORT-001").status, CheckStatus::Skipped);
    assert!(
        check(&r, "APK-EXPORT-001")
            .reason
            .as_deref()
            .unwrap()
            .starts_with("not_checked")
    );
    assert!(!r.completed());
    // ZIP без манифеста: правила манифеста пропущены, секреты всё равно проверены.
    let r = scan(
        &Builder::with(vec![Spec::stored("assets/a.txt", b"hello")])
            .build()
            .0,
    );
    assert_eq!(check(&r, "apk.manifest").status, CheckStatus::Error);
    assert_eq!(check(&r, "APK-SECRET-006").status, CheckStatus::Completed);
    // Текстовый, а не бинарный манифест.
    let r = scan(
        &Builder::with(vec![Spec::stored("AndroidManifest.xml", b"<manifest/>")])
            .build()
            .0,
    );
    assert!(
        check(&r, "apk.manifest")
            .reason
            .as_deref()
            .unwrap()
            .contains("not a binary Android XML")
    );
    // Перекрывающиеся записи — архив partial.
    let manifest = Spec::stored("AndroidManifest.xml", &compiled("rules/debug-30.xml"));
    let mut b = Builder::with(vec![manifest.clone()]);
    b.cd_only.push((manifest, 0));
    let r = scan(&b.build().0);
    assert_eq!(check(&r, "apk.archive").status, CheckStatus::Partial);
}

#[test]
fn report_json_and_text() {
    let r = scan(&apk("rules/debug-30.xml", vec![]));
    let json = super::report::render_json(&r, "debug.apk");
    let parsed = crate::json::parse(&json).unwrap();
    assert_eq!(
        parsed
            .get("schema_version")
            .and_then(crate::json::Json::as_f64),
        Some(2.0)
    );
    let scan = parsed.get("scan").unwrap();
    assert_eq!(
        scan.get("mode").and_then(crate::json::Json::as_str),
        Some("apk_static")
    );
    let first = &parsed
        .get("findings")
        .and_then(crate::json::Json::as_array)
        .unwrap()[0];
    let location = first.get("location").unwrap();
    assert_eq!(
        location
            .get("archive_entry")
            .and_then(crate::json::Json::as_str),
        Some("AndroidManifest.xml")
    );
    assert_eq!(location.get("line"), Some(&crate::json::Json::Null));
    let text = super::report::render_text(&r, "debug.apk");
    assert!(text.contains("HIGH [potential] APK-DEBUG-002  AndroidManifest.xml"));
    assert!(text.contains("classes*.dex: only the string pool is scanned"));
    assert!(text.contains("APK signatures (v1/v2/v3) are not verified"));
    assert_eq!(
        super::report::render_json(&scan_again(), "debug.apk"),
        json,
        "deterministic"
    );
}

fn scan_again() -> ApkScanResult {
    scan(&apk("rules/debug-30.xml", vec![]))
}

/// Demo 3: настоящий вывод aapt2 9.5.1 (манифест + network security config + resources.arsc),
/// без DEX и без подписи. Ссылка `@xml/network_security_config` в манифесте — ресурсный id,
/// config находится по содержимому, без разбора resources.arsc.
#[test]
fn demo3_aapt2_built_apk_end_to_end() {
    let path = fixture("demo/demo.apk");
    let r = super::scan::scan_apk(&path, &ApkScanOptions::default()).unwrap();
    assert_eq!(r.apk.package.as_deref(), Some("com.jetscan.demo"));
    assert_eq!((r.apk.min_sdk, r.apk.target_sdk), (Some(24), Some(34)));
    assert_eq!(
        r.apk.network_configs,
        vec!["res/xml/network_security_config.xml".to_string()]
    );
    let mut all: Vec<(&str, String, Severity, Confidence)> = r
        .findings
        .iter()
        .map(|f| {
            (
                f.rule_id,
                f.location.component.clone().unwrap_or_default(),
                f.severity,
                f.confidence,
            )
        })
        .collect();
    all.sort();
    assert_eq!(
        all,
        vec![
            (
                "APK-BACKUP-004",
                "application".to_string(),
                Medium,
                NeedsReview
            ),
            ("APK-DEBUG-002", "application".to_string(), High, Potential),
            (
                "APK-EXPORT-001",
                "service .TestService".to_string(),
                Medium,
                Potential
            ),
            (
                "APK-NET-003",
                "debug-overrides certificates src=user".to_string(),
                Low,
                Potential
            ),
        ]
    );
    assert!(
        r.checks.iter().all(|c| c.status == CheckStatus::Completed),
        "{:?}",
        r.checks
    );
    // resources.arsc — двоичная запись вне рамок SECRET-006 (и это сказано в отчёте).
    assert!(
        r.limitations
            .iter()
            .any(|l| l.starts_with("1 binary entr(ies)"))
    );
    assert!(r.limitations.iter().any(|l| l.contains("signatures")));

    let (code, text) =
        super::cli::tests::run_capture(&[path.display().to_string(), "--exit-code".to_string()]);
    assert_eq!(code, 1, "a high finding fails --exit-code");
    assert!(text.contains("HIGH [potential] APK-DEBUG-002"));
}

/// Битый APK (Demo 4) через CLI: отчёт есть, но с ошибкой, а `--exit-code` — 2, не 0.
#[test]
fn demo4_corrupt_apk_is_not_clean() {
    let t = crate::web_audit::testutil::TempProject::new();
    let mut bytes = fs::read(fixture("demo/demo.apk")).unwrap();
    bytes.truncate(bytes.len() - 30);
    t.write_bytes("broken.apk", &bytes);
    let (code, text) = super::cli::tests::run_capture(&[
        t.path().join("broken.apk").display().to_string(),
        "--exit-code".to_string(),
    ]);
    assert_eq!(code, 2);
    assert!(text.contains("error apk.archive"));
    assert!(text.contains("skipped APK-EXPORT-001: not_checked"));
}

#[test]
fn completed_requires_at_least_one_check() {
    let mut r = scan(&apk("rules/exports-30.xml", vec![]));
    assert!(r.completed());
    let broken = scan(b"not a zip");
    assert!(
        broken
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Skipped)
            .all(|c| c.reason.as_deref().is_some_and(|reason| !reason.is_empty()))
    );
    r.checks.clear();
    assert!(!r.completed(), "no checks means nothing was verified");
}

/// SECRET-006 по пулу строк DEX (ADR-DEX): high/potential + source:dex, AIza — info,
/// одна находка на значение на весь APK, место — DEX + индекс строки, без строки исходника.
#[test]
fn secret_006_dex_string_pools() {
    use super::dex::tests::{build, build_items, fix_checksum, items};
    let stripe = crate::web_audit::testutil::stripe_secret();
    let github = crate::web_audit::testutil::github_token();
    let google = format!("{}{}", "AIza", crate::web_audit::testutil::body(35));
    let multiline = format!("line one\nAuthorization: token {github}");
    let classes = build(&[
        "Lcom/jetscan/Fixture;",
        &stripe,
        &google,
        &crate::web_audit::testutil::stripe_placeholder(),
        "plain text",
    ]);
    let classes2 = build(&["Lcom/jetscan/Other;", &stripe, &multiline]);
    let mut corrupt = build(&["just strings"]);
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0x10; // checksum больше не сходится
    let container = build_items(b"041", &items(&["x"]));
    let bytes = apk(
        "rules/exports-30.xml",
        vec![
            Spec::stored("classes.dex", &classes),
            Spec::stored("classes2.dex", &classes2),
            Spec::stored("classes3.dex", &corrupt),
            Spec::stored("classes4.dex", &container),
            Spec::stored("assets/payload.dex", &classes),
        ],
    );
    let r = scan(&bytes);
    let mut dex: Vec<(String, String, Severity, Confidence)> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APK-SECRET-006")
        .map(|f| {
            assert_eq!(f.location.line, None, "never a source line from DEX");
            assert!(f.tags.contains(&"source:dex".to_string()));
            (
                f.location.archive_entry.clone().unwrap(),
                f.location.component.clone().unwrap(),
                f.severity,
                f.confidence,
            )
        })
        .collect();
    dex.sort();
    assert_eq!(
        dex,
        vec![
            (
                "classes.dex".into(),
                "string_ids[1]".into(),
                High,
                Potential
            ),
            (
                "classes.dex".into(),
                "string_ids[2]".into(),
                Info,
                NeedsReview
            ),
            (
                "classes2.dex".into(),
                "string_ids[2]".into(),
                High,
                Potential
            ),
        ]
    );
    let stripe_finding = r
        .findings
        .iter()
        .find(|f| f.location.component.as_deref() == Some("string_ids[1]"))
        .unwrap();
    assert!(
        stripe_finding
            .tags
            .contains(&"also_in:classes2.dex".to_string())
    );
    assert!(
        stripe_finding
            .tags
            .iter()
            .any(|t| t.starts_with("byte_offset:"))
    );
    assert!(stripe_finding.explanation.contains("bundled library"));
    let c = check(&r, "APK-SECRET-006");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .contains("classes4.dex: unsupported dex version 041")
    );
    assert!(
        r.limitations
            .iter()
            .any(|l| l.starts_with("classes3.dex: checksum mismatch"))
    );
    assert!(
        r.limitations
            .iter()
            .any(|l| l.starts_with("1 DEX/JAR/ZIP/APK file(s) inside the APK"))
    );
    let dump = format!("{r:?}");
    for raw in [&stripe, &github, &google] {
        assert!(!dump.contains(raw.as_str()), "raw value leaked");
    }
    // Тот же DEX с исправленной суммой — замечания нет.
    let mut fixed = corrupt.clone();
    fix_checksum(&mut fixed);
    let r = scan(&apk(
        "rules/exports-30.xml",
        vec![Spec::stored("classes.dex", &fixed)],
    ));
    assert!(r.limitations.iter().all(|l| !l.contains("checksum")));
    assert_eq!(check(&r, "APK-SECRET-006").status, CheckStatus::Completed);
}

#[test]
fn secret_006_dex_hit_cap_is_partial() {
    use super::dex::tests::build;
    let token = crate::web_audit::testutil::github_token();
    // 300 разных ключеподобных строк в одном DEX — больше лимита 200.
    let many: Vec<String> = (0..300)
        .map(|i| format!("{}{:04}", &token[..token.len() - 4], i))
        .collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let r = scan(&apk(
        "rules/exports-30.xml",
        vec![Spec::stored("classes.dex", &build(&refs))],
    ));
    let c = check(&r, "APK-SECRET-006");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .contains("more than 200 matches")
    );
    assert_eq!(
        r.findings
            .iter()
            .filter(|f| f.rule_id == "APK-SECRET-006")
            .count(),
        200
    );
}

/// Field test 2026-11-12, A1 (реальный FP в DEX популярного приложения): строки пула, где есть
/// только заголовок PEM (с `\n` и без), — не ключ; строка с телом — ключ (high, source:dex).
#[test]
fn secret_006_pem_header_only_is_not_a_key() {
    use super::dex::tests::build;
    use crate::web_audit::testutil::{pem_header, pem_key};
    let header = pem_header();
    let with_nl = format!("{header}\n");
    let only_headers = build(&["Lcom/jetscan/PemUtils;", &header, &with_nl]);
    let r = scan(&apk(
        "rules/exports-30.xml",
        vec![
            Spec::stored("classes.dex", &only_headers),
            Spec::stored("assets/header.txt", format!("{header}\n").as_bytes()),
        ],
    ));
    assert!(
        r.findings.iter().all(|f| f.rule_id != "APK-SECRET-006"),
        "{:?}",
        r.findings
    );
    assert_eq!(check(&r, "APK-SECRET-006").status, CheckStatus::Completed);
    let key = pem_key();
    let with_key = build(&["Lcom/jetscan/PemUtils;", &header, &key]);
    let r = scan(&apk(
        "rules/exports-30.xml",
        vec![
            Spec::stored("classes.dex", &with_key),
            Spec::stored("assets/key.pem", key.as_bytes()),
        ],
    ));
    let mut hits: Vec<(String, Severity)> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APK-SECRET-006")
        .map(|f| (f.location.archive_entry.clone().unwrap(), f.severity))
        .collect();
    hits.sort();
    assert_eq!(
        hits,
        vec![
            ("assets/key.pem".to_string(), Critical),
            ("classes.dex".to_string(), High)
        ]
    );
}

/// Field test 2026-11-12, A2: ошибка `jetscan apk <path>` называет путь.
#[test]
fn scan_errors_name_the_path() {
    let t = crate::web_audit::testutil::TempProject::new();
    let dir = t.path().join("not-an-apk-dir");
    std::fs::create_dir_all(&dir).unwrap();
    let missing = t.path().join("missing.apk");
    for path in [&dir, &missing] {
        let err = super::scan::scan_apk(path, &ApkScanOptions::default()).unwrap_err();
        assert!(err.contains(&path.display().to_string()), "{err}");
    }
    let dir_err = super::scan::scan_apk(&dir, &ApkScanOptions::default()).unwrap_err();
    assert!(dir_err.ends_with("not a regular file"), "{dir_err}");
}

/// Field test 2026-11-12, NET-003 дубль: флаг манифеста (minSdk 23) + base-config → одна находка.
#[test]
fn net_003_manifest_flag_and_config_merge_into_one() {
    let r = scan(&apk(
        "rules/nsc-min23.xml",
        vec![nsc("res/8G.xml", "rules/nsc-user-ca.xml")],
    ));
    assert_eq!(
        rows(&r, "APK-NET-003"),
        vec![
            row(
                "base-config cleartextTrafficPermitted=true",
                Medium,
                Potential
            ),
            row(
                "domain-config cleartextTrafficPermitted=true",
                Low,
                NeedsReview
            ),
            row("trust-anchors certificates src=user", Medium, Potential),
        ]
    );
    let merged = explanation(
        &r,
        "APK-NET-003",
        "base-config cleartextTrafficPermitted=true",
    );
    assert!(
        merged.contains("below Android 7.0 (minSdk is 23)"),
        "{merged}"
    );
    // Без config флаг манифеста остаётся отдельной находкой (debug-30).
    let r = scan(&apk("rules/debug-30.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-NET-003"),
        vec![row("application", Medium, Potential)]
    );
}

/// Field test 2026-11-12, паттерн 12: документированные публичные точки входа → info/needs_review;
/// явный экспорт без intent-filter → medium; свои действия и provider — как раньше.
#[test]
fn export_001_public_entry_points_are_info() {
    let r = scan(&apk("rules/entry-points.xml", vec![]));
    assert_eq!(
        rows(&r, "APK-EXPORT-001"),
        vec![
            row("activity .LinkActivity", Info, NeedsReview),
            row("activity .PreviewActivity", Medium, Potential),
            row("activity .ShareActivity", Info, NeedsReview),
            row("activity-alias .LegacyLinkAlias", Info, NeedsReview),
            row("activity-alias .OrphanAlias", Medium, Potential),
            row("activity-alias .PreviewAlias", Medium, Potential),
            row(
                "activity-alias com.jetscan.fixture.entry.ShareAlias",
                Info,
                NeedsReview
            ),
            row("provider .SettingsProvider", Medium, Potential),
            row("receiver .BootReceiver", Info, NeedsReview),
            row("receiver .CustomReceiver", Low, Potential),
            row("service .MixedService", Medium, Potential),
            row("service .PlayerService", Info, NeedsReview),
        ]
    );
    let link = explanation(&r, "APK-EXPORT-001", "activity .LinkActivity");
    assert!(link.contains("VIEW (BROWSABLE deep link)"), "{link}");
    assert!(
        explanation(&r, "APK-EXPORT-001", "activity .PreviewActivity").contains("no intent-filter")
    );
    let info = r
        .findings
        .iter()
        .find(|f| f.location.component.as_deref() == Some("service .PlayerService"))
        .unwrap();
    assert_eq!(
        info.title,
        "Exported service is a documented public entry point"
    );
    assert!(
        info.tags
            .contains(&"purpose:public-entry-point".to_string())
    );
    let alias = explanation(&r, "APK-EXPORT-001", "activity-alias .LegacyLinkAlias");
    assert!(
        alias.contains("alias of .LinkActivity") && alias.contains("VIEW (BROWSABLE deep link)"),
        "{alias}"
    );
    assert!(
        explanation(&r, "APK-EXPORT-001", "activity-alias .PreviewAlias")
            .contains("no intent-filter")
    );
}
