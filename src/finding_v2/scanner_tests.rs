//! Web/APK/Android/iOS adapters on real scanner output (fixtures), end to end:
//! scan -> adapt -> validate -> redacted JSON -> wire::parse -> compare.
use super::output::{FINGERPRINT_LIMITATION, is_canonical_id, is_core_fingerprint};
use super::*;
use crate::android_audit::{self, AndroidScanOptions, AndroidScanResult};
use crate::apk_audit::zip::tests::{Builder, Spec};
use crate::apk_audit::{self, ApkScanOptions, ApkScanResult, zip};
use crate::ios_audit::{self, IosScanOptions, IosScanResult};
use crate::web_audit::{self, WebScanOptions, WebScanResult, testutil};
use std::collections::BTreeMap;
use std::path::Path;

const WEB_FIXTURES: &[&str] = &[
    "next-app",
    "next-pages",
    "next-routes",
    "vite-react",
    "unsupported-nuxt",
    "broken-manifest",
];

/// Every synthetic value the fixtures materialize (see `web_audit::testutil`).
fn fake_values() -> Vec<String> {
    let body = testutil::body;
    vec![
        testutil::stripe_secret(),
        testutil::github_token(),
        testutil::supabase_jwt("service_role"),
        testutil::supabase_jwt("anon"),
        format!("{}{}", "pk_live_", body(28)),
        format!("{}{}", "AIza", body(35)),
        format!("{}{}", "sb_secret_", body(31)),
        format!("{}{}", "sb_publishable_", body(31)),
        body(24),
    ]
    .into_iter()
    // Android fixtures (`android_audit::testutil` placeholders).
    .chain(
        [
            "STRIPE_SECRET",
            "GITHUB_TOKEN",
            "GOOGLE_API_KEY",
            "SLACK_TOKEN",
            "PEM_KEY",
            "PEM_KEY_JSON",
            "PASSWORD",
            "PASSWORD2",
        ]
        .iter()
        .map(|label| android_audit::testutil::expand(&format!("@@{label}@@"))),
    )
    // iOS fixtures use the same placeholders; these are the bodies of the
    // signing-file fixtures, which must never be read into a finding.
    .chain([
        "fixture pkcs12 identity".to_string(),
        "Salted__fixture".to_string(),
    ])
    .collect()
}

fn web_scan(root: &Path) -> WebScanResult {
    web_audit::scan_source(root, &WebScanOptions::default()).expect("scan fixture")
}

/// Adapt, export through the redacted path, re-import, and check the
/// invariants every scanner result must keep. Returns the exported view.
fn export_and_reimport(v2: &ScanResultV2) -> RedactedScan {
    v2.validate().expect("adapter output validates");
    let policy = RedactionPolicy::default();
    let safe = v2.redacted(&policy).expect("export");
    let json = safe.render_json();
    for raw in fake_values() {
        assert!(!json.contains(&raw), "raw fixture value in V2 JSON");
        assert!(!safe.render_html().contains(&raw));
    }
    let back = wire::parse(&json, &policy).expect("strict re-import");
    assert_eq!(back, safe, "wire roundtrip is exact");
    assert_eq!(back.render_json(), json, "byte-identical re-export");
    for f in &safe.as_scan().findings {
        assert!(is_canonical_id(&f.id, &f.rule_id), "{}", f.id);
    }
    let has_fp = safe
        .as_scan()
        .findings
        .iter()
        .any(|f| f.evidence.fingerprint.is_some());
    assert_eq!(
        has_fp,
        safe.as_scan()
            .limitations
            .contains(&FINGERPRINT_LIMITATION.to_string())
    );
    safe
}

fn checks_of(checks: &[RuleCheck]) -> BTreeMap<String, (CheckStatus, Option<String>)> {
    checks
        .iter()
        .map(|c| (c.id.clone(), (c.status, c.reason.clone())))
        .collect()
}

fn status(s: web_audit::CheckStatus) -> CheckStatus {
    match s {
        web_audit::CheckStatus::Completed => CheckStatus::Completed,
        web_audit::CheckStatus::Partial => CheckStatus::Partial,
        web_audit::CheckStatus::Skipped => CheckStatus::Skipped,
        web_audit::CheckStatus::Error => CheckStatus::Error,
    }
}

#[test]
fn web_fixtures_map_one_to_one_and_roundtrip() {
    let mut total = 0;
    for name in WEB_FIXTURES {
        let project = testutil::fixture(name);
        let r = web_scan(project.path());
        let v2 = adapters::web(&r).unwrap();
        let safe = export_and_reimport(&v2);
        let out = safe.as_scan();
        assert_eq!(out.completed(), r.completed(), "{name}: completeness");
        // Checks 1:1, including skipped-with-reason (WEB-DEPS-008, :rls).
        let web_checks: BTreeMap<_, _> = r
            .checks
            .iter()
            .map(|c| (c.id.clone(), (status(c.status), c.reason.clone())))
            .collect();
        assert_eq!(checks_of(&out.checks), web_checks, "{name}: checks");
        assert!(out.checks.iter().any(|c| c.id == "WEB-DEPS-008"
            && c.status == CheckStatus::Skipped
            && c.reason.is_some()));
        for l in &r.limitations {
            assert!(out.limitations.contains(l), "{name}: limitation kept");
        }
        assert!(out.network_activities.is_empty());
        // Findings 1:1: same ids, fields and core fingerprints.
        assert_eq!(out.findings.len(), r.findings.len(), "{name}: no merge");
        for w in &r.findings {
            let f = out
                .findings
                .iter()
                .find(|f| f.id == w.id)
                .expect("web id kept as is");
            assert_eq!(f.rule_id, w.rule_id);
            assert_eq!(f.category, w.category);
            assert_eq!(f.title, w.title);
            assert_eq!(f.severity.to_string_for_test(), w.severity.label());
            assert_eq!(f.confidence.to_string_for_test(), w.confidence.label());
            assert_eq!(f.location.relative_path, w.location.relative_path);
            assert_eq!(f.location.line, w.location.line);
            assert_eq!(f.location.column, w.location.column);
            assert_eq!(
                (&f.location.archive_entry, &f.location.component),
                (&None, &None)
            );
            assert_eq!(f.remediation_id, w.remediation_id);
            assert_eq!(f.cwe_ids.len(), w.cwe_ids.len());
            if let Some(fp) = &w.evidence.fingerprint {
                assert!(is_core_fingerprint(fp), "web emits core fingerprints");
            }
            assert_eq!(f.evidence.fingerprint, w.evidence.fingerprint);
            // The excerpt is either kept or wholly blanked, never edited.
            assert!(
                f.evidence.redacted_excerpt == w.evidence.redacted_excerpt
                    || f.evidence.redacted_excerpt.as_deref() == Some("[redacted]")
            );
            total += 1;
        }
    }
    assert!(total >= 25, "fixtures produced {total} findings");
}

#[test]
fn web_incomplete_scan_stays_incomplete() {
    // broken-manifest: the Web scanner itself reports partial/error coverage.
    let project = testutil::fixture("broken-manifest");
    let r = web_scan(project.path());
    assert!(!r.completed());
    let safe = export_and_reimport(&adapters::web(&r).unwrap());
    assert!(!safe.as_scan().completed());
    assert!(
        safe.as_scan().findings.is_empty(),
        "no findings is not clean"
    );
    let mut wrong = r.clone();
    wrong.schema_version = 1;
    assert_eq!(
        adapters::web(&wrong),
        Err(ModelError("unsupported_schema_version"))
    );
}

#[test]
fn web_ids_survive_a_blank_line_inserted_above() {
    for name in ["next-app", "next-routes", "vite-react"] {
        let project = testutil::fixture(name);
        let export = |root: &Path| {
            let safe = adapters::web(&web_scan(root))
                .unwrap()
                .redacted(&RedactionPolicy::default())
                .unwrap();
            safe.as_scan()
                .findings
                .iter()
                .map(|f| {
                    (
                        f.id.clone(),
                        (f.location.relative_path.clone(), f.location.line),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let before = export(project.path());
        assert!(!before.is_empty());
        let mut files: Vec<_> = before.values().map(|(p, _)| p.clone()).collect();
        files.sort();
        files.dedup();
        for file in &files {
            let path = project.path().join(file);
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, format!("\n{text}")).unwrap();
        }
        let after = export(project.path());
        assert_eq!(
            after.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>(),
            "{name}: same ids after the shift"
        );
        let mut shifted = 0;
        for (id, (path, line)) in &before {
            assert_eq!(after[id].0, *path);
            if let Some(line) = line {
                assert_eq!(after[id].1, Some(line + 1), "{name}: {path} moved down");
                shifted += 1;
            }
        }
        assert!(shifted > 0, "{name}: test must move at least one finding");
    }
}

fn demo_apk() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/apk/demo/demo.apk")
}

#[test]
fn apk_demo_maps_one_to_one_and_roundtrips() {
    let r = apk_audit::scan_apk(&demo_apk(), &ApkScanOptions::default()).unwrap();
    let safe = export_and_reimport(&adapters::apk(&r).unwrap());
    let out = safe.as_scan();
    assert!(r.completed() && out.completed());
    let web_checks: BTreeMap<_, _> = r
        .checks
        .iter()
        .map(|c| (c.id.clone(), (status(c.status), c.reason.clone())))
        .collect();
    assert_eq!(checks_of(&out.checks), web_checks);
    assert!(out.checks.iter().any(|c| c.id == "apk.archive"));
    for l in &r.limitations {
        assert!(out.limitations.contains(l));
    }
    let mut rules: Vec<_> = out
        .findings
        .iter()
        .map(|f| (f.rule_id.as_str(), f.severity))
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            ("APK-BACKUP-004", Severity::Medium),
            ("APK-DEBUG-002", Severity::High),
            ("APK-EXPORT-001", Severity::Medium),
            ("APK-NET-003", Severity::Low),
        ]
    );
    assert_eq!(out.findings.len(), r.findings.len());
    for a in &r.findings {
        let f = out
            .findings
            .iter()
            .find(|f| f.id == a.id)
            .expect("apk id kept");
        assert!(f.id.starts_with("apk/"));
        let entry = a.location.archive_entry.clone().unwrap();
        assert_eq!(f.location.relative_path, entry);
        assert_eq!(f.location.archive_entry.as_deref(), Some(entry.as_str()));
        assert_eq!(f.location.component, a.location.component);
        assert_eq!(f.location.line, a.location.line);
        assert_eq!(f.location.column, None);
        assert_eq!(f.evidence.fingerprint, a.evidence.fingerprint);
    }
    let mut broken = r.clone();
    broken.findings[0].location.archive_entry = None;
    assert_eq!(
        adapters::apk(&broken),
        Err(ModelError("missing_archive_entry"))
    );
}

/// The demo manifest (real aapt2 output) plus one text asset.
fn apk_with_asset(asset: &str) -> Vec<u8> {
    apk_with(vec![Spec::stored("assets/config.json", asset.as_bytes())])
}

/// The demo manifest (real aapt2 output) plus the given entries.
fn apk_with(extra: Vec<Spec>) -> Vec<u8> {
    let bytes = std::fs::read(demo_apk()).unwrap();
    let limits = zip::Limits::default();
    let archive = zip::Archive::parse(&bytes, &limits).unwrap();
    let i = archive.find("AndroidManifest.xml").unwrap();
    let manifest = archive.read(i, &mut zip::Budget::new(&limits)).unwrap();
    let mut specs = vec![Spec::deflated("AndroidManifest.xml", &manifest)];
    specs.extend(extra);
    Builder::with(specs).build().0
}

fn secret_findings(s: &RedactedScan) -> Vec<FindingV2> {
    s.as_scan()
        .findings
        .iter()
        .filter(|f| f.rule_id == "APK-SECRET-006")
        .cloned()
        .collect()
}

#[test]
fn apk_dex_string_pool_findings_export() {
    use crate::apk_audit::dex::tests::build;
    let stripe = testutil::stripe_secret();
    let github = testutil::github_token();
    let (r, safe) = apk_export(&apk_with(vec![
        Spec::stored("classes.dex", &build(&[&stripe, "plain text", &github])),
        // The same key again in a second DEX: the scanner folds it (`also_in:`).
        Spec::stored("classes2.dex", &build(&[&stripe])),
    ]));
    let dex: Vec<_> = secret_findings(&safe)
        .into_iter()
        .filter(|f| f.tags.contains(&"source:dex".to_string()))
        .collect();
    assert_eq!(dex.len(), 2, "one finding per key");
    assert_eq!(
        dex.len(),
        r.findings
            .iter()
            .filter(|f| f.tags.contains(&"source:dex".to_string()))
            .count()
    );
    for f in &dex {
        assert_eq!(f.location.relative_path, "classes.dex");
        assert_eq!(f.location.archive_entry.as_deref(), Some("classes.dex"));
        assert_eq!(f.location.line, None);
        assert!(
            f.location
                .component
                .as_deref()
                .is_some_and(|c| c.starts_with("string_ids["))
        );
        assert_eq!(f.severity, Severity::High, "ADR-DEX: never critical");
        assert!(is_core_fingerprint(
            f.evidence.fingerprint.as_deref().unwrap()
        ));
        assert!(f.tags.iter().any(|t| t.starts_with("byte_offset:")));
    }
    let fps: Vec<_> = dex
        .iter()
        .map(|f| f.evidence.fingerprint.clone().unwrap())
        .collect();
    assert!(fps.contains(&crate::secrets::fingerprint(&stripe)));
    assert!(fps.contains(&crate::secrets::fingerprint(&github)));
    let folded = dex
        .iter()
        .find(|f| f.evidence.fingerprint == Some(crate::secrets::fingerprint(&stripe)))
        .unwrap();
    assert!(folded.tags.contains(&"also_in:classes2.dex".to_string()));
}

#[test]
fn apk_same_key_in_two_xml_attributes_is_one_finding() {
    use crate::apk_audit::axml::encode::{Options, encode};
    let github = testutil::github_token();
    let xml = encode(
        &format!(
            "<resources><item name=\"a\" value=\"{github}\" /><entry name=\"b\" value=\"{github}\" /></resources>"
        ),
        Options::default(),
    );
    let (r, safe) = apk_export(&apk_with(vec![Spec::deflated("res/xml/keys.xml", &xml)]));
    // Scanner: two findings, one id (key = fingerprint), different components.
    let raw: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.location.archive_entry.as_deref() == Some("res/xml/keys.xml"))
        .collect();
    assert_eq!(raw.len(), 2);
    assert_eq!(raw[0].id, raw[1].id);
    assert_ne!(raw[0].location.component, raw[1].location.component);
    // V2: one logical finding (the component is where in the entry, like a
    // line), the first component kept, the count recorded.
    let v2: Vec<_> = secret_findings(&safe)
        .into_iter()
        .filter(|f| f.location.relative_path == "res/xml/keys.xml")
        .collect();
    assert_eq!(v2.len(), 1);
    assert_eq!(v2[0].id, raw[0].id);
    assert!(v2[0].tags.contains(&"occurrences:2".to_string()));
    let mut components: Vec<_> = raw.iter().map(|f| f.location.component.clone()).collect();
    components.sort();
    assert_eq!(v2[0].location.component, components[0]);
}

fn apk_export(bytes: &[u8]) -> (ApkScanResult, RedactedScan) {
    let r = apk_audit::scan_bytes(bytes, &ApkScanOptions::default());
    let safe = export_and_reimport(&adapters::apk(&r).unwrap());
    (r, safe)
}

#[test]
fn apk_secret_keeps_fingerprint_and_id_across_a_line_shift() {
    let stripe = testutil::stripe_secret();
    let asset = format!("{{\n  \"stripe\": \"{stripe}\"\n}}\n");
    let (r, safe) = apk_export(&apk_with_asset(&asset));
    let secret = |s: &RedactedScan| {
        s.as_scan()
            .findings
            .iter()
            .find(|f| f.rule_id == "APK-SECRET-006")
            .cloned()
            .expect("secret finding")
    };
    let first = secret(&safe);
    assert_eq!(first.location.relative_path, "assets/config.json");
    assert_eq!(first.location.line, Some(2));
    assert_eq!(
        first.evidence.fingerprint,
        Some(crate::secrets::fingerprint(&stripe))
    );
    assert!(r.findings.iter().any(|f| f.id == first.id));
    let ids = |s: &RedactedScan| {
        s.as_scan()
            .findings
            .iter()
            .map(|f| f.id.clone())
            .collect::<Vec<_>>()
    };
    let (_, shifted) = apk_export(&apk_with_asset(&format!("\n\n{asset}")));
    assert_eq!(ids(&shifted), ids(&safe));
    assert_eq!(secret(&shifted).location.line, Some(4));
    // The same key twice in the asset: the APK scanner reports two findings
    // with ONE id (line-independent) on lines 2 and 4. V2 folds them into one
    // logical finding: first line kept, count recorded.
    let twice = format!("{asset}{{\"again\": \"{stripe}\"}}\n");
    let (r, merged) = apk_export(&apk_with_asset(&twice));
    let scanner_hits: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == "APK-SECRET-006")
        .map(|f| (f.id.clone(), f.location.line))
        .collect();
    assert_eq!(
        scanner_hits,
        [(first.id.clone(), Some(2)), (first.id.clone(), Some(4))]
    );
    let f = secret(&merged);
    assert_eq!(f.id, first.id);
    assert_eq!(f.location.line, Some(2));
    assert!(f.tags.contains(&"occurrences:2".to_string()));
    assert_eq!(merged.as_scan().findings.len(), r.findings.len() - 1);
}

#[test]
fn apk_unreadable_archive_is_incomplete_not_clean() {
    let (r, safe) = apk_export(b"definitely not a zip archive");
    assert!(!r.completed());
    assert!(!safe.as_scan().completed());
    assert!(safe.as_scan().findings.is_empty());
    assert!(
        safe.as_scan()
            .checks
            .iter()
            .any(|c| c.status == CheckStatus::Error && c.reason.is_some())
    );
}

const ANDROID_FIXTURES: &[&str] = &["insecure-app", "hardened-app", "flavors-kts"];

fn android_scan(root: &Path) -> AndroidScanResult {
    android_audit::scan_source(root, &AndroidScanOptions::default()).expect("scan fixture")
}

#[test]
fn android_fixtures_map_one_to_one_and_roundtrip() {
    let mut total = 0;
    let mut with_component = 0;
    for name in ANDROID_FIXTURES {
        let project = android_audit::testutil::fixture(name);
        let r = android_scan(project.path());
        let safe = export_and_reimport(&adapters::android(&r).unwrap());
        let out = safe.as_scan();
        assert_eq!(out.completed(), r.completed(), "{name}: completeness");
        let android_checks: BTreeMap<_, _> = r
            .checks
            .iter()
            .map(|c| (c.id.clone(), (status(c.status), c.reason.clone())))
            .collect();
        assert_eq!(checks_of(&out.checks), android_checks, "{name}: checks");
        assert!(out.checks.iter().any(|c| c.id == "android.project"));
        for l in &r.limitations {
            assert!(out.limitations.contains(l), "{name}: limitation kept");
        }
        assert!(out.network_activities.is_empty());
        assert_eq!(out.findings.len(), r.findings.len(), "{name}: no merge");
        for a in &r.findings {
            let f = out
                .findings
                .iter()
                .find(|f| f.id == a.id)
                .expect("android id kept as is");
            assert!(f.id.starts_with("android/"));
            assert_eq!(f.rule_id, a.rule_id);
            assert_eq!(f.category, a.category);
            assert_eq!(f.title, a.title);
            assert_eq!(f.severity.to_string_for_test(), a.severity.label());
            assert_eq!(f.confidence.to_string_for_test(), a.confidence.label());
            assert_ne!(f.confidence, Confidence::Confirmed, "never confirmed");
            assert_eq!(f.location.relative_path, a.location.relative_path);
            assert_eq!(f.location.line, a.location.line);
            assert_eq!(f.location.column, a.location.column);
            assert_eq!(f.location.archive_entry, None);
            if a.location.component.is_some() {
                with_component += 1;
                // Redaction may blank metadata wholesale, never edit it.
                assert!(
                    f.location.component == a.location.component
                        || f.location.component.as_deref() == Some("[redacted]")
                );
            } else {
                assert_eq!(f.location.component, None);
            }
            assert_eq!(f.remediation_id, a.remediation_id);
            assert_eq!(f.cwe_ids.len(), a.cwe_ids.len());
            if let Some(fp) = &a.evidence.fingerprint {
                assert!(is_core_fingerprint(fp), "android emits core fingerprints");
            }
            assert_eq!(f.evidence.fingerprint, a.evidence.fingerprint);
            assert!(
                f.evidence.redacted_excerpt == a.evidence.redacted_excerpt
                    || f.evidence.redacted_excerpt.as_deref() == Some("[redacted]")
            );
            total += 1;
        }
    }
    assert!(total >= 20, "fixtures produced {total} findings");
    assert!(
        with_component > 0,
        "components (manifest/Gradle) are carried"
    );
    let mut wrong = android_scan(android_audit::testutil::fixture("hardened-app").path());
    wrong.schema_version = 1;
    assert_eq!(
        adapters::android(&wrong),
        Err(ModelError("unsupported_schema_version"))
    );
}

#[test]
fn android_ids_survive_a_line_shift() {
    let project = android_audit::testutil::fixture("insecure-app");
    let export = |root: &Path| {
        let safe = adapters::android(&android_scan(root))
            .unwrap()
            .redacted(&RedactionPolicy::default())
            .unwrap();
        safe.as_scan()
            .findings
            .iter()
            .map(|f| {
                (
                    f.id.clone(),
                    (f.location.relative_path.clone(), f.location.line),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let before = export(project.path());
    let shifted_files = [
        "app/build.gradle",
        "app/src/main/AndroidManifest.xml",
        "app/src/main/java/com/example/insecure/Crypto.kt",
    ];
    for file in shifted_files {
        let path = project.path().join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        let text = if file.ends_with(".xml") {
            text.replacen(
                "<manifest",
                "<!-- added -->

<manifest",
                1,
            )
        } else {
            format!(
                "// added

{text}"
            )
        };
        std::fs::write(&path, text).unwrap();
    }
    let after = export(project.path());
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>(),
        "same ids after the shift"
    );
    let mut shifted = 0;
    for (id, (path, line)) in &before {
        assert_eq!(after[id].0, *path);
        if let (Some(line), true) = (line, shifted_files.contains(&path.as_str())) {
            assert_eq!(after[id].1, Some(line + 2), "{path} moved down");
            shifted += 1;
        }
    }
    assert!(shifted > 0, "test must move at least one finding");
}

#[test]
fn android_incomplete_scan_stays_incomplete() {
    let t = testutil::TempProject::new();
    t.write("settings.gradle", "include ':app'");
    t.write(
        "app/build.gradle",
        "apply plugin: 'com.android.application'
android { defaultConfig { minSdkVersion 24
 targetSdkVersion 34 } }",
    );
    t.write(
        "app/src/main/AndroidManifest.xml",
        "<manifest><application></manifest>",
    );
    let r = android_scan(t.path());
    assert!(!r.completed());
    let safe = export_and_reimport(&adapters::android(&r).unwrap());
    assert!(!safe.as_scan().completed());
    assert!(
        safe.as_scan()
            .checks
            .iter()
            .any(|c| c.status == CheckStatus::Partial && c.reason.is_some())
    );
}

const IOS_FIXTURES: &[&str] = &["insecure-app", "hardened-app", "xcodegen-app"];

fn ios_scan(root: &Path) -> IosScanResult {
    ios_audit::scan_source(root, &IosScanOptions::default()).expect("scan fixture")
}

#[test]
fn ios_fixtures_map_one_to_one_and_roundtrip() {
    let mut total = 0;
    let mut with_component = 0;
    let mut without_line = 0;
    for name in IOS_FIXTURES {
        let project = ios_audit::testutil::fixture(name);
        let r = ios_scan(project.path());
        let safe = export_and_reimport(&adapters::ios(&r).unwrap());
        let out = safe.as_scan();
        assert_eq!(out.completed(), r.completed(), "{name}: completeness");
        let ios_checks: BTreeMap<_, _> = r
            .checks
            .iter()
            .map(|c| (c.id.clone(), (status(c.status), c.reason.clone())))
            .collect();
        assert_eq!(checks_of(&out.checks), ios_checks, "{name}: checks");
        assert!(out.checks.iter().any(|c| c.id == "ios.project"));
        for l in &r.limitations {
            assert!(out.limitations.contains(l), "{name}: limitation kept");
        }
        assert!(out.network_activities.is_empty());
        assert_eq!(out.findings.len(), r.findings.len(), "{name}: no merge");
        for a in &r.findings {
            let f = out
                .findings
                .iter()
                .find(|f| f.id == a.id)
                .expect("ios id kept as is");
            assert!(f.id.starts_with("ios/"));
            assert_eq!(f.rule_id, a.rule_id);
            assert_eq!(f.category, a.category);
            assert_eq!(f.title, a.title);
            assert_eq!(f.severity.to_string_for_test(), a.severity.label());
            assert_eq!(f.confidence.to_string_for_test(), a.confidence.label());
            assert_ne!(f.confidence, Confidence::Confirmed, "never confirmed");
            assert_eq!(f.location.relative_path, a.location.relative_path);
            assert_eq!(f.location.line, a.location.line);
            assert_eq!(f.location.column, a.location.column);
            assert_eq!(f.location.archive_entry, None);
            if a.location.line.is_none() {
                without_line += 1;
            }
            if a.location.component.is_some() {
                with_component += 1;
                // Redaction may blank metadata wholesale, never edit it.
                assert!(
                    f.location.component == a.location.component
                        || f.location.component.as_deref() == Some("[redacted]")
                );
            } else {
                assert_eq!(f.location.component, None);
            }
            assert_eq!(f.remediation_id, a.remediation_id);
            assert_eq!(f.cwe_ids.len(), a.cwe_ids.len());
            if let Some(fp) = &a.evidence.fingerprint {
                assert!(is_core_fingerprint(fp), "ios emits core fingerprints");
            }
            assert_eq!(f.evidence.fingerprint, a.evidence.fingerprint);
            assert!(
                f.evidence.redacted_excerpt == a.evidence.redacted_excerpt
                    || f.evidence.redacted_excerpt.as_deref() == Some("[redacted]")
            );
            total += 1;
        }
    }
    assert!(total >= 20, "fixtures produced {total} findings");
    assert!(
        with_component > 0,
        "components (target / plist key) are carried"
    );
    assert!(
        without_line > 0,
        "signing files keep a location without a line"
    );
    let mut wrong = ios_scan(ios_audit::testutil::fixture("hardened-app").path());
    wrong.schema_version = 1;
    assert_eq!(
        adapters::ios(&wrong),
        Err(ModelError("unsupported_schema_version"))
    );
}

#[test]
fn ios_ids_survive_a_line_shift() {
    let project = ios_audit::testutil::fixture("insecure-app");
    let export = |root: &Path| {
        let safe = adapters::ios(&ios_scan(root))
            .unwrap()
            .redacted(&RedactionPolicy::default())
            .unwrap();
        safe.as_scan()
            .findings
            .iter()
            .map(|f| {
                (
                    f.id.clone(),
                    (f.location.relative_path.clone(), f.location.line),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let before = export(project.path());
    let shifted_files = [
        "InsecureApp/Info.plist",
        "InsecureApp/InsecureApp.entitlements",
        "InsecureApp/Session.swift",
        "InsecureApp/Legacy.m",
    ];
    for file in shifted_files {
        let path = project.path().join(file);
        let text = std::fs::read_to_string(&path).unwrap();
        let text = if file.ends_with(".plist") || file.ends_with(".entitlements") {
            text.replacen(
                "<plist",
                "<!-- added -->

<plist",
                1,
            )
        } else {
            format!(
                "// added

{text}"
            )
        };
        std::fs::write(&path, text).unwrap();
    }
    let after = export(project.path());
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>(),
        "same ids after the shift"
    );
    let mut shifted = 0;
    for (id, (path, line)) in &before {
        assert_eq!(after[id].0, *path);
        if let (Some(line), true) = (line, shifted_files.contains(&path.as_str())) {
            assert_eq!(after[id].1, Some(line + 2), "{path} moved down");
            shifted += 1;
        }
    }
    assert!(shifted > 0, "test must move at least one finding");
}

#[test]
fn ios_incomplete_scan_stays_incomplete() {
    let t = testutil::TempProject::new();
    t.write(
        "App/App.swift",
        "import UIKit
",
    );
    t.write(
        "App/Info.plist",
        "<plist version=\"1.0\"><dict><key>A</key>",
    );
    let r = ios_scan(t.path());
    assert!(!r.completed());
    let safe = export_and_reimport(&adapters::ios(&r).unwrap());
    assert!(!safe.as_scan().completed());
    assert!(
        safe.as_scan()
            .checks
            .iter()
            .any(|c| c.status == CheckStatus::Partial && c.reason.is_some())
    );
}

trait Label {
    fn to_string_for_test(&self) -> &'static str;
}
impl Label for Severity {
    fn to_string_for_test(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}
impl Label for Confidence {
    fn to_string_for_test(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "confirmed",
            Confidence::Potential => "potential",
            Confidence::NeedsReview => "needs_review",
        }
    }
}
