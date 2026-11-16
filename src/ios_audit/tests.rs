//! Сквозные тесты iOS Source Audit на фикстурах `fixtures/ios/*` и временных проектах.

use super::report;
use super::rules;
use super::scan::{IosScanOptions, IosScanResult, scan_source};
use super::testutil::{expand, fixture};
use super::types::{CheckStatus, Confidence};
use crate::json::{self, Json};
use crate::web_audit::testutil::TempProject;

fn scan_path(path: &std::path::Path) -> IosScanResult {
    scan_source(path, &IosScanOptions::default()).unwrap()
}

fn scan(name: &str) -> IosScanResult {
    let project = fixture(name);
    scan_path(project.path())
}

/// (правило, путь[:строка], severity) — отсортировано.
fn rows(r: &IosScanResult) -> Vec<(String, String, String)> {
    let mut rows: Vec<_> = r
        .findings
        .iter()
        .map(|f| {
            let at = match f.location.line {
                Some(l) => format!("{}:{l}", f.location.relative_path),
                None => f.location.relative_path.clone(),
            };
            (f.rule_id.to_string(), at, f.severity.label().to_string())
        })
        .collect();
    rows.sort();
    rows
}

fn row(rule: &str, at: &str, severity: &str) -> (String, String, String) {
    (rule.to_string(), at.to_string(), severity.to_string())
}

fn check<'a>(r: &'a IosScanResult, id: &str) -> &'a super::types::RuleCheck {
    r.checks.iter().find(|c| c.id == id).unwrap()
}

#[test]
fn insecure_app_findings_are_exact() {
    let r = scan("insecure-app");
    let app = "InsecureApp";
    let mut expected = vec![
        row(rules::ATS_ID, &format!("{app}/Info.plist:22"), "high"),
        row(rules::ATS_ID, &format!("{app}/Info.plist:30"), "medium"),
        row(rules::ATS_ID, &format!("{app}/Info.plist:32"), "medium"),
        row(rules::URLSCHEME_ID, &format!("{app}/Info.plist:16"), "info"),
        row(rules::SECRET_ID, &format!("{app}/Info.plist:38"), "medium"),
        row(
            rules::ENTITLEMENTS_ID,
            &format!("{app}/InsecureApp.entitlements:5"),
            "high",
        ),
        row(
            rules::ENTITLEMENTS_ID,
            &format!("{app}/InsecureApp.entitlements:9"),
            "low",
        ),
        row(
            rules::ENTITLEMENTS_ID,
            &format!("{app}/InsecureApp.entitlements:14"),
            "medium",
        ),
        row(
            rules::SECRET_ID,
            &format!("{app}/Network.swift:4"),
            "critical",
        ),
        row(rules::TLS_ID, &format!("{app}/Network.swift:14"), "high"),
        row(
            rules::STORAGE_ID,
            &format!("{app}/Session.swift:7"),
            "medium",
        ),
        row(rules::LOG_ID, &format!("{app}/Session.swift:8"), "low"),
        row(
            rules::PASTEBOARD_ID,
            &format!("{app}/Session.swift:9"),
            "low",
        ),
        row(
            rules::KEYCHAIN_ID,
            &format!("{app}/Session.swift:12"),
            "high",
        ),
        row(rules::WEBVIEW_ID, &format!("{app}/Web.swift:8"), "medium"),
        row(rules::WEBVIEW_ID, &format!("{app}/Web.swift:14"), "low"),
        row(rules::CRYPTO_ID, &format!("{app}/Web.swift:20"), "low"),
        row(rules::LOG_ID, &format!("{app}/Legacy.m:8"), "low"),
        row(rules::STORAGE_ID, &format!("{app}/Legacy.m:9"), "medium"),
        row(rules::TLS_ID, &format!("{app}/Legacy.m:11"), "high"),
        row(rules::CRYPTO_ID, &format!("{app}/Legacy.m:15"), "medium"),
        row(rules::WEBVIEW_ID, &format!("{app}/Legacy.m:20"), "info"),
        row(rules::SECRET_ID, "Config/Release.xcconfig:5", "medium"),
        row(rules::SECRET_ID, "Config/Local.xcconfig:2", "low"),
        row(rules::SECRET_ID, "fastlane/.env:2", "high"),
        row(rules::SIGNING_ID, "certs/AuthKey_FIXTURE01.p8", "high"),
        row(rules::SIGNING_ID, "certs/Distribution.p12", "high"),
        row(
            rules::SIGNING_ID,
            "certs/InsecureApp.mobileprovision",
            "low",
        ),
        row(rules::SIGNING_ID, "certs/match/Enterprise.p12", "low"),
    ];
    expected.sort();
    assert_eq!(rows(&r), expected, "{}", report::render_text(&r, "i"));
    assert!(
        r.findings
            .iter()
            .all(|f| f.confidence != Confidence::Confirmed)
    );
    assert!(r.completed(), "{:?}", r.checks);
    // Тесты пропущены (код и Info.plist тестовой цели), ключ Firebase не находка,
    // debug-entitlements (get-task-allow) не находка, `#if DEBUG`-print не находка.
    assert_eq!(r.stats.test_files_skipped, 1);
    assert_eq!(r.stats.firebase_config_keys, 1);
    assert_eq!(r.stats.info_plists_checked, 1);
    assert_eq!(r.stats.entitlements_checked, 2);
    // Цель и конфигурация в находке entitlements; Info.plist привязан к цели.
    let gta = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::ENTITLEMENTS_ID && f.severity == super::types::Severity::High)
        .unwrap();
    assert!(gta.explanation.contains("InsecureApp (Release)"));
    assert_eq!(
        gta.location.component.as_deref(),
        Some("target InsecureApp")
    );
    let p = &r.projects[0];
    assert_eq!(p.path, "InsecureApp.xcodeproj/project.pbxproj");
    assert_eq!(p.targets[0].info_plists, vec!["InsecureApp/Info.plist"]);
    assert_eq!(
        p.targets[0].entitlements,
        vec![
            "InsecureApp/InsecureApp.entitlements",
            "InsecureApp/InsecureAppDebug.entitlements"
        ]
    );
    assert_eq!(p.targets[0].deployment_target.as_deref(), Some("15.0"));
    assert_eq!(p.targets[1].kind, "bundle.unit-test");
    // Положение — реальная колонка ключа plist и литерала в коде.
    let ats = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::ATS_ID)
        .unwrap();
    assert_eq!(ats.location.column, Some(3));
    let stripe = r
        .findings
        .iter()
        .find(|f| {
            f.location.relative_path.ends_with("Network.swift") && f.rule_id == rules::SECRET_ID
        })
        .unwrap();
    assert_eq!(stripe.location.column, Some(29));
    assert!(stripe.evidence.fingerprint.is_some());
    // ObjC-фрагмент сохраняет `@` у разрешённого ключа; интерполяция видна как код.
    let objc = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::STORAGE_ID && f.location.relative_path.ends_with(".m"))
        .unwrap();
    assert!(
        objc.evidence
            .redacted_excerpt
            .as_deref()
            .unwrap()
            .contains("@\"authToken\"")
    );
    let log = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::LOG_ID && f.location.relative_path.ends_with(".swift"))
        .unwrap();
    assert_eq!(
        log.evidence.redacted_excerpt.as_deref(),
        Some("print(\"…\\(password)…\")")
    );
}

#[test]
fn hardened_app_is_quiet_and_complete() {
    let r = scan("hardened-app");
    assert_eq!(rows(&r), Vec::new(), "{}", report::render_text(&r, "h"));
    assert!(r.completed(), "{:?}", r.checks);
    for c in &r.checks {
        assert_eq!(c.status, CheckStatus::Completed, "{c:?}");
    }
    assert_eq!(r.stats.test_files_skipped, 1);
    assert_eq!(r.stats.swift_files_checked, 1);
    assert_eq!(r.stats.objc_files_checked, 1);
}

#[test]
fn generated_project_without_pbxproj_is_partial() {
    let r = scan("xcodegen-app");
    let mut expected = vec![
        row(rules::ATS_ID, "Sources/Info.plist:7", "low"),
        row(rules::ATS_ID, "Sources/Info.plist:9", "low"),
        row(
            rules::ENTITLEMENTS_ID,
            "Sources/Generated.entitlements:5",
            "medium",
        ),
        row(rules::STORAGE_ID, "Sources/App.swift:5", "medium"),
    ];
    expected.sort();
    assert_eq!(rows(&r), expected);
    let project = check(&r, "ios.project");
    assert_eq!(project.status, CheckStatus::Partial);
    assert!(project.reason.as_deref().unwrap().contains("XcodeGen"));
    assert!(!r.completed());
    // NSAllowsArbitraryLoads вместе с InWebContent: на iOS 10+ игнорируется.
    let ats = r
        .findings
        .iter()
        .find(|f| f.title.contains("NSAllowsArbitraryLoads)"))
        .unwrap();
    assert!(ats.explanation.contains("ignore"));
    let ent = &r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::ENTITLEMENTS_ID)
        .unwrap();
    assert_eq!(ent.confidence, Confidence::NeedsReview);
    assert!(
        r.limitations
            .iter()
            .any(|l| l.contains("no project.pbxproj"))
    );
}

#[test]
fn json_has_contract_fields_and_no_raw_secrets() {
    let project = fixture("insecure-app");
    let r = scan_path(project.path());
    let text = report::render_json(&r, "./insecure-app");
    let parsed = json::parse(&text).expect("valid JSON");
    assert_eq!(
        parsed.get("schema_version").and_then(Json::as_f64),
        Some(2.0)
    );
    let scan = parsed.get("scan").unwrap();
    assert_eq!(scan.get("mode").and_then(Json::as_str), Some("ios_source"));
    assert_eq!(scan.get("completed").and_then(Json::as_bool), Some(true));
    assert_eq!(
        scan.get("network_activity")
            .and_then(Json::as_array)
            .map(|a| a.len()),
        Some(0)
    );
    let checks = scan.get("checks").and_then(Json::as_array).unwrap();
    assert_eq!(checks.len(), rules::ALL.len() + 1);
    let findings = parsed.get("findings").and_then(Json::as_array).unwrap();
    assert_eq!(findings.len(), r.findings.len());
    for f in findings {
        for key in [
            "id",
            "rule_id",
            "title",
            "category",
            "severity",
            "confidence",
            "location",
            "evidence",
            "explanation",
            "remediation_id",
            "references",
            "cwe_ids",
            "tags",
        ] {
            assert!(f.get(key).is_some(), "missing {key}");
        }
        let id = f.get("id").and_then(Json::as_str).unwrap();
        let rule = f.get("rule_id").and_then(Json::as_str).unwrap();
        assert!(crate::finding_v2::output::is_canonical_id(id, rule), "{id}");
        assert_ne!(
            f.get("confidence").and_then(Json::as_str),
            Some("confirmed")
        );
    }
    // Ни одного сырого значения фикстуры (и тела закрытого ключа .p8).
    for label in [
        "STRIPE_SECRET",
        "GOOGLE_API_KEY",
        "PASSWORD",
        "PASSWORD2",
        "PEM_KEY",
    ] {
        let raw = expand(&format!("@@{label}@@"));
        assert!(!text.contains(&raw), "{label} leaked");
    }
    assert!(!text.contains("JetscanFixture0NotARealKey0JetscanFixture0NotARealKey0"));
    assert!(!text.contains("Salted__fixture"));
    // Детерминированность.
    let again = scan_path(project.path());
    assert_eq!(report::render_json(&again, "./insecure-app"), text);
    let plain = report::render_text(&r, "insecure-app");
    assert!(!plain.chars().any(|c| c.is_control() && c != '\n'));
    for label in ["STRIPE_SECRET", "PASSWORD", "PASSWORD2"] {
        assert!(
            !plain.contains(&expand(&format!("@@{label}@@"))),
            "{label} leaked"
        );
    }
}

#[test]
fn ids_survive_inserted_lines() {
    let project = fixture("insecure-app");
    let before = scan_path(project.path());
    for path in [
        "InsecureApp/Info.plist",
        "InsecureApp/InsecureApp.entitlements",
        "InsecureApp/Session.swift",
        "InsecureApp/Legacy.m",
        "Config/Release.xcconfig",
    ] {
        let full = project.path().join(path);
        let text = std::fs::read_to_string(&full).unwrap();
        let shifted = match path.rsplit('.').next() {
            Some("plist" | "entitlements") => {
                text.replacen("<plist", "<!-- added -->\n\n<plist", 1)
            }
            _ => format!("// added\n\n{text}"),
        };
        std::fs::write(&full, shifted).unwrap();
    }
    let after = scan_path(project.path());
    let ids = |r: &IosScanResult| {
        let mut v: Vec<String> = r.findings.iter().map(|f| f.id.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(ids(&before), ids(&after));
    assert_ne!(rows(&before), rows(&after));
}

#[test]
fn not_an_ios_project_is_skipped() {
    let t = TempProject::new();
    t.write("README.md", "hello");
    t.write(
        "app/build.gradle",
        "apply plugin: 'com.android.application'",
    );
    let r = scan_path(t.path());
    assert!(r.findings.is_empty());
    assert!(r.checks.iter().all(|c| c.status == CheckStatus::Skipped));
    assert!(r.completed());
}

const INFO_ATS: &str = "<?xml version=\"1.0\"?><plist><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict></dict></plist>";

#[test]
fn binary_and_malformed_plists_are_partial() {
    let t = TempProject::new();
    t.write_bytes("App/Info.plist", b"bplist00\xd1\x01\x02\x00\x00");
    t.write("App/A.swift", "let a = 1");
    let r = scan_path(t.path());
    let ats = check(&r, rules::ATS_ID);
    assert_eq!(ats.status, CheckStatus::Partial);
    assert!(
        ats.reason.as_deref().unwrap().contains("bplist00"),
        "{ats:?}"
    );
    assert!(!r.completed());

    let t = TempProject::new();
    t.write("App/Info.plist", "<plist><dict><key>A</key></dict></plist>");
    t.write("App/App.entitlements", "<plist><dict>");
    let r = scan_path(t.path());
    let ats = check(&r, rules::ATS_ID);
    assert_eq!(ats.status, CheckStatus::Partial);
    assert!(
        ats.reason.as_deref().unwrap().contains("malformed at 1:"),
        "{ats:?}"
    );
    assert_eq!(
        check(&r, rules::ENTITLEMENTS_ID).status,
        CheckStatus::Partial
    );
    // Нет Swift/ObjC — правила кода skipped с причиной.
    let code = check(&r, rules::TLS_ID);
    assert_eq!(code.status, CheckStatus::Skipped);
    assert!(
        code.reason
            .as_deref()
            .unwrap()
            .contains("no Swift/Objective-C")
    );
}

#[test]
fn unresolved_build_settings_make_the_project_partial() {
    let t = TempProject::new();
    t.write("App/Info.plist", INFO_ATS);
    t.write(
        "App.xcodeproj/project.pbxproj",
        "{ objects = { P = {isa = PBXProject; buildConfigurationList = L; targets = (T); }; L = {isa = XCConfigurationList; buildConfigurations = (C); }; T = {isa = PBXNativeTarget; name = App; productType = \"com.apple.product-type.application\"; buildConfigurationList = L2; }; L2 = {isa = XCConfigurationList; buildConfigurations = (R); }; C = {isa = XCBuildConfiguration; name = Release; buildSettings = {}; }; R = {isa = XCBuildConfiguration; name = Release; buildSettings = {INFOPLIST_FILE = \"$(CUSTOM_DIR)/Info.plist\"; }; }; }; rootObject = P; }",
    );
    let r = scan_path(t.path());
    let p = check(&r, "ios.project");
    assert_eq!(p.status, CheckStatus::Partial);
    assert!(
        p.reason.as_deref().unwrap().contains("$(CUSTOM_DIR)"),
        "{p:?}"
    );
    // Info.plist всё равно найден по имени и проверен.
    assert_eq!(
        rows(&r),
        vec![row(rules::ATS_ID, "App/Info.plist:1", "high")]
    );
}

#[test]
fn inline_ignore_and_budgets() {
    let t = TempProject::new();
    t.write(
        "App/A.swift",
        "let q = kSecAttrAccessibleAlways // jetscan:ignore\nlet r = kSecAttrAccessibleAlwaysThisDeviceOnly\n",
    );
    let r = scan_path(t.path());
    assert_eq!(
        rows(&r),
        vec![row(rules::KEYCHAIN_ID, "App/A.swift:2", "high")]
    );
    assert_eq!(r.stats.ignored_inline, 1);

    t.write(
        "App/Big.swift",
        &format!(
            "let q = kSecAttrAccessibleAlways\n{}",
            "// pad\n".repeat(300)
        ),
    );
    let options = IosScanOptions {
        budgets: super::walk::Budgets {
            max_file_bytes: 1024,
            ..super::walk::Budgets::default()
        },
    };
    let r = scan_source(t.path(), &options).unwrap();
    let k = check(&r, rules::KEYCHAIN_ID);
    assert_eq!(k.status, CheckStatus::Partial);
    assert!(k.reason.as_deref().unwrap().contains("App/Big.swift"));
    // Неполнота адресная: правила по plist ей не затронуты.
    assert_eq!(check(&r, rules::SIGNING_ID).status, CheckStatus::Completed);
}

#[test]
fn field_test_secret_patterns() {
    // Signal/Firefox: `https://user:pass@host` в тестах — фальшивые данные; ядро ставит этому формату
    // не высокую уверенность, в тестах он не находка. Ключ провайдера в тесте — находка (medium).
    let t = TempProject::new();
    t.write(
        "AppTests/URLTests.swift",
        "let u = URL(string: \"https://alice:hunter2pass@example.com/x\")!",
    );
    t.write(
        "AppTests/KeyTests.swift",
        &expand("let k = \"@@STRIPE_SECRET@@\""),
    );
    t.write("App/Main.swift", "let a = 1");
    let r = scan_path(t.path());
    assert_eq!(
        rows(&r),
        vec![row(rules::SECRET_ID, "AppTests/KeyTests.swift:1", "medium")]
    );
}

#[test]
fn third_party_dirs_are_not_scanned() {
    let t = TempProject::new();
    for dir in [
        "Pods/Lib",
        "Carthage/Checkouts/Lib",
        "Carthage/Build/iOS",
        ".build/checkouts/Lib",
        "Vendor/X.xcframework",
    ] {
        t.write(
            &format!("{dir}/Trust.swift"),
            "let q = kSecAttrAccessibleAlways",
        );
    }
    t.write("App/Main.swift", "let a = 1");
    let r = scan_path(t.path());
    assert!(r.findings.is_empty(), "{:?}", rows(&r));
}

/// Проверка соответствия FindingV2 (код адаптера из `HANDOFF_IOS.md` §4а, дословно — со своими
/// копиями приватных функций `adapters.rs`).
mod v2_adapter {
    use crate::finding_v2::{
        CheckStatus, Confidence, Evidence, FindingV2, ModelError, RedactionPolicy, RuleCheck,
        SCHEMA_VERSION, ScanResultV2, Severity, SourceLocation,
    };
    use crate::ios_audit::IosScanResult;
    use crate::web_audit::types as scanner;

    fn severity(s: scanner::Severity) -> Severity {
        match s {
            scanner::Severity::Critical => Severity::Critical,
            scanner::Severity::High => Severity::High,
            scanner::Severity::Medium => Severity::Medium,
            scanner::Severity::Low => Severity::Low,
            scanner::Severity::Info => Severity::Info,
        }
    }

    fn confidence(c: scanner::Confidence) -> Confidence {
        match c {
            scanner::Confidence::Confirmed => Confidence::Confirmed,
            scanner::Confidence::Potential => Confidence::Potential,
            scanner::Confidence::NeedsReview => Confidence::NeedsReview,
        }
    }

    pub fn ios(r: &IosScanResult) -> Result<ScanResultV2, ModelError> {
        if r.schema_version != SCHEMA_VERSION {
            return Err(ModelError("unsupported_schema_version"));
        }
        let findings = r
            .findings
            .iter()
            .map(|f| FindingV2 {
                id: f.id.clone(),
                rule_id: f.rule_id.into(),
                title: f.title.clone(),
                category: f.category.into(),
                severity: severity(f.severity),
                confidence: confidence(f.confidence),
                location: SourceLocation {
                    relative_path: f.location.relative_path.clone(),
                    line: f.location.line,
                    column: f.location.column,
                    archive_entry: None,
                    component: f.location.component.clone(),
                },
                evidence: Evidence {
                    redacted_excerpt: f.evidence.redacted_excerpt.clone(),
                    fingerprint: f.evidence.fingerprint.clone(),
                },
                explanation: f.explanation.clone(),
                remediation_id: f.remediation_id.clone(),
                references: f.references.iter().map(|s| (*s).to_owned()).collect(),
                cwe_ids: f.cwe_ids.iter().map(|s| (*s).to_owned()).collect(),
                tags: f.tags.clone(),
            })
            .collect();
        let result = ScanResultV2 {
            schema_version: SCHEMA_VERSION,
            findings,
            checks: r
                .checks
                .iter()
                .map(|c| RuleCheck {
                    id: c.id.clone(),
                    status: match c.status {
                        scanner::CheckStatus::Completed => CheckStatus::Completed,
                        scanner::CheckStatus::Partial => CheckStatus::Partial,
                        scanner::CheckStatus::Skipped => CheckStatus::Skipped,
                        scanner::CheckStatus::Error => CheckStatus::Error,
                    },
                    reason: c.reason.clone(),
                })
                .collect(),
            limitations: r.limitations.clone(),
            network_activities: r.network_activities.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    #[test]
    fn ios_maps_to_v2_and_keeps_ids_and_fingerprints() {
        for name in ["insecure-app", "hardened-app", "xcodegen-app"] {
            let r = super::scan(name);
            let v2 = ios(&r).expect("valid V2");
            assert_eq!(v2.completed(), r.completed(), "{name}");
            let safe = v2.redacted(&RedactionPolicy::default()).expect("redacted");
            let out = safe.as_scan();
            assert_eq!(out.findings.len(), r.findings.len(), "{name}");
            let mut before: Vec<(&str, Option<&str>)> = r
                .findings
                .iter()
                .map(|f| (f.id.as_str(), f.evidence.fingerprint.as_deref()))
                .collect();
            let mut after: Vec<(&str, Option<&str>)> = out
                .findings
                .iter()
                .map(|f| (f.id.as_str(), f.evidence.fingerprint.as_deref()))
                .collect();
            before.sort();
            after.sort();
            assert_eq!(before, after, "{name}");
        }
    }
}
