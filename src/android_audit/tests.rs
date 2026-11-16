//! Сквозные тесты Android Source Audit на фикстурах `fixtures/android/*` и временных проектах.

use super::report;
use super::rules;
use super::scan::{AndroidScanOptions, AndroidScanResult, scan_source};
use super::testutil::{expand, fixture};
use super::types::{CheckStatus, Confidence};
use crate::json::{self, Json};
use crate::web_audit::testutil::TempProject;

fn scan_path(path: &std::path::Path) -> AndroidScanResult {
    scan_source(path, &AndroidScanOptions::default()).unwrap()
}

fn scan(name: &str) -> AndroidScanResult {
    let project = fixture(name);
    scan_path(project.path())
}

/// (правило, путь[:строка], severity) — отсортировано.
fn rows(r: &AndroidScanResult) -> Vec<(String, String, String)> {
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

fn check<'a>(r: &'a AndroidScanResult, id: &str) -> &'a super::types::RuleCheck {
    r.checks.iter().find(|c| c.id == id).unwrap()
}

#[test]
fn insecure_app_findings_are_exact() {
    let r = scan("insecure-app");
    let m = "app/src/main/AndroidManifest.xml";
    let java = "app/src/main/java/com/example/insecure";
    let mut expected = vec![
        row(rules::SECRET_ID, "app/build.gradle:13", "critical"),
        row(
            rules::SECRET_ID,
            "app/src/main/assets/service-account.json:5",
            "critical",
        ),
        row(rules::SIGNING_ID, "app/build.gradle:20", "high"),
        row(rules::SIGNING_ID, "app/build.gradle:22", "high"),
        row(rules::DEBUG_ID, "app/build.gradle:32", "high"),
        row(rules::KEYSTORE_ID, "app/release.jks", "high"),
        row(rules::TLS_ID, &format!("{java}/TrustAll.kt:11"), "high"),
        row(rules::TLS_ID, &format!("{java}/TrustAll.kt:17"), "high"),
        row(rules::SIGNING_ID, "gradle.properties:3", "high"),
        row(rules::BACKUP_ID, &format!("{m}:11"), "medium"),
        row(rules::EXPORT_ID, &format!("{m}:23"), "medium"),
        row(rules::EXPORT_ID, &format!("{m}:25"), "medium"),
        row(rules::CRYPTO_ID, &format!("{java}/Crypto.kt:9"), "medium"),
        row(rules::CRYPTO_ID, &format!("{java}/Crypto.kt:18"), "medium"),
        row(
            rules::WEBVIEW_ID,
            &format!("{java}/WebScreen.java:10"),
            "medium",
        ),
        row(
            rules::WEBVIEW_ID,
            &format!("{java}/WebScreen.java:11"),
            "medium",
        ),
        row(
            rules::NET_ID,
            "app/src/main/res/xml/network_security_config.xml:3",
            "medium",
        ),
        row(
            rules::NET_ID,
            "app/src/main/res/xml/network_security_config.xml:6",
            "medium",
        ),
        row(
            rules::EXPORT_ID,
            "lib/src/main/AndroidManifest.xml:4",
            "medium",
        ),
        row(rules::MINIFY_ID, "app/build.gradle:31", "low"),
        row(rules::PERMS_ID, &format!("{m}:8"), "low"),
        row(rules::CRYPTO_ID, &format!("{java}/Crypto.kt:14"), "low"),
        row(rules::LOG_ID, &format!("{java}/Session.kt:10"), "low"),
        row(rules::SECRET_ID, "local.properties:3", "low"),
        row(rules::PERMS_ID, &format!("{m}:6"), "info"),
        row(rules::STORAGE_ID, &format!("{java}/Session.kt:11"), "info"),
        row(
            rules::SECRET_ID,
            "app/src/main/res/values/strings.xml:4",
            "info",
        ),
        row(rules::SECRET_ID, "local.properties:2", "info"),
    ];
    expected.sort();
    assert_eq!(rows(&r), expected);
    // Никогда `confirmed`; все проверки полные (SDK библиотеки взят у приложения).
    assert!(
        r.findings
            .iter()
            .all(|f| f.confidence != Confidence::Confirmed)
    );
    assert!(r.completed(), "{:?}", r.checks);
    // Тест-набор пропущен, ключ google-services.json не находка, debug-манифест не слит.
    assert_eq!(r.stats.test_files_skipped, 1);
    assert_eq!(r.stats.firebase_config_keys, 1);
    let app = r.modules.iter().find(|m| m.dir == "app").unwrap();
    assert_eq!(
        app.manifests_not_merged,
        vec!["app/src/debug/AndroidManifest.xml"]
    );
    assert_eq!((app.min_sdk, app.target_sdk), (Some(21), Some(30)));
    assert_eq!(
        app.network_security_config.as_deref(),
        Some("app/src/main/res/xml/network_security_config.xml")
    );
    // Плейсхолдер `${cleartext}` разрешён из Gradle: флаг манифеста слит в находку config.
    let net = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::NET_ID && f.title.contains("for all domains"))
        .unwrap();
    assert!(net.explanation.contains("minSdk is 21"));
    // Положение — реальная колонка атрибута.
    let backup = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::BACKUP_ID)
        .unwrap();
    assert_eq!(backup.location.column, Some(9));
    assert!(backup.explanation.contains("debuggable build"));
}

#[test]
fn hardened_app_is_quiet_and_complete() {
    let r = scan("hardened-app");
    assert_eq!(rows(&r), Vec::new(), "{}", report::render_text(&r, "h"));
    assert!(r.completed(), "{:?}", r.checks);
    for c in &r.checks {
        assert_eq!(c.status, CheckStatus::Completed, "{c:?}");
    }
    let app = &r.modules[0];
    assert_eq!((app.min_sdk, app.target_sdk), (Some(26), Some(34)));
    // Алиас плагина из каталога версий — стандартный плагин, не convention.
    assert!(
        !r.limitations
            .iter()
            .any(|l| l.contains("convention plugins"))
    );
    assert!(
        r.limitations
            .iter()
            .any(|l| l.contains("libs.versions.toml:3"))
    );
}

#[test]
fn flavors_overlays_placeholders_and_resources() {
    let r = scan("flavors-kts");
    let m = "app/src/main/AndroidManifest.xml";
    let mut expected = vec![
        row(rules::NET_ID, &format!("{m}:5"), "medium"),
        row(
            rules::EXPORT_ID,
            "app/src/release/AndroidManifest.xml:4",
            "medium",
        ),
        row(rules::BACKUP_ID, &format!("{m}:4"), "low"),
        row(rules::EXPORT_ID, &format!("{m}:7"), "info"),
    ];
    expected.sort();
    assert_eq!(rows(&r), expected);
    let net = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::NET_ID)
        .unwrap();
    assert!(
        net.explanation
            .contains("manifestPlaceholders usesCleartext = true at app/build.gradle.kts:19")
    );
    let backup = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::BACKUP_ID)
        .unwrap();
    assert!(backup.explanation.contains("@bool/allow_backup = true"));
    // `tools:node="remove"` во flavor убрал InternalReceiver; freeDebug не слит.
    assert!(!r.findings.iter().any(|f| {
        f.location
            .component
            .as_deref()
            .is_some_and(|c| c.contains("InternalReceiver"))
    }));
    assert_eq!(
        r.modules[0].manifests,
        vec![
            "app/src/main/AndroidManifest.xml",
            "app/src/free/AndroidManifest.xml",
            "app/src/release/AndroidManifest.xml"
        ]
    );
    // Кода нет — правила кода skipped с причиной.
    let code = check(&r, rules::TLS_ID);
    assert_eq!(code.status, CheckStatus::Skipped);
    assert!(code.reason.as_deref().unwrap().contains("no Kotlin/Java"));
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
    assert_eq!(
        scan.get("mode").and_then(Json::as_str),
        Some("android_source")
    );
    assert_eq!(scan.get("completed").and_then(Json::as_bool), Some(true));
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
    }
    // Ни одного сырого значения фикстуры.
    for label in [
        "STRIPE_SECRET",
        "GITHUB_TOKEN",
        "GOOGLE_API_KEY",
        "PASSWORD",
        "PASSWORD2",
    ] {
        let raw = expand(&format!("@@{label}@@"));
        assert!(!text.contains(&raw), "{label} leaked");
    }
    assert!(!text.contains("JetscanFixture0NotARealKey0JetscanFixture0NotARealKey0"));
    // Детерминированность.
    let again = scan_path(project.path());
    assert_eq!(report::render_json(&again, "./insecure-app"), text);
    let plain = report::render_text(&r, "insecure-app");
    assert!(!plain.chars().any(|c| c.is_control() && c != '\n'));
}

#[test]
fn ids_survive_inserted_lines() {
    let project = fixture("insecure-app");
    let before = scan_path(project.path());
    for path in [
        "app/build.gradle",
        "app/src/main/AndroidManifest.xml",
        "app/src/main/java/com/example/insecure/Crypto.kt",
    ] {
        let full = project.path().join(path);
        let text = std::fs::read_to_string(&full).unwrap();
        let shifted = match path.rsplit('.').next() {
            Some("xml") => text.replacen("<manifest", "<!-- added -->\n\n<manifest", 1),
            _ => format!("// added\n\n{text}"),
        };
        std::fs::write(&full, shifted).unwrap();
    }
    let after = scan_path(project.path());
    let ids = |r: &AndroidScanResult| {
        let mut v: Vec<String> = r.findings.iter().map(|f| f.id.clone()).collect();
        v.sort();
        v
    };
    assert_eq!(ids(&before), ids(&after));
    assert_ne!(rows(&before), rows(&after));
}

fn write_app(t: &TempProject, gradle: &str, manifest: &str) {
    t.write("settings.gradle", "include ':app'");
    t.write("app/build.gradle", gradle);
    t.write("app/src/main/AndroidManifest.xml", manifest);
}

const NS: &str = "xmlns:android=\"http://schemas.android.com/apk/res/android\"";

#[test]
fn unknown_sdk_makes_sdk_dependent_rules_partial() {
    let t = TempProject::new();
    write_app(
        &t,
        "apply plugin: 'com.android.application'\nandroid { defaultConfig { minSdkVersion 21\n targetSdkVersion computeTarget() } }",
        &format!(
            "<manifest {NS}><application android:allowBackup=\"true\"><provider android:name=\".P\" android:authorities=\"x\"/></application></manifest>"
        ),
    );
    let r = scan_path(t.path());
    for id in [rules::EXPORT_ID, rules::BACKUP_ID, rules::NET_ID] {
        let c = check(&r, id);
        assert_eq!(c.status, CheckStatus::Partial, "{id}");
        assert!(c.reason.as_deref().unwrap().contains("assumed 34"), "{c:?}");
    }
    assert_eq!(check(&r, rules::DEBUG_ID).status, CheckStatus::Completed);
    assert!(!r.completed());
    assert_eq!(r.modules[0].target_sdk, None);
}

#[test]
fn malformed_manifest_and_unresolved_placeholder_are_partial() {
    let t = TempProject::new();
    write_app(
        &t,
        "apply plugin: 'com.android.application'\nandroid { defaultConfig { minSdkVersion 24\n targetSdkVersion 34\n manifestPlaceholders = [clear: someVar] }\n buildTypes { release { minifyEnabled true } } }",
        &format!(
            "<manifest {NS}><application android:usesCleartextTraffic=\"${{clear}}\"></application></manifest>"
        ),
    );
    let r = scan_path(t.path());
    let net = check(&r, rules::NET_ID);
    assert_eq!(net.status, CheckStatus::Partial);
    assert!(
        net.reason.as_deref().unwrap().contains("${clear}"),
        "{net:?}"
    );
    assert!(!net.reason.as_deref().unwrap().contains("resources.arsc"));

    t.write(
        "app/src/main/AndroidManifest.xml",
        "<manifest><application></manifest>",
    );
    let r = scan_path(t.path());
    let export = check(&r, rules::EXPORT_ID);
    assert_eq!(export.status, CheckStatus::Partial);
    assert!(
        export
            .reason
            .as_deref()
            .unwrap()
            .contains("XML is malformed at 1:"),
        "{export:?}"
    );
}

#[test]
fn inline_ignore_suppresses_findings() {
    let t = TempProject::new();
    write_app(
        &t,
        "apply plugin: 'com.android.application'\nandroid { defaultConfig { minSdkVersion 24\n targetSdkVersion 34 }\n buildTypes { release { minifyEnabled true\n debuggable true // jetscan:ignore\n } } }",
        &format!("<manifest {NS}><application android:allowBackup=\"false\"/></manifest>"),
    );
    t.write(
        "app/src/main/java/A.kt",
        "import javax.crypto.Cipher\nval c = Cipher.getInstance(\"AES\") // jetscan:ignore\nval d = Cipher.getInstance(\"DES\")",
    );
    let r = scan_path(t.path());
    assert_eq!(
        rows(&r),
        vec![row(rules::CRYPTO_ID, "app/src/main/java/A.kt:3", "medium")]
    );
    assert_eq!(r.stats.ignored_inline, 2);
}

#[test]
fn kotlin_signing_and_keystores() {
    let t = TempProject::new();
    let pw = expand("@@PASSWORD@@");
    write_app(
        &t,
        "apply plugin: 'com.android.application'\nandroid { defaultConfig { minSdkVersion 24\n targetSdkVersion 34 }\n buildTypes { release { minifyEnabled true } } }",
        &format!("<manifest {NS}><application android:allowBackup=\"false\"/></manifest>"),
    );
    t.write(
        "app/signing.gradle.kts",
        &format!(
            "android {{\n signingConfigs {{\n  create(\"upload\") {{\n   storeFile = rootProject.file(\"keys/upload.jks\")\n   storePassword = \"{pw}\"\n  }}\n  getByName(\"debug\") {{ storePassword = \"android\"; keyPassword = \"android\" }}\n }}\n}}"
        ),
    );
    t.write("keys/upload.jks", "x");
    t.write("debug.keystore", "x");
    t.write("ignored/local.jks", "x");
    t.write(".gitignore", "/ignored/\n");
    t.write(
        "keystore.properties",
        &format!("storePassword={pw}\nkeyAlias=upload\n"),
    );
    let r = scan_path(t.path());
    let mut expected = vec![
        row(rules::SIGNING_ID, "app/signing.gradle.kts:5", "high"),
        row(rules::KEYSTORE_ID, "keys/upload.jks", "high"),
        row(rules::KEYSTORE_ID, "debug.keystore", "low"),
        row(rules::KEYSTORE_ID, "ignored/local.jks", "low"),
        row(rules::SIGNING_ID, "keystore.properties:1", "medium"),
    ];
    expected.sort();
    assert_eq!(rows(&r), expected);
    let text = report::render_json(&r, ".");
    assert!(!text.contains(&pw));
    // Отпечаток — ядра: тот же, что у `jetscan secrets` / `.jetscanignore`.
    let signing = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::SIGNING_ID)
        .unwrap();
    assert_eq!(
        signing.evidence.fingerprint.as_deref(),
        Some(crate::secrets::fingerprint(&pw).as_str())
    );
}

#[test]
fn legacy_layout_and_library_target_fallback() {
    let t = TempProject::new();
    t.write("settings.gradle", "include ':app', ':lib'");
    t.write(
        "app/build.gradle",
        "apply plugin: 'com.android.application'\nandroid {\n defaultConfig { minSdkVersion 15\n targetSdkVersion 16 }\n sourceSets { main { manifest.srcFile 'AndroidManifest.xml' } }\n buildTypes { release { minifyEnabled true } }\n}",
    );
    t.write(
        "app/AndroidManifest.xml",
        &format!("<manifest {NS} package=\"com.old\"><application android:allowBackup=\"false\"><provider android:name=\".Legacy\" android:authorities=\"a\"/></application></manifest>"),
    );
    t.write(
        "lib/build.gradle",
        "apply plugin: 'com.android.library'\nandroid { defaultConfig { minSdkVersion 15 } }",
    );
    t.write(
        "lib/src/main/AndroidManifest.xml",
        &format!("<manifest {NS}><application><provider android:name=\"lib.P\" android:authorities=\"b\"/></application></manifest>"),
    );
    let r = scan_path(t.path());
    // targetSdk 16: провайдеры без exported экспортированы по умолчанию (и у библиотеки — по app).
    let exported: Vec<String> = r
        .findings
        .iter()
        .filter(|f| f.rule_id == rules::EXPORT_ID)
        .map(|f| f.location.relative_path.clone())
        .collect();
    assert_eq!(
        exported,
        vec![
            "app/AndroidManifest.xml",
            "lib/src/main/AndroidManifest.xml"
        ]
    );
    assert!(r.completed(), "{:?}", r.checks);
    assert!(
        r.limitations
            .iter()
            .any(|l| l.contains("targetSdk 16 of application module app"))
    );
}

#[test]
fn small_file_budget_is_partial_not_clean() {
    let project = fixture("hardened-app");
    let options = AndroidScanOptions {
        budgets: super::walk::Budgets {
            max_file_bytes: 256,
            ..Default::default()
        },
    };
    let r = scan_source(project.path(), &options).unwrap();
    assert!(!r.completed());
    assert!(r.checks.iter().any(|c| c.status == CheckStatus::Partial
        && c.reason.as_deref().is_some_and(|w| w.contains("too large"))));
}

#[test]
fn not_an_android_project() {
    let t = TempProject::new();
    t.write("package.json", "{}");
    let r = scan_path(t.path());
    assert!(r.findings.is_empty());
    assert!(r.checks.iter().all(|c| c.status == CheckStatus::Skipped));
    assert!(r.completed());
    // Kotlin/JVM-модуль без Android: правила манифеста не применимы, код проверяется.
    let t = TempProject::new();
    t.write("build.gradle.kts", "plugins { kotlin(\"jvm\") }");
    t.write(
        "src/main/kotlin/A.kt",
        "import javax.crypto.Cipher\nval c = Cipher.getInstance(\"AES\")",
    );
    let r = scan_path(t.path());
    assert_eq!(
        rows(&r),
        vec![row(rules::CRYPTO_ID, "src/main/kotlin/A.kt:2", "medium")]
    );
    assert_eq!(check(&r, rules::EXPORT_ID).status, CheckStatus::Skipped);
}

#[test]
fn apk_rules_and_output_are_unchanged() {
    // Правила манифеста общие с `jetscan apk`: demo.apk даёт те же находки, что и до этого модуля
    // (см. HANDOFF_APK.md «Demo 3»).
    let demo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/apk/demo/demo.apk");
    let r =
        crate::apk_audit::scan_apk(&demo, &crate::apk_audit::ApkScanOptions::default()).unwrap();
    let mut got: Vec<(&str, &str)> = r
        .findings
        .iter()
        .map(|f| (f.rule_id, f.severity.label()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("APK-BACKUP-004", "medium"),
            ("APK-DEBUG-002", "high"),
            ("APK-EXPORT-001", "medium"),
            ("APK-NET-003", "low"),
        ]
    );
}

#[test]
fn hostile_inputs_do_not_panic() {
    let t = TempProject::new();
    t.write("settings.gradle", "include ':app'");
    t.write(
        "app/build.gradle",
        &format!("android {{ {} }}", "{".repeat(5000)),
    );
    t.write(
        "app/src/main/AndroidManifest.xml",
        &format!("<manifest {NS}>{}</manifest>", "<a>".repeat(400)),
    );
    t.write("app/src/main/java/A.kt", &"\"${".repeat(2000));
    t.write("app/src/main/java/B.java", &"Log.d(".repeat(3000));
    t.write("app/x.properties", &"=".repeat(10_000));
    let r = scan_path(t.path());
    assert!(!r.checks.is_empty());
}

/// Паттерны из полевого теста (`docs/rules/android/FIELD.md`): convention-плагины в `build-plugin/`,
/// id плагина константой, AGP 9 `targetSdk { version = release(…) }`, `apply false` в корне,
/// `tools:ignore="Exported…"`, плейсхолдер в неважном атрибуте, сводка разрешений библиотеки,
/// «пароль в URL» в комментарии, большой файл — неполнота только у правила ключей.
#[test]
fn field_test_project_patterns() {
    let t = TempProject::new();
    t.write("settings.gradle.kts", "include(\":app\", \":lib\")");
    t.write(
        "gradle/libs.versions.toml",
        "[plugins]\nandroid-application = { id = \"com.android.application\", version = \"9.0.0\" }",
    );
    t.write(
        "build.gradle.kts",
        "plugins {\n    alias(libs.plugins.android.application) apply false\n}",
    );
    t.write(
        "build-plugin/src/main/kotlin/MyPlugins.kt",
        "object MyPlugins {\n    object App {\n        const val android = \"my.app.android\"\n    }\n    object Library {\n        const val android = \"my.library.android\"\n    }\n}",
    );
    t.write(
        "build-plugin/src/main/kotlin/Config.kt",
        "object Config {\n    const val sdkMin = 24\n    const val sdkTarget = 35\n}",
    );
    t.write(
        "build-plugin/src/main/kotlin/my.app.android.gradle.kts",
        "plugins { id(\"com.android.application\") }\nandroid {\n    defaultConfig {\n        minSdk = Config.sdkMin\n        targetSdk {\n            version = release(Config.sdkTarget)\n        }\n    }\n    buildTypes {\n        release {\n            isMinifyEnabled = false\n        }\n    }\n}",
    );
    t.write(
        "build-plugin/src/main/kotlin/my.library.android.gradle.kts",
        "plugins { id(\"com.android.library\") }\nandroid { buildTypes { release { isMinifyEnabled = true } } }",
    );
    t.write(
        "app/build.gradle.kts",
        "plugins {\n    id(MyPlugins.App.android)\n}\nandroid { namespace = \"com.example.conv\" }",
    );
    t.write(
        "app/src/main/AndroidManifest.xml",
        &format!(
            "<manifest {NS} xmlns:tools=\"http://schemas.android.com/tools\">\n<application android:allowBackup=\"false\">\n<provider android:name=\".Shared\" android:authorities=\"${{applicationId}}.${{flavorSuffix}}\" android:exported=\"true\" tools:ignore=\"ExportedContentProvider\"/>\n</application>\n</manifest>"
        ),
    );
    t.write(
        "lib/build.gradle.kts",
        "plugins { id(MyPlugins.Library.android) }",
    );
    t.write(
        "lib/src/main/AndroidManifest.xml",
        &format!("<manifest {NS}><uses-permission android:name=\"android.permission.CAMERA\"/></manifest>"),
    );
    t.write(
        "app/src/main/java/Mail.java",
        // Значение собирается в рантайме: в исходнике теста не должно быть «пароля в URL».
        &format!(
            "/**\n * smtp://user:{}@server:port\n */\nclass Mail {{}}",
            ["pass", "word1234"].concat()
        ),
    );
    t.write(
        "app/src/main/assets/big.json",
        &format!("{{\"a\":\"{}\"}}", "x".repeat(1_100_000)),
    );
    let r = scan_path(t.path());
    let m = |dir: &str| r.modules.iter().find(|x| x.dir == dir);
    assert!(
        m(".").is_none(),
        "root with `apply false` is not an Android module"
    );
    let app = m("app").unwrap();
    assert_eq!(app.kind, super::project::ModuleKind::Application);
    assert_eq!((app.min_sdk, app.target_sdk), (Some(24), Some(35)));
    assert_eq!(m("lib").unwrap().kind, super::project::ModuleKind::Library);
    assert_eq!(
        rows(&r),
        vec![
            row(
                rules::EXPORT_ID,
                "app/src/main/AndroidManifest.xml:3",
                "info"
            ),
            row(
                rules::MINIFY_ID,
                "build-plugin/src/main/kotlin/my.app.android.gradle.kts:11",
                "low"
            ),
        ]
    );
    let export = r
        .findings
        .iter()
        .find(|f| f.rule_id == rules::EXPORT_ID)
        .unwrap();
    assert!(
        export
            .explanation
            .contains("tools:ignore=\"ExportedContentProvider\"")
    );
    for c in &r.checks {
        let expected = if c.id == rules::SECRET_ID {
            CheckStatus::Partial
        } else {
            CheckStatus::Completed
        };
        assert_eq!(c.status, expected, "{c:?}");
    }
    assert!(
        check(&r, rules::SECRET_ID)
            .reason
            .as_deref()
            .unwrap()
            .contains("app/src/main/assets/big.json")
    );
}

/// Тот же код, что предложен интегратору в `HANDOFF_ANDROID.md` §4 (адаптер `finding_v2::adapters::android`):
/// проверяем, что результат проходит `validate()`/`redacted()` и id не пересчитываются.
mod v2_adapter {
    use crate::android_audit::AndroidScanResult;
    use crate::finding_v2::{
        CheckStatus, Confidence, Evidence, FindingV2, ModelError, RedactionPolicy, RuleCheck,
        SCHEMA_VERSION, ScanResultV2, Severity, SourceLocation,
    };
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

    pub fn android(r: &AndroidScanResult) -> Result<ScanResultV2, ModelError> {
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
    fn android_maps_to_v2_and_keeps_ids_and_fingerprints() {
        for name in ["insecure-app", "hardened-app", "flavors-kts"] {
            let r = super::scan(name);
            let v2 = android(&r).expect("valid V2");
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
