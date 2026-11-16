//! Сквозные тесты Web Source Audit на фикстурах `fixtures/web/**`.

use super::testutil::{self, TempProject, fixture};
use super::*;

fn scan(project: &TempProject) -> WebScanResult {
    scan_source(project.path(), &WebScanOptions::default()).expect("scan")
}

/// (путь, строка, severity, confidence) находок правила.
fn of_rule(result: &WebScanResult, rule: &str) -> Vec<(String, u32, Severity, Confidence)> {
    result
        .findings
        .iter()
        .filter(|f| f.rule_id == rule)
        .map(|f| {
            (
                f.location.relative_path.clone(),
                f.location.line.unwrap_or(0),
                f.severity,
                f.confidence,
            )
        })
        .collect()
}

fn check<'a>(result: &'a WebScanResult, id: &str) -> &'a RuleCheck {
    result
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"))
}

/// Ни одно сырое значение фикстуры не попало в результат (ни в одно поле).
fn assert_no_raw_secrets(result: &WebScanResult) {
    let dump = format!("{result:?}");
    for secret in [
        testutil::stripe_secret(),
        testutil::github_token(),
        testutil::supabase_jwt("service_role"),
        testutil::supabase_jwt("anon"),
        testutil::body(24),
    ] {
        assert!(!dump.contains(&secret), "raw value leaked into the result");
    }
}

#[test]
fn web_secret_001_next_app_router() {
    let project = fixture("next-app");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-SECRET-001"),
        vec![
            (
                "app/components/Checkout.tsx".to_string(),
                6,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                "app/components/Tricky.tsx".to_string(),
                6,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                "lib/shared-config.ts".to_string(),
                3,
                Severity::High,
                Confidence::NeedsReview
            ),
        ]
    );
    // Tricky.tsx (WEB-SECRET-001) + .env.local (WEB-ENV-002).
    assert_eq!(result.stats.ignored_inline, 2);
    assert_eq!(
        check(&result, "WEB-SECRET-001").status,
        CheckStatus::Completed
    );
    assert_no_raw_secrets(&result);
}

#[test]
fn web_secret_001_finding_shape() {
    let project = fixture("next-app");
    let result = scan(&project);
    let f = result
        .findings
        .iter()
        .find(|f| f.location.relative_path == "app/components/Checkout.tsx")
        .expect("checkout finding");
    assert_eq!(f.location.column, Some(24));
    let masked = crate::secrets::mask(&testutil::stripe_secret());
    assert_eq!(
        f.evidence.redacted_excerpt.as_deref(),
        Some(format!("const STRIPE_SECRET = \"{masked}\";").as_str())
    );
    assert_eq!(
        f.evidence.fingerprint.as_deref(),
        Some(crate::secrets::fingerprint(&testutil::stripe_secret()).as_str())
    );
    assert!(f.id.starts_with("web/web-secret-001/"));
    assert_eq!(f.cwe_ids, vec!["CWE-798", "CWE-200"]);
    assert!(f.tags.contains(&"reach:client".to_string()));
    assert!(f.tags.contains(&"key:stripe-live".to_string()));
    assert!(f.explanation.contains("'use client' directive"));
}

#[test]
fn web_secret_001_ids_are_stable_across_line_moves() {
    let checkout = |r: &WebScanResult| {
        r.findings
            .iter()
            .find(|f| f.location.relative_path == "app/components/Checkout.tsx")
            .cloned()
            .expect("checkout finding")
    };
    let a = fixture("next-app");
    let first = checkout(&scan(&a));
    let path = a.path().join("app/components/Checkout.tsx");
    let text = std::fs::read_to_string(&path).unwrap();
    // Пустые строки перед директивой допустимы — пролог от этого не меняется.
    std::fs::write(&path, format!("\n\n{text}")).unwrap();
    let again = checkout(&scan(&a));
    assert_eq!(again.id, first.id);
    assert_eq!(first.location.line, Some(6));
    assert_eq!(again.location.line, Some(8));
}

#[test]
fn web_secret_001_next_pages_router() {
    let project = fixture("next-pages");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-SECRET-001"),
        vec![(
            "pages/index.tsx".to_string(),
            5,
            Severity::Critical,
            Confidence::Potential
        )]
    );
    assert_no_raw_secrets(&result);
}

#[test]
fn web_secret_001_vite_react() {
    let project = fixture("vite-react");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-SECRET-001"),
        vec![
            (
                "index.html".to_string(),
                4,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                "src/App.tsx".to_string(),
                3,
                Severity::Critical,
                Confidence::Potential
            ),
        ]
    );
    // В HTML нет разметки литералов — фрагмент только из маски.
    let html = result
        .findings
        .iter()
        .find(|f| f.location.relative_path == "index.html")
        .unwrap();
    assert_eq!(
        html.evidence.redacted_excerpt.as_deref(),
        Some(crate::secrets::mask(&testutil::github_token()).as_str())
    );
    assert_no_raw_secrets(&result);
}

#[test]
fn web_secret_001_demo2_relocate_then_rescan() {
    // Demo 2: ключ в клиентском файле → находка; перенесли в серверный модуль → находки нет.
    let project = fixture("vite-react");
    assert!(!of_rule(&scan(&project), "WEB-SECRET-001").is_empty());
    let t = TempProject::new();
    t.write(
        "package.json",
        r#"{"dependencies":{"next":"15","react":"19"}}"#,
    );
    t.write(
        "app/pay/Client.tsx",
        &format!(
            "'use client'\nexport const k = \"{}\";\n",
            testutil::stripe_secret()
        ),
    );
    assert_eq!(of_rule(&scan(&t), "WEB-SECRET-001").len(), 1);
    t.write(
        "app/pay/Client.tsx",
        "'use client'\nexport const k = await fetch('/api/pay');\n",
    );
    t.write(
        "app/api/pay/route.ts",
        &format!(
            "const k = \"{}\";\nexport async function POST() {{}}\n",
            testutil::stripe_secret()
        ),
    );
    let after = scan(&t);
    assert!(of_rule(&after, "WEB-SECRET-001").is_empty());
}

#[test]
fn unimplemented_rules_are_reported_as_skipped_not_clean() {
    let project = fixture("next-app");
    let result = scan(&project);
    let skipped = check(&result, "WEB-DEPS-008");
    assert_eq!(skipped.status, CheckStatus::Skipped);
    assert!(
        skipped
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not implemented")
    );
}

#[test]
fn budget_exhaustion_makes_checks_partial() {
    let project = fixture("next-app");
    let options = WebScanOptions {
        budgets: Budgets {
            max_files: 1,
            ..Budgets::default()
        },
    };
    let result = scan_source(project.path(), &options).unwrap();
    assert_eq!(
        check(&result, "WEB-SECRET-001").status,
        CheckStatus::Partial
    );
    assert!(!result.completed());
}

#[test]
fn broken_manifest_marks_discovery_partial() {
    let project = fixture("broken-manifest");
    let result = scan(&project);
    assert_eq!(check(&result, "web.discovery").status, CheckStatus::Partial);
    assert_eq!(result.framework.kind, FrameworkKind::Generic);
}

#[test]
fn missing_root_is_an_error() {
    let t = TempProject::new();
    assert!(scan_source(&t.path().join("nope"), &WebScanOptions::default()).is_err());
}

#[test]
fn web_env_002_next_app() {
    let project = fixture("next-app");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-ENV-002"),
        vec![
            (
                ".env.local".to_string(),
                4,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                ".env.local".to_string(),
                6,
                Severity::High,
                Confidence::NeedsReview
            ),
            (
                "app/components/Analytics.tsx".to_string(),
                7,
                Severity::High,
                Confidence::NeedsReview
            ),
        ]
    );
    let env: Vec<&WebFinding> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-ENV-002")
        .collect();
    let masked = crate::secrets::mask(&testutil::stripe_secret());
    assert_eq!(
        env[0].evidence.redacted_excerpt.as_deref(),
        Some(format!("NEXT_PUBLIC_STRIPE_SECRET_KEY={masked}").as_str())
    );
    assert_eq!(env[0].location.column, Some(31));
    assert!(env[0].tags.contains(&"referenced:false".to_string()));
    // NEXT_PUBLIC_ADMIN_PASSWORD читается в Analytics.tsx — это видно в объяснении.
    assert!(
        env[1]
            .explanation
            .contains("app/components/Analytics.tsx:5")
    );
    assert!(env[1].tags.contains(&"referenced:true".to_string()));
    assert_eq!(env[1].location.column, Some(29));
    assert_eq!(env[2].evidence.fingerprint, None);
    assert_eq!(check(&result, "WEB-ENV-002").status, CheckStatus::Completed);
    assert_no_raw_secrets(&result);
}

#[test]
fn web_env_002_vite() {
    let project = fixture("vite-react");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-ENV-002"),
        vec![(
            ".env".to_string(),
            4,
            Severity::Critical,
            Confidence::Potential
        )]
    );
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "WEB-ENV-002")
        .unwrap();
    assert!(f.explanation.contains("src/github.ts:4"));
    assert!(f.explanation.contains("Vite"));
    assert_no_raw_secrets(&result);
}

#[test]
fn web_env_002_generic_checks_both_prefixes() {
    let t = TempProject::new();
    t.write(
        ".env.production",
        &format!(
            "NEXT_PUBLIC_A_SECRET={}\nVITE_B_TOKEN={}\n",
            testutil::body(20),
            testutil::github_token()
        ),
    );
    let result = scan(&t);
    let rows = of_rule(&result, "WEB-ENV-002");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].2, Severity::High);
    assert_eq!(rows[1].2, Severity::Critical);
}

#[test]
fn web_supabase_005_next_app() {
    let project = fixture("next-app");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-SUPABASE-005"),
        vec![
            (
                ".env.local".to_string(),
                23,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                "app/components/AdminPanel.tsx".to_string(),
                6,
                Severity::Critical,
                Confidence::Potential
            ),
            (
                "app/components/AdminPanel.tsx".to_string(),
                9,
                Severity::Medium,
                Confidence::NeedsReview
            ),
        ]
    );
    // Публичная переменная с service-role не дублируется в WEB-ENV-002 (ни в .env, ни как чтение).
    assert!(result.findings.iter().all(|f| !(f.rule_id == "WEB-ENV-002"
        && (f.title.contains("SERVICE_ROLE")
            || f.location.relative_path.ends_with("AdminPanel.tsx")))));
    let rls = check(&result, "WEB-RLS-009");
    assert_eq!(rls.status, CheckStatus::Skipped);
    let reason = rls.reason.as_deref().unwrap();
    assert!(reason.starts_with("not_checked: no SQL schema"), "{reason}");
    assert!(reason.contains("supabase db dump --schema public"));
    assert!(
        result
            .limitations
            .iter()
            .any(|l| l.contains("Row Level Security"))
    );
    let jwt = testutil::supabase_jwt("service_role");
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "WEB-SUPABASE-005" && f.location.line == Some(6))
        .unwrap();
    assert_eq!(
        f.evidence.fingerprint.as_deref(),
        Some(crate::secrets::fingerprint(&jwt).as_str())
    );
    assert!(f.title.starts_with("Supabase service-role key"));
    assert_no_raw_secrets(&result);
}

#[test]
fn web_supabase_005_vite_and_migrations() {
    let project = fixture("vite-react");
    let result = scan(&project);
    assert_eq!(
        of_rule(&result, "WEB-SUPABASE-005"),
        vec![(
            "src/supabase.ts".to_string(),
            7,
            Severity::Critical,
            Confidence::Potential
        )]
    );
    // Миграция разобрана: RLS включён, политик нет — info, проверка `completed`.
    let rls = check(&result, "WEB-RLS-009");
    assert_eq!(rls.status, CheckStatus::Completed);
    assert_eq!(
        of_rule(&result, "WEB-RLS-009"),
        vec![(
            "supabase/migrations/0001_init.sql".to_string(),
            3,
            Severity::Info,
            Confidence::Potential
        )]
    );
    assert!(
        result
            .limitations
            .iter()
            .any(|l| l.starts_with("WEB-RLS-009: 1 SQL file(s)"))
    );
    let dump = format!("{result:?}");
    assert!(!dump.contains(&format!("{}{}", "sb_secret_", testutil::body(31))));
}

#[test]
fn web_rls_009_supabase_migrations() {
    let project = fixture("supabase-rls");
    let result = scan(&project);
    let init = "supabase/migrations/20240101000000_init.sql".to_string();
    let more = "supabase/migrations/20240201000000_more.sql".to_string();
    use Confidence::{NeedsReview, Potential};
    use Severity::{High, Info, Low, Medium};
    assert_eq!(
        of_rule(&result, "WEB-RLS-009"),
        vec![
            (init.clone(), 5, High, Potential),
            (init.clone(), 26, High, Potential),
            (init.clone(), 31, Low, NeedsReview),
            (init.clone(), 35, Info, Potential),
            (more.clone(), 6, High, NeedsReview),
            (more.clone(), 10, High, Potential),
            (more.clone(), 18, Medium, NeedsReview),
            (more.clone(), 28, Medium, NeedsReview),
            (more.clone(), 32, Info, NeedsReview),
            (more.clone(), 33, Medium, NeedsReview),
        ]
    );
    let rls = check(&result, "WEB-RLS-009");
    assert_eq!(rls.status, CheckStatus::Completed);
    assert!(rls.reason.is_none());
    assert!(result.completed());
    assert_eq!(result.stats.ignored_inline, 1);
    assert!(
        result
            .limitations
            .iter()
            .any(|l| l.contains("1 SQL statement(s) were not understood")
                && l.contains("create rule"))
    );
    assert!(
        result
            .limitations
            .iter()
            .any(|l| l.contains("2 SQL file(s)") && l.contains("graphql_public, public"))
    );
    // Публичный anon-ключ в клиенте — не находка; про RLS не молчим.
    assert!(of_rule(&result, "WEB-SUPABASE-005").is_empty());
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "WEB-RLS-009" && f.location.line == Some(5))
        .unwrap();
    assert_eq!(f.title, "Table public.profiles has no Row Level Security");
    assert_eq!(f.category, "access_control");
    assert!(f.evidence.fingerprint.is_none());
    assert!(f.id.starts_with("web/web-rls-009/"));
    assert!(
        f.evidence
            .redacted_excerpt
            .as_deref()
            .unwrap()
            .starts_with("create table public.profiles")
    );
    // Детерминированность.
    let again = scan(&project);
    assert_eq!(
        format!("{:?}", again.findings),
        format!("{:?}", result.findings)
    );
}

#[test]
fn web_firebase_010_rules_files() {
    let project = fixture("firebase-rules");
    let result = scan(&project);
    use Confidence::{NeedsReview, Potential};
    use Severity::{High, Low, Medium};
    let db = "database.rules.json".to_string();
    let fs = "firestore.rules".to_string();
    assert_eq!(
        of_rule(&result, "WEB-FIREBASE-010"),
        vec![
            (db.clone(), 4, High, Potential),
            (db.clone(), 6, Medium, NeedsReview),
            (fs.clone(), 7, High, Potential),
            (fs.clone(), 17, Low, NeedsReview),
            (fs.clone(), 23, High, Potential),
            ("storage.rules".to_string(), 7, Medium, NeedsReview),
        ]
    );
    let titles: Vec<&str> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-FIREBASE-010")
        .map(|f| f.title.as_str())
        .collect();
    assert!(titles.contains(
        &"Realtime Database rules are in test mode: anyone can write the entire database until 2025-01-01"
    ));
    assert!(titles.contains(
        &"Firestore rules are in test mode: anyone can read and write every document until 2025-06-01"
    ));
    let fb = check(&result, "WEB-FIREBASE-010");
    assert_eq!(fb.status, CheckStatus::Completed);
    assert!(result.completed());
    assert!(result.framework.uses_firebase);
    // Публичный Firebase apiKey — не находка ни одного правила.
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.location.relative_path != "src/firebase.ts"),
        "{:?}",
        result.findings
    );
    assert!(
        result
            .limitations
            .iter()
            .any(|l| l.starts_with("WEB-FIREBASE-010: 3 rules file(s) analysed"))
    );
    assert!(
        result
            .limitations
            .iter()
            .all(|l| !l.contains("points to rules file"))
    );
}

#[test]
fn web_firebase_010_skipped_without_rules() {
    let t = TempProject::new();
    t.write(
        "package.json",
        r#"{"dependencies":{"firebase":"^10.0.0","react":"^18.0.0","vite":"^5.0.0"}}"#,
    );
    t.write("src/main.ts", "export const x = 1;");
    let r = scan(&t);
    let fb = check(&r, "WEB-FIREBASE-010");
    assert_eq!(fb.status, CheckStatus::Skipped);
    assert!(fb.reason.as_deref().unwrap().starts_with("not_checked"));
    let r = scan(&fixture("next-pages"));
    let fb = check(&r, "WEB-FIREBASE-010");
    assert!(fb.reason.as_deref().unwrap().starts_with("not_applicable"));
}

#[test]
fn no_supabase_no_rls_check() {
    let project = fixture("next-pages");
    let result = scan(&project);
    let rls = check(&result, "WEB-RLS-009");
    assert_eq!(rls.status, CheckStatus::Skipped);
    assert!(rls.reason.as_deref().unwrap().starts_with("not_applicable"));
    assert_eq!(
        check(&result, "WEB-SUPABASE-005").status,
        CheckStatus::Completed
    );
}

#[test]
fn web_xss_003_sinks_potential_only() {
    let project = fixture("next-app");
    let result = scan(&project);
    let rows: Vec<(String, u32, Severity, Confidence)> = of_rule(&result, "WEB-XSS-003");
    let expected = |line, severity| {
        (
            "app/components/Comment.tsx".to_string(),
            line,
            severity,
            Confidence::Potential,
        )
    };
    assert_eq!(
        rows,
        vec![
            expected(10, Severity::Medium),
            expected(11, Severity::High),
            expected(25, Severity::Medium),
            expected(26, Severity::High),
        ]
    );
    let f = result
        .findings
        .iter()
        .find(|f| f.rule_id == "WEB-XSS-003" && f.location.line == Some(11))
        .unwrap();
    // Литералы в фрагменте скрыты, синк виден.
    assert_eq!(
        f.evidence.redacted_excerpt.as_deref(),
        Some("<div dangerouslySetInnerHTML={{ __html: params.get(\"…\") ?? \"\" }} />")
    );
    assert_eq!(f.cwe_ids, vec!["CWE-79"]);
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.confidence != Confidence::Confirmed)
    );
}

#[test]
fn web_xss_003_unit_cases() {
    let t = TempProject::new();
    t.write(
        "package.json",
        r#"{"dependencies":{"next":"15","react":"19"}}"#,
    );
    t.write(
        "app/ui.tsx",
        "export const a = (el) => { el.outerHTML = el.dataset.html; };\n\
         export const b = (h) => document.write(h);\n\
         export const c = () => document.write(\"<p>static</p>\");\n\
         export const d = (el, v) => { el.innerHTML += v; };\n\
         export const e = { dangerouslySetInnerHTML: { __html: purify(x) } };\n\
         export const f = (el) => { el.innerHTMLx = 1; el.innerHTML == 2; };\n",
    );
    t.write(
        "app/ui.test.tsx",
        "el.innerHTML = userInput; // tests are out of scope\n",
    );
    let lines: Vec<u32> = of_rule(&scan(&t), "WEB-XSS-003")
        .into_iter()
        .map(|r| r.1)
        .collect();
    assert_eq!(lines, vec![1, 2, 4]);
}

fn rows_sorted(result: &WebScanResult, rule: &str) -> Vec<(String, u32, Severity, Confidence)> {
    let mut rows = of_rule(result, rule);
    rows.sort();
    rows
}

#[test]
fn web_auth_004_next_routes() {
    let project = fixture("next-routes");
    let result = scan(&project);
    let review = |path: &str, line| {
        (
            path.to_string(),
            line,
            Severity::Medium,
            Confidence::NeedsReview,
        )
    };
    assert_eq!(
        rows_sorted(&result, "WEB-AUTH-004"),
        vec![
            review("app/(shop)/api/cart/[id]/route.ts", 5),
            review("app/actions.ts", 7),
            review("app/api/items/route.ts", 6),
            review("pages/api/notes.ts", 6),
        ]
    );
    let by_path = |p: &str| {
        result
            .findings
            .iter()
            .find(|f| f.rule_id == "WEB-AUTH-004" && f.location.relative_path == p)
            .unwrap()
    };
    assert!(
        by_path("app/api/items/route.ts")
            .explanation
            .contains("curl -i -X POST https://<your-host>/api/items ")
    );
    assert!(
        by_path("app/(shop)/api/cart/[id]/route.ts")
            .explanation
            .contains("-X DELETE https://<your-host>/api/cart/[id] ")
    );
    assert!(
        by_path("app/actions.ts")
            .title
            .starts_with("2 Server Action(s)")
    );
    assert_eq!(
        check(&result, "WEB-AUTH-004").status,
        CheckStatus::Completed
    );
    assert!(
        result
            .findings
            .iter()
            .all(|f| f.confidence != Confidence::Confirmed)
    );
}

#[test]
fn web_auth_004_middleware_with_auth_withholds_and_marks_partial() {
    // next-app/middleware.ts отвечает 401 — покрытие matcher-ом не анализируем.
    let project = fixture("next-app");
    let result = scan(&project);
    assert!(of_rule(&result, "WEB-AUTH-004").is_empty());
    let c = check(&result, "WEB-AUTH-004");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason.as_deref().unwrap().starts_with(
            "middleware.ts contains an access gate whose matcher may cover 1 handler(s)"
        )
    );
}

#[test]
fn web_cors_006_next_routes() {
    let project = fixture("next-routes");
    let result = scan(&project);
    let row =
        |path: &str, line, severity, confidence| (path.to_string(), line, severity, confidence);
    assert_eq!(
        rows_sorted(&result, "WEB-CORS-006"),
        vec![
            row(
                "app/api/cors-reflect/route.ts",
                5,
                Severity::High,
                Confidence::Potential
            ),
            row(
                "app/api/cors-star/route.ts",
                5,
                Severity::Low,
                Confidence::NeedsReview
            ),
            row(
                "next.config.mjs",
                13,
                Severity::Low,
                Confidence::NeedsReview
            ),
            row(
                "server/express.ts",
                6,
                Severity::High,
                Confidence::Potential
            ),
        ]
    );
    assert_eq!(
        check(&result, "WEB-CORS-006").status,
        CheckStatus::Completed
    );
}

#[test]
fn web_debug_007_source_maps() {
    let next = scan(&fixture("next-routes"));
    assert_eq!(
        of_rule(&next, "WEB-DEBUG-007"),
        vec![(
            "next.config.mjs".to_string(),
            4,
            Severity::Low,
            Confidence::Potential
        )]
    );
    let vite = scan(&fixture("vite-react"));
    assert_eq!(
        of_rule(&vite, "WEB-DEBUG-007"),
        vec![(
            "vite.config.ts".to_string(),
            12,
            Severity::Low,
            Confidence::Potential
        )]
    );
    let t = TempProject::new();
    t.write(
        "package.json",
        r#"{"devDependencies":{"vite":"5","react":"18"}}"#,
    );
    t.write(
        "vite.config.ts",
        "export default { build: { sourcemap: 'hidden' } };\n// sourcemap: true\nconst s = 'sourcemap: true';\n",
    );
    t.write(
        "next.config.mjs",
        "export default { productionBrowserSourceMaps: false };\n",
    );
    assert!(of_rule(&scan(&t), "WEB-DEBUG-007").is_empty());
}

#[test]
fn completed_requires_at_least_one_check() {
    let t = TempProject::new();
    t.write("index.js", "console.log(1)");
    let mut result = scan(&t);
    assert!(result.completed());
    // Каждая skipped-проверка обязана объяснить, почему (контракт V2).
    assert!(
        result
            .checks
            .iter()
            .filter(|c| c.status == CheckStatus::Skipped)
            .all(|c| c.reason.as_deref().is_some_and(|r| !r.is_empty()))
    );
    result.checks.clear();
    assert!(!result.completed(), "no checks means nothing was verified");
}

/// Field test 2026-11-12, FP-паттерн 11: заголовок PEM без тела — не ключ; полный ключ — ключ.
#[test]
fn web_secret_001_pem_header_alone_is_not_a_key() {
    let result = scan(&fixture("pem-utils"));
    assert_eq!(
        of_rule(&result, "WEB-SECRET-001"),
        vec![(
            "app/crypto/PemFormat.tsx".to_string(),
            11,
            Severity::Critical,
            Confidence::Potential
        )]
    );
    assert!(!format!("{result:?}").contains(&testutil::pem_key()));
}

#[test]
fn pem_body_detection() {
    use super::rules::secret::has_pem_body;
    let header = testutil::pem_header();
    assert!(!has_pem_body(&header));
    assert!(!has_pem_body(&format!("{header}\n")));
    assert!(!has_pem_body(&format!("{header}\", \"\");")));
    assert!(!has_pem_body(&format!("{header}\\n\" + body + \"")));
    assert!(has_pem_body(&testutil::pem_key()));
    // Тело через экранирование `\n` в одном литерале и склейкой литералов.
    let b = testutil::body(64);
    assert!(has_pem_body(&format!("{header}\\n{b}\\n-----END")));
    assert!(has_pem_body(&format!("{header}\\n\" +\n  \"{b}\"")));
    assert!(!has_pem_body(&format!("{header}\\n{}", &b[..63])));
}

/// Field test 2026-11-12, W3: правило, которое для фреймворка не запускалось, — skipped с причиной.
#[test]
fn auth_004_is_not_applicable_outside_nextjs() {
    for project in [fixture("vite-react"), fixture("unsupported-nuxt")] {
        let result = scan(&project);
        let c = check(&result, "WEB-AUTH-004");
        assert_eq!(c.status, CheckStatus::Skipped);
        assert!(
            c.reason
                .as_deref()
                .unwrap()
                .starts_with("not_applicable: framework is")
        );
    }
    let t = TempProject::new();
    t.write("app/api/x/route.ts", "export async function POST() {}\n");
    let result = scan(&t);
    assert_eq!(check(&result, "WEB-AUTH-004").status, CheckStatus::Skipped);
    assert_eq!(
        check(&fixture_scan("next-routes"), "WEB-AUTH-004").status,
        CheckStatus::Completed
    );
}

fn fixture_scan(name: &str) -> WebScanResult {
    scan(&fixture(name))
}

#[test]
fn help_lists_every_rule() {
    for id in [
        "WEB-SECRET-001",
        "WEB-ENV-002",
        "WEB-XSS-003",
        "WEB-AUTH-004",
        "WEB-SUPABASE-005",
        "WEB-CORS-006",
        "WEB-DEBUG-007",
        "WEB-DEPS-008",
    ] {
        assert!(super::cli::USAGE.contains(id), "{id} missing from help");
    }
}

/// Field test 2026-11-12, W1 + W2: pnpm-монорепо узнаётся и называет вложенные приложения;
/// Vite-приложение без `vite` в своих зависимостях и без src/ — vite-react, клиентский корень из index.html.
#[test]
fn monorepo_root_hint_and_vite_app_without_vite_dependency() {
    let project = fixture("monorepo-pnpm");
    let root = scan(&project);
    assert_eq!(root.framework.kind, FrameworkKind::Generic);
    let hint = root
        .limitations
        .iter()
        .find(|l| l.starts_with("workspace root"))
        .expect("workspace hint");
    assert!(
        hint.contains("apps/editor (vite-react)") && hint.contains("apps/web (nextjs)"),
        "{hint}"
    );
    assert!(hint.contains("jetscan web source apps/editor"), "{hint}");
    assert_eq!(check(&root, "WEB-AUTH-004").status, CheckStatus::Skipped);

    let editor = scan_source(
        &project.path().join("apps/editor"),
        &WebScanOptions::default(),
    )
    .unwrap();
    assert_eq!(editor.framework.kind, FrameworkKind::ViteReact);
    assert_eq!(editor.framework.vite_entry_dir.as_deref(), Some(""));
    assert_eq!(
        of_rule(&editor, "WEB-SECRET-001"),
        vec![(
            "App.tsx".to_string(),
            3,
            Severity::Critical,
            Confidence::Potential
        )]
    );
    let web = scan_source(&project.path().join("apps/web"), &WebScanOptions::default()).unwrap();
    assert_eq!(web.framework.kind, FrameworkKind::NextJs);
    assert_eq!(of_rule(&web, "WEB-AUTH-004").len(), 1);
}

/// Field test 2026-11-12, W4: шлюз, чей matcher не покрывает /api, ничего не удерживает, и чистый
/// скан остаётся `completed` (раньше — partial и exit 2).
#[test]
fn auth_004_middleware_scoped_matcher_does_not_withhold() {
    let r = scan(&fixture("middleware-scoped"));
    assert!(of_rule(&r, "WEB-AUTH-004").is_empty());
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
    assert!(r.completed());
}

/// W4: middleware, которое только обновляет сессию, — не шлюз: маршрут не удерживается.
#[test]
fn auth_004_session_refresh_middleware_is_not_a_gate() {
    let r = scan(&fixture("middleware-refresh"));
    assert_eq!(
        of_rule(&r, "WEB-AUTH-004"),
        vec![(
            "app/api/notes/route.ts".to_string(),
            2,
            Severity::Medium,
            Confidence::NeedsReview
        )]
    );
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
}

/// W5: `proxy.ts` в Next.js 16 — middleware; удерживается только покрытый matcher-ом маршрут.
#[test]
fn auth_004_next16_proxy_is_middleware() {
    let project = fixture("proxy-next16");
    let r = scan(&project);
    assert_eq!(
        of_rule(&r, "WEB-AUTH-004"),
        vec![(
            "app/pages-like/save/route.ts".to_string(),
            2,
            Severity::Medium,
            Confidence::NeedsReview
        )]
    );
    let c = check(&r, "WEB-AUTH-004");
    assert_eq!(c.status, CheckStatus::Partial);
    assert!(
        c.reason
            .as_deref()
            .unwrap()
            .starts_with("proxy.ts contains an access gate whose matcher may cover 1 handler(s)")
    );
    // Тот же proxy.ts в Next.js 15 — обычный файл: ничего не удерживается.
    std::fs::write(
        project.path().join("package.json"),
        r#"{"dependencies":{"next":"15.0.3","react":"19"}}"#,
    )
    .unwrap();
    let r = scan(&project);
    assert_eq!(of_rule(&r, "WEB-AUTH-004").len(), 2);
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
}

/// Field test 2026-11-12, паттерны 1–3 и W7: обёртки, делегирование, пакет-верификатор,
/// revalidate-only — не находки; настоящие TP-шаблоны (неаутентифицированный POST, платный LLM,
/// unstable_cache-экспорт) остаются.
#[test]
fn auth_004_wrappers_delegation_and_revalidate_only() {
    let r = scan(&fixture("auth-patterns"));
    assert_eq!(
        of_rule(&r, "WEB-AUTH-004"),
        vec![
            (
                "app/actions/cache.ts".to_string(),
                12,
                Severity::Medium,
                Confidence::NeedsReview
            ),
            (
                "app/actions/generate.ts".to_string(),
                7,
                Severity::Medium,
                Confidence::NeedsReview
            ),
            (
                "app/api/photos/download/route.ts".to_string(),
                4,
                Severity::Medium,
                Confidence::NeedsReview
            ),
        ]
    );
    let cache = r
        .findings
        .iter()
        .find(|f| f.location.relative_path == "app/actions/cache.ts")
        .unwrap();
    assert_eq!(
        cache.title,
        "1 Server Action(s) without a visible access check"
    );
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
}

/// Field test 2026-11-12, паттерны 5–8: санитайзер из проекта и по имени, подсветка, константы,
/// ld+json, многострочный синк; настоящие TP-шаблоны остаются.
#[test]
fn xss_003_field_test_patterns() {
    let r = scan(&fixture("xss-patterns"));
    let mut rows = of_rule(&r, "WEB-XSS-003");
    rows.sort();
    assert_eq!(
        rows,
        vec![
            (
                "app/SpeculationRules.tsx".to_string(),
                10,
                Severity::Low,
                Confidence::Potential
            ),
            (
                "app/SpeculationRules.tsx".to_string(),
                19,
                Severity::Low,
                Confidence::Potential
            ),
            (
                "app/SpeculationRules.tsx".to_string(),
                24,
                Severity::Medium,
                Confidence::Potential
            ),
            (
                "app/product/JsonLd.tsx".to_string(),
                4,
                Severity::Low,
                Confidence::Potential
            ),
            (
                "app/ui/CodeBlock.tsx".to_string(),
                13,
                Severity::Info,
                Confidence::Potential
            ),
            (
                "app/ui/Prose.tsx".to_string(),
                7,
                Severity::Medium,
                Confidence::Potential
            ),
            (
                "app/ui/Prose.tsx".to_string(),
                17,
                Severity::Medium,
                Confidence::Potential
            ),
        ]
    );
    let prose = r
        .findings
        .iter()
        .find(|f| f.rule_id == "WEB-XSS-003" && f.location.line == Some(7))
        .unwrap();
    let excerpt = prose.evidence.redacted_excerpt.as_deref().unwrap();
    assert!(excerpt.contains("__html: html"), "{excerpt}");
    let json_ld = r
        .findings
        .iter()
        .find(|f| f.location.relative_path == "app/product/JsonLd.tsx")
        .unwrap();
    assert!(json_ld.explanation.contains("does not escape"));
    let at = |line: u32| {
        r.findings
            .iter()
            .find(|f| {
                f.location.relative_path == "app/SpeculationRules.tsx"
                    && f.location.line == Some(line)
            })
            .unwrap()
    };
    assert!(at(10).explanation.contains("type=\"speculationrules\""));
    assert!(at(19).explanation.contains("type=\"importmap\""));
    assert!(!at(24).explanation.contains("does not escape"));
}

/// Field test 2026-11-12, паттерн 10: заголовок говорит, кто импортирует модуль без границы.
#[test]
fn supabase_005_shared_module_names_its_importers() {
    let r = scan(&fixture("supabase-admin"));
    let mut rows = of_rule(&r, "WEB-SUPABASE-005");
    rows.sort();
    assert_eq!(
        rows,
        vec![
            (
                "lib/admin-client.ts".to_string(),
                5,
                Severity::Medium,
                Confidence::NeedsReview
            ),
            (
                "utils/supabase/admin.ts".to_string(),
                7,
                Severity::Info,
                Confidence::NeedsReview
            ),
        ]
    );
    let title = |path: &str| {
        r.findings
            .iter()
            .find(|f| f.location.relative_path == path)
            .unwrap()
            .title
            .clone()
    };
    assert_eq!(
        title("utils/supabase/admin.ts"),
        "Module without a client/server boundary reads SUPABASE_SERVICE_ROLE_KEY (imported only by server code)"
    );
    assert_eq!(
        title("lib/admin-client.ts"),
        "Module without a client/server boundary reads SUPABASE_SERVICE_ROLE_KEY (imported by client or shared code: app/ui/Panel.tsx)"
    );
    let admin = r
        .findings
        .iter()
        .find(|f| f.location.relative_path == "utils/supabase/admin.ts")
        .unwrap();
    assert!(
        admin
            .explanation
            .contains("app/api/webhooks/route.ts, utils/stripe/server.ts")
    );
    assert!(admin.explanation.contains("import \"server-only\""));
    // Раунд 2, N4: объяснение не противоречит себе.
    assert!(
        admin.explanation.starts_with(
            "Module without a client/server boundary reads SUPABASE_SERVICE_ROLE_KEY. "
        ),
        "{}",
        admin.explanation
    );
    for stale in ["Client-reachable", "where the browser runs it"] {
        assert!(!admin.explanation.contains(stale), "{}", admin.explanation);
    }
}

/// Field test round 2, N5 (блокер): Server Actions не удерживаются; `/:path*/embed` покрывает только
/// пути с хвостом /embed; чистый скан — `completed`, `--exit-code` не 2.
#[test]
fn auth_004_gate_never_withholds_actions_and_parameter_first_patterns_match_suffix() {
    let project = fixture("proxy-actions");
    let r = scan(&project);
    assert_eq!(
        of_rule(&r, "WEB-AUTH-004"),
        vec![
            (
                "app/api/things/route.ts".to_string(),
                2,
                Severity::Medium,
                Confidence::NeedsReview
            ),
            (
                "app/cache/schedule.ts".to_string(),
                7,
                Severity::Medium,
                Confidence::NeedsReview
            ),
        ]
    );
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
    assert!(r.completed());
    let action = r
        .findings
        .iter()
        .find(|f| f.location.relative_path == "app/cache/schedule.ts")
        .unwrap();
    assert!(
        action
            .explanation
            .contains("An access gate exists in proxy.ts")
    );
    assert!(action.tags.contains(&"gate:unknown-coverage".to_string()));
    let (code, _) = super::cli::tests::run_capture(&[
        "source".to_string(),
        project.path().display().to_string(),
        "--exit-code".to_string(),
    ]);
    assert_eq!(code, 0, "only medium findings and every check completed");
}

/// Field test round 2, N3: `proxy.test.ts` / `middleware.spec.ts` — не шлюз (даже с redirect/401 в коде).
#[test]
fn auth_004_test_files_are_never_middleware() {
    let r = scan(&fixture("proxy-test-only"));
    assert_eq!(
        of_rule(&r, "WEB-AUTH-004"),
        vec![(
            "app/api/x/route.ts".to_string(),
            2,
            Severity::Medium,
            Confidence::NeedsReview
        )]
    );
    assert_eq!(check(&r, "WEB-AUTH-004").status, CheckStatus::Completed);
}

/// Field test round 2, N1: в причинах проверок и объяснениях нет «склеенных» пробелов от переноса строки.
#[test]
fn reasons_and_explanations_have_no_space_runs() {
    for name in [
        "monorepo-pnpm",
        "proxy-actions",
        "next-app",
        "auth-patterns",
        "xss-patterns",
        "supabase-admin",
    ] {
        let r = scan(&fixture(name));
        for c in &r.checks {
            let reason = c.reason.as_deref().unwrap_or("");
            assert!(!reason.contains("   "), "{name} {}: {reason}", c.id);
        }
        for f in &r.findings {
            assert!(
                !f.explanation.contains("   "),
                "{name} {}: {}",
                f.rule_id,
                f.explanation
            );
        }
        for l in &r.limitations {
            assert!(!l.contains("   "), "{name}: {l}");
        }
    }
}
