//! CL-WEB-11: устойчивость к плохим входам и бенчмарк на синтетическом дереве.
//!
//! Большие файлы не коммитятся: дерево генерируется во временный каталог в момент теста.
//! Бенчмарк (`#[ignore]`) запускается руками:
//! `cargo test --release --lib web_audit::bench -- --ignored --nocapture`.
//! Результаты — в `docs/rules/web/BENCH.md`.

use super::testutil::{self, TempProject};
use super::*;
use std::time::{Duration, Instant};

/// Верхняя граница для «не зависло»: линейный разбор мегабайта занимает миллисекунды даже в
/// debug-сборке, квадратичный — минуты. Граница щедрая, чтобы не флапать на медленной машине.
const NOT_HUNG: Duration = Duration::from_secs(20);

fn next_project() -> TempProject {
    let t = TempProject::new();
    t.write(
        "package.json",
        r#"{"dependencies":{"next":"15","react":"19"}}"#,
    );
    t.write(
        "app/page.tsx",
        "export default function P() { return null }\n",
    );
    t
}

fn timed_scan(t: &TempProject) -> (WebScanResult, Duration) {
    let started = Instant::now();
    let result = scan_source(t.path(), &WebScanOptions::default()).expect("scan");
    (result, started.elapsed())
}

fn status(result: &WebScanResult, id: &str) -> CheckStatus {
    result
        .checks
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.status)
        .expect("check present")
}

#[test]
fn huge_minified_line_is_linear_and_still_scanned() {
    let t = next_project();
    // ~900 КБ одной строкой, как минифицированный бандл в public/, ключ в самом конце.
    let mut line = String::from("!function(){");
    while line.len() < 900_000 {
        line.push_str("var a=b?c(d,\"x\"):e/2/f;g[h]=`t${i}`;/re[/]x/g.test(j);");
    }
    line.push_str(&format!("var k=\"{}\";}}();", testutil::stripe_secret()));
    t.write("public/vendor.min.js", &line);
    let (result, took) = timed_scan(&t);
    assert!(took < NOT_HUNG, "took {took:?}");
    let f: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-SECRET-001")
        .collect();
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].location.line, Some(1));
    // Колонка — реальная позиция в символах (строка ASCII: байт = символ, +1 за кавычку).
    let expected_col = line.find("sk_live_").unwrap() + 1;
    assert_eq!(f[0].location.column, Some(expected_col as u32));
    assert!(
        f[0].evidence
            .redacted_excerpt
            .as_deref()
            .unwrap()
            .chars()
            .count()
            <= 162
    );
}

#[test]
fn adversarial_line_of_tokens_is_capped_and_reported_partial() {
    let t = next_project();
    let token = testutil::github_token();
    let line = vec![format!("\"{token}\""); 20_000].join(",");
    t.write(
        "app/c.tsx",
        &format!("'use client'\nexport const a = [{line}];\n"),
    );
    let (result, took) = timed_scan(&t);
    assert!(took < NOT_HUNG, "took {took:?}");
    let count = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-SECRET-001")
        .count();
    assert_eq!(count, rules::MAX_HITS_PER_FILE);
    assert_eq!(status(&result, "WEB-SECRET-001"), CheckStatus::Partial);
    let reason = result
        .checks
        .iter()
        .find(|c| c.id == "WEB-SECRET-001")
        .and_then(|c| c.reason.clone())
        .unwrap();
    assert!(reason.contains("app/c.tsx"));
    assert!(!result.completed());
}

#[test]
fn many_sinks_on_one_line_are_capped() {
    let t = next_project();
    let line = "a.innerHTML=b;".repeat(50_000);
    t.write("app/x.tsx", &format!("'use client'\n{line}\n"));
    let (result, took) = timed_scan(&t);
    assert!(took < NOT_HUNG, "took {took:?}");
    assert_eq!(status(&result, "WEB-XSS-003"), CheckStatus::Partial);
}

#[test]
fn broken_syntax_does_not_panic_and_is_disclosed() {
    let t = next_project();
    let cases = [
        "'use client'\nconst a = \"never closed\nconst b = 1;",
        "'use client'\nconst t = `open template ${ x ",
        "'use client'\n/* open comment",
        "'use client'\nconst r = /[unclosed regex",
        "'use client'\n}}}}{{{{)))(((",
        "'use client'\n`${`${`${`${",
        "\u{feff}'use client'\r\nconst crlf = 1;\r\n",
        "",
    ];
    for (i, text) in cases.iter().enumerate() {
        t.write(&format!("app/broken{i}.tsx"), text);
    }
    let (result, _) = timed_scan(&t);
    assert!(result.stats.files_with_recoveries >= 3);
    // Полевой тест 2026-11-12, W6: перечислены пути (не больше 5), остальное — счётчиком.
    let line = result
        .limitations
        .iter()
        .find(|l| l.contains("unterminated strings/comments"))
        .expect("recovery limitation");
    assert!(line.contains("app/broken0.tsx"), "{line}");
    assert_eq!(
        result.stats.recovery_paths.len().min(5),
        result.stats.recovery_paths.len()
    );
    let t = next_project();
    for i in 0..8 {
        t.write(
            &format!("app/open{i}.tsx"),
            "'use client'\nconst a = \"never closed\n",
        );
    }
    let (many, _) = timed_scan(&t);
    let line = many
        .limitations
        .iter()
        .find(|l| l.contains("unterminated strings/comments"))
        .unwrap();
    assert!(line.ends_with(" and 3 more"), "{line}");
}

#[test]
fn deeply_nested_templates_and_brackets_do_not_overflow() {
    let t = next_project();
    let depth = 50_000;
    let nested = format!("{}x{}", "`${".repeat(depth), "}`".repeat(depth));
    let brackets = format!("{}{}", "([{".repeat(depth), "}])".repeat(depth));
    t.write(
        "app/deep.tsx",
        &format!(
            "'use client'\nconst a = {nested};\nconst b = {brackets};\nel.innerHTML = {brackets};\n"
        ),
    );
    let (result, took) = timed_scan(&t);
    assert!(took < NOT_HUNG, "took {took:?}");
    // page.tsx + deep.tsx (package.json обход не читает).
    assert_eq!(result.stats.walk.files_read, 2);
}

#[test]
fn deep_directory_nesting_hits_depth_budget() {
    let t = next_project();
    let deep: String = (0..70).map(|_| "d/").collect();
    t.write(&format!("{deep}leaf.ts"), "export {}");
    let (result, _) = timed_scan(&t);
    assert!(result.stats.walk.depth_limited >= 1);
    assert_eq!(status(&result, "WEB-SECRET-001"), CheckStatus::Partial);
}

#[test]
fn non_utf8_and_utf16_inputs() {
    let t = next_project();
    // Невалидный UTF-8 → замена U+FFFD (1 символ), ключ после него всё равно находится.
    let mut bytes = b"'use client'\nconst a = '\xff\xfe'; const k = \"".to_vec();
    bytes.extend_from_slice(testutil::stripe_secret().as_bytes());
    bytes.extend_from_slice(b"\";\n");
    t.write_bytes("app/latin.tsx", &bytes);
    // UTF-16 (NUL-байты) — бинарник: не читается, но считается.
    let utf16: Vec<u8> = "'use client'\nconst x = 1;\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    t.write_bytes("app/utf16.tsx", &[&[0xff, 0xfe][..], &utf16].concat());
    let (result, _) = timed_scan(&t);
    let f = result
        .findings
        .iter()
        .find(|f| f.location.relative_path == "app/latin.tsx")
        .expect("key after invalid bytes");
    assert_eq!(f.location.line, Some(2));
    // `const a = '` (11) + 2 замены + `'; const k = "` (14) → ключ с колонки 28.
    assert_eq!(f.location.column, Some(28));
    assert_eq!(result.stats.walk.skipped_binary, 1);
}

#[test]
fn file_over_size_limit_makes_rules_partial() {
    let t = next_project();
    t.write("app/huge.ts", &"a".repeat(1024 * 1024 + 1));
    let (result, _) = timed_scan(&t);
    assert_eq!(result.stats.walk.skipped_large, 1);
    assert_eq!(status(&result, "WEB-ENV-002"), CheckStatus::Partial);
}

/// Генерирует синтетический Next.js-проект ~`target_bytes`: смесь клиентских компонентов,
/// серверных route handlers, общих модулей, `.env`-файлов; ключ подкладывается в каждый
/// `plant_every`-й клиентский файл. Возвращает (файлов, байт, подложено ключей).
fn generate_tree(
    t: &TempProject,
    target_bytes: usize,
    plant_every: usize,
) -> (usize, usize, usize) {
    t.write(
        "package.json",
        r#"{"dependencies":{"next":"15","react":"19","@supabase/supabase-js":"2"}}"#,
    );
    let client_body: String = (0..120)
        .map(|i| {
            format!(
                "  const v{i} = useMemo(() => items.filter((x) => x.id !== {i} && x.name !== \"n{i}\"), [items]); // c{i}\n"
            )
        })
        .collect();
    let server_body: String = (0..120)
        .map(|i| {
            format!(
                "  const r{i} = await db.query(`select * from t where id = ${{id}} and k = {i}`);\n"
            )
        })
        .collect();
    let (mut files, mut bytes, mut planted, mut n) = (0, 0, 0, 0usize);
    while bytes < target_bytes {
        let dir = format!("app/f{}/s{}", n / 400, (n / 20) % 20);
        let (path, text) = match n % 4 {
            0 | 1 => {
                let key = if (n / 4) % plant_every == 0 {
                    planted += 1;
                    format!("const KEY = \"{}\";\n", testutil::stripe_secret())
                } else {
                    String::new()
                };
                (
                    format!("{dir}/C{n}.tsx"),
                    format!(
                        "\"use client\";\nimport {{ useMemo }} from \"react\";\n{key}/* component {n} */\nexport function C{n}({{ items }}) {{\n{client_body}  return <div className=\"c\">{{items.length}}</div>;\n}}\n"
                    ),
                )
            }
            2 => (
                format!("{dir}/api{n}/route.ts"),
                format!(
                    "const SECRET = \"{}\";\nexport async function GET(id) {{\n{server_body}  return Response.json({{ ok: SECRET.length }});\n}}\n",
                    testutil::stripe_secret()
                ),
            ),
            _ => (
                format!("lib/m{n}.ts"),
                format!("export const helper{n} = (x: number) => x * {n};\n{server_body}"),
            ),
        };
        bytes += text.len();
        files += 1;
        t.write(&path, &text);
        n += 1;
    }
    t.write(
        ".env.local",
        "NEXT_PUBLIC_SITE_URL=https://example.test\nSTRIPE_SECRET_KEY=placeholder\n",
    );
    // + .env.local (package.json не исходник и не читается обходом).
    (files + 1, bytes, planted)
}

#[test]
fn small_generated_tree_finds_exactly_the_planted_keys() {
    let t = TempProject::new();
    let (files, _, planted) = generate_tree(&t, 400_000, 3);
    let result = scan_source(t.path(), &WebScanOptions::default()).unwrap();
    let found = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-SECRET-001")
        .count();
    assert_eq!(found, planted, "server route keys must not be reported");
    assert_eq!(result.stats.walk.files_read, files);
    assert!(result.completed());
}

#[test]
#[ignore = "benchmark: cargo test --release --lib web_audit::bench -- --ignored --nocapture"]
fn bench_synthetic_tree() {
    let target_mb: usize = std::env::var("JETSCAN_WEB_BENCH_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let t = TempProject::new();
    let generated = Instant::now();
    let (files, bytes, planted) = generate_tree(&t, target_mb * 1024 * 1024, 50);
    let generated = generated.elapsed();
    let options = WebScanOptions {
        budgets: Budgets {
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_files: 1_000_000,
            ..Budgets::default()
        },
    };
    let mut web_runs = Vec::new();
    let mut result = None;
    for _ in 0..3 {
        let started = Instant::now();
        result = Some(scan_source(t.path(), &options).unwrap());
        web_runs.push(started.elapsed());
    }
    let result = result.unwrap();
    let core_options = crate::secrets::scan::ScanOptions {
        history: false,
        ..Default::default()
    };
    let mut core_runs = Vec::new();
    for _ in 0..3 {
        let started = Instant::now();
        let _ = crate::secrets::scan::scan(t.path(), &core_options).unwrap();
        core_runs.push(started.elapsed());
    }
    web_runs.sort();
    core_runs.sort();
    let mb = bytes as f64 / (1024.0 * 1024.0);
    let found = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "WEB-SECRET-001")
        .count();
    println!(
        "BENCH files={files} source_mb={mb:.1} planted={planted} found={found} generate={generated:?}\n\
         BENCH web_source  median={:?} min={:?} max={:?} ({:.1} MB/s)\n\
         BENCH core_secrets median={:?} min={:?} max={:?} ({:.1} MB/s, --no-history)",
        web_runs[1],
        web_runs[0],
        web_runs[2],
        mb / web_runs[1].as_secs_f64(),
        core_runs[1],
        core_runs[0],
        core_runs[2],
        mb / core_runs[1].as_secs_f64(),
    );
    assert_eq!(found, planted);
}
