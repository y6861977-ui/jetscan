//! WEB-SUPABASE-005: ключ Supabase с правами service-role там, где его увидит браузер.
//!
//! Что считаем привилегированным (факт о самом значении, без сети):
//! - JWT, у которого в payload `"role":"service_role"` (старые ключи Supabase — JWT; payload
//!   декодируем из base64url, подпись НЕ проверяем — это и не нужно, чтобы узнать роль);
//! - ключ нового формата `sb_secret_…`.
//!
//! Что НЕ находка: JWT с `role=anon`, `sb_publishable_…` — они созданы для браузера, защита
//! данных держится на Row Level Security. RLS проверяет отдельное правило WEB-RLS-009
//! (`rules::rls`) по SQL-схеме из репозитория.
//!
//! Где ищем: клиентский/общий код (как WEB-SECRET-001), публичные переменные `.env*`, и чтения
//! `process.env.*SERVICE_ROLE*` без публичного префикса из клиентского кода (`needs_review`).

use super::env::{parse_env_line, public_prefixes};
use super::{FileContext, MAX_HITS_PER_FILE, RuleStats};
use crate::json;
use crate::secrets::{self, Span, rules};
use crate::web_audit::framework::FrameworkInfo;
use crate::web_audit::lexer;
use crate::web_audit::location::code_excerpt;
use crate::web_audit::provenance::Reach;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};

pub const RULE_ID: &str = "WEB-SUPABASE-005";

pub const REFERENCES: &[&str] = &[
    "https://supabase.com/docs/guides/api/api-keys",
    "https://supabase.com/docs/guides/database/postgres/row-level-security",
    "https://cwe.mitre.org/data/definitions/798.html",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupabaseKey {
    /// JWT с `role=service_role`. `supabase_issuer` — `iss` содержит `supabase`.
    ServiceRoleJwt { supabase_issuer: bool },
    /// `sb_secret_…`.
    SecretKey,
}

impl SupabaseKey {
    fn name(self) -> &'static str {
        match self {
            SupabaseKey::ServiceRoleJwt {
                supabase_issuer: true,
            } => "Supabase service-role key",
            SupabaseKey::ServiceRoleJwt {
                supabase_issuer: false,
            } => "JWT with a service_role claim",
            SupabaseKey::SecretKey => "Supabase secret API key",
        }
    }
}

/// Base64url (и обычный base64), с `=` или без. `None` — не base64.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Один «лишний» символ (6 бит) — невалидная длина.
    (bits < 6).then_some(out)
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// Роль из JWT `header.payload.signature`. `None` — не JWT или в payload нет строки `role`.
fn jwt_role(token: &str) -> Option<(String, bool)> {
    let mut parts = token.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || signature.is_empty() {
        return None;
    }
    let header = json::parse(std::str::from_utf8(&base64_decode(header)?).ok()?).ok()?;
    header.get("alg")?.as_str()?;
    let payload = json::parse(std::str::from_utf8(&base64_decode(payload)?).ok()?).ok()?;
    let role = payload.get("role")?.as_str()?.to_string();
    let supabase = payload
        .get("iss")
        .and_then(|i| i.as_str())
        .is_some_and(|iss| iss.to_ascii_lowercase().contains("supabase"));
    Some((role, supabase))
}

fn left_boundary(line: &str, start: usize) -> bool {
    start == 0 || !is_b64url(line.as_bytes()[start - 1])
}

/// Привилегированные ключи Supabase на строке: участки и вид ключа.
pub fn find_keys(line: &str) -> Vec<(Span, SupabaseKey)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    for (start, _) in line.match_indices("eyJ") {
        if !left_boundary(line, start) {
            continue;
        }
        let mut end = start;
        let mut dots = 0;
        while end < b.len() && (is_b64url(b[end]) || (b[end] == b'.' && dots < 2)) {
            if b[end] == b'.' {
                dots += 1;
            }
            end += 1;
        }
        if dots != 2 {
            continue;
        }
        if let Some((role, supabase_issuer)) = jwt_role(&line[start..end])
            && role == "service_role"
        {
            out.push((
                Span { start, end },
                SupabaseKey::ServiceRoleJwt { supabase_issuer },
            ));
        }
    }
    for (start, prefix) in line.match_indices("sb_secret_") {
        if !left_boundary(line, start) {
            continue;
        }
        let mut end = start + prefix.len();
        while end < b.len() && is_b64url(b[end]) {
            end += 1;
        }
        if end - start - prefix.len() >= 20
            && !rules::is_placeholder(&line[start + prefix.len()..end])
        {
            out.push((Span { start, end }, SupabaseKey::SecretKey));
        }
    }
    out.sort_by_key(|(span, _)| span.start);
    out
}

/// Значение целиком — привилегированный ключ Supabase (для `.env`).
pub fn classify_value(value: &str) -> Option<SupabaseKey> {
    let value = value.trim();
    find_keys(value)
        .into_iter()
        .find(|(span, _)| span.start == 0 && span.end == value.len())
        .map(|(_, key)| key)
}

#[allow(clippy::too_many_arguments)]
fn finding(
    path: &str,
    line: usize,
    col: usize,
    severity: Severity,
    confidence: Confidence,
    title: String,
    explanation: String,
    excerpt: String,
    fingerprint: Option<String>,
    tags: Vec<String>,
) -> WebFinding {
    let key = fingerprint.clone().unwrap_or_else(|| excerpt.clone());
    WebFinding {
        id: finding_id(RULE_ID, path, &key),
        rule_id: RULE_ID,
        title,
        category: "secret_exposure",
        severity,
        confidence,
        location: SourceLocation {
            relative_path: path.to_string(),
            line: u32::try_from(line).ok(),
            column: u32::try_from(col).ok(),
        },
        evidence: Evidence {
            redacted_excerpt: Some(excerpt),
            fingerprint,
        },
        explanation,
        remediation_id: Some(format!("{RULE_ID}:rotate-and-move-to-server")),
        references: REFERENCES.to_vec(),
        cwe_ids: vec!["CWE-798", "CWE-200"],
        tags,
    }
}

const BYPASS: &str = "A service-role/secret key bypasses Row Level Security: whoever holds it can read \
                      and change every row of every table. If this key reached a browser, rotate it \
                      in the Supabase dashboard, then use it only from server code.";

/// Ключи в исходнике и чтения `process.env.*SERVICE_ROLE*` из клиентского кода.
pub fn check(ctx: &FileContext, findings: &mut Vec<WebFinding>, stats: &mut RuleStats) {
    let (severity, confidence, where_) = match ctx.reach {
        Reach::Client(reason) => (Severity::Critical, Confidence::Potential, reason),
        Reach::Shared => (
            Severity::High,
            Confidence::NeedsReview,
            "module has no visible client/server boundary and may be imported by client code",
        ),
        Reach::Server(_) | Reach::Test => return,
    };
    let keys: Vec<(usize, &str, Span, SupabaseKey)> = ctx
        .stripped
        .lines()
        .enumerate()
        .flat_map(|(i, line)| {
            find_keys(line)
                .into_iter()
                .map(move |(s, k)| (i, line, s, k))
        })
        .collect();
    stats.note_cap(RULE_ID, ctx.path, keys.len());
    for (line_index, line, span, key) in keys.into_iter().take(MAX_HITS_PER_FILE) {
        {
            let line_no = line_index + 1;
            let col = line[..span.start].chars().count() + 1;
            let Some(start) = ctx.index.byte_at(ctx.text, line_no, col) else {
                continue;
            };
            let value = &line[span.start..span.end];
            let end = start + value.len();
            if ctx.text.get(start..end) != Some(value) || ctx.in_server_range(start) {
                continue;
            }
            if ctx.line_ignored(line_no) {
                stats.ignored_inline += 1;
                continue;
            }
            let masked = secrets::mask(value);
            findings.push(finding(
                ctx.path,
                line_no,
                col,
                severity,
                confidence,
                format!("{} in client-reachable code", key.name()),
                format!(
                    "{} appears in client-reachable code ({where_}). {BYPASS}",
                    key.name()
                ),
                code_excerpt(ctx.text, &ctx.lexed, &ctx.index, start, end, &masked),
                Some(secrets::fingerprint(value)),
                vec![
                    "web".to_string(),
                    "supabase".to_string(),
                    ctx.framework.kind.label().to_string(),
                    format!("reach:{}", ctx.reach.label()),
                ],
            ));
        }
    }
    if ctx.kind != crate::web_audit::enumerate::FileKind::Script {
        return;
    }
    // Чтение серверной переменной из клиентского кода: значения в браузере не будет (Next.js
    // подставляет только NEXT_PUBLIC_, Vite — только VITE_), но admin-клиент создают на клиенте,
    // и типичная «починка» — переименовать переменную в публичную — сольёт ключ.
    let prefixes = public_prefixes(ctx.framework);
    let mut reads = 0usize;
    for access in ["process.env.", "import.meta.env."] {
        for start in lexer::code_occurrences(ctx.text, &ctx.lexed, access) {
            let name: String = ctx.text[start + access.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let upper = name.to_ascii_uppercase();
            let privileged = upper.contains("SERVICE_ROLE") || upper.contains("SUPABASE_SECRET");
            if !privileged || prefixes.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            if ctx.in_server_range(start) {
                continue;
            }
            reads += 1;
            if reads > MAX_HITS_PER_FILE {
                stats.note_cap(RULE_ID, ctx.path, reads);
                return;
            }
            let Some((line, col)) = ctx.index.line_col(ctx.text, start) else {
                continue;
            };
            if ctx.line_ignored(line as usize) {
                stats.ignored_inline += 1;
                continue;
            }
            findings.push(finding(
                ctx.path,
                line as usize,
                col as usize,
                Severity::Medium,
                Confidence::NeedsReview,
                format!("Client-reachable code reads {name}"),
                format!(
                    "Client-reachable code ({where_}) reads the server-only variable {name}. The bundler does \
                     not inline it, so the value is not exposed by this line, but a Supabase admin \
                     client is being built where the browser runs it. Renaming the variable to a \
                     public prefix would leak the key; move this code to a server route instead."
                ),
                format!("{access}{name}"),
                None,
                vec![
                    "web".to_string(),
                    "supabase".to_string(),
                    ctx.framework.kind.label().to_string(),
                    "env-reference".to_string(),
                    format!("reach:{}", ctx.reach.label()),
                ],
            ));
        }
    }
}

/// Публичные переменные `.env*` со значением-ключом Supabase service-role/secret.
pub fn env_file(
    path: &str,
    text: &str,
    framework: &FrameworkInfo,
    findings: &mut Vec<WebFinding>,
    ignored: &mut usize,
) {
    let prefixes = public_prefixes(framework);
    for (index, line) in text.lines().enumerate() {
        let Some((key, value, value_start)) = parse_env_line(line) else {
            continue;
        };
        if !prefixes.iter().any(|p| key.starts_with(p)) {
            continue;
        }
        let Some(kind) = classify_value(value) else {
            continue;
        };
        if line.contains(secrets::scan::INLINE_IGNORE) {
            *ignored += 1;
            continue;
        }
        findings.push(finding(
            path,
            index + 1,
            line[..value_start].chars().count() + 1,
            Severity::Critical,
            Confidence::Potential,
            format!("{} in public environment variable {key}", kind.name()),
            format!(
                "{key} has a public prefix, so the framework inlines its value into the client \
                 bundle wherever it is read. {BYPASS}"
            ),
            format!("{key}={}", secrets::mask(value.trim())),
            Some(secrets::fingerprint(value.trim())),
            vec![
                "web".to_string(),
                "supabase".to_string(),
                framework.kind.label().to_string(),
                "env-file".to_string(),
            ],
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_audit::testutil::{base64url, body, supabase_jwt};

    #[test]
    fn base64_round_trip_and_rejects_garbage() {
        for data in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"{\"role\":\"anon\"}",
            &[0xff, 0xfe, 0xfd],
        ] {
            assert_eq!(base64_decode(&base64url(data)).as_deref(), Some(data));
        }
        assert_eq!(base64_decode("Zg==").as_deref(), Some(&b"f"[..]));
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("ab$c").is_none());
    }

    #[test]
    fn service_role_jwt_is_found_anon_is_not() {
        let service = supabase_jwt("service_role");
        let line = format!("createClient(url, \"{service}\")");
        let keys = find_keys(&line);
        assert_eq!(keys.len(), 1);
        assert_eq!(&line[keys[0].0.start..keys[0].0.end], service);
        assert_eq!(
            keys[0].1,
            SupabaseKey::ServiceRoleJwt {
                supabase_issuer: true
            }
        );
        assert!(find_keys(&format!("k = '{}'", supabase_jwt("anon"))).is_empty());
        assert!(find_keys(&format!("k = '{}'", supabase_jwt("authenticated"))).is_empty());
    }

    #[test]
    fn broken_or_non_jwt_tokens_are_ignored() {
        let service = supabase_jwt("service_role");
        let (head, _) = service.rsplit_once('.').unwrap();
        assert!(find_keys(&format!("{head}.")).is_empty(), "empty signature");
        assert!(
            find_keys(&format!("x{service}")).is_empty(),
            "no left boundary"
        );
        assert!(find_keys("eyJhbGciOi.not-json.sig").is_empty());
        assert!(
            find_keys(&format!(
                "{}.{}.sig",
                base64url(b"{}"),
                base64url(b"{\"role\":\"service_role\"}")
            ))
            .is_empty(),
            "header must start with eyJ and have alg"
        );
    }

    #[test]
    fn new_format_secret_key_but_not_publishable() {
        let secret = format!("{}{}", "sb_secret_", body(31));
        assert_eq!(classify_value(&secret), Some(SupabaseKey::SecretKey));
        assert_eq!(
            classify_value(&format!("{}{}", "sb_publishable_", body(31))),
            None
        );
        assert_eq!(
            classify_value(&format!("{}{}", "sb_secret_", "x".repeat(24))),
            None
        );
        assert_eq!(classify_value("sb_secret_short"), None);
    }
}
