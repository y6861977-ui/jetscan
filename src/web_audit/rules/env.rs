//! WEB-ENV-002: секрет в переменной окружения, которую фреймворк вшивает в клиентский бандл.
//!
//! Next.js при сборке подставляет значения `NEXT_PUBLIC_*` в JavaScript для браузера;
//! Vite отдаёт `VITE_*` через `import.meta.env` в клиентском коде. Ядро (`jetscan secrets`)
//! такие ключи сознательно пропускает: слово `PUBLIC` в имени для него — признак публичного
//! значения. Здесь мы проверяем именно этот случай.
//!
//! Уровни:
//! - значение в `.env*` совпало с привилегированным форматом ядра → `critical`/`potential`
//!   (формат — факт; что сборка действительно вшила переменную — не доказано);
//! - значение есть, имя «секретное» (`SECRET`, `PASSWORD`, `PRIVATE`, ...) → `high`/`needs_review`;
//! - ссылка `process.env.NEXT_PUBLIC_*SECRET*` / `import.meta.env.VITE_*SECRET*` в клиентском
//!   или общем коде, а в `.env*` такой переменной нет → `high`/`needs_review`.
//!
//! Шаблоны `.env.example`/`.sample`/`.template` не читаются (их отсекает обход).
//! Свой префикс Vite (`envPrefix`) и `env` в `next.config` не разбираются — ограничение.

use super::FileContext;
use crate::secrets::{self, rules};
use crate::web_audit::framework::{FrameworkInfo, FrameworkKind};
use crate::web_audit::lexer;
use crate::web_audit::provenance::Reach;
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};
use std::collections::{HashMap, HashSet};

pub const RULE_ID: &str = "WEB-ENV-002";

pub const REFERENCES: &[&str] = &[
    "https://vite.dev/guide/env-and-mode",
    "https://cwe.mitre.org/data/definitions/200.html",
];

/// Публичные префиксы для фреймворка. Неизвестный фреймворк — оба.
pub fn public_prefixes(framework: &FrameworkInfo) -> &'static [&'static str] {
    match framework.kind {
        FrameworkKind::NextJs => &["NEXT_PUBLIC_"],
        FrameworkKind::ViteReact => &["VITE_"],
        FrameworkKind::Generic | FrameworkKind::Unsupported => &["NEXT_PUBLIC_", "VITE_"],
    }
}

/// Имя (без префикса) говорит, что значение секретное. Слова-маркеры публичности
/// (`PUBLISHABLE`, `ANON`, `SITE`, ...) отменяют вывод: `RECAPTCHA_SITE_KEY` — публичный.
pub fn secret_like_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let words: Vec<&str> = upper.split('_').filter(|w| !w.is_empty()).collect();
    if words.iter().any(|w| {
        matches!(
            *w,
            "PUBLISHABLE" | "PUBLIC" | "ANON" | "SITE" | "PUB" | "CLIENTID" | "DSN"
        )
    }) {
        return false;
    }
    let service_role = words.windows(2).any(|p| p == ["SERVICE", "ROLE"]);
    service_role
        || words.iter().any(|w| {
            matches!(
                *w,
                "SECRET" | "SECRETS" | "PASSWORD" | "PASSWD" | "PWD" | "PRIVATE" | "SERVICEROLE"
            ) || w.ends_with("SECRET")
                || w.ends_with("PASSWORD")
                || w.starts_with("PRIVATEKEY")
        })
}

/// Значение — не секрет: пусто, заглушка, флаг или число.
fn not_a_value(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    lower.is_empty()
        || rules::is_placeholder(value)
        || [
            "your", "replace", "change", "insert", "enter", "example", "todo", "fixme", "<", "...",
            "xxx",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
        || matches!(
            lower.as_str(),
            "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "none" | "undefined"
        )
        || lower.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// Строка `.env`: `KEY=value`, `export KEY="value"`, `KEY='v' # comment`.
/// Возвращает имя, значение и байтовое смещение значения в строке.
pub(super) fn parse_env_line(line: &str) -> Option<(&str, &str, usize)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let offset = line.len() - trimmed.len();
    let (body, offset) = match trimmed.strip_prefix("export ") {
        Some(rest) => (
            rest.trim_start(),
            offset + (trimmed.len() - rest.trim_start().len()),
        ),
        None => (trimmed, offset),
    };
    let eq = body.find('=')?;
    let key = body[..eq].trim_end();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let raw = &body[eq + 1..];
    let lead = raw.len() - raw.trim_start().len();
    let raw_trimmed = raw.trim_start();
    let value_start = offset + eq + 1 + lead;
    let (value, value_start) = match raw_trimmed.as_bytes().first() {
        Some(&q @ (b'"' | b'\'')) => {
            let inner = &raw_trimmed[1..];
            let end = inner.find(char::from(q)).unwrap_or(inner.len());
            (&inner[..end], value_start + 1)
        }
        _ => {
            let end = raw_trimmed.find(" #").unwrap_or(raw_trimmed.len());
            (raw_trimmed[..end].trim_end(), value_start)
        }
    };
    Some((key, value, value_start))
}

/// Кандидат из `.env*`: сырое значение уже превращено в маску и отпечаток.
struct Candidate {
    path: String,
    line: usize,
    col: usize,
    key: String,
    masked: String,
    fingerprint: String,
    /// Имя правила ядра, если значение совпало с привилегированным форматом.
    format: Option<&'static str>,
}

struct Reference {
    path: String,
    line: u32,
    col: u32,
    name: String,
    reach: Reach,
}

/// Собирает кандидатов и ссылки по ходу обхода; находки — в `finish`, когда всё видно.
#[derive(Default)]
pub struct EnvCollector {
    candidates: Vec<Candidate>,
    references: Vec<Reference>,
    /// Переменные, чьё значение разобрало другое правило: ссылки на них здесь не дублируем.
    claimed: Vec<String>,
    pub ignored_inline: usize,
}

impl EnvCollector {
    /// Файл `.env*`. `skip_value` — значение, которое разбирает другое правило (Supabase).
    pub fn env_file(
        &mut self,
        path: &str,
        text: &str,
        framework: &FrameworkInfo,
        skip_value: &dyn Fn(&str) -> bool,
    ) {
        let prefixes = public_prefixes(framework);
        for (index, line) in text.lines().enumerate() {
            let Some((key, value, value_start)) = parse_env_line(line) else {
                continue;
            };
            let Some(name) = prefixes.iter().find_map(|p| key.strip_prefix(p)) else {
                continue;
            };
            if not_a_value(value) {
                continue;
            }
            if skip_value(value) {
                self.claimed.push(key.to_string());
                continue;
            }
            let format = secrets::scan_line(rules::all(), 1, value)
                .into_iter()
                .find(|hit| hit.rule.id != "google-api")
                .map(|hit| hit.rule.name);
            if format.is_none() && !secret_like_name(name) {
                continue;
            }
            if line.contains(secrets::scan::INLINE_IGNORE) {
                self.ignored_inline += 1;
                continue;
            }
            self.candidates.push(Candidate {
                path: path.to_string(),
                line: index + 1,
                col: line[..value_start].chars().count() + 1,
                key: key.to_string(),
                masked: secrets::mask(value),
                fingerprint: secrets::fingerprint(value),
                format,
            });
        }
    }

    /// Ссылки на публичные переменные в исходнике.
    pub fn source_file(&mut self, ctx: &FileContext) {
        if ctx.kind != crate::web_audit::enumerate::FileKind::Script {
            return;
        }
        let prefixes = public_prefixes(ctx.framework);
        for access in ["process.env.", "import.meta.env."] {
            for start in lexer::code_occurrences(ctx.text, &ctx.lexed, access) {
                let name_start = start + access.len();
                let name: String = ctx.text[name_start..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !prefixes
                    .iter()
                    .any(|p| name.starts_with(p) && name.len() > p.len())
                {
                    continue;
                }
                let Some((line, col)) = ctx.index.line_col(ctx.text, start) else {
                    continue;
                };
                self.references.push(Reference {
                    path: ctx.path.to_string(),
                    line,
                    col,
                    name,
                    reach: ctx.reach,
                });
            }
        }
    }

    pub fn finish(self, framework: &FrameworkInfo) -> Vec<WebFinding> {
        let mut findings = Vec::new();
        let how = match framework.kind {
            FrameworkKind::NextJs => {
                "Next.js inlines NEXT_PUBLIC_ variables into the JavaScript sent to the browser at build time"
            }
            FrameworkKind::ViteReact => {
                "Vite exposes VITE_ variables to client code through import.meta.env and inlines them into the bundle"
            }
            _ => {
                "NEXT_PUBLIC_ (Next.js) and VITE_ (Vite) variables are inlined into the client bundle at build time"
            }
        };
        // Индексы по имени: без них сопоставление «переменная ↔ чтения» квадратично.
        let mut client_reads: HashMap<&str, Vec<&Reference>> = HashMap::new();
        for r in &self.references {
            if !matches!(r.reach, Reach::Server(_) | Reach::Test) {
                client_reads.entry(r.name.as_str()).or_default().push(r);
            }
        }
        let known: HashSet<&str> = self
            .candidates
            .iter()
            .map(|c| c.key.as_str())
            .chain(self.claimed.iter().map(String::as_str))
            .collect();
        for c in &self.candidates {
            let client_refs: &[&Reference] =
                client_reads.get(c.key.as_str()).map_or(&[], Vec::as_slice);
            let used = match client_refs.first() {
                Some(r) => format!(
                    "It is read in {} scanned client/shared file(s), e.g. {}:{}.",
                    client_refs.len(),
                    crate::ui::sanitize_line(&r.path),
                    r.line
                ),
                None => {
                    "No read of it was found in the scanned source, but any code that reads it \
                         (including dependencies) gets the value inlined."
                        .to_string()
                }
            };
            let (title, severity, confidence, what) = match c.format {
                Some(format) => (
                    format!("{format} in public environment variable {}", c.key),
                    Severity::Critical,
                    Confidence::Potential,
                    format!("The value has the format of a {format}."),
                ),
                None => (
                    format!("Secret-looking public environment variable {}", c.key),
                    Severity::High,
                    Confidence::NeedsReview,
                    "The name says it is a secret; the value format is not one jetscan recognises."
                        .to_string(),
                ),
            };
            findings.push(WebFinding {
                id: finding_id(RULE_ID, &c.path, &format!("{}\0{}", c.key, c.fingerprint)),
                rule_id: RULE_ID,
                title,
                category: "secret_exposure",
                severity,
                confidence,
                location: SourceLocation {
                    relative_path: c.path.clone(),
                    line: u32::try_from(c.line).ok(),
                    column: u32::try_from(c.col).ok(),
                },
                evidence: Evidence {
                    redacted_excerpt: Some(format!(
                        "{}={}",
                        c.key,
                        crate::ui::sanitize_line(&c.masked)
                    )),
                    fingerprint: Some(c.fingerprint.clone()),
                },
                explanation: format!("{how}. {what} {used}"),
                remediation_id: Some(format!("{RULE_ID}:rename-and-move-to-server")),
                references: REFERENCES.to_vec(),
                cwe_ids: if c.format.is_some() {
                    vec!["CWE-200", "CWE-798"]
                } else {
                    vec!["CWE-200"]
                },
                tags: vec![
                    "web".to_string(),
                    framework.kind.label().to_string(),
                    "env-file".to_string(),
                    format!("referenced:{}", !client_refs.is_empty()),
                ],
            });
        }
        for r in &self.references {
            if matches!(r.reach, Reach::Server(_) | Reach::Test) || known.contains(r.name.as_str())
            {
                continue;
            }
            let prefix = public_prefixes(framework)
                .iter()
                .find(|p| r.name.starts_with(*p))
                .copied()
                .unwrap_or("");
            if !secret_like_name(&r.name[prefix.len()..]) {
                continue;
            }
            findings.push(WebFinding {
                id: finding_id(RULE_ID, &r.path, &r.name),
                rule_id: RULE_ID,
                title: format!(
                    "Client code reads secret-looking public variable {}",
                    r.name
                ),
                category: "secret_exposure",
                severity: Severity::High,
                confidence: Confidence::NeedsReview,
                location: SourceLocation {
                    relative_path: r.path.clone(),
                    line: Some(r.line),
                    column: Some(r.col),
                },
                evidence: Evidence {
                    redacted_excerpt: Some(r.name.clone()),
                    fingerprint: None,
                },
                explanation: format!(
                    "{how}. The variable name says it is a secret, and this {} file reads it, so \
                     whatever value the build environment holds ends up in the bundle. Its value \
                     was not found in the scanned .env files.",
                    r.reach.label()
                ),
                remediation_id: Some(format!("{RULE_ID}:rename-and-move-to-server")),
                references: REFERENCES.to_vec(),
                cwe_ids: vec!["CWE-200"],
                tags: vec![
                    "web".to_string(),
                    framework.kind.label().to_string(),
                    "env-reference".to_string(),
                    format!("reach:{}", r.reach.label()),
                ],
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_lines() {
        assert_eq!(parse_env_line("A=1"), Some(("A", "1", 2)));
        assert_eq!(
            parse_env_line("export B = \"x y\" # c"),
            Some(("B", "x y", 12))
        );
        assert_eq!(parse_env_line("C='q' "), Some(("C", "q", 3)));
        assert_eq!(parse_env_line("D=v # note"), Some(("D", "v", 2)));
        assert_eq!(parse_env_line("  # comment"), None);
        assert_eq!(parse_env_line("not an assignment"), None);
        assert_eq!(parse_env_line("BAD-KEY=1"), None);
        assert_eq!(parse_env_line("E="), Some(("E", "", 2)));
    }

    #[test]
    fn secret_like_names() {
        for name in [
            "ADMIN_PASSWORD",
            "WEBHOOK_SECRET",
            "CLIENT_SECRET",
            "SUPABASE_SERVICE_ROLE_KEY",
            "PRIVATE_KEY",
            "JWTSECRET",
        ] {
            assert!(secret_like_name(name), "{name}");
        }
        for name in [
            "STRIPE_PUBLISHABLE_KEY",
            "SUPABASE_ANON_KEY",
            "RECAPTCHA_SITE_KEY",
            "FIREBASE_API_KEY",
            "POSTHOG_KEY",
            "API_URL",
            "SENTRY_DSN",
            "PASSWORDLESS_ENABLED",
        ] {
            assert!(!secret_like_name(name), "{name}");
        }
    }

    #[test]
    fn placeholders_and_flags_are_not_values() {
        for v in [
            "",
            "your_secret_here",
            "<secret>",
            "changeme",
            "true",
            "3600",
            "xxx",
            "${X}",
        ] {
            assert!(not_a_value(v), "{v}");
        }
        assert!(!not_a_value("Zq8Lk2Pn"));
    }
}
