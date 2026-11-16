//! IOS-SECRET-004 (ключи в файлах проекта) и IOS-SIGNING-005 (материалы подписи в дереве).
//!
//! Форматы ключей — матчеры ядра (`secrets::rules::scan_line` с префильтром, `special::scan` для
//! спецфайлов вроде `.env`); здесь не дублируются. Своё — «куда попадёт файл» и iOS-специфика:
//! - код Swift/Objective-C и plist'ы приложения попадают в бандл .ipa → critical (в ветке `#if DEBUG` —
//!   high); прочие файлы репозитория (xcconfig, fastlane, скрипты, JSON) → high; тесты → medium/needs_review;
//!   файл в `.gitignore` → low/needs_review;
//! - Google API key (`AIza…`) публичен по замыслу (Firebase/Maps) → info; в `GoogleService-Info.plist` — не
//!   находка вовсе (счётчик в limitations). Прочие ключи в этом файле — как есть;
//! - ключи plist / xcconfig с «секретным» именем и литеральным значением (`APISecret`, `CLIENT_SECRET = …`)
//!   — medium/needs_review (формат не известен ядру);
//! - файлы подписи определяются по имени и первым байтам заголовка, содержимое не читается и не выводится:
//!   `*.p12`/`*.pfx` (закрытый ключ) и `*.p8` / `AuthKey_*.p8` (ключ App Store Connect / APNs) → high;
//!   зашифрованные fastlane match (`Salted__`) → low; `*.cer` — только если внутри PEM-заголовок закрытого
//!   ключа; `*.mobileprovision` → low (закрытого ключа в нём нет).
//!
//! Сырые значения не выводятся никогда: в отчёте маска ядра и отпечаток.

use super::{MAX_HITS_PER_FILE, New, REF_MASVS, RuleOutput, SECRET_ID, SIGNING_ID, words};
use crate::android_audit::rules::secret::{GitIgnore, redact_line};
use crate::ios_audit::lex::Lexed;
use crate::ios_audit::plist::{self, Node};
use crate::ios_audit::project::{self, is_test_path, is_tooling_path};
use crate::ios_audit::types::{Confidence, Severity};
use crate::ios_audit::walk::{Entry, FileKind};
use crate::secrets::{self, rules};
use crate::ui;
use std::path::Path;

/// Куда попадает файл.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Собирается в приложение; `true` — только в debug-сборке (`#if DEBUG`).
    App(bool),
    Test,
    Repo,
}

pub fn reach_of(path: &str, kind: FileKind) -> Reach {
    if is_test_path(path) {
        Reach::Test
    } else if is_tooling_path(path) {
        Reach::Repo
    } else {
        match kind {
            FileKind::Swift | FileKind::ObjC | FileKind::Plist | FileKind::Entitlements => {
                Reach::App(false)
            }
            _ => Reach::Repo,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretStats {
    pub files_scanned: usize,
    /// Публичные по замыслу ключи Firebase в `GoogleService-Info.plist` (не находки).
    pub firebase_config_keys: usize,
    pub ignored_inline: usize,
    pub capped: Vec<String>,
}

fn byte_of_col(line: &str, col: usize) -> Option<usize> {
    line.char_indices().nth(col.checked_sub(1)?).map(|(i, _)| i)
}

struct Hit {
    line: usize,
    col: usize,
    byte: usize,
    hit: secrets::Hit,
}

fn severity_for(reach: Reach, ignored: bool) -> (Severity, Confidence) {
    if ignored {
        return (Severity::Low, Confidence::NeedsReview);
    }
    match reach {
        Reach::App(false) => (Severity::Critical, Confidence::Potential),
        Reach::App(true) => (Severity::High, Confidence::Potential),
        Reach::Test => (Severity::Medium, Confidence::NeedsReview),
        Reach::Repo => (Severity::High, Confidence::Potential),
    }
}

fn reach_tag(reach: Reach) -> &'static str {
    match reach {
        Reach::App(false) => "reach:app",
        Reach::App(true) => "reach:debug-app",
        Reach::Test => "reach:test",
        Reach::Repo => "reach:repository",
    }
}

/// Ключи в одном файле. `code` — разметка Swift/ObjC (комментарии и ветки `#if DEBUG`).
/// Возвращает номера строк с находками ядра (чтобы правило имён ключей их не дублировало).
pub fn check_file(
    ignore: &GitIgnore,
    entry: &Entry,
    text: &str,
    code: Option<&Lexed>,
    out: &mut RuleOutput,
    stats: &mut SecretStats,
) -> Vec<usize> {
    stats.files_scanned += 1;
    let path = entry.relative_path.as_str();
    let name = entry.name().to_ascii_lowercase();
    let firebase_config = name == "googleservice-info.plist";
    let ignored = ignore.ignored(path);
    let file_reach = reach_of(path, entry.kind);
    let mut hits: Vec<Hit> = Vec::new();
    let mut total = 0usize;
    let mut offset = 0usize;
    let mut capped = false;
    for (i, raw) in text.split('\n').enumerate() {
        let line_start = offset;
        offset += raw.len() + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        for hit in rules::scan_line(i + 1, line) {
            total += 1;
            if total > MAX_HITS_PER_FILE {
                capped = true;
                break;
            }
            if rules::is_placeholder(&hit.secret) {
                continue;
            }
            let Some(col_byte) = byte_of_col(line, hit.col) else {
                continue;
            };
            let byte = line_start + col_byte;
            if hit.rule.id == "private-key"
                && !crate::web_audit::rules::secret::has_pem_body(&text[byte..])
            {
                continue;
            }
            if line.contains(secrets::scan::INLINE_IGNORE) {
                stats.ignored_inline += 1;
                continue;
            }
            hits.push(Hit {
                line: i + 1,
                col: hit.col,
                byte,
                hit,
            });
        }
        if capped {
            break;
        }
    }
    if crate::secrets::special::is_special(Path::new(path)) {
        let lines: Vec<&str> = text.split('\n').collect();
        for hit in crate::secrets::special::scan(Path::new(path), text) {
            let Some(line) = lines.get(hit.line.saturating_sub(1)) else {
                continue;
            };
            if line.contains(secrets::scan::INLINE_IGNORE) {
                stats.ignored_inline += 1;
                continue;
            }
            let line_start: usize = lines[..hit.line - 1].iter().map(|l| l.len() + 1).sum();
            let Some(col_byte) = byte_of_col(line, hit.col) else {
                continue;
            };
            if hits
                .iter()
                .any(|h| h.line == hit.line && h.hit.secret == hit.secret)
            {
                continue;
            }
            hits.push(Hit {
                line: hit.line,
                col: hit.col,
                byte: line_start + col_byte,
                hit,
            });
        }
    }
    if capped {
        stats.capped.push(path.to_string());
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut seen = std::collections::HashSet::new();
    let mut lines_with_hits = Vec::new();
    for h in &hits {
        lines_with_hits.push(h.line);
        let fingerprint = secrets::fingerprint(&h.hit.secret);
        if !seen.insert((h.line, fingerprint.clone())) {
            continue;
        }
        let public = h.hit.rule.id == "google-api";
        if public && firebase_config {
            stats.firebase_config_keys += 1;
            continue;
        }
        let in_comment =
            code.is_some_and(|l| l.comments.iter().any(|&(s, e)| h.byte >= s && h.byte < e));
        // В комментариях — документация, в тестах — фальшивые данные (`https://user:pass@host`):
        // только форматы высокой уверенности ядра (полевой тест, Signal и Firefox).
        if (in_comment || file_reach == Reach::Test)
            && h.hit.rule.confidence != secrets::Confidence::High
        {
            continue;
        }
        let debug = code.is_some_and(|l| {
            l.tokens
                .iter()
                .any(|t| t.debug && t.start <= h.byte && h.byte < t.end)
        });
        let reach = match file_reach {
            Reach::App(_) if in_comment => Reach::Repo,
            Reach::App(_) => Reach::App(debug),
            r => r,
        };
        let line = lines
            .get(h.line - 1)
            .map_or("", |l| l.strip_suffix('\r').unwrap_or(l));
        let spans: Vec<(usize, usize, String)> = hits
            .iter()
            .filter(|o| o.line == h.line)
            .filter_map(|o| {
                let s = byte_of_col(line, o.col)?;
                Some((s, s + o.hit.secret.len(), secrets::mask(&o.hit.secret)))
            })
            .collect();
        let excerpt = redact_line(line, &spans);
        let (mut severity, mut confidence) = severity_for(reach, ignored);
        let key_name = h.hit.rule.name.to_string();
        let where_ = match reach {
            Reach::App(debug) => format!(
                "app {} that is built into the{} app bundle, so anyone who has the .ipa can extract it",
                match entry.kind {
                    FileKind::Swift | FileKind::ObjC => "code",
                    _ => "resources",
                },
                if debug { " debug build of the" } else { "" }
            ),
            Reach::Test => {
                "test code or test data (often fake, but a real key here is still readable by \
                            anyone with the repository)"
                    .to_string()
            }
            Reach::Repo if in_comment => {
                "a comment (not compiled into the app, but readable by anyone with the repository)"
                    .to_string()
            }
            Reach::Repo => "a project file, readable by anyone with the repository".to_string(),
        };
        let mut explanation = if public {
            severity = Severity::Info;
            confidence = Confidence::NeedsReview;
            format!(
                "A Google API key (AIza…) is in {where_}. Firebase and Maps keys are meant to ship in apps and \
                 are not secret by themselves; make sure the key is restricted to this app (bundle ID) and to \
                 the APIs it needs."
            )
        } else {
            format!(
                "A value in the format of a {key_name} is in {where_}. Potential: the format matches, but whether \
                 the key is real and active is not checked. If it is real: revoke it, then move the call that \
                 needs it to your server (or out of the repository)."
            )
        };
        if ignored {
            explanation.push_str(
                " The file is listed in .gitignore, so it is probably a local-only file that is not committed.",
            );
        }
        let (title_where, remediation) = match reach {
            Reach::App(_) => ("in app sources", "revoke-and-move-to-server"),
            Reach::Test => ("in test sources", "revoke-and-remove"),
            Reach::Repo => ("in a project file", "revoke-and-remove"),
        };
        out.findings.push(
            New {
                rule: SECRET_ID,
                category: "secret_exposure",
                title: if public {
                    format!("Google API key {title_where}")
                } else {
                    format!("{key_name} {title_where}")
                },
                severity,
                confidence,
                path,
                line: u32::try_from(h.line).ok(),
                column: u32::try_from(h.col).ok(),
                component: None,
                excerpt: Some(excerpt),
                fingerprint: Some(fingerprint),
                key: String::new(),
                explanation,
                remediation: if public { "restrict-key" } else { remediation },
                references: vec!["https://cwe.mitre.org/data/definitions/798.html", REF_MASVS],
                cwe_ids: vec!["CWE-798"],
                tags: vec![
                    format!("key:{}", h.hit.rule.id),
                    reach_tag(reach).to_string(),
                    "masvs:MASVS-STORAGE".into(),
                ],
            }
            .build(),
        );
    }
    lines_with_hits
}

/// Имя ключа говорит, что значение — секрет: password/secret/token/apikey/…, `api key`, `client secret`.
pub fn secret_key(key: &str) -> bool {
    let w = words(key);
    if w.iter().any(|x| {
        matches!(
            x.as_str(),
            "public"
                | "publishable"
                | "pub"
                | "url"
                | "uri"
                | "endpoint"
                | "host"
                | "id"
                | "name"
                | "type"
                | "path"
                | "file"
                | "label"
                | "header"
                | "length"
                | "expiry"
                | "expiration"
        )
    }) {
        return false;
    }
    let Some(last) = w.last() else { return false };
    let prev = w.len().checked_sub(2).map(|i| w[i].as_str());
    match last.as_str() {
        "password" | "passwd" | "pwd" | "secret" | "token" | "apikey" | "privatekey"
        | "credentials" => true,
        "key" => matches!(
            prev,
            Some("api" | "private" | "secret" | "access" | "client" | "signing")
        ),
        _ => false,
    }
}

/// Значение явно не секрет: короткое, переменная сборки, заглушка, булево/число, URL без учётных данных.
pub fn not_secret_value(value: &str) -> bool {
    let v = value.trim().trim_matches('"');
    let lower = v.to_ascii_lowercase();
    v.chars().count() < 8
        || rules::is_placeholder(v)
        || v.contains("$(")
        || v.contains("${")
        || v.starts_with('$')
        || v.contains(' ')
        || matches!(
            lower.as_str(),
            "true" | "false" | "yes" | "no" | "null" | "nil" | "none"
        )
        || v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || ((lower.starts_with("http://") || lower.starts_with("https://")) && !v.contains('@'))
        || [
            "your", "replace", "change", "insert", "enter", "example", "todo", "xxx", "<", "fixme",
            "dummy", "test",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
}

/// Ключи plist (Info.plist и прочие `*.plist` приложения) с «секретным» именем и литеральным значением.
pub fn plist_named(
    entry: &Entry,
    root: &Node,
    ignore: &GitIgnore,
    lines_with_hits: &[usize],
    lines: &[&str],
    out: &mut RuleOutput,
    stats: &mut SecretStats,
) {
    let path = entry.relative_path.as_str();
    if entry
        .name()
        .eq_ignore_ascii_case("GoogleService-Info.plist")
    {
        return;
    }
    let reach = reach_of(path, entry.kind);
    let ignored = ignore.ignored(path);
    for (key_path, key, node) in plist::string_leaves(root) {
        let Some(value) = node.as_str() else { continue };
        let last = key_path.rsplit('.').next().unwrap_or(&key_path);
        if !secret_key(last) || not_secret_value(value) {
            continue;
        }
        if lines_with_hits.contains(&(node.line as usize))
            || lines_with_hits.contains(&(key.line as usize))
        {
            continue;
        }
        if lines
            .get(key.line as usize - 1)
            .is_some_and(|l| l.contains(secrets::scan::INLINE_IGNORE))
        {
            stats.ignored_inline += 1;
            continue;
        }
        named_finding(
            path,
            &key_path,
            value,
            node.line,
            node.column,
            reach,
            ignored,
            "plist",
            out,
        );
    }
}

/// `KEY = value` в `*.xcconfig` с «секретным» именем и литеральным значением.
pub fn xcconfig_named(
    entry: &Entry,
    text: &str,
    ignore: &GitIgnore,
    lines_with_hits: &[usize],
    out: &mut RuleOutput,
    stats: &mut SecretStats,
) {
    let path = entry.relative_path.as_str();
    let ignored = ignore.ignored(path);
    let lines: Vec<&str> = text.split('\n').collect();
    for (key, value, line, column) in project::xcconfig_assignments(text) {
        if !secret_key(&key)
            || not_secret_value(&value)
            || lines_with_hits.contains(&(line as usize))
        {
            continue;
        }
        if lines
            .get(line as usize - 1)
            .is_some_and(|l| l.contains(secrets::scan::INLINE_IGNORE))
        {
            stats.ignored_inline += 1;
            continue;
        }
        named_finding(
            path,
            &key,
            &value,
            line,
            column,
            Reach::Repo,
            ignored,
            "xcconfig",
            out,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn named_finding(
    path: &str,
    key: &str,
    value: &str,
    line: u32,
    column: u32,
    reach: Reach,
    ignored: bool,
    source: &str,
    out: &mut RuleOutput,
) {
    let key = ui::sanitize_line(key);
    let masked = secrets::mask(value);
    let (severity, note) = if ignored {
        (
            Severity::Low,
            " The file is listed in .gitignore, so it is probably local-only.",
        )
    } else {
        match reach {
            Reach::App(_) => (
                Severity::Medium,
                " The property list is copied into the app bundle, where anyone with the .ipa can read it.",
            ),
            Reach::Test => (Severity::Low, " The file is test data."),
            Reach::Repo if source == "xcconfig" => (
                Severity::Medium,
                " Build settings are committed with the project and are often copied into Info.plist \
                 ($(KEY)), which ships in the app bundle.",
            ),
            Reach::Repo => (Severity::Medium, " The file is part of the repository."),
        }
    };
    out.findings.push(
        New {
            rule: SECRET_ID,
            category: "secret_exposure",
            title: format!("Secret-like value for {key}"),
            severity,
            confidence: Confidence::NeedsReview,
            path,
            line: Some(line),
            column: Some(column),
            component: Some(key.clone()),
            excerpt: Some(format!("{key} = {masked}")),
            fingerprint: Some(secrets::fingerprint(value)),
            key: String::new(),
            explanation: format!(
                "{key} has a literal value and its name says it is a secret.{note} The value's format is not a \
                 known provider key, so this needs a human look: if it is a real secret, revoke it and keep it \
                 on a server (or inject it at build time from CI secrets, knowing that anything in the app is \
                 still extractable)."
            ),
            remediation: "revoke-and-remove",
            references: vec!["https://cwe.mitre.org/data/definitions/798.html", REF_MASVS],
            cwe_ids: vec!["CWE-798"],
            tags: vec![
                format!("source:{source}"),
                "key:named-secret".to_string(),
                reach_tag(reach).to_string(),
                "masvs:MASVS-STORAGE".into(),
            ],
        }
        .build(),
    );
}

/// IOS-SIGNING-005: один файл подписи. `header` — первые байты (тип, не содержимое).
pub fn signing(entry: &Entry, header: Option<&[u8]>, ignore: &GitIgnore, out: &mut RuleOutput) {
    let path = entry.relative_path.as_str();
    let name = entry.name().to_string();
    let lower = name.to_ascii_lowercase();
    let ignored = ignore.ignored(path);
    let test = is_test_path(path);
    let header = header.unwrap_or(&[]);
    let salted = header.starts_with(b"Salted__");
    let head_text = String::from_utf8_lossy(header);
    let pem_private = head_text.contains("PRIVATE KEY");
    let (title, mut severity, mut confidence, what) = match entry.kind {
        FileKind::Pkcs12 => (
            "PKCS#12 signing identity in the project tree",
            Severity::High,
            Confidence::Potential,
            "a PKCS#12 bundle (.p12/.pfx), which normally holds a certificate together with its private \
             key; a distribution or push certificate's key lets anyone sign builds or send pushes as you once \
             its export password is known (often weak or committed nearby)",
        ),
        FileKind::P8 => (
            if lower.starts_with("authkey_") {
                "App Store Connect / APNs private key (AuthKey_*.p8) in the project tree"
            } else {
                "Private key file (.p8) in the project tree"
            },
            Severity::High,
            Confidence::Potential,
            "an unencrypted private key (App Store Connect API, APNs or Sign in with Apple); whoever has \
             it can call those APIs as your team until the key is revoked",
        ),
        FileKind::Cert if pem_private => (
            "Certificate file containing a private key",
            Severity::High,
            Confidence::Potential,
            "a certificate file that starts with a PEM private-key header, so it is not just a (public) \
             certificate",
        ),
        FileKind::Cert => return,
        FileKind::Provision => (
            "Provisioning profile in the project tree",
            Severity::Low,
            Confidence::NeedsReview,
            "a provisioning profile: it holds no private key, but it lists the team, App ID, entitlements \
             and (for development/ad hoc) device identifiers; with the matching .p12 it is everything needed \
             to sign builds",
        ),
        FileKind::Keychain => (
            "Keychain file in the project tree",
            Severity::Medium,
            Confidence::NeedsReview,
            "a keychain file, which can hold signing identities and passwords behind its own password",
        ),
        _ => return,
    };
    let mut note = String::new();
    if salted {
        severity = Severity::Low;
        confidence = Confidence::NeedsReview;
        note.push_str(
            " Its header shows it is encrypted (OpenSSL \"Salted__\", as fastlane match stores certificates), \
             so it is only as safe as the match passphrase.",
        );
    } else if ignored {
        severity = Severity::Low;
        confidence = Confidence::NeedsReview;
        note.push_str(
            " It is listed in .gitignore, so it is probably a local copy that is not committed.",
        );
    } else if test && severity < Severity::Low {
        severity = Severity::Low;
        confidence = Confidence::NeedsReview;
        note.push_str(
            " It is in a test folder, so it may be a test identity (for TLS or pinning tests).",
        );
    }
    out.findings.push(
        New {
            rule: SIGNING_ID,
            category: "secret_exposure",
            title: title.to_string(),
            severity,
            confidence,
            path,
            line: None,
            column: None,
            component: None,
            excerpt: Some(format!(
                "{} ({} bytes, contents not shown)",
                ui::sanitize_line(&name),
                entry.len
            )),
            fingerprint: None,
            key: path.to_string(),
            explanation: format!(
                "{} is {what}.{note} Only its name and first bytes were read. Keep signing material out of the \
                 repository (Xcode-managed signing, a CI secret store, fastlane match with a strong passphrase) \
                 and revoke/rotate it if it was ever pushed.",
                ui::sanitize_line(path)
            ),
            remediation: "remove-signing-material",
            references: vec![
                "https://developer.apple.com/help/account/manage-keys/revoke-edit-and-download-keys/",
                "https://cwe.mitre.org/data/definitions/321.html",
                REF_MASVS,
            ],
            cwe_ids: vec!["CWE-321"],
            tags: vec![
                format!("encrypted:{salted}"),
                "masvs:MASVS-CODE".to_string(),
            ],
        }
        .build(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reach_by_path_and_kind() {
        assert_eq!(reach_of("App/A.swift", FileKind::Swift), Reach::App(false));
        assert_eq!(reach_of("AppTests/A.swift", FileKind::Swift), Reach::Test);
        assert_eq!(
            reach_of("fastlane/Fastfile", FileKind::OtherText),
            Reach::Repo
        );
        assert_eq!(
            reach_of("App/Info.plist", FileKind::Plist),
            Reach::App(false)
        );
        assert_eq!(
            reach_of("Config/Release.xcconfig", FileKind::XcConfig),
            Reach::Repo
        );
        assert_eq!(reach_of("Package.swift", FileKind::Swift), Reach::Repo);
    }

    #[test]
    fn key_names_and_values() {
        for yes in [
            "APISecret",
            "CLIENT_SECRET",
            "authToken",
            "API_KEY",
            "MixpanelApiKey",
            "dbPassword",
        ] {
            assert!(secret_key(yes), "{yes}");
        }
        for no in [
            "TokenURL",
            "CFBundleIdentifier",
            "PUBLIC_API_KEY",
            "tokenType",
            "NSFaceIDUsageDescription",
            "SecretName",
            "passwordLength",
            "keychainGroup",
        ] {
            assert!(!secret_key(no), "{no}");
        }
        for no in [
            "$(API_KEY)",
            "short",
            "https://api.example.com",
            "YOUR_API_KEY_HERE",
            "true",
            "some words here",
        ] {
            assert!(not_secret_value(no), "{no}");
        }
        assert!(!not_secret_value("a8f3k2m9x7q1"));
    }

    fn signing_one(path: &str, kind: FileKind, header: &[u8]) -> Vec<(Severity, String)> {
        let mut out = RuleOutput::default();
        let e = Entry {
            relative_path: path.into(),
            kind,
            len: 10,
        };
        signing(&e, Some(header), &GitIgnore::default(), &mut out);
        out.findings
            .into_iter()
            .map(|f| (f.severity, f.title))
            .collect()
    }

    #[test]
    fn signing_material_by_name_and_header() {
        assert_eq!(
            signing_one("certs/dist.p12", FileKind::Pkcs12, b"0\x82")[0].0,
            Severity::High
        );
        assert_eq!(
            signing_one("match/certs/x.p12", FileKind::Pkcs12, b"Salted__abc")[0].0,
            Severity::Low
        );
        let p8 = signing_one(
            "AuthKey_ABC123.p8",
            FileKind::P8,
            crate::web_audit::testutil::pem_header().as_bytes(),
        );
        assert!(p8[0].1.starts_with("App Store Connect"));
        assert!(signing_one("App/pin.cer", FileKind::Cert, b"0\x82\x05").is_empty());
        assert_eq!(
            signing_one(
                "App/both.crt",
                FileKind::Cert,
                format!("{}{}", "-----BEGIN RSA ", "PRIVATE KEY-----").as_bytes()
            )[0]
            .0,
            Severity::High
        );
        assert_eq!(
            signing_one("App.mobileprovision", FileKind::Provision, b"0\x80")[0].0,
            Severity::Low
        );
        // Тестовые .p12 (для тестов TLS) — low.
        assert_eq!(
            signing_one("AppTests/client.p12", FileKind::Pkcs12, b"0\x82")[0].0,
            Severity::Low
        );
    }
}
