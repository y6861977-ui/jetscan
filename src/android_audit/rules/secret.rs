//! ANDROID-SECRET-006 (ключи в файлах проекта), ANDROID-KEYSTORE-009 (хранилища ключей в дереве) и
//! пароли подписи в `*.properties` (ANDROID-SIGNING-008).
//!
//! Форматы ключей — матчеры ядра (`secrets::rules::scan_line` с префильтром, `special::scan` для
//! спецфайлов вроде `.env`); здесь не дублируются. Своё — только «куда попадёт файл»:
//! - код и ресурсы набора, который собирается в APK (`src/<set>/{java,kotlin,res,assets,resources}`,
//!   `AndroidManifest.xml`), и `buildConfigField`/`resValue`/`manifestPlaceholders` в Gradle — ключ уйдёт
//!   в APK каждому → critical (только debug-набор → high);
//! - прочие файлы репозитория (Gradle, properties, скрипты) → high; тесты → medium/needs_review;
//! - файл в `.gitignore` (простое сопоставление, без `!`) → low/needs_review: локальный секрет;
//! - Google API key (`AIza…`) публичен по замыслу (Firebase/Maps) → info; в `google-services.json` — не
//!   находка вовсе (только счётчик в limitations). Закрытый ключ сервисного аккаунта (`"private_key"`) —
//!   находка как есть.
//!
//! Сырые значения не выводятся никогда: в отчёте маска ядра и отпечаток.

use super::{
    KEYSTORE_ID, MAX_HITS_PER_FILE, New, REF_MASVS, RuleOutput, SECRET_ID, SIGNING_ID, words,
};
use crate::android_audit::gradle::{GradleFile, Stmt};
use crate::android_audit::project::{self, Project};
use crate::android_audit::rules::manifest::{SetRole, set_role};
use crate::android_audit::types::{Confidence, Severity};
use crate::android_audit::walk::{Entry, FileKind};
use crate::secrets::{self, rules};
use crate::ui;
use std::path::Path;

/// Куда попадает файл.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Собирается в APK; `true` — только debug-сборка.
    Shipped(bool),
    Test,
    Repo,
}

const SHIPPED_DIRS: &[&str] = &["java", "kotlin", "res", "assets", "resources", "aidl"];

/// Набор исходников файла (`src/<set>/…`) и куда он идёт.
pub fn reach_of(path: &str) -> Reach {
    let segs: Vec<&str> = path.split('/').collect();
    // Каталог (в т. ч. модуль) с тестовыми утилитами: `mail/testing`, `core/test-utils`, `benchmarks`.
    let test_dir = |s: &&str| {
        let l = s.to_ascii_lowercase();
        matches!(
            l.as_str(),
            "test"
                | "tests"
                | "androidtest"
                | "testfixtures"
                | "fixtures"
                | "testdata"
                | "testing"
                | "testutils"
                | "test-utils"
                | "testutil"
                | "test-util"
                | "testlib"
                | "test-lib"
                | "testshared"
                | "test-shared"
                | "benchmark"
                | "benchmarks"
        )
    };
    for i in 0..segs.len() {
        if segs[i] != "src" || i + 2 >= segs.len() {
            continue;
        }
        let set = segs[i + 1];
        let next = segs[i + 2];
        if SHIPPED_DIRS.contains(&next) || (next == "AndroidManifest.xml" && i + 3 == segs.len()) {
            if segs[..i].iter().any(test_dir) {
                return Reach::Test;
            }
            return match set_role(set) {
                SetRole::Test => Reach::Test,
                SetRole::Debug => Reach::Shipped(true),
                _ => Reach::Shipped(false),
            };
        }
    }
    if segs.iter().take(segs.len().saturating_sub(1)).any(test_dir) {
        Reach::Test
    } else {
        Reach::Repo
    }
}

/// Простое сопоставление `.gitignore`: шаблоны с `*`/`?`, якорь `/`, каталоги `name/`. Если в файле
/// есть отрицания (`!`), ничего не считаем игнорируемым (не берёмся решать).
#[derive(Clone, Debug, Default)]
pub struct GitIgnore {
    /// (каталог файла `.gitignore`, шаблоны).
    files: Vec<(String, Vec<Pattern>)>,
}

#[derive(Clone, Debug)]
struct Pattern {
    glob: String,
    anchored: bool,
}

impl GitIgnore {
    pub fn from_project(project: &Project) -> GitIgnore {
        GitIgnore::from_files(project.entries_of(FileKind::GitIgnore).filter_map(|e| {
            project
                .texts
                .get(&e.relative_path)
                .map(|text| (e.relative_path.as_str(), text.as_str()))
        }))
    }

    /// Из пар (путь `.gitignore` от корня, текст) — для других сканеров исходников (iOS).
    pub fn from_files<'a>(gitignores: impl Iterator<Item = (&'a str, &'a str)>) -> GitIgnore {
        let mut files = Vec::new();
        for (path, text) in gitignores {
            if text.lines().any(|l| l.trim_start().starts_with('!')) {
                continue;
            }
            let dir = path
                .rsplit_once('/')
                .map_or(String::new(), |(d, _)| d.to_string());
            let patterns = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| {
                    let l = l.trim_end_matches('/');
                    let l = l.strip_prefix("**/").unwrap_or(l);
                    let anchored = l.starts_with('/') || l.trim_start_matches('/').contains('/');
                    Pattern {
                        glob: l.trim_start_matches('/').to_string(),
                        anchored,
                    }
                })
                .filter(|p| !p.glob.is_empty())
                .collect();
            files.push((dir, patterns));
        }
        GitIgnore { files }
    }

    pub fn ignored(&self, path: &str) -> bool {
        for (dir, patterns) in &self.files {
            let rel = if dir.is_empty() {
                path
            } else {
                match path
                    .strip_prefix(dir.as_str())
                    .and_then(|r| r.strip_prefix('/'))
                {
                    Some(r) => r,
                    None => continue,
                }
            };
            let segs: Vec<&str> = rel.split('/').collect();
            for p in patterns {
                let hit = if p.anchored {
                    // Совпадение с путём или его каталогом-префиксом.
                    (1..=segs.len()).any(|n| glob(&p.glob, &segs[..n].join("/")))
                } else {
                    segs.iter().any(|s| glob(&p.glob, s))
                };
                if hit {
                    return true;
                }
            }
        }
        false
    }
}

/// `*` — любые символы кроме `/`, `?` — один символ. Без рекурсии (жадный перебор с откатом).
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' && t[ti] != '/' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if let Some((sp, st)) = star
            && t[st] != '/'
        {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretStats {
    pub files_scanned: usize,
    /// Публичные по замыслу ключи Firebase в `google-services.json` (не находки).
    pub firebase_config_keys: usize,
    pub ignored_inline: usize,
    /// Файлы, где срабатываний больше лимита.
    pub capped: Vec<String>,
}

/// Байтовое смещение символа `col` (с 1) в строке.
fn byte_of_col(line: &str, col: usize) -> Option<usize> {
    line.char_indices().nth(col.checked_sub(1)?).map(|(i, _)| i)
}

/// Строка для фрагмента: найденные значения заменены масками, прочие строковые литералы — `…`.
pub fn redact_line(line: &str, spans: &[(usize, usize, String)]) -> String {
    let mut out = String::new();
    let mut i = 0usize;
    let bytes = line.as_bytes();
    while i < line.len() {
        if let Some((_, end, mask)) = spans.iter().find(|(s, _, _)| *s == i) {
            out.push_str(mask);
            i = *end;
            continue;
        }
        let c = bytes[i];
        if c == b'"' || c == b'\'' {
            // Литерал: если внутри есть найденное значение — маска, иначе `…`.
            let close = line[i + 1..]
                .char_indices()
                .find(|&(k, ch)| {
                    ch as u32 == u32::from(c) && !line[i + 1..i + 1 + k].ends_with('\\')
                })
                .map(|(k, _)| i + 1 + k);
            let end = close.unwrap_or(line.len());
            out.push(c as char);
            let inner: Vec<&(usize, usize, String)> = spans
                .iter()
                .filter(|(s, _, _)| *s > i && *s < end)
                .collect();
            if inner.is_empty() {
                out.push('…');
            } else {
                for (_, _, mask) in inner {
                    out.push_str(mask);
                }
            }
            if close.is_some() {
                out.push(c as char);
            }
            i = (end + 1).min(line.len());
            continue;
        }
        let ch = line[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Gradle-оператор, значение которого компилируется в APK.
fn shipping_stmt(file: &GradleFile, byte: usize) -> Option<&Stmt> {
    file.stmts.iter().find(|s| {
        s.start <= byte
            && byte < s.end
            && (matches!(s.target.as_str(), "buildConfigField" | "resValue")
                || s.target.starts_with("manifestPlaceholders")
                || s.target == "addManifestPlaceholders")
    })
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
        Reach::Shipped(false) => (Severity::Critical, Confidence::Potential),
        Reach::Shipped(true) => (Severity::High, Confidence::Potential),
        Reach::Test => (Severity::Medium, Confidence::NeedsReview),
        Reach::Repo => (Severity::High, Confidence::Potential),
    }
}

/// Ключи в одном файле. `comments` — байтовые диапазоны комментариев (для Kotlin/Java): ключ в
/// комментарии в APK не попадает, но остаётся в репозитории.
#[allow(clippy::too_many_arguments)]
pub fn check_file(
    project: &Project,
    ignore: &GitIgnore,
    entry: &Entry,
    text: &str,
    comments: &[(usize, usize)],
    out: &mut RuleOutput,
    stats: &mut SecretStats,
) {
    stats.files_scanned += 1;
    let path = entry.relative_path.as_str();
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let firebase_config = name == "google-services.json";
    let service_account = entry.kind == FileKind::Json
        && text.contains("\"service_account\"")
        && text.contains("\"private_key\"");
    let ignored = ignore.ignored(path);
    let file_reach = reach_of(path);
    let gradle = project.gradle.get(path);
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
    // Спецфайлы ядра (`.env`, `.npmrc`, …) — их собственные правила.
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
    for h in &hits {
        let fingerprint = secrets::fingerprint(&h.hit.secret);
        if !seen.insert((h.line, fingerprint.clone())) {
            continue;
        }
        let public = h.hit.rule.id == "google-api";
        if public && firebase_config {
            stats.firebase_config_keys += 1;
            continue;
        }
        let in_comment = comments.iter().any(|&(s, e)| h.byte >= s && h.byte < e);
        // В комментариях — документация (`smtp://user:password@host`): только форматы высокой
        // уверенности ядра (ключи провайдеров); «пароль в URL» — нет (полевой тест, Thunderbird).
        if in_comment && h.hit.rule.confidence != secrets::Confidence::High {
            continue;
        }
        let stmt = gradle.and_then(|g| shipping_stmt(g, h.byte));
        let reach = match (stmt, file_reach) {
            (Some(s), _) => Reach::Shipped(
                s.child_of("buildTypes")
                    .is_some_and(|b| b.to_ascii_lowercase().contains("debug")),
            ),
            (None, Reach::Shipped(_)) if in_comment => Reach::Repo,
            (None, r) => r,
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
        let account = service_account && h.hit.rule.id == "private-key";
        let name = if account {
            "Google service account private key".to_string()
        } else {
            h.hit.rule.name.to_string()
        };
        let where_ = match (reach, stmt) {
            (Reach::Shipped(_), Some(s)) => format!(
                "a Gradle {} that is compiled into the APK, so anyone who downloads the app can read it",
                s.target
            ),
            (Reach::Shipped(debug), None) => format!(
                "app {} that is packaged into the{} APK, so anyone who has the APK can read it",
                if entry.kind == FileKind::Kotlin || entry.kind == FileKind::Java {
                    "code"
                } else {
                    "resources"
                },
                if debug { " debug" } else { "" }
            ),
            (Reach::Test, _) => "test code or test data (often fake, but a real key here is still \
                                 readable by anyone with the repository)"
                .to_string(),
            (Reach::Repo, _) if in_comment => {
                "a comment (not compiled into the APK, but readable by anyone with the repository)"
                    .to_string()
            }
            (Reach::Repo, _) => {
                "a project file, readable by anyone with the repository".to_string()
            }
        };
        let mut explanation = if public {
            severity = Severity::Info;
            confidence = Confidence::NeedsReview;
            format!(
                "A Google API key (AIza…) is in {where_}. Firebase and Maps keys are meant to ship in \
                 apps and are not secret by themselves; make sure the key is restricted to this app \
                 (package name + signing certificate) and to the APIs it needs."
            )
        } else {
            format!(
                "A value in the format of a {name} is in {where_}. Potential: the format matches, but \
                 whether the key is real and active is not checked. If it is real: revoke it, then \
                 move the call that needs it to your server (or out of the repository)."
            )
        };
        if ignored {
            explanation.push_str(if matches!(reach, Reach::Shipped(_)) {
                " The file is listed in .gitignore, so it is probably not committed, but it is still \
                 packaged into any APK built from this checkout."
            } else {
                " The file is listed in .gitignore, so it is probably a local-only file that is not \
                 committed."
            });
        }
        let (title_where, remediation) = match reach {
            Reach::Shipped(_) => ("in app sources", "revoke-and-move-to-server"),
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
                    format!("{name} {title_where}")
                },
                severity,
                confidence,
                path,
                line: u32::try_from(h.line).ok(),
                column: u32::try_from(h.col).ok(),
                component: stmt.map(|s| s.target.clone()),
                excerpt: Some(excerpt),
                fingerprint: Some(fingerprint),
                key: String::new(),
                explanation,
                remediation: if public { "restrict-key" } else { remediation },
                references: vec!["https://cwe.mitre.org/data/definitions/798.html", REF_MASVS],
                cwe_ids: vec!["CWE-798"],
                tags: vec![
                    format!("key:{}", h.hit.rule.id),
                    format!(
                        "reach:{}",
                        match reach {
                            Reach::Shipped(false) => "apk",
                            Reach::Shipped(true) => "debug-apk",
                            Reach::Test => "test",
                            Reach::Repo => "repository",
                        }
                    ),
                    "masvs:MASVS-STORAGE".into(),
                ],
            }
            .build(),
        );
    }
    if entry.kind == FileKind::Properties {
        properties_secrets(path, text, ignored, &hits, out, stats);
    }
}

/// Ключ `*.properties` про пароль подписи: (store|keystore|key|signing|release|upload) + password.
fn signing_key(key: &str) -> bool {
    let w = words(key);
    let password = w
        .iter()
        .any(|x| matches!(x.as_str(), "password" | "passwd" | "pwd" | "pass"));
    let signing = w.iter().any(|x| {
        matches!(
            x.as_str(),
            "store"
                | "keystore"
                | "key"
                | "signing"
                | "release"
                | "upload"
                | "storepassword"
                | "keypassword"
        )
    }) || w.iter().any(|x| x == "storepassword" || x == "keypassword");
    (password && signing) || w.iter().any(|x| x == "storepassword" || x == "keypassword")
}

/// Ключ похож на секрет: одно из слов — password/secret/token/…, или `api key`/`private key`.
fn secret_key(key: &str) -> bool {
    let w = words(key);
    if w.iter()
        .any(|x| matches!(x.as_str(), "public" | "publishable" | "pub"))
    {
        return false;
    }
    w.iter().enumerate().any(|(i, x)| match x.as_str() {
        "password" | "passwd" | "pwd" | "secret" | "token" | "apikey" | "credentials"
        | "privatekey" | "storepassword" | "keypassword" => true,
        "key" => {
            i > 0
                && matches!(
                    w[i - 1].as_str(),
                    "api" | "private" | "secret" | "access" | "maps"
                )
        }
        _ => false,
    })
}

fn not_secret_value(value: &str) -> bool {
    let v = value.trim();
    let lower = v.to_ascii_lowercase();
    v.len() < 4
        || rules::is_placeholder(v)
        || matches!(
            lower.as_str(),
            "true" | "false" | "null" | "none" | "android"
        )
        || v.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        || v.starts_with("${")
        || v.starts_with('$')
        || [
            "your", "replace", "change", "insert", "enter", "example", "todo", "xxx", "<",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
}

fn properties_secrets(
    path: &str,
    text: &str,
    ignored: bool,
    provider_hits: &[Hit],
    out: &mut RuleOutput,
    stats: &mut SecretStats,
) {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let committed_by_design = name == "gradle.properties";
    let lines: Vec<&str> = text.split('\n').collect();
    for p in project::properties(text) {
        if p.value.is_empty() || not_secret_value(&p.value) {
            continue;
        }
        let signing = signing_key(&p.key);
        if !signing && !secret_key(&p.key) {
            continue;
        }
        if provider_hits.iter().any(|h| h.line == p.line as usize) {
            continue;
        }
        if lines
            .get(p.line as usize - 1)
            .is_some_and(|l| l.contains(secrets::scan::INLINE_IGNORE))
        {
            stats.ignored_inline += 1;
            continue;
        }
        let masked = secrets::mask(&p.value);
        let fingerprint = secrets::fingerprint(&p.value);
        let (severity, confidence, note) = if ignored {
            (
                Severity::Low,
                Confidence::NeedsReview,
                " The file is listed in .gitignore, so it is probably local-only.",
            )
        } else if signing && committed_by_design {
            (
                Severity::High,
                Confidence::Potential,
                " gradle.properties in the project is normally committed.",
            )
        } else {
            (
                Severity::Medium,
                Confidence::NeedsReview,
                " Files like local.properties / keystore.properties are meant to stay out of version \
                 control; make sure this one is not committed.",
            )
        };
        let key = ui::sanitize_line(&p.key);
        let (rule, title, explanation, remediation, tags) = if signing {
            (
                SIGNING_ID,
                format!("Signing password in {name}"),
                format!(
                    "{key} holds a literal password that looks like a keystore/key password.{note} \
                     With the keystore it lets anyone sign APKs as you. Potential: whether it is real \
                     is not checked."
                ),
                "move-signing-secrets",
                vec!["source:properties".to_string(), format!("field:{key}")],
            )
        } else {
            (
                SECRET_ID,
                format!("Secret-like value in {name}"),
                format!(
                    "{key} has a literal value and its name says it is a secret.{note} The value's \
                     format is not a known provider key, so this needs a human look."
                ),
                "revoke-and-remove",
                vec![
                    "source:properties".to_string(),
                    "key:named-secret".to_string(),
                ],
            )
        };
        out.findings.push(
            New {
                rule,
                category: "secret_exposure",
                title,
                severity,
                confidence: if signing { confidence } else { Confidence::NeedsReview },
                path,
                line: Some(p.line),
                column: Some(p.value_column),
                component: None,
                excerpt: Some(format!("{key}={masked}")),
                fingerprint: Some(fingerprint),
                key: String::new(),
                explanation,
                remediation,
                references: vec![
                    "https://developer.android.com/studio/publish/app-signing#secure-shared-keystore",
                    "https://cwe.mitre.org/data/definitions/798.html",
                ],
                cwe_ids: vec!["CWE-798"],
                tags,
            }
            .build(),
        );
    }
}

/// ANDROID-KEYSTORE-009: хранилища ключей в дереве проекта (содержимое не читается).
pub fn keystores(project: &Project, ignore: &GitIgnore, with_passwords: &[String]) -> RuleOutput {
    let mut out = RuleOutput::default();
    for e in project.entries_of(FileKind::Keystore) {
        let path = e.relative_path.as_str();
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        let ignored = ignore.ignored(path);
        let reach = reach_of(path);
        let paired = with_passwords.iter().any(|p| p == path);
        let debug = name.contains("debug");
        let (severity, confidence, why) = if paired {
            (
                Severity::High,
                Confidence::Potential,
                "A Gradle signingConfig points to this file and has its passwords as literals, so the \
                 repository holds everything needed to sign APKs as you."
                    .to_string(),
            )
        } else if ignored {
            (
                Severity::Low,
                Confidence::NeedsReview,
                "It is listed in .gitignore, so it is probably a local copy that is not committed."
                    .to_string(),
            )
        } else if debug || reach == Reach::Test {
            (
                Severity::Low,
                Confidence::NeedsReview,
                "The name/location suggests a debug or test keystore; a committed debug keystore lets \
                 others build debug APKs signed like yours, which matters only if such builds reach \
                 users."
                    .to_string(),
            )
        } else {
            (
                Severity::Medium,
                Confidence::Potential,
                "If this is the release or upload keystore, anyone who also learns its password can sign \
                 APKs as you. Its contents were not opened, so whether it holds a release key is not \
                 known."
                    .to_string(),
            )
        };
        out.findings.push(
            New {
                rule: KEYSTORE_ID,
                category: "secret_exposure",
                title: "Keystore file in the project tree".to_string(),
                severity,
                confidence,
                path,
                line: None,
                column: None,
                component: None,
                excerpt: Some(format!("{} ({} bytes, not opened)", ui::sanitize_line(&name), e.len)),
                fingerprint: None,
                key: path.to_string(),
                explanation: format!(
                    "{} is a key store ({}). {why} Keep signing keys out of the repository (Play App \
                     Signing, a CI secret store) and rotate the upload key if it was pushed.",
                    ui::sanitize_line(path),
                    name.rsplit('.').next().unwrap_or("")
                ),
                remediation: "remove-keystore",
                references: vec![
                    "https://developer.android.com/studio/publish/app-signing#secure_key",
                    "https://cwe.mitre.org/data/definitions/321.html",
                ],
                cwe_ids: vec!["CWE-321"],
                tags: vec![format!("paired_with_password:{paired}")],
            }
            .build(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reach_by_source_set() {
        assert_eq!(reach_of("app/src/main/java/A.kt"), Reach::Shipped(false));
        // Модуль с тестовыми утилитами (полевой тест, Thunderbird `mail/testing`).
        assert_eq!(reach_of("mail/testing/src/main/java/T.kt"), Reach::Test);
        assert_eq!(
            reach_of("core/test-utils/src/main/kotlin/T.kt"),
            Reach::Test
        );
        assert_eq!(reach_of("feature/src/commonTest/kotlin/T.kt"), Reach::Test);
        assert_eq!(
            reach_of("feature/src/commonMain/kotlin/T.kt"),
            Reach::Shipped(false)
        );
        assert_eq!(
            reach_of("app/src/main/res/values/s.xml"),
            Reach::Shipped(false)
        );
        assert_eq!(
            reach_of("app/src/main/AndroidManifest.xml"),
            Reach::Shipped(false)
        );
        assert_eq!(reach_of("app/src/debug/kotlin/A.kt"), Reach::Shipped(true));
        assert_eq!(reach_of("app/src/test/java/A.kt"), Reach::Test);
        assert_eq!(reach_of("app/src/androidTest/java/A.kt"), Reach::Test);
        assert_eq!(reach_of("app/build.gradle"), Reach::Repo);
        assert_eq!(reach_of("testdata/keys.json"), Reach::Test);
        assert_eq!(reach_of("gradle.properties"), Reach::Repo);
    }

    #[test]
    fn globs() {
        assert!(glob("*.jks", "release.jks"));
        assert!(glob("local.properties", "local.properties"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("*.jks", "a/b.jks"));
        assert!(glob("*", "anything"));
        assert!(!glob("*.jks", "release.keystore"));
        assert!(glob("app/*.json", "app/google-services.json"));
    }

    #[test]
    fn redaction_masks_hits_and_hides_other_literals() {
        let line = r#"login("admin", "hunter2", "SECRETVALUE1")"#;
        let start = line.find("SECRETVALUE1").unwrap();
        let spans = vec![(start, start + 12, "SECR****UE1".to_string())];
        assert_eq!(
            redact_line(line, &spans),
            r#"login("…", "…", "SECR****UE1")"#
        );
        let line = "MAPS_KEY=VALUEVALUE";
        let spans = vec![(9, 19, "VALU**LUE".to_string())];
        assert_eq!(redact_line(line, &spans), "MAPS_KEY=VALU**LUE");
    }

    #[test]
    fn property_key_classification() {
        for k in [
            "RELEASE_STORE_PASSWORD",
            "storePassword",
            "signing.keyPassword",
            "KEYSTORE_PASS",
        ] {
            assert!(signing_key(k), "{k}");
        }
        for k in [
            "systemProp.http.proxyPassword",
            "org.gradle.jvmargs",
            "MAPS_API_KEY",
        ] {
            assert!(!signing_key(k), "{k}");
        }
        for k in [
            "MAPS_API_KEY",
            "github.token",
            "systemProp.http.proxyPassword",
            "clientSecret",
        ] {
            assert!(secret_key(k), "{k}");
        }
        for k in [
            "org.gradle.jvmargs",
            "android.useAndroidX",
            "keyAlias",
            "PUBLIC_API_KEY",
        ] {
            assert!(!secret_key(k), "{k}");
        }
    }
}
