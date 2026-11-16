//! Тестовые помощники: временный проект и материализация фикстур.
//!
//! В файлах `fixtures/web/**` нет ни одной строки, похожей на ключ: вместо значений там
//! метки `@@NAME@@`, а настоящие по форме (но заведомо фальшивые) значения собираются здесь
//! в рантайме. Поэтому `jetscan scan .` по самому репозиторию ничего не находит в фикстурах —
//! ни в файлах, ни в git-истории. Файл с именем `dot-xxx` копируется как `.xxx`
//! (`dot-env.local` → `.env.local`), чтобы и ядро не принимало фикстуру за настоящий `.env`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

pub struct TempProject(PathBuf);

impl TempProject {
    pub fn new() -> TempProject {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "jetscan-web-{}-{nanos}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp project");
        TempProject(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, relative: &str, content: &str) {
        self.write_bytes(relative, content.as_bytes());
    }

    pub fn write_bytes(&self, relative: &str, content: &[u8]) {
        let path = self.0.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, content).expect("write file");
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Тело фальшивого ключа нужной длины: только `[A-Za-z0-9]`, явно читается как «не ключ».
pub fn body(len: usize) -> String {
    "JetscanFixture0NotARealKey0"
        .chars()
        .cycle()
        .take(len)
        .collect()
}

pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// JWT в форме ключа Supabase: `header.payload.signature`. Подпись — фальшивая.
pub fn supabase_jwt(role: &str) -> String {
    let header = base64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = base64url(
        format!(r#"{{"iss":"supabase","ref":"jetscanfixture","role":"{role}","iat":1700000000,"exp":2000000000}}"#)
            .as_bytes(),
    );
    format!("{header}.{payload}.{}", body(43))
}

pub fn stripe_secret() -> String {
    format!("{}{}", "sk_live_", body(28))
}

pub fn github_token() -> String {
    format!("{}{}", "ghp_", body(36))
}

/// Явная заглушка вида `sk_live_xxxx…`: не находка. Собирается в рантайме, иначе
/// GitHub push protection принимает её за настоящий ключ Stripe.
pub fn stripe_placeholder() -> String {
    format!("{}{}{}", "sk_", "live_", "x".repeat(24))
}

/// Строка-заголовок PEM без тела (так её держат утилиты разбора PEM).
pub fn pem_header() -> String {
    format!("{}{}", "-----BEGIN ", "PRIVATE KEY-----")
}

/// Заведомо фальшивый ключ PEM: заголовок, два ряда «base64» из тела фикстуры, конец.
pub fn pem_key() -> String {
    format!(
        "{}\n{}\n{}\n{}{}",
        pem_header(),
        body(64),
        body(40),
        "-----END ",
        "PRIVATE KEY-----"
    )
}

/// Значение для метки фикстуры. Неизвестная метка — ошибка фикстуры, а не тихая пустота.
fn placeholder(name: &str) -> String {
    match name {
        "STRIPE_SECRET" => stripe_secret(),
        "STRIPE_PUBLISHABLE" => format!("{}{}", "pk_live_", body(28)),
        "STRIPE_PLACEHOLDER" => stripe_placeholder(),
        "GITHUB_TOKEN" => github_token(),
        "FIREBASE_API_KEY" => format!("{}{}", "AIza", body(35)),
        "SUPABASE_SERVICE_JWT" => supabase_jwt("service_role"),
        "SUPABASE_ANON_JWT" => supabase_jwt("anon"),
        "SB_SECRET" => format!("{}{}", "sb_secret_", body(31)),
        "SB_PUBLISHABLE" => format!("{}{}", "sb_publishable_", body(31)),
        "DB_PASSWORD" => body(24),
        "PEM_HEADER" => pem_header(),
        "PEM_KEY" => pem_key(),
        other => panic!("unknown fixture placeholder @@{other}@@"),
    }
}

fn expand(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("@@") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("@@") {
            Some(end)
                if end > 0
                    && after[..end]
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') =>
            {
                out.push_str(&placeholder(&after[..end]));
                rest = &after[end + 2..];
            }
            _ => {
                out.push_str("@@");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Копирует `fixtures/web/<name>` во временный каталог, подставляя значения меток.
pub fn fixture(name: &str) -> TempProject {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("web")
        .join(name);
    assert!(source.is_dir(), "missing fixture {}", source.display());
    let project = TempProject::new();
    copy_tree(&source, &source, &project);
    project
}

fn copy_tree(base: &Path, dir: &Path, project: &TempProject) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read fixture dir")
        .map(|e| e.expect("fixture entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            copy_tree(base, &path, project);
            continue;
        }
        let relative = path.strip_prefix(base).expect("inside fixture");
        let mut parts: Vec<String> = relative
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if let Some(last) = parts.last_mut()
            && let Some(stripped) = last.strip_prefix("dot-")
        {
            *last = format!(".{stripped}");
        }
        let text = fs::read_to_string(&path).expect("fixture is UTF-8");
        project.write(&parts.join("/"), &expand(&text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_known_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn expand_replaces_known_labels_and_keeps_other_text() {
        let text = expand("a @@GITHUB_TOKEN@@ b @@ c @@lower@@");
        assert!(text.starts_with(&format!("a {} b", github_token())));
        assert!(text.ends_with("b @@ c @@lower@@"));
    }

    #[test]
    fn fake_values_are_detected_by_core_rules() {
        // Если ядро перестанет узнавать фальшивые ключи, фикстуры станут бесполезны — ловим это здесь.
        for value in [stripe_secret(), github_token()] {
            let hits = crate::secrets::scan_text(crate::secrets::rules::all(), &value);
            assert_eq!(hits.len(), 1, "core must match the synthetic value");
        }
    }
}
