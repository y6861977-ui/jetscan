//! Фикстуры Android Source Audit: `fixtures/android/<имя>` копируется во временный каталог.
//!
//! В файлах фикстур нет ни одной строки, похожей на ключ: вместо значений там метки `@@NAME@@`,
//! а фальшивые (но правильные по форме) значения собираются здесь в рантайме — как в
//! `web_audit::testutil`. Поэтому `jetscan secrets fixtures/android` ничего не находит, и GitHub push
//! protection не блокирует коммит. Файл `dot-xxx` копируется как `.xxx` (`dot-gitignore`).
//! Файл `*.jks.txt` копируется как `*.jks` (хранилище ключей фикстуры — просто текст: оно никогда не
//! открывается, правило смотрит на имя).

use crate::web_audit::testutil::{TempProject, body, github_token, pem_key, stripe_secret};
use std::fs;
use std::path::Path;

fn placeholder(name: &str) -> String {
    match name {
        "STRIPE_SECRET" => stripe_secret(),
        "GITHUB_TOKEN" => github_token(),
        "GOOGLE_API_KEY" => format!("{}{}", "AIza", body(35)),
        "SLACK_TOKEN" => format!(
            "{}{}",
            "xoxb-",
            "1234567890-1234567890-".to_string() + &body(24)
        ),
        "PEM_KEY" => pem_key(),
        // Закрытый ключ в JSON сервисного аккаунта: переводы строк экранированы.
        "PEM_KEY_JSON" => pem_key().replace('\n', "\\n"),
        "PASSWORD" => format!("Fx{}", body(14)),
        "PASSWORD2" => format!("Qz{}", body(12)),
        other => panic!("unknown fixture placeholder @@{other}@@"),
    }
}

pub fn expand(text: &str) -> String {
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

/// Копирует `fixtures/android/<name>` во временный каталог, подставляя значения меток.
pub fn fixture(name: &str) -> TempProject {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("android")
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
        if let Some(last) = parts.last_mut() {
            if let Some(stripped) = last.strip_prefix("dot-") {
                *last = format!(".{stripped}");
            }
            for ext in [".jks.txt", ".keystore.txt"] {
                if let Some(stripped) = last.strip_suffix(".txt")
                    && last.ends_with(ext)
                {
                    *last = stripped.to_string();
                }
            }
        }
        let text = fs::read_to_string(&path).expect("fixture is UTF-8");
        project.write(&parts.join("/"), &expand(&text));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_values_are_detected_by_core_rules() {
        for label in [
            "STRIPE_SECRET",
            "GITHUB_TOKEN",
            "GOOGLE_API_KEY",
            "SLACK_TOKEN",
        ] {
            let value = placeholder(label);
            let hits = crate::secrets::rules::scan_line(1, &value);
            assert_eq!(hits.len(), 1, "{label}");
            assert!(
                !crate::secrets::rules::is_placeholder(&hits[0].secret),
                "{label}"
            );
        }
    }

    #[test]
    fn expand_keeps_unknown_text() {
        assert_eq!(expand("a @@ b @@lower@@"), "a @@ b @@lower@@");
        assert!(expand("k=@@PASSWORD@@").starts_with("k=Fx"));
    }
}
