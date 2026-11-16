//! Фикстуры iOS Source Audit: `fixtures/ios/<имя>` копируется во временный каталог.
//!
//! В файлах фикстур нет ни одной строки, похожей на ключ: вместо значений там метки `@@NAME@@`,
//! которые раскрывает `android_audit::testutil::expand` (фальшивые, но правильные по форме значения
//! собираются в рантайме). Поэтому `jetscan secrets fixtures/ios` ничего не находит, и GitHub push
//! protection не блокирует коммит. Переименования при копировании: `dot-xxx` → `.xxx`;
//! `*.p12.txt`, `*.p8.txt`, `*.mobileprovision.txt`, `*.cer.txt` → без `.txt` (файлы подписи фикстур —
//! просто текст: правило смотрит на имя и первые байты).

pub use crate::android_audit::testutil::expand;
use crate::web_audit::testutil::TempProject;
use std::fs;
use std::path::Path;

/// Копирует `fixtures/ios/<name>` во временный каталог, подставляя значения меток.
pub fn fixture(name: &str) -> TempProject {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("ios")
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
            for ext in [".p12.txt", ".p8.txt", ".mobileprovision.txt", ".cer.txt"] {
                if last.ends_with(ext)
                    && let Some(stripped) = last.strip_suffix(".txt")
                {
                    *last = stripped.to_string();
                }
            }
        }
        let text = fs::read_to_string(&path).expect("fixture is UTF-8");
        project.write(&parts.join("/"), &expand(&text));
    }
}
