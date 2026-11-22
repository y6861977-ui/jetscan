//! Проверка GitHub Actions (T7.1): известные опасные конструкции в
//! `.github/workflows/*.yml` и `action.yml` — инъекция в `run:`, «pwn request»,
//! действия без закреплённого SHA и т.п. Факты по файлу, а не стиль.
//!
//! Контракт — не ослаблять:
//! - Только чтение, только локально, без сети и без запуска внешних программ.
//! - Только конструкции, опасность которых задокументирована (GitHub Security Lab,
//!   GitHub Docs «Security hardening for GitHub Actions»). Не разобрали YAML или
//!   не уверены — нет находки: ложная тревога в CI = jetscan выключат.
//! - Файлы workflow — недоверенный ввод (чужой репозиторий): в `message`/`fix`
//!   попадают только наши фиксированные строки, имя контекста из нашего списка и
//!   имя действия (`owner/repo@ref`, обрезанное до 100 символов). Вывод всё равно
//!   санитизирует отчёт.
//! - Детерминированно: сортировка по (path, line, id).
//! - Пути — относительно корня проекта, с `/`: `.github/workflows/ci.yml`.

pub mod checks;

use std::path::Path;

/// Та же форма, что у гигиены машины: один формат вывода для text/JSON/SARIF.
pub use crate::hygiene::{Issue, Level};

/// Все проверки над проектом `root`: `root/.github/workflows/*.yml|*.yaml`
/// (не рекурсивно) и `root/action.yml|action.yaml`. Нет папки или файл не
/// читается — нечего проверять, не ошибка.
pub fn check(root: &Path) -> Vec<Issue> {
    let mut issues = checks::run(root);
    issues.sort_by(|a, b| (&a.path, a.line, a.id).cmp(&(&b.path, b.line, b.id)));
    issues
}

#[cfg(test)]
mod guard_tests {
    /// The `active` feature (ACTIVE website tests) is closed and local-only until a lawyer
    /// reviews it: NO CI/release workflow may build it. This guard fails the build (in the
    /// default feature set, so it always runs) if any of those workflows mentions `active`.
    #[test]
    fn active_feature_is_never_in_a_release_workflow() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        for name in ["ci.yml", "release.yml", "pro-ci.yml", "pro-release.yml"] {
            let path = root.join(".github").join("workflows").join(name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue; // not present in this checkout (e.g. the public export)
            };
            assert!(
                !text.to_ascii_lowercase().contains("active"),
                "{name} must not mention the `active` feature — it is local-only until legal review"
            );
        }
    }
}
