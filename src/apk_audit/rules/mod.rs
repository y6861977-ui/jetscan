//! Правила APK. Каждое получает уже разобранную модель и возвращает находки и, если не всё
//! удалось проверить, причину неполноты (→ `partial`). `confirmed` не выдаётся никогда.

pub mod manifest_rules;
pub mod net;
pub mod secret;

use super::types::ApkFinding;

/// Итог одного правила.
#[derive(Default)]
pub struct RuleOutput {
    pub findings: Vec<ApkFinding>,
    /// Почему проверка неполная (ссылки на ресурсы, нечитаемые записи, лимиты).
    pub partial: Vec<String>,
}
