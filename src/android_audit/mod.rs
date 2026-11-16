//! Android Source Audit: локальная статическая проверка ИСХОДНИКОВ Android-приложения (Gradle-проект:
//! Kotlin/Java, XML). Дополняет `jetscan apk` (собранный APK): здесь есть точные `файл:строка:колонка`
//! и то, чего в APK нет (Gradle, пароли подписи, хранилища ключей, тестовые/отладочные наборы).
//! Владелец — агент «Android» (`docs/architecture/CONTRACTS_V2.md`; интеграция — `HANDOFF_ANDROID.md`).
//!
//! Никогда не исполняет код проекта, не запускает Gradle/сборку, не ходит в сеть, ничего не пишет.
//!
//! Слои: `walk` (ограниченный обход) → `lex` (токены Kotlin/Java/Groovy), `xml` (текстовый XML без DTD),
//! `gradle` (блоки и операторы скриптов) → `project` (модули, SDK) → `rules` (манифест — правилами
//! `apk_audit` по той же модели, Gradle, ключи, шаблоны кода) → `scan` ([`scan_source`]) → `report`, `cli`.

pub mod cli;
pub mod gradle;
pub mod lex;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;
pub mod types;
pub mod walk;
pub mod xml;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) mod testutil;

pub use scan::{AndroidScanOptions, AndroidScanResult, ModuleInfo, SCHEMA_VERSION, scan_source};
pub use types::{AndroidFinding, AndroidLocation};
