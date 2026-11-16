//! iOS Source Audit: локальная статическая проверка ИСХОДНИКОВ iOS-приложения (Xcode-проект,
//! Swift/Objective-C, property lists, entitlements, xcconfig, CocoaPods/SPM-манифесты как файлы).
//! Владелец — агент «iOS» (`docs/architecture/CONTRACTS_V2.md`; интеграция — `HANDOFF_IOS.md`).
//!
//! Никогда не исполняет код проекта, не запускает xcodebuild/сборку, не ходит в сеть, ничего не пишет.
//! Собранный .ipa не анализируется.
//!
//! Слои: `walk` (ограниченный обход; бюджеты — общие с `android_audit::walk`) → `plist` (XML через
//! `android_audit::xml` и ASCII/OpenStep) и `lex` (токены Swift/ObjC) → `project` (pbxproj: цели,
//! конфигурации, xcconfig) → `rules` (Info.plist, entitlements, ключи ядра, шаблоны кода) →
//! `scan` ([`scan_source`]) → `report`, `cli`.

pub mod cli;
pub mod lex;
pub mod plist;
pub mod project;
pub mod report;
pub mod rules;
pub mod scan;
pub mod types;
pub mod walk;

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) mod testutil;

pub use scan::{
    IosScanOptions, IosScanResult, ProjectInfo, SCHEMA_VERSION, TargetInfo, scan_source,
};
pub use types::{IosFinding, IosLocation};
