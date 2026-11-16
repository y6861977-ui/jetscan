//! APK Static Audit: локальная проверка Android APK без запуска кода.
//! Владелец — агент «Сканеры». Решения — `docs/architecture/ADR-001-dependencies.md`
//! (ADR-APK одобрен 2026-11-12: свои ZIP + CRC-32 + inflate + AXML, std-only).
//!
//! Слои: `cursor` (чтение с проверкой границ) → `crc32`, `inflate` (порт puff.c) → `zip`
//! (центральный каталог, лимиты, враждебные архивы) → `axml` (бинарный XML) → `manifest`
//! (модель и значения по умолчанию) → `rules` → `scan` (точка входа [`scan_apk`]) → `report`, `cli`.
//! Ничего не исполняется, на диск ничего не пишется, сети нет.

pub mod axml;
pub mod cli;
pub mod crc32;
pub mod cursor;
pub mod dex;
pub mod inflate;
pub mod manifest;
pub mod report;
pub mod rules;
pub mod scan;
pub mod types;
pub mod zip;

pub use scan::{ApkInfo, ApkScanOptions, ApkScanResult, scan_apk, scan_bytes};
pub use types::{ApkFinding, ApkLocation};

#[cfg(test)]
mod tests;
