//! SBOM — список компонентов проекта.
//! Нужен для EU Cyber Resilience Act (с 11.12.2027) и аудитов (SOC 2, ISO 27001).
//!
//! Контракт:
//! - Вход — `DepsReport` (пакеты уже найдены и проверены), выход — JSON-строка.
//! - Детерминированно: одинаковый вход → одинаковый выход байт в байт. Время — только
//!   из `SOURCE_DATE_EPOCH`, если задан, иначе без даты; serialNumber/namespace — из хэша
//!   содержимого, не случайный UUID.
//! - Уязвимости (CycloneDX `vulnerabilities`) — из `DepsReport::findings`.
//! - Никаких путей к файлам пользователя в документе, кроме относительных путей lockfile'ов.

pub mod cyclonedx;
pub mod purl;
pub mod spdx;

use crate::deps::scan::DepsReport;

/// CycloneDX 1.6 JSON.
pub fn cyclonedx(r: &DepsReport) -> Result<String, String> {
    cyclonedx::render(r)
}

/// SPDX 2.3 JSON.
pub fn spdx(r: &DepsReport) -> Result<String, String> {
    spdx::render(r)
}
