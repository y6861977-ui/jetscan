//! Уязвимости в зависимостях (Фаза 2): lockfile'ы → пакеты → OSV.dev → находки.
//!
//! Контракт (T2.1). Публичные типы и сигнатуры парсеров lockfile'ов меняются только
//! по согласованию — от них зависят параллельные задачи.
//!
//! Поток данных:
//!   discover (пути lockfile'ов) → lockfiles::<формат>::parse (Dep)
//!     → Package (экосистема + где встречается) → osv (Vuln) → VulnFinding → report.
//!
//! Приватность: наружу (api.osv.dev) уходят только экосистема, имя и версия пакета —
//! ни код, ни пути, ни имя проекта. `offline` — только локальный кэш.

pub mod discover;
pub mod fix;
pub mod lockfiles;
pub mod osv;
pub mod report;
pub mod scan;
pub mod scripts;
pub mod typosquat;

/// Экосистема пакета — как её называет OSV.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
    CratesIo,
    Go,
    Maven,
}

impl Ecosystem {
    /// Имя экосистемы в запросах и ответах OSV (регистр важен).
    pub fn osv_name(self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Maven => "Maven",
        }
    }

    /// Совпадают ли имена пакетов. В PyPI имена сравниваются по PEP 503
    /// (`Django` = `django`, `zope.interface` = `zope-interface`), в остальных — точно.
    pub fn same_name(self, a: &str, b: &str) -> bool {
        match self {
            Ecosystem::PyPI => pep503(a) == pep503(b),
            _ => a == b,
        }
    }
}

/// Нормализация имени PyPI по PEP 503: нижний регистр, `-_.` (и их серии) → `-`.
pub fn pep503(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
            continue;
        }
        if sep && !out.is_empty() {
            out.push('-');
        }
        sep = false;
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Одна зависимость, как её вернул парсер lockfile'а. Только установленные/зафиксированные
/// версии — диапазоны (`^1.2`) парсер не возвращает: по ним нельзя сказать, что стоит.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Dep {
    pub name: String,
    pub version: String,
}

/// Пакет к проверке: уникален по (экосистема, имя, версия).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Где встречается: пути lockfile'ов относительно корня скана, через `/`, по порядку.
    pub lockfiles: Vec<String>,
}

/// Уровень опасности. Порядок вариантов = порядок `Ord`: Critical — самый высокий.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Unknown => "unknown",
        }
    }

    /// Обратно из `label()` — для чтения кэша и флагов.
    pub fn from_label(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" | "moderate" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            "unknown" => Some(Severity::Unknown),
            _ => None,
        }
    }

    /// CVSS base score → уровень (пороги CVSS 3.1).
    pub fn from_score(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Unknown
        }
    }
}

/// Уязвимость применительно к одному пакету. Все строки — из недоверенного ответа OSV,
/// уже прошли `ui::sanitize_line`.
#[derive(Clone, Debug, PartialEq)]
pub struct Vuln {
    /// `GHSA-...`, `PYSEC-...`, `RUSTSEC-...`, `GO-...` — проверен по алфавиту.
    pub id: String,
    /// Другие id той же дыры (обычно `CVE-...`), по порядку.
    pub aliases: Vec<String>,
    /// Одна строка.
    pub summary: String,
    pub severity: Severity,
    pub cvss: Option<f64>,
    /// Версии с исправлением для ЭТОГО пакета (все диапазоны), по порядку из OSV.
    pub fixed: Vec<String>,
    /// Вредоносный пакет, а не дыра (T4.1): id `MAL-…` (OpenSSF malicious packages) или
    /// CWE-506 «Embedded Malicious Code» в GHSA. Факт из базы, не эвристика. Обновлять
    /// бесполезно — удалять и считать машину, где он ставился, скомпрометированной.
    pub malicious: bool,
}

/// Находка для отчёта.
#[derive(Clone, Debug, PartialEq)]
pub struct VulnFinding {
    pub package: Package,
    pub vuln: Vuln,
    /// Ближайшая версия с исправлением выше установленной; `None` — исправления нет
    /// (или версии не сравнить — тогда смотреть `vuln.fixed`).
    pub fix: Option<String>,
}

/// Ближайшая исправленная версия выше `installed`. Сравнение — по числовым частям
/// (`v1.2.10` > `1.2.9`); pre-release-хвосты и непарсящиеся версии не угадываем.
pub fn best_fix(installed: &str, fixed: &[String]) -> Option<String> {
    let parsed: Vec<(Vec<u64>, &String)> = fixed
        .iter()
        .filter_map(|f| numeric_version(f).map(|v| (v, f)))
        .collect();
    match numeric_version(installed) {
        // Сравнимо — только выше установленной: фикс старой ветки (1.2.5 при 2.0.1) —
        // это откат, а не исправление.
        Some(cur) if !parsed.is_empty() => parsed
            .into_iter()
            .filter(|(v, _)| *v > cur)
            .min_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, f)| f.clone()),
        // Не сравнить, но вариант один — его и показываем.
        _ if fixed.len() == 1 => Some(fixed[0].clone()),
        _ => None,
    }
}

/// `v1.2.3-beta+x` → `[1, 2, 3]`. `None`, если в начале нет числа.
pub(crate) fn numeric_version(v: &str) -> Option<Vec<u64>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let core = v.split(['-', '+']).next()?;
    let parts: Option<Vec<u64>> = core.split('.').map(|p| p.parse().ok()).collect();
    parts.filter(|p| !p.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pep503_normalizes_names() {
        assert_eq!(pep503("Django"), "django");
        assert_eq!(pep503("zope.interface"), "zope-interface");
        assert_eq!(pep503("Foo__Bar-.baz"), "foo-bar-baz");
        assert!(Ecosystem::PyPI.same_name("PyYAML", "pyyaml"));
        assert!(!Ecosystem::Npm.same_name("Lodash", "lodash"));
    }

    #[test]
    fn best_fix_picks_nearest_higher_version() {
        let fixed = vec![
            "1.2.5".to_string(),
            "2.0.3".to_string(),
            "3.0.0".to_string(),
        ];
        assert_eq!(best_fix("2.0.1", &fixed).as_deref(), Some("2.0.3"));
        assert_eq!(best_fix("1.0.0", &fixed).as_deref(), Some("1.2.5"));
        assert_eq!(best_fix("1.2.10", &fixed).as_deref(), Some("2.0.3"));
        assert_eq!(
            best_fix("v0.9.0", &["v1.0.1".into(), "v0.9.4".into()]).as_deref(),
            Some("v0.9.4")
        );
        // Фикс только для старой ветки — это не исправление для 2.x.
        assert_eq!(best_fix("2.0.1", &["1.2.5".to_string()]), None);
        // Не сравнить, вариант один — его; ни одного — None.
        assert_eq!(
            best_fix("weird", &["2.0".to_string()]).as_deref(),
            Some("2.0")
        );
        assert_eq!(best_fix("1.0", &[]), None);
        // Не сравнить — не угадываем.
        assert_eq!(best_fix("abc", &fixed), None);
    }

    #[test]
    fn severity_order_and_labels() {
        assert!(Severity::Critical > Severity::High && Severity::Low > Severity::Unknown);
        assert_eq!(Severity::from_score(9.8), Severity::Critical);
        assert_eq!(Severity::from_score(0.0), Severity::Unknown);
        assert_eq!(Severity::from_label("MODERATE"), Some(Severity::Medium));
        for s in [
            Severity::Unknown,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(Severity::from_label(s.label()), Some(s));
        }
    }
}
