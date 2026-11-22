//! Что открывает ключ: единственное место, где решается, можно ли запустить
//! платную проверку (CLI, меню и MCP зовут одну и ту же функцию).
//!
//! | тариф  | Pro-сканы (web, apk, android, ios, url) | CI-отчёты | льгота |
//! |--------|------------------------------------------|-----------|--------|
//! | teams  | все                                      | да        | 14 дн. |
//! | pro    | все                                      | нет       | 14 дн. |
//! | audit  | все, 30 дней                             | нет       | нет    |
//! | trial  | только своя `area`, `scans` штук          | нет       | нет    |
//!
//! Pro (личный) не включает CI-отчёты: это то, за что платит компания (Teams).
//! URL-аудит в пробный не входит: пробный — это ровно один сканер исходников/APK.
//!
//! Счётчик пробного — `~/.jetscan/trial-<id>.json` (или `JETSCAN_HOME`). Честный
//! предел: удалённый файл обнуляет счётчик на этой машине (и в чистом CI-контейнере
//! он каждый раз новый). Защита — короткий срок ключа (сайт даёт 14 дней) и один
//! пробный на почту на сайте; проверка всё равно локальная и без сети по замыслу.

use super::{Area, Checked, Claims, Plan, Status, format_date, jetscan_home, load_checked};
use crate::json::{self, Json};
use crate::ui;
use std::path::{Path, PathBuf};

const SITE: &str = "https://jetscan.jet.kim";
/// Сколько дней до конца годового ключа начинаем напоминать.
const WARN_DAYS: i64 = 30;
/// У 30-дневного аудита — за неделю.
const WARN_DAYS_AUDIT: i64 = 7;

/// Платная возможность.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProFeature {
    WebSource,
    Apk,
    AndroidSource,
    IosSource,
    UrlAudit,
    CiReports,
}

impl ProFeature {
    pub const ALL: [ProFeature; 6] = [
        ProFeature::WebSource,
        ProFeature::Apk,
        ProFeature::AndroidSource,
        ProFeature::IosSource,
        ProFeature::UrlAudit,
        ProFeature::CiReports,
    ];

    /// Слово в поле `features:` ключа.
    pub fn token(self) -> &'static str {
        match self {
            ProFeature::WebSource => "web",
            ProFeature::Apk => "apk",
            ProFeature::AndroidSource => "android",
            ProFeature::IosSource => "ios",
            ProFeature::UrlAudit => "url",
            ProFeature::CiReports => "ci",
        }
    }

    /// Область пробного ключа, которая открывает эту возможность.
    pub fn area(self) -> Option<Area> {
        match self {
            ProFeature::WebSource => Some(Area::Web),
            ProFeature::Apk => Some(Area::Apk),
            ProFeature::AndroidSource => Some(Area::Android),
            ProFeature::IosSource => Some(Area::Ios),
            ProFeature::UrlAudit | ProFeature::CiReports => None,
        }
    }

    /// Что это делает — одной фразой, для пейволла.
    pub fn what(self) -> &'static str {
        match self {
            ProFeature::WebSource => "A static security audit of a web project's source code",
            ProFeature::Apk => "A static security audit of an Android APK",
            ProFeature::AndroidSource => {
                "A static security audit of an Android app's source project"
            }
            ProFeature::IosSource => "A static security audit of an iOS app's source project",
            ProFeature::UrlAudit => "A security audit of a live web address",
            ProFeature::CiReports => "CI reports (--sarif, --sbom, --baseline)",
        }
    }

    /// Какой тариф это продаёт.
    pub fn product(self) -> &'static str {
        match self {
            ProFeature::CiReports => "jetscan Teams",
            _ => "jetscan Pro",
        }
    }
}

/// Ответ на «можно ли».
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entitlement {
    /// Платный ключ открывает. `warning` — в stderr (скоро срок, идёт льгота).
    Allowed {
        plan: Plan,
        license_id: String,
        expires: i64,
        warning: Option<String>,
    },
    /// Пробный ключ открывает; `remaining` — сканов осталось ДО этого запуска.
    Trial {
        area: Area,
        remaining: u32,
        license_id: String,
        expires: i64,
    },
    Denied {
        reason: String,
        how_to_get: String,
    },
}

impl Entitlement {
    pub fn allowed(&self) -> bool {
        !matches!(self, Entitlement::Denied { .. })
    }

    /// Предупреждение для stderr у разрешённого запуска.
    pub fn warning(&self) -> Option<String> {
        match self {
            Entitlement::Allowed { warning, .. } => warning.clone(),
            Entitlement::Trial {
                area, remaining, ..
            } => Some(format!(
                "jetscan Pro trial ({}): {} left including this one — buy jetscan Pro: {SITE}",
                area.as_str(),
                ui::plural(*remaining as usize, "scan", "scans")
            )),
            Entitlement::Denied { .. } => None,
        }
    }

    /// Пейволл для отказа: «<что делает> — part of jetscan Pro. <почему>. <как получить>».
    /// Сам ключ не печатается никогда — только его состояние.
    pub fn paywall(&self, feature: ProFeature) -> Option<String> {
        match self {
            Entitlement::Denied { reason, how_to_get } => Some(format!(
                "{} — part of {}. {reason}. {how_to_get}",
                feature.what(),
                feature.product()
            )),
            _ => None,
        }
    }
}

fn how_to_get(feature: ProFeature) -> String {
    match feature {
        ProFeature::CiReports => format!(
            "Get jetscan Teams at {SITE} and put the key in JETSCAN_LICENSE (a CI secret) or \
             ~/.jetscan/license; it is checked on this machine, nothing is sent"
        ),
        _ => format!(
            "Free trial or buy: {SITE} — then put the key in ~/.jetscan/license or \
             JETSCAN_LICENSE; it is checked on this machine, nothing is sent"
        ),
    }
}

/// Открывает ли тариф (без учёта срока и счётчика).
fn plan_allows(c: &Claims, feature: ProFeature) -> bool {
    let by_plan = match c.plan {
        Plan::Teams => true,
        Plan::Pro | Plan::Audit => feature != ProFeature::CiReports,
        Plan::Trial => feature.area().is_some() && feature.area() == c.area,
    };
    by_plan
        && c.features
            .as_ref()
            .is_none_or(|list| list.contains(&feature))
}

/// Решение по уже проверенному ключу. `trial_used` — сканов пробного уже сделано
/// (для других тарифов не важно). Чистая функция: её и тестируем.
pub fn entitlement_of(feature: ProFeature, checked: &Checked, trial_used: u32) -> Entitlement {
    let deny = |reason: String| Entitlement::Denied {
        reason,
        how_to_get: how_to_get(feature),
    };
    let claims = checked.claims.as_ref();
    let title = claims.map_or("jetscan", |c| c.plan.title());
    let (license, days, grace) = match &checked.status {
        Status::Free => return deny("No jetscan license key was found on this machine".into()),
        Status::Invalid(reason) => {
            return deny(format!(
                "The license key on this machine was not accepted: {}",
                ui::sanitize_line(reason)
            ));
        }
        Status::Expired { license, .. } => {
            let verb = match claims.map(|c| c.plan) {
                Some(Plan::Trial) => "trial ended",
                Some(Plan::Audit) => "audit access ended",
                _ => "license expired",
            };
            return deny(format!(
                "Your {title} {verb} on {}",
                format_date(license.expires)
            ));
        }
        Status::Active { license, days_left } => (license, *days_left, false),
        Status::Grace { license, days_over } => (license, *days_over, true),
    };
    let Some(c) = claims else {
        return deny("The license key on this machine was not accepted".into());
    };
    if !plan_allows(c, feature) {
        let reason = match (c.plan, c.area) {
            (Plan::Trial, Some(area)) => format!(
                "Your jetscan Pro trial covers the {} scan only",
                area.as_str()
            ),
            _ if feature == ProFeature::CiReports => format!(
                "Your {title} key unlocks the Pro scans; CI reports are part of jetscan Teams"
            ),
            _ => format!("Your {title} key does not include this check"),
        };
        return deny(reason);
    }
    let expires = license.expires;
    let license_id = license.id.clone();
    if c.plan == Plan::Trial {
        let limit = c.scans.unwrap_or(0);
        let remaining = limit.saturating_sub(trial_used);
        if remaining == 0 {
            return deny(format!(
                "Your jetscan Pro trial's {} are used up",
                ui::plural(limit as usize, "scan", "scans")
            ));
        }
        return Entitlement::Trial {
            area: c.area.unwrap_or(Area::Web),
            remaining,
            license_id,
            expires,
        };
    }
    let warning = if grace {
        Some(format!(
            "{title} license expired on {}; it keeps working for {} more — renew at {SITE}",
            format_date(expires),
            ui::plural((c.plan.grace_days() - days).max(0) as usize, "day", "days")
        ))
    } else {
        let warn = if c.plan == Plan::Audit {
            WARN_DAYS_AUDIT
        } else {
            WARN_DAYS
        };
        (days <= warn).then(|| {
            format!(
                "{title} key expires on {} ({} left)",
                format_date(expires),
                ui::plural(days as usize, "day", "days")
            )
        })
    };
    Entitlement::Allowed {
        plan: c.plan,
        license_id,
        expires,
        warning,
    }
}

/// Решение по ключу этой машины (`JETSCAN_LICENSE` или `~/.jetscan/license`) и
/// локальному счётчику пробного.
pub fn entitlement(feature: ProFeature) -> Entitlement {
    entitlement_for(feature, &load_checked())
}

/// Решение по данному проверенному ключу и локальному счётчику пробного (для
/// MCP-сервера, который подставляет загрузчик ключа в тестах).
pub fn entitlement_for(feature: ProFeature, checked: &Checked) -> Entitlement {
    entitlement_of(feature, checked, trial_used_for(checked))
}

/// То же решение со счётчиком пробного в папке `trial_dir` (CLI, меню и MCP передают
/// `jetscan_home()`, тесты — временную папку). Нет папки — пробный считается
/// исчерпанным (ошибка закрывает).
pub fn entitlement_in(
    feature: ProFeature,
    checked: &Checked,
    trial_dir: Option<&Path>,
) -> Entitlement {
    entitlement_of(feature, checked, trial_used_in(checked, trial_dir))
}

/// Сканов пробного уже сделано на этой машине; 0 — ключ не пробный (или истёк).
pub fn trial_used_for(checked: &Checked) -> u32 {
    trial_used_in(checked, jetscan_home().as_deref())
}

/// Сканов пробного уже сделано по счётчику в `dir`; 0 — ключ не пробный (или истёк).
pub fn trial_used_in(checked: &Checked, dir: Option<&Path>) -> u32 {
    match (&checked.status, &checked.claims) {
        (Status::Active { license, .. }, Some(c)) if c.plan == Plan::Trial => {
            dir.map_or(u32::MAX, |d| used_in(d, &license.id))
        }
        _ => 0,
    }
}

// --- счётчик пробного ---

/// Имя файла счётчика: id как есть, если он безопасен для имени файла, иначе хеш.
fn counter_name(id: &str) -> String {
    let safe = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if safe {
        format!("trial-{id}.json")
    } else {
        let h = crate::hash::sha256(id.as_bytes());
        format!("trial-{}.json", &crate::hash::hex(&h)[..16])
    }
}

/// Где лежит счётчик пробного ключа `id` (`~/.jetscan/trial-<id>.json`).
pub fn trial_counter_file(id: &str) -> Option<PathBuf> {
    jetscan_home().map(|h| h.join(counter_name(id)))
}

/// Сколько сканов пробного `id` уже сделано на этой машине.
pub fn trial_used(id: &str) -> u32 {
    jetscan_home().map_or(u32::MAX, |dir| used_in(&dir, id))
}

/// Нет файла — ноль. Файл есть, но не читается или чужой — пробный считается
/// исчерпанным (ошибка закрывает, а не открывает).
fn used_in(dir: &Path, id: &str) -> u32 {
    let text = match std::fs::read_to_string(dir.join(counter_name(id))) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(_) => return u32::MAX,
    };
    let Ok(doc) = json::parse(&text) else {
        return u32::MAX;
    };
    let used = doc.get("used").and_then(Json::as_f64);
    match (doc.get("license").and_then(Json::as_str), used) {
        (Some(l), Some(n)) if l == id && n >= 0.0 && n.fract() == 0.0 && n <= 1e6 => n as u32,
        _ => u32::MAX,
    }
}

/// Засчитать успешный скан пробного ключа этой машины. `Ok(Some(n))` — осталось
/// `n`; `Ok(None)` — ключ не пробный (считать нечего).
pub fn record_trial_scan() -> Result<Option<u32>, String> {
    let checked = load_checked();
    let Some(dir) = jetscan_home() else {
        return match is_trial(&checked) {
            true => Err("no home folder for the jetscan trial counter".into()),
            false => Ok(None),
        };
    };
    record_trial_scan_in(&dir, &checked)
}

fn is_trial(checked: &Checked) -> bool {
    checked
        .claims
        .as_ref()
        .is_some_and(|c| c.plan == Plan::Trial)
}

/// То же, с явной папкой и ключом (для тестов и для MCP-сервера).
pub fn record_trial_scan_in(dir: &Path, checked: &Checked) -> Result<Option<u32>, String> {
    let (Status::Active { license, .. }, Some(c)) = (&checked.status, &checked.claims) else {
        return Ok(None);
    };
    if c.plan != Plan::Trial {
        return Ok(None);
    }
    let limit = c.scans.unwrap_or(0);
    let used = used_in(dir, &license.id).saturating_add(1).min(limit);
    let doc = Json::Obj(
        [
            ("license".to_string(), Json::Str(license.id.clone())),
            ("used".to_string(), Json::Num(f64::from(used))),
        ]
        .into_iter()
        .collect(),
    );
    let file = dir.join(counter_name(&license.id));
    let tmp = dir.join(format!("{}.tmp", counter_name(&license.id)));
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(&tmp, format!("{}\n", json::stringify(&doc)))?;
        std::fs::rename(&tmp, &file)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("cannot save the jetscan trial counter: {e}")
    })?;
    Ok(Some(limit.saturating_sub(used)))
}

// --- `jetscan license` ---

fn unlocks(c: &Claims) -> String {
    let base = match c.plan {
        Plan::Teams => "Unlocks: every Pro scan (web source, live website URL, APK, Android, \
                        iOS) and the CI reports (--sarif, --sbom, --baseline)."
            .to_string(),
        Plan::Pro => "Unlocks: every Pro scan (web source, live website URL, APK, Android, \
                      iOS). CI reports (--sarif, --sbom, --baseline) are part of jetscan Teams."
            .to_string(),
        Plan::Audit => "Unlocks: every Pro scan (web source, live website URL, APK, Android, \
                        iOS) until the date above; intended for one project. CI reports are \
                        part of jetscan Teams."
            .to_string(),
        Plan::Trial => format!(
            "Unlocks: the {} scan only (the live website URL check is not in the trial). \
             Buy jetscan Pro: {SITE}",
            c.area.map_or("?", Area::as_str)
        ),
    };
    match &c.features {
        Some(list) => {
            let names: Vec<&str> = list
                .iter()
                .filter(|f| plan_allows(c, **f))
                .map(|f| f.token())
                .collect();
            format!(
                "{base}\nThis key is limited to: {}.",
                if names.is_empty() {
                    "nothing".to_string()
                } else {
                    names.join(", ")
                }
            )
        }
        None => base,
    }
}

/// Текст `jetscan license` (сам ключ не печатается никогда). `Err` — ключ не принят.
pub fn describe(checked: &Checked, trial_used: u32) -> Result<String, String> {
    let (license, claims) = match (&checked.status, &checked.claims) {
        (Status::Free, _) => {
            return Ok(format!(
                "jetscan Free — no license key (JETSCAN_LICENSE or ~/.jetscan/license).\n\
                 Every free scan works without a key. Pro scans (web source, live website \
                 URL, APK, Android, iOS) need jetscan Pro, a one-time audit or a free trial \
                 (one scanner, a few scans); --sarif, --sbom and --baseline need jetscan Teams.\n\
                 Pro, trial and Teams: {SITE}"
            ));
        }
        (Status::Invalid(reason), _) => {
            return Err(format!(
                "license key not accepted: {}",
                ui::sanitize_line(reason)
            ));
        }
        (
            Status::Active { license, .. }
            | Status::Grace { license, .. }
            | Status::Expired { license, .. },
            Some(c),
        ) => (license, c),
        _ => return Err("license key not accepted".into()),
    };
    let mut head = claims.plan.title().to_string();
    if let Some(area) = claims.area {
        head.push_str(&format!(" ({})", area.as_str()));
    }
    head.push_str(" — ");
    if claims.plan == Plan::Teams {
        head.push_str(&format!(
            "{} · {} · ",
            ui::sanitize_line(&license.org),
            ui::plural(license.seats as usize, "seat", "seats")
        ));
    }
    head.push_str(&format!(
        "{} · issued {}",
        ui::sanitize_line(&license.id),
        format_date(license.issued)
    ));
    let expires = format_date(license.expires);
    let state = match &checked.status {
        Status::Active { days_left, .. } => {
            let mut s = format!(
                "✓ valid until {expires} ({} left)",
                ui::plural(*days_left as usize, "day", "days")
            );
            if claims.plan == Plan::Trial {
                let limit = claims.scans.unwrap_or(0);
                let left = limit.saturating_sub(trial_used);
                s.push_str(&format!(" · {left} of {limit} trial scans left"));
            }
            if left_is_zero(claims, trial_used) {
                ui::yellow(&s)
            } else {
                ui::green(&s)
            }
        }
        Status::Grace { days_over, .. } => ui::yellow(&format!(
            "! expired on {expires}; paid features stop in {}",
            ui::plural(
                (claims.plan.grace_days() - days_over).max(0) as usize,
                "day",
                "days"
            )
        )),
        _ => ui::red(&format!(
            "✗ expired on {expires} — paid features are off, free scans keep working. \
             Renew or buy: {SITE}"
        )),
    };
    Ok(format!("{head}\n{state}\n{}", unlocks(claims)))
}

fn left_is_zero(c: &Claims, used: u32) -> bool {
    c.plan == Plan::Trial && c.scans.unwrap_or(0) <= used
}

/// `jetscan license`: печатает состояние ключа этой машины. Код выхода: 0, или 2,
/// если ключ есть, но не принят.
pub fn print_status() -> i32 {
    let checked = load_checked();
    match describe(&checked, trial_used_for(&checked)) {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(e) => {
            ui::eprint_error(&e);
            2
        }
    }
}

#[cfg(test)]
#[path = "entitlement_tests.rs"]
mod tests;
