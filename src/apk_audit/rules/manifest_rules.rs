//! APK-EXPORT-001, APK-DEBUG-002, APK-BACKUP-004, APK-PERMS-005 — правила по модели манифеста.

use super::RuleOutput;
use crate::apk_audit::manifest::{Exported, Flag, Kind, Manifest, effective_exported};
use crate::apk_audit::types::{Confidence, Severity, manifest_finding};
use crate::ui;

pub const EXPORT_ID: &str = "APK-EXPORT-001";
pub const DEBUG_ID: &str = "APK-DEBUG-002";
pub const BACKUP_ID: &str = "APK-BACKUP-004";
pub const PERMS_ID: &str = "APK-PERMS-005";

const REF_APPLICATION: &str =
    "https://developer.android.com/guide/topics/manifest/application-element";
const REF_ACTIVITY: &str = "https://developer.android.com/guide/topics/manifest/activity-element";
const REF_PROVIDER: &str = "https://developer.android.com/guide/topics/manifest/provider-element";
const REF_BACKUP: &str = "https://developer.android.com/guide/topics/data/autobackup";
const REF_PERMISSIONS: &str = "https://developer.android.com/guide/topics/permissions/overview";
const REF_MASVS: &str = "https://mas.owasp.org/MASVS/";

/// APK-DEBUG-002: `android:debuggable="true"` в манифесте.
pub fn debuggable(m: &Manifest) -> RuleOutput {
    let mut out = RuleOutput::default();
    let Some(app) = &m.application else {
        return out;
    };
    match app.debuggable {
        Flag::True => out.findings.push(manifest_finding(
            DEBUG_ID,
            "debug_build",
            Some("application".to_string()),
            "Application is debuggable".to_string(),
            Severity::High,
            Confidence::Potential,
            "android:debuggable=\"true\": on any device a debugger can attach to the app process, \
             `run-as` gives a shell with the app's own data, and debug-overrides of the network \
             security config take effect. Release builds should never set it. Potential, not \
             confirmed: this may be a debug build that was never meant to be shipped."
                .to_string(),
            "remove-debuggable",
            &[
                REF_APPLICATION,
                "https://cwe.mitre.org/data/definitions/489.html",
                REF_MASVS,
            ],
            &["CWE-489"],
            vec!["apk".into(), "masvs:MASVS-RESILIENCE".into()],
        )),
        Flag::Unresolved => out.partial.push(
            "android:debuggable is a resource reference (resources.arsc is not parsed)".to_string(),
        ),
        Flag::False | Flag::Absent => {}
    }
    out
}

/// APK-BACKUP-004: резервное копирование данных приложения разрешено.
pub fn backup(m: &Manifest) -> RuleOutput {
    let mut out = RuleOutput::default();
    let Some(app) = &m.application else {
        return out;
    };
    let explicit = match app.allow_backup {
        Flag::False => return out,
        Flag::Unresolved => {
            out.partial.push(
                "android:allowBackup is a resource reference (resources.arsc is not parsed)"
                    .to_string(),
            );
            return out;
        }
        Flag::True => true,
        Flag::Absent => false,
    };
    let how = if explicit {
        "android:allowBackup=\"true\""
    } else {
        "android:allowBackup is not set, and it defaults to true"
    };
    let rules = app.full_backup_content || app.data_extraction_rules;
    let adb_includes_data = m.sdk.target < 31 || app.debuggable == Flag::True;
    let (severity, confidence, detail) = if adb_includes_data && !rules {
        (
            Severity::Medium,
            if explicit {
                Confidence::Potential
            } else {
                Confidence::NeedsReview
            },
            format!(
                "With targetSdk {} {}`adb backup` copies the app's private data from a device \
                 with USB debugging enabled, and Auto Backup uploads it to the user's cloud backup.",
                m.sdk.target,
                if app.debuggable == Flag::True {
                    "and a debuggable build "
                } else {
                    ""
                }
            ),
        )
    } else {
        (
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "{}Cloud backup and device-to-device transfer still include app data unless \
                 backup rules exclude it{}.",
                if adb_includes_data {
                    ""
                } else {
                    "For targetSdk >= 31 `adb backup` no longer includes app data. "
                },
                if rules {
                    " (backup rules are declared; their contents were not analysed)"
                } else {
                    ""
                }
            ),
        )
    };
    out.findings.push(manifest_finding(
        BACKUP_ID,
        "data_storage",
        Some("application".to_string()),
        "Application data can be backed up".to_string(),
        severity,
        confidence,
        format!(
            "{how}. {detail} Review whether tokens, keys or personal data in the app's storage \
             should be excluded (fullBackupContent / dataExtractionRules) or backup disabled."
        ),
        "restrict-backup",
        &[
            REF_BACKUP,
            REF_APPLICATION,
            "https://cwe.mitre.org/data/definitions/530.html",
            REF_MASVS,
        ],
        &["CWE-530"],
        vec!["apk".into(), "masvs:MASVS-STORAGE".into()],
    ));
    out
}

/// APK-EXPORT-001: экспортированный компонент без защиты разрешением.
pub fn exported(m: &Manifest) -> RuleOutput {
    let mut out = RuleOutput::default();
    let Some(app) = &m.application else {
        return out;
    };
    let weak = |perm: &str| {
        m.declared_permissions
            .iter()
            .find(|d| d.name == perm)
            .is_some_and(|d| d.is_weak())
    };
    for c in &app.components {
        if c.enabled == Flag::False {
            continue;
        }
        let state = effective_exported(c, &m.sdk);
        if state == Exported::Unknown {
            out.partial.push(format!(
                "{} {}: android:exported is a resource reference (resources.arsc is not parsed)",
                c.kind.label(),
                ui::sanitize_line(&c.name)
            ));
            continue;
        }
        if !state.is_exported()
            || (c.kind == Kind::Activity || c.kind == Kind::ActivityAlias) && c.is_launcher()
        {
            continue;
        }
        // Защита: своё разрешение компонента, иначе разрешение приложения.
        let inherited = c.permission.clone().or_else(|| app.permission.clone());
        let (unprotected, weakly): (Vec<&str>, Option<String>) = if c.kind == Kind::Provider {
            let read = c.read_permission.clone().or_else(|| inherited.clone());
            let write = c.write_permission.clone().or_else(|| inherited.clone());
            let mut missing = Vec::new();
            if read.is_none() {
                missing.push("read");
            }
            if write.is_none() {
                missing.push("write");
            }
            let weak_perm = [read, write].into_iter().flatten().find(|p| weak(p));
            (missing, weak_perm)
        } else {
            match &inherited {
                None => (vec!["all"], None),
                Some(p) if weak(p) => (Vec::new(), Some(p.clone())),
                Some(_) => (Vec::new(), None),
            }
        };
        if unprotected.is_empty() && weakly.is_none() {
            continue;
        }
        let label = format!("{} {}", c.kind.label(), c.name);
        let (how, confidence) = match state {
            Exported::Explicit(_) => (
                "is exported (android:exported=\"true\")".to_string(),
                Confidence::Potential,
            ),
            Exported::Implicit(_, why) => (
                format!("is exported by default ({why})"),
                Confidence::NeedsReview,
            ),
            Exported::Unknown => unreachable!("handled above"),
        };
        let protection = if let Some(p) = &weakly {
            format!(
                "It is guarded by {}, which this app declares with normal/dangerous protection, so any \
                 app can obtain it.",
                ui::sanitize_line(p)
            )
        } else if c.kind == Kind::Provider {
            format!("No permission guards {} access.", unprotected.join(" and "))
        } else {
            "No permission guards it.".to_string()
        };
        let install = if matches!(state, Exported::Implicit(true, _))
            && c.kind != Kind::Provider
            && m.sdk.target >= 31
        {
            " With targetSdk >= 31 Android 12+ refuses to install an APK whose component has an \
             intent-filter but no explicit android:exported."
        } else {
            ""
        };
        // Полевой тест 2026-11-12 (паттерн 12): компоненты, чьи intent-filter'ы объявляют только
        // документированные публичные точки входа Android, экспортированы по замыслу → info.
        // Явный экспорт без единого intent-filter и без разрешения — самый сильный сигнал → medium.
        let entry_points = if weakly.is_none() {
            public_entry_actions(c)
        } else {
            None
        };
        // Полевой тест, раунд 2: `activity-alias` без своих фильтров лишь второе имя экспортированной
        // цели. Если цель сама — публичная точка входа (лаунчер или документированные действия),
        // алиас новой поверхности не добавляет и наследует её статус.
        let alias_of = if weakly.is_none() && entry_points.is_none() && c.filters.is_empty() {
            alias_target_entry(m, app, c)
        } else {
            None
        };
        let entry_points = entry_points.or_else(|| alias_of.as_ref().map(|(_, a)| a.clone()));
        let no_filter_explicit = c.filters.is_empty() && matches!(state, Exported::Explicit(true));
        let severity = match (c.kind, weakly.is_some()) {
            _ if entry_points.is_some() => Severity::Info,
            (_, true) => Severity::Low,
            (Kind::Service | Kind::Provider, false) => Severity::Medium,
            _ if no_filter_explicit => Severity::Medium,
            _ => Severity::Low,
        };
        let confidence = if entry_points.is_some() {
            Confidence::NeedsReview
        } else {
            confidence
        };
        let purpose = match &entry_points {
            Some(actions) if alias_of.is_some() => format!(
                " It is an alias of {}, which is itself exported as an Android-documented public entry \
                 point ({}); the alias has no intent-filter of its own, so it adds no new way in: review \
                 how the target validates what it receives (extras, URIs, files).",
                ui::sanitize_line(alias_of.as_ref().map_or("", |(t, _)| t.as_str())),
                ui::sanitize_line(&actions.join(", "))
            ),
            Some(actions) => format!(
                " Its intent-filters declare only Android-documented public entry points ({}), so being \
                 reachable from other apps is its purpose: review how it validates what it receives \
                 (extras, URIs, files).",
                ui::sanitize_line(&actions.join(", "))
            ),
            None if no_filter_explicit => " It has no intent-filter, so nothing in the manifest explains why \
                 other apps need it: often a debug/tooling or internal component exported by mistake."
                .to_string(),
            None => String::new(),
        };
        let grant = if c.kind == Kind::Provider && c.grant_uri_permissions == Flag::True {
            " It also sets grantUriPermissions."
        } else {
            ""
        };
        out.findings.push(manifest_finding(
            EXPORT_ID,
            "ipc",
            Some(label.clone()),
            if entry_points.is_some() {
                format!("Exported {} is a documented public entry point", c.kind.label())
            } else {
                format!("Exported {} without permission protection", c.kind.label())
            },
            severity,
            confidence,
            format!(
                "The {} {}. {protection}{grant}{install}{purpose} Other apps on the device can start, bind to \
                 or query it. Export by itself is not an exploit: check what it does with \
                 untrusted input, then set android:exported=\"false\" or require a \
                 signature-level permission where it is not meant to be public.",
                ui::sanitize_line(&label),
                how
            ),
            "restrict-export",
            &[
                if c.kind == Kind::Provider { REF_PROVIDER } else { REF_ACTIVITY },
                "https://cwe.mitre.org/data/definitions/926.html",
                REF_MASVS,
            ],
            &["CWE-926"],
            vec![
                "apk".into(),
                "masvs:MASVS-PLATFORM".into(),
                format!("component:{}", c.kind.label()),
                format!("export:{}", if matches!(state, Exported::Explicit(_)) { "explicit" } else { "default" }),
                format!(
                    "purpose:{}",
                    if entry_points.is_some() {
                        "public-entry-point"
                    } else if no_filter_explicit {
                        "no-intent-filter"
                    } else {
                        "custom-actions"
                    }
                ),
            ],
        ));
    }
    out
}

/// Действия intent-filter, которые Android документирует как публичные точки входа: их вызывают
/// система, лаунчер или любое приложение по замыслу (Intent, MediaBrowserService, SyncAdapter, …).
/// `BOOT_COMPLETED`/`LOCKED_BOOT_COMPLETED`/`MY_PACKAGE_REPLACED` — защищённые системные broadcast'ы.
const PUBLIC_ENTRY_ACTIONS: &[&str] = &[
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.SENDTO",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.OPEN_DOCUMENT",
    "android.intent.action.PICK",
    "android.intent.action.PROCESS_TEXT",
    "android.intent.action.CREATE_SHORTCUT",
    "android.intent.action.SEARCH",
    "android.intent.action.MEDIA_BUTTON",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.LOCKED_BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.appwidget.action.APPWIDGET_UPDATE",
    "android.media.browse.MediaBrowserService",
    "androidx.media3.session.MediaSessionService",
    "androidx.media3.session.MediaLibraryService",
    "android.content.SyncAdapter",
    "android.accounts.AccountAuthenticator",
    "android.support.customtabs.action.CustomTabsService",
    "android.service.quicksettings.action.QS_TILE",
    "android.content.action.DOCUMENTS_PROVIDER",
];

/// Полное имя класса компонента: `.Foo` и `Foo` дополняются пакетом манифеста.
fn qualified(package: Option<&str>, name: &str) -> String {
    match package {
        Some(p) if name.starts_with('.') => format!("{p}{name}"),
        Some(p) if !name.contains('.') => format!("{p}.{name}"),
        _ => name.to_string(),
    }
}

/// Для `activity-alias`: (имя цели, её публичные точки входа), если цель — экспортированная
/// включённая `<activity>`, которая сама лаунчер или объявляет только публичные точки входа.
fn alias_target_entry(
    m: &Manifest,
    app: &crate::apk_audit::manifest::Application,
    c: &crate::apk_audit::manifest::Component,
) -> Option<(String, Vec<String>)> {
    if c.kind != Kind::ActivityAlias {
        return None;
    }
    let package = m.package.as_deref();
    let target = qualified(package, c.target_activity.as_deref()?);
    let t = app
        .components
        .iter()
        .find(|t| t.kind == Kind::Activity && qualified(package, &t.name) == target)?;
    if t.enabled == Flag::False || !effective_exported(t, &m.sdk).is_exported() {
        return None;
    }
    let actions = if t.is_launcher() {
        vec!["MAIN (launcher)".to_string()]
    } else {
        public_entry_actions(t)?
    };
    Some((t.name.clone(), actions))
}

/// Действия всех фильтров компонента, если КАЖДЫЙ фильтр состоит только из публичных точек входа.
/// Хоть одно своё действие (или фильтр без действий) — `None`: такой компонент оцениваем как обычно.
fn public_entry_actions(c: &crate::apk_audit::manifest::Component) -> Option<Vec<String>> {
    if c.filters.is_empty() {
        return None;
    }
    let mut actions = Vec::new();
    for f in &c.filters {
        if f.actions.is_empty()
            || !f
                .actions
                .iter()
                .all(|a| PUBLIC_ENTRY_ACTIONS.contains(&a.as_str()))
        {
            return None;
        }
        // VIEW из браузера (deep link) требует BROWSABLE; VIEW без него — «открыть с помощью» из других
        // приложений; оба документированы как публичные, отмечаем, какой это.
        for a in &f.actions {
            let short = a.rsplit('.').next().unwrap_or(a);
            let label = if short == "VIEW"
                && f.categories
                    .iter()
                    .any(|c| c == "android.intent.category.BROWSABLE")
            {
                "VIEW (BROWSABLE deep link)".to_string()
            } else {
                short.to_string()
            };
            if !actions.contains(&label) {
                actions.push(label);
            }
        }
    }
    Some(actions)
}

/// Разрешения уровня `dangerous` (выдаются пользователем во время работы).
const DANGEROUS: &[&str] = &[
    "READ_CALENDAR",
    "WRITE_CALENDAR",
    "CAMERA",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO",
    "READ_PHONE_STATE",
    "READ_PHONE_NUMBERS",
    "CALL_PHONE",
    "ANSWER_PHONE_CALLS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "ADD_VOICEMAIL",
    "USE_SIP",
    "PROCESS_OUTGOING_CALLS",
    "BODY_SENSORS",
    "BODY_SENSORS_BACKGROUND",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_SMS",
    "RECEIVE_WAP_PUSH",
    "RECEIVE_MMS",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO",
    "ACTIVITY_RECOGNITION",
    "POST_NOTIFICATIONS",
    "NEARBY_WIFI_DEVICES",
    "BLUETOOTH_SCAN",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_ADVERTISE",
    "UWB_RANGING",
];

/// Особо чувствительные разрешения: доступ к другим приложениям, оверлеи, SMS, фоновая геолокация.
const SENSITIVE: &[&str] = &[
    "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES",
    "MANAGE_EXTERNAL_STORAGE",
    "QUERY_ALL_PACKAGES",
    "PACKAGE_USAGE_STATS",
    "WRITE_SETTINGS",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
];

/// APK-PERMS-005: какие чувствительные разрешения запрашивает приложение (для проверки «нужно ли»).
pub fn permissions(m: &Manifest) -> RuleOutput {
    let mut out = RuleOutput::default();
    let short = |name: &str| name.strip_prefix("android.permission.").map(str::to_string);
    let mut dangerous: Vec<String> = m
        .uses_permissions
        .iter()
        .filter_map(|p| short(&p.name))
        .filter(|s| DANGEROUS.contains(&s.as_str()))
        .collect();
    dangerous.sort();
    dangerous.dedup();
    if !dangerous.is_empty() {
        out.findings.push(manifest_finding(
            PERMS_ID,
            "permissions",
            Some("uses-permission".to_string()),
            format!("Requests {} runtime (dangerous) permission(s)", dangerous.len()),
            Severity::Info,
            Confidence::NeedsReview,
            format!(
                "The app asks for: {}. Each needs user consent at runtime; this is information for a \
                 review of whether every permission is needed, not a vulnerability.",
                dangerous.join(", ")
            ),
            "review-permissions",
            &[REF_PERMISSIONS],
            &[],
            vec!["apk".into()],
        ));
    }
    for p in &m.uses_permissions {
        let Some(s) = short(&p.name) else { continue };
        if !SENSITIVE.contains(&s.as_str()) {
            continue;
        }
        let capped = p
            .max_sdk
            .map(|v| format!(" (only up to API {v})"))
            .unwrap_or_default();
        out.findings.push(manifest_finding(
            PERMS_ID,
            "permissions",
            Some(format!("uses-permission {}", p.name)),
            format!("Requests sensitive permission {s}"),
            Severity::Low,
            Confidence::NeedsReview,
            format!(
                "{s}{capped} gives broad access (other apps, overlays, SMS/call data or background \
                 location) and is restricted by store policies. Keep it only if a core feature needs it."
            ),
            "review-permissions",
            &[REF_PERMISSIONS],
            &[],
            vec!["apk".into(), format!("permission:{s}")],
        ));
    }
    out
}
