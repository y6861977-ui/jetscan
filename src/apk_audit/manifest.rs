//! Модель `AndroidManifest.xml` поверх декодера AXML и семантика значений по умолчанию.
//!
//! Значения по умолчанию — по документации Android (ссылки в `docs/rules/apk/*.md`):
//! - `minSdkVersion` по умолчанию 1, `targetSdkVersion` по умолчанию = `minSdkVersion`;
//! - `android:exported` у activity/service/receiver: по умолчанию `true`, если у компонента есть
//!   `<intent-filter>`, иначе `false`; с targetSdk ≥ 31 компонент с intent-filter обязан явно
//!   указать `exported` (иначе установка на Android 12+ падает);
//! - `android:exported` у provider: по умолчанию `true` при targetSdk < 17, иначе `false`;
//! - `android:debuggable` по умолчанию `false`, `android:allowBackup` по умолчанию `true`;
//! - `android:usesCleartextTraffic` по умолчанию `true` при targetSdk ≤ 27, `false` при ≥ 28.
//!
//! Ссылки на ресурсы (`@bool/…`) без `resources.arsc` не разрешаются: такое значение — `Flag::Unresolved`,
//! и правило, которому оно нужно, честно становится `partial`.

use super::axml::{Attribute, Document, Element, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    True,
    False,
    Absent,
    /// Ссылка на ресурс или неожиданный тип — значение неизвестно.
    Unresolved,
}

pub fn flag(attr: Option<&Attribute>) -> Flag {
    match attr.map(|a| &a.value) {
        None => Flag::Absent,
        Some(Value::Bool(true)) => Flag::True,
        Some(Value::Bool(false)) => Flag::False,
        Some(Value::String(s)) if s == "true" => Flag::True,
        Some(Value::String(s)) if s == "false" => Flag::False,
        Some(_) => Flag::Unresolved,
    }
}

/// Строковое значение атрибута (типизированное или сохранённое raw).
pub fn string(attr: Option<&Attribute>) -> Option<String> {
    let attr = attr?;
    match &attr.value {
        Value::String(s) => Some(s.clone()),
        _ => attr.raw_value.clone(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sdk {
    pub min: i32,
    pub target: i32,
    pub min_declared: bool,
    pub target_declared: bool,
    /// min или target задан ссылкой/строкой, которую не разобрать.
    pub unresolved: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Activity => "activity",
            Kind::ActivityAlias => "activity-alias",
            Kind::Service => "service",
            Kind::Receiver => "receiver",
            Kind::Provider => "provider",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub kind: Kind,
    pub name: String,
    pub exported: Flag,
    pub enabled: Flag,
    pub permission: Option<String>,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
    pub grant_uri_permissions: Flag,
    pub filters: Vec<IntentFilter>,
    /// `android:targetActivity` у `<activity-alias>`.
    pub target_activity: Option<String>,
}

impl Component {
    /// Точка входа лаунчера (`MAIN` + `LAUNCHER`) — экспортируется по замыслу.
    pub fn is_launcher(&self) -> bool {
        self.filters.iter().any(|f| {
            f.actions.iter().any(|a| a == "android.intent.action.MAIN")
                && f.categories.iter().any(|c| {
                    c == "android.intent.category.LAUNCHER"
                        || c == "android.intent.category.LEANBACK_LAUNCHER"
                })
        })
    }
}

/// Итог `exported` с учётом значений по умолчанию.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exported {
    Explicit(bool),
    /// Значение по умолчанию; причина — для объяснения.
    Implicit(bool, &'static str),
    Unknown,
}

impl Exported {
    pub fn is_exported(self) -> bool {
        matches!(self, Exported::Explicit(true) | Exported::Implicit(true, _))
    }
}

pub fn effective_exported(c: &Component, sdk: &Sdk) -> Exported {
    match c.exported {
        Flag::True => Exported::Explicit(true),
        Flag::False => Exported::Explicit(false),
        Flag::Unresolved => Exported::Unknown,
        Flag::Absent if c.kind == Kind::Provider => {
            if sdk.target < 17 {
                Exported::Implicit(
                    true,
                    "content providers are exported by default when targetSdk < 17",
                )
            } else {
                Exported::Implicit(
                    false,
                    "content providers are not exported by default when targetSdk >= 17",
                )
            }
        }
        Flag::Absent if !c.filters.is_empty() => Exported::Implicit(
            true,
            "a component with an intent-filter is exported by default",
        ),
        Flag::Absent => Exported::Implicit(
            false,
            "a component without an intent-filter is not exported by default",
        ),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsesPermission {
    pub name: String,
    pub max_sdk: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredPermission {
    pub name: String,
    /// Базовый уровень защиты: 0 normal, 1 dangerous, 2 signature, 3 signatureOrSystem.
    /// `None` — не задан (= normal) или задан неразбираемо (см. `protection_unresolved`).
    pub protection_base: Option<u32>,
    pub protection_unresolved: bool,
}

impl DeclaredPermission {
    /// Любое приложение может получить: normal (автоматически) или dangerous (после согласия).
    pub fn is_weak(&self) -> bool {
        !self.protection_unresolved && self.protection_base.unwrap_or(0) <= 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    pub debuggable: Flag,
    pub allow_backup: Flag,
    pub uses_cleartext: Flag,
    pub network_security_config: bool,
    pub full_backup_content: bool,
    pub data_extraction_rules: bool,
    pub permission: Option<String>,
    pub components: Vec<Component>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub package: Option<String>,
    pub sdk: Sdk,
    pub application: Option<Application>,
    pub uses_permissions: Vec<UsesPermission>,
    pub declared_permissions: Vec<DeclaredPermission>,
}

fn int(attr: Option<&Attribute>) -> Result<Option<i32>, ()> {
    match attr.map(|a| &a.value) {
        None => Ok(None),
        Some(Value::Int(i)) => Ok(Some(*i)),
        Some(Value::String(s)) => s.trim().parse().map(Some).map_err(|_| ()),
        Some(_) => Err(()),
    }
}

fn children<'a>(e: &'a Element, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
    e.children.iter().filter(move |c| c.name == name)
}

fn component(e: &Element, kind: Kind) -> Component {
    let filters = children(e, "intent-filter")
        .map(|f| IntentFilter {
            actions: children(f, "action")
                .filter_map(|a| string(a.android("name")))
                .collect(),
            categories: children(f, "category")
                .filter_map(|c| string(c.android("name")))
                .collect(),
        })
        .collect();
    Component {
        kind,
        name: string(e.android("name")).unwrap_or_default(),
        exported: flag(e.android("exported")),
        enabled: flag(e.android("enabled")),
        permission: string(e.android("permission")),
        read_permission: string(e.android("readPermission")),
        write_permission: string(e.android("writePermission")),
        grant_uri_permissions: flag(e.android("grantUriPermissions")),
        filters,
        target_activity: if kind == Kind::ActivityAlias {
            string(e.android("targetActivity"))
        } else {
            None
        },
    }
}

/// `None` — корень не `<manifest>`.
pub fn from_document(doc: &Document) -> Option<Manifest> {
    let root = doc.root.as_ref().filter(|r| r.name == "manifest")?;
    let uses_sdk = children(root, "uses-sdk").next();
    let min = int(uses_sdk.and_then(|u| u.android("minSdkVersion")));
    let target = int(uses_sdk.and_then(|u| u.android("targetSdkVersion")));
    let unresolved = min.is_err() || target.is_err();
    let min_value = min.ok().flatten();
    let target_value = target.ok().flatten();
    let min_sdk = min_value.unwrap_or(1);
    let sdk = Sdk {
        min: min_sdk,
        target: target_value.unwrap_or(min_sdk),
        min_declared: min_value.is_some(),
        target_declared: target_value.is_some(),
        unresolved,
    };
    let application = children(root, "application").next().map(|app| {
        let mut components = Vec::new();
        for child in &app.children {
            let kind = match child.name.as_str() {
                "activity" => Kind::Activity,
                "activity-alias" => Kind::ActivityAlias,
                "service" => Kind::Service,
                "receiver" => Kind::Receiver,
                "provider" => Kind::Provider,
                _ => continue,
            };
            components.push(component(child, kind));
        }
        Application {
            debuggable: flag(app.android("debuggable")),
            allow_backup: flag(app.android("allowBackup")),
            uses_cleartext: flag(app.android("usesCleartextTraffic")),
            network_security_config: app.android("networkSecurityConfig").is_some(),
            full_backup_content: app.android("fullBackupContent").is_some(),
            data_extraction_rules: app.android("dataExtractionRules").is_some(),
            permission: string(app.android("permission")),
            components,
        }
    });
    let uses_permissions = root
        .children
        .iter()
        .filter(|c| c.name == "uses-permission" || c.name == "uses-permission-sdk-23")
        .filter_map(|c| {
            Some(UsesPermission {
                name: string(c.android("name"))?,
                max_sdk: int(c.android("maxSdkVersion")).ok().flatten(),
            })
        })
        .collect();
    let declared_permissions = children(root, "permission")
        .filter_map(|p| {
            let level = p.android("protectionLevel");
            let (base, unresolved) = match level.map(|a| &a.value) {
                None => (None, false),
                Some(Value::Int(i)) => (Some((*i as u32) & 0xf), false),
                Some(Value::Hex(h)) => (Some(h & 0xf), false),
                Some(Value::String(s)) => match s.split('|').next().unwrap_or("") {
                    "normal" => (Some(0), false),
                    "dangerous" => (Some(1), false),
                    "signature" => (Some(2), false),
                    "signatureOrSystem" => (Some(3), false),
                    _ => (None, true),
                },
                Some(_) => (None, true),
            };
            Some(DeclaredPermission {
                name: string(p.android("name"))?,
                protection_base: base,
                protection_unresolved: unresolved,
            })
        })
        .collect();
    Some(Manifest {
        package: string(root.plain("package")),
        sdk,
        application,
        uses_permissions,
        declared_permissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apk_audit::axml::encode::{Options, encode};
    use crate::apk_audit::axml::{Limits, decode};

    const NS: &str = "xmlns:android=\"http://schemas.android.com/apk/res/android\"";

    fn manifest(body: &str, sdk: &str) -> Manifest {
        let xml = format!("<manifest {NS} package=\"p\">{sdk}{body}</manifest>");
        let doc = decode(&encode(&xml, Options::default()), &Limits::default()).unwrap();
        from_document(&doc).unwrap()
    }

    fn sdk(min: Option<i32>, target: Option<i32>) -> String {
        let attr = |n: &str, v: Option<i32>| {
            v.map(|v| format!(" android:{n}=\"{v}\""))
                .unwrap_or_default()
        };
        format!(
            "<uses-sdk{}{} />",
            attr("minSdkVersion", min),
            attr("targetSdkVersion", target)
        )
    }

    #[test]
    fn sdk_defaults() {
        let m = manifest("", "");
        assert_eq!((m.sdk.min, m.sdk.target), (1, 1));
        assert!(!m.sdk.min_declared && !m.sdk.target_declared);
        let m = manifest("", &sdk(Some(21), None));
        assert_eq!((m.sdk.min, m.sdk.target), (21, 21));
        let m = manifest("", &sdk(Some(21), Some(34)));
        assert_eq!((m.sdk.min, m.sdk.target), (21, 34));
    }

    fn first_component(body: &str, sdk_xml: &str) -> (Component, Sdk) {
        let m = manifest(&format!("<application>{body}</application>"), sdk_xml);
        (m.application.unwrap().components.remove(0), m.sdk)
    }

    #[test]
    fn exported_defaults_follow_intent_filters_and_target_sdk() {
        let filter = "<intent-filter><action android:name=\"x.ACTION\" /></intent-filter>";
        let (c, s) = first_component(
            &format!("<service android:name=\".S\">{filter}</service>"),
            &sdk(Some(21), Some(30)),
        );
        assert_eq!(
            effective_exported(&c, &s),
            Exported::Implicit(
                true,
                "a component with an intent-filter is exported by default"
            )
        );
        let (c, s) = first_component("<service android:name=\".S\" />", &sdk(Some(21), Some(30)));
        assert!(!effective_exported(&c, &s).is_exported());
        let (c, s) = first_component("<provider android:name=\".P\" />", &sdk(Some(9), Some(16)));
        assert!(effective_exported(&c, &s).is_exported());
        let (c, s) = first_component("<provider android:name=\".P\" />", &sdk(Some(9), Some(17)));
        assert!(!effective_exported(&c, &s).is_exported());
        let (c, s) = first_component(
            "<receiver android:name=\".R\" android:exported=\"false\">{}</receiver>",
            &sdk(None, Some(34)),
        );
        assert_eq!(effective_exported(&c, &s), Exported::Explicit(false));
    }

    #[test]
    fn launcher_and_permissions() {
        let m = manifest(
            "<permission android:name=\"p.WEAK\" /><permission android:name=\"p.SIG\" android:protectionLevel=\"signature\" />\
             <uses-permission android:name=\"android.permission.CAMERA\" />\
             <application android:permission=\"p.SIG\"><activity android:name=\".Main\"><intent-filter>\
             <action android:name=\"android.intent.action.MAIN\" /><category android:name=\"android.intent.category.LAUNCHER\" />\
             </intent-filter></activity></application>",
            "",
        );
        let app = m.application.unwrap();
        assert!(app.components[0].is_launcher());
        assert_eq!(app.permission.as_deref(), Some("p.SIG"));
        assert_eq!(m.uses_permissions[0].name, "android.permission.CAMERA");
        // Тестовый кодировщик пишет protectionLevel строкой (aapt2 пишет флагом) — разбираем оба.
        assert!(m.declared_permissions[0].is_weak());
        assert!(!m.declared_permissions[1].is_weak());
    }

    #[test]
    fn flags_from_strings_and_references() {
        assert_eq!(flag(None), Flag::Absent);
        let attr = |value| Attribute {
            namespace: None,
            raw_name: String::new(),
            resource_id: None,
            raw_value: None,
            value,
        };
        assert_eq!(flag(Some(&attr(Value::Bool(true)))), Flag::True);
        assert_eq!(
            flag(Some(&attr(Value::String("false".into())))),
            Flag::False
        );
        assert_eq!(
            flag(Some(&attr(Value::Reference(0x7f05_0001)))),
            Flag::Unresolved
        );
    }
}
