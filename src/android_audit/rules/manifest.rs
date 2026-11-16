//! Правила манифеста на исходниках: те же APK-EXPORT/DEBUG/NET/BACKUP/PERMS, что у `jetscan apk`
//! (`apk_audit::rules`), но по текстовому `AndroidManifest.xml` модуля и с настоящими `файл:строка:колонка`.
//!
//! Слияние (консервативно, и об этом пишется в limitations):
//! - `src/main/AndroidManifest.xml` — основа; поверх — манифесты прочих source set'ов, кроме debug- и
//!   test-наборов (`src/release/`, `src/<flavor>/`, `src/<flavor>Release/`): атрибуты перекрываются,
//!   компоненты объединяются по имени, `tools:node="remove"`/`"removeAll"` убирает элемент, `"replace"`
//!   заменяет. Все не-debug варианты сливаются в ОДНУ картину (вариант по варианту не перебираем);
//! - debug/test-манифесты не анализируются; манифесты библиотек-зависимостей (AAR) не видны;
//! - манифесты библиотечных модулей проекта проверяются отдельно и только EXPORT/PERMS (атрибуты
//!   `<application>` библиотеки решает приложение).
//!
//! Значения: `${плейсхолдер}` — из `manifestPlaceholders` defaultConfig/release (литералы), `@bool/…`,
//! `@integer/…`, `@string/…` — из `res/values/` модуля, если имя не переопределено в `values-*/`.
//! Не разрешилось — флаг неизвестен, правило `partial`. SDK — из Gradle (литерал/best effort), иначе
//! из `<uses-sdk>`, иначе — допущение (targetSdk 34, minSdk 21) с `partial`.

use super::gradle as gradle_rules;
use super::{BACKUP_ID, DEBUG_ID, EXPORT_ID, NET_ID, PERMS_ID, RuleOutput};
use crate::android_audit::project::{Module, ModuleKind, Project, SdkValue};
use crate::android_audit::types::{AndroidFinding, AndroidLocation, Evidence, finding_id};
use crate::android_audit::walk::FileKind;
use crate::android_audit::xml::{self, Pos, TOOLS_NS, XmlAttr, XmlDoc, XmlElement};
use crate::apk_audit::manifest::{self as apk_manifest, Flag};
use crate::apk_audit::rules::{RuleOutput as ApkOutput, manifest_rules as mr, net};
use crate::apk_audit::types::ApkFinding;
use crate::ui;
use std::collections::{BTreeMap, HashSet};

pub const MANIFEST_RULES: &[&str] = &[EXPORT_ID, DEBUG_ID, NET_ID, BACKUP_ID, PERMS_ID];

/// Допущения, когда SDK не известен.
pub const ASSUMED_TARGET: i32 = 34;
pub const ASSUMED_MIN: i32 = 21;

/// Что узнали о модуле (для отчёта).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModuleManifest {
    pub package: Option<String>,
    pub min_sdk: Option<i32>,
    pub target_sdk: Option<i32>,
    /// Использованные манифесты (основа первой).
    pub merged: Vec<String>,
    /// Не анализировались: debug/test-наборы.
    pub not_merged: Vec<String>,
    pub network_config: Option<String>,
}

fn rule_for(apk_rule: &str) -> &'static str {
    match apk_rule {
        mr::EXPORT_ID => EXPORT_ID,
        mr::DEBUG_ID => DEBUG_ID,
        net::NET_ID => NET_ID,
        mr::BACKUP_ID => BACKUP_ID,
        _ => PERMS_ID,
    }
}

/// Тексты причин APK-правил говорят про `resources.arsc`; на исходниках причина другая.
fn rewrite_reason(reason: &str, nsc: Option<&str>) -> String {
    if reason.starts_with("the manifest references a network security config") {
        return format!(
            "the manifest references a network security config ({}), but the file was not found in \
             the module's res/xml directories",
            ui::sanitize_line(nsc.unwrap_or("?"))
        );
    }
    reason
        .replace(
            "is a resource reference (resources.arsc is not parsed)",
            "is not a literal (an unresolved resource reference or manifest placeholder)",
        )
        .replace(
            "android:usesCleartextTraffic is a resource reference",
            "android:usesCleartextTraffic is not a literal (an unresolved resource reference or \
             manifest placeholder)",
        )
}

/// Набор исходников (`src/<set>/…`) и его роль.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetRole {
    Main,
    Overlay,
    Debug,
    Test,
}

pub fn set_role(set: &str) -> SetRole {
    let lower = set.to_ascii_lowercase();
    if lower == "main" {
        SetRole::Main
    } else if lower.contains("test") {
        SetRole::Test
    } else if lower.contains("debug") {
        SetRole::Debug
    } else {
        SetRole::Overlay
    }
}

/// Манифесты модуля: (source set, путь).
fn module_manifests(project: &Project, module: &Module) -> Vec<(String, String)> {
    let prefix = module.path("src/");
    let mut out = Vec::new();
    for e in project.entries_of(FileKind::Manifest) {
        let Some(rest) = e.relative_path.strip_prefix(&prefix) else {
            continue;
        };
        if let Some((set, "AndroidManifest.xml")) = rest.split_once('/') {
            out.push((set.to_string(), e.relative_path.clone()));
        }
    }
    // Старая раскладка (Eclipse): `manifest.srcFile 'AndroidManifest.xml'` или файл в корне модуля.
    if !out.iter().any(|(s, _)| s == "main") {
        let declared = project.gradle.get(&module.build_file).and_then(|f| {
            f.stmts
                .iter()
                .filter(|s| s.target.ends_with("srcFile") && s.in_block("sourceSets"))
                .find_map(|s| {
                    s.args.first().and_then(|a| match &a.value {
                        crate::android_audit::gradle::GValue::Str(v) => Some(v.clone()),
                        crate::android_audit::gradle::GValue::Expr(t) => {
                            t.iter().find_map(|t| t.literal_str().map(str::to_string))
                        }
                        _ => None,
                    })
                })
        });
        let candidate = module.path(declared.as_deref().unwrap_or("AndroidManifest.xml"));
        if project
            .entries_of(FileKind::Manifest)
            .any(|e| e.relative_path == candidate)
        {
            out.push(("main".to_string(), candidate));
        }
    }
    out.sort_by_key(|(set, _)| {
        let lower = set.to_ascii_lowercase();
        (lower != "main", lower.contains("release"), lower)
    });
    out
}

fn tools_node(e: &XmlElement) -> Option<&str> {
    e.attr_ns(TOOLS_NS, "node").map(|a| a.value.as_str())
}

fn qualify(package: Option<&str>, name: &str) -> String {
    match package {
        Some(p) if name.starts_with('.') => format!("{p}{name}"),
        Some(p) if !name.contains('.') => format!("{p}.{name}"),
        _ => name.to_string(),
    }
}

fn key_of(e: &XmlElement, package: Option<&str>) -> (String, Option<String>) {
    (
        e.local.clone(),
        e.android("name").map(|a| qualify(package, &a.value)),
    )
}

fn merge_attrs(base: &mut XmlElement, overlay: &XmlElement) {
    for a in &overlay.attributes {
        if a.namespace.as_deref() == Some(TOOLS_NS) {
            continue;
        }
        match base
            .attributes
            .iter_mut()
            .find(|b| b.namespace == a.namespace && b.local == a.local)
        {
            Some(b) => *b = a.clone(),
            None => base.attributes.push(a.clone()),
        }
    }
}

/// Сливает дочерние элементы `overlay` в `base` (по ключу тег + android:name).
fn merge_children(base: &mut XmlElement, overlay: &XmlElement, package: Option<&str>) {
    for child in &overlay.children {
        let key = key_of(child, package);
        let found = base
            .children
            .iter()
            .position(|c| key_of(c, package) == key && (key.1.is_some() || is_singleton(&key.0)));
        match (tools_node(child), found) {
            (Some("remove" | "removeAll"), Some(i)) => {
                base.children.remove(i);
            }
            (Some("remove" | "removeAll"), None) => {}
            (Some("replace"), Some(i)) => base.children[i] = child.clone(),
            (_, Some(i)) => {
                let target = &mut base.children[i];
                merge_attrs(target, child);
                if child.local == "application" {
                    merge_children(target, child, package);
                } else {
                    target.children.extend(child.children.iter().cloned());
                }
            }
            (_, None) => base.children.push(child.clone()),
        }
    }
}

fn is_singleton(tag: &str) -> bool {
    matches!(tag, "application" | "uses-sdk")
}

/// Убирает элементы с `tools:node="remove"`/`"removeAll"` (они удаляют что-то из библиотек, а не
/// объявляют своё).
fn strip_removed(e: &mut XmlElement) {
    e.children
        .retain(|c| !matches!(tools_node(c), Some("remove" | "removeAll")));
    for c in &mut e.children {
        strip_removed(c);
    }
}

/// Ресурсы `values/` модуля: (тип, имя) → (значение, где). Переопределённые в `values-*/` — неоднозначны.
#[derive(Default)]
struct Values {
    known: BTreeMap<(String, String), (String, String)>,
    qualified: HashSet<(String, String)>,
}

fn module_values(project: &Project, module: &Module, sets: &[String]) -> Values {
    let mut values = Values::default();
    for set in sets {
        let res = module.path(&format!("src/{set}/res/"));
        for (path, text) in project.texts.range(res.clone()..) {
            let Some(rest) = path.strip_prefix(&res) else {
                break;
            };
            let Some((dir, file)) = rest.split_once('/') else {
                continue;
            };
            if !dir.starts_with("values") || file.contains('/') || !file.ends_with(".xml") {
                continue;
            }
            let Ok(doc) = xml::parse(text, 0, &xml::Limits::default()) else {
                continue;
            };
            if doc.root.local != "resources" {
                continue;
            }
            for item in &doc.root.children {
                let kind = match item.local.as_str() {
                    "bool" | "integer" | "string" => item.local.clone(),
                    "item" => match item.plain("type") {
                        Some(t) => t.value.clone(),
                        None => continue,
                    },
                    _ => continue,
                };
                let Some(name) = item.plain("name") else {
                    continue;
                };
                let key = (kind, name.value.clone());
                if dir == "values" {
                    values.known.insert(
                        key,
                        (
                            item.text.trim().to_string(),
                            format!("{path}:{}", item.pos.line),
                        ),
                    );
                } else {
                    values.qualified.insert(key);
                }
            }
        }
    }
    values
}

/// Подставляет плейсхолдеры и ссылки на ресурсы в значения атрибутов.
fn resolve_values(
    e: &mut XmlElement,
    placeholders: &gradle_rules::Placeholders,
    values: &Values,
    unresolved: &mut Vec<(String, String)>,
) {
    for a in &mut e.attributes {
        resolve_attr(a, placeholders, values, unresolved);
    }
    for c in &mut e.children {
        resolve_values(c, placeholders, values, unresolved);
    }
}

fn resolve_attr(
    a: &mut XmlAttr,
    placeholders: &gradle_rules::Placeholders,
    values: &Values,
    unresolved: &mut Vec<(String, String)>,
) {
    if a.value.contains("${") {
        let mut out = String::new();
        let mut rest = a.value.as_str();
        let mut notes = Vec::new();
        let mut complete = true;
        while let Some(open) = rest.find("${") {
            out.push_str(&rest[..open]);
            let after = &rest[open + 2..];
            let Some(close) = after.find('}') else {
                out.push_str(&rest[open..]);
                rest = "";
                complete = false;
                break;
            };
            let name = &after[..close];
            match placeholders.known.get(name) {
                Some((value, at)) => {
                    out.push_str(value);
                    notes.push(format!("manifestPlaceholders {name} = {value} at {at}"));
                }
                None => {
                    complete = false;
                    out.push_str(&rest[open..open + 3 + close]);
                    if unresolved.len() < 200 {
                        unresolved.push((
                            a.local.clone(),
                            format!(
                                "{} = ${{{}}}: the release value of this manifest placeholder is \
                                 not a literal in Gradle",
                                a.qualified(),
                                ui::sanitize_line(name)
                            ),
                        ));
                    }
                }
            }
            rest = &after[close + 1..];
        }
        out.push_str(rest);
        if complete {
            a.value = out;
            a.note = Some(notes.join("; "));
        }
        return;
    }
    if let Some(reference) = a.value.strip_prefix('@')
        && let Some((kind, name)) = reference.split_once('/')
        && matches!(kind, "bool" | "integer" | "string")
    {
        let key = (kind.to_string(), name.to_string());
        if values.qualified.contains(&key) {
            return;
        }
        if let Some((value, at)) = values.known.get(&key) {
            a.note = Some(format!("@{kind}/{name} = {value} at {at}"));
            a.value = value.clone();
        }
    }
}

/// Карта «элемент модели → место в исходнике».
struct Locator<'a> {
    root: &'a XmlElement,
    files: &'a [String],
    package: Option<&'a str>,
}

impl Locator<'_> {
    fn application(&self) -> Option<&XmlElement> {
        self.root.children.iter().find(|c| c.local == "application")
    }

    fn file(&self, pos: Pos) -> String {
        self.files.get(pos.file).cloned().unwrap_or_default()
    }

    /// Значение `tools:ignore` компонента, если оно гасит lint-предупреждение об экспорте
    /// (`ExportedService`, `ExportedReceiver`, `ExportedContentProvider`, `ExportedActivity`).
    fn lint_ignored_export(&self, component: &str) -> Option<String> {
        let (kind, name) = component.split_once(' ')?;
        let wanted = qualify(self.package, name);
        let e = self.application()?.children.iter().find(|c| {
            c.local == kind
                && c.android("name")
                    .is_some_and(|n| qualify(self.package, &n.value) == wanted)
        })?;
        let value = e.attr_ns(TOOLS_NS, "ignore")?.value.clone();
        value
            .split(',')
            .any(|v| v.trim().starts_with("Exported") || v.trim() == "all")
            .then_some(value)
    }

    /// Место находки по компоненту из APK-правила (`application`, `service .S`, `uses-permission X`).
    fn locate(&self, rule: &str, component: &str) -> (Pos, Option<String>) {
        let app = self.application();
        if component == "application" {
            let attr = match rule {
                mr::DEBUG_ID => "debuggable",
                mr::BACKUP_ID => "allowBackup",
                net::NET_ID => "usesCleartextTraffic",
                _ => "",
            };
            if let Some(a) = app.and_then(|a| a.android(attr)) {
                return (a.pos, a.note.clone());
            }
            return (app.map_or(self.root.pos, |a| a.pos), None);
        }
        if let Some(rest) = component.strip_prefix("uses-permission") {
            let name = rest.trim();
            let found = self.root.children.iter().find(|c| {
                c.local.starts_with("uses-permission")
                    && (name.is_empty() || c.android("name").is_some_and(|n| n.value == name))
            });
            return (found.map_or(self.root.pos, |e| e.pos), None);
        }
        if let Some((kind, name)) = component.split_once(' ')
            && let Some(app) = app
        {
            let wanted = qualify(self.package, name);
            if let Some(e) = app.children.iter().find(|c| {
                c.local == kind
                    && c.android("name")
                        .is_some_and(|n| qualify(self.package, &n.value) == wanted)
            }) {
                let note = e.android("exported").and_then(|a| a.note.clone());
                return (e.pos, note);
            }
        }
        (self.root.pos, None)
    }
}

/// Место находки в network security config.
fn locate_config(doc: &XmlDoc, component: &str) -> Pos {
    let root = &doc.root;
    let mut all: Vec<(&XmlElement, bool)> = Vec::new();
    let mut work: Vec<(&XmlElement, bool)> = vec![(root, false)];
    while let Some((e, in_debug)) = work.pop() {
        all.push((e, in_debug));
        for c in e.children.iter().rev() {
            work.push((c, in_debug || c.local == "debug-overrides"));
        }
    }
    let attr_true = |e: &XmlElement| {
        e.plain("cleartextTrafficPermitted")
            .filter(|a| a.value.eq_ignore_ascii_case("true"))
            .map(|a| a.pos)
    };
    let user_cert = |e: &XmlElement| {
        e.local == "certificates" && e.plain("src").is_some_and(|s| s.value == "user")
    };
    let found = if component.starts_with("base-config cleartext") {
        all.iter()
            .find(|(e, _)| e.local == "base-config")
            .and_then(|(e, _)| attr_true(e))
    } else if component.starts_with("base-config") {
        all.iter()
            .find(|(e, _)| e.local == "base-config")
            .map(|(e, _)| e.pos)
    } else if component.starts_with("domain-config") {
        all.iter()
            .filter(|(e, _)| e.local == "domain-config")
            .find_map(|(e, _)| attr_true(e))
    } else if component.starts_with("trust-anchors") {
        all.iter()
            .find(|(e, d)| !d && user_cert(e))
            .map(|(e, _)| e.pos)
    } else if component.starts_with("debug-overrides") {
        all.iter()
            .find(|(e, d)| *d && user_cert(e))
            .map(|(e, _)| e.pos)
    } else {
        None
    };
    found.unwrap_or(root.pos)
}

fn convert(
    f: ApkFinding,
    path: String,
    pos: Pos,
    note: Option<String>,
    module: &Module,
) -> AndroidFinding {
    let rule = rule_for(f.rule_id);
    let component = f.location.component.clone();
    let key = format!("{}\0{}", component.as_deref().unwrap_or(""), f.title);
    let mut tags: Vec<String> = vec!["android-source".into()];
    tags.extend(f.tags.into_iter().filter(|t| t != "apk"));
    tags.push(format!("module:{}", module.display_name()));
    let mut explanation = f.explanation;
    if let Some(note) = note.filter(|n| !n.is_empty()) {
        explanation.push_str(&format!(
            " The value was resolved from {}.",
            ui::sanitize_line(&note)
        ));
    }
    AndroidFinding {
        id: finding_id(rule, &path, &key),
        rule_id: rule,
        title: f.title,
        category: f.category,
        severity: f.severity,
        confidence: f.confidence,
        location: AndroidLocation {
            relative_path: path,
            line: (pos.line > 0).then_some(pos.line),
            column: (pos.line > 0 && pos.column > 0).then_some(pos.column),
            component,
        },
        evidence: Evidence {
            redacted_excerpt: f.evidence.redacted_excerpt,
            fingerprint: f.evidence.fingerprint,
        },
        explanation,
        remediation_id: f.remediation_id.map(|r| match r.split_once(':') {
            Some((_, rest)) => format!("{rule}:{rest}"),
            None => format!("{rule}:{r}"),
        }),
        references: f.references,
        cwe_ids: f.cwe_ids,
        tags,
    }
}

fn sdk_value(module_value: &SdkValue, declared: Option<i32>) -> (Option<i32>, Option<String>) {
    match module_value {
        SdkValue::Known { value, .. } => (Some(*value), None),
        SdkValue::Unknown(reason) => match declared {
            Some(v) => (Some(v), None),
            None => (None, Some(reason.clone())),
        },
    }
}

/// Правила манифеста по одному модулю.
pub fn check(project: &Project, module: &Module) -> (RuleOutput, ModuleManifest, Vec<String>) {
    let mut out = RuleOutput::default();
    let mut info = ModuleManifest::default();
    let mut limitations = Vec::new();
    if !matches!(
        module.kind,
        ModuleKind::Application | ModuleKind::Library | ModuleKind::DynamicFeature
    ) {
        return (out, info, limitations);
    }
    let rules: &[&'static str] = if module.kind == ModuleKind::Application {
        MANIFEST_RULES
    } else {
        &[EXPORT_ID, PERMS_ID]
    };
    let manifests = module_manifests(project, module);
    let mut files: Vec<String> = Vec::new();
    let mut base: Option<XmlDoc> = None;
    let mut overlays: Vec<XmlDoc> = Vec::new();
    let mut sets = Vec::new();
    let mut problems: Vec<String> = Vec::new();
    for (set, path) in &manifests {
        let role = set_role(set);
        if matches!(role, SetRole::Debug | SetRole::Test) {
            info.not_merged.push(path.clone());
            continue;
        }
        let Some(text) = project.texts.get(path) else {
            problems.push(format!("{}: not read", ui::sanitize_line(path)));
            continue;
        };
        match xml::parse(text, files.len(), &xml::Limits::default()) {
            Ok(doc) => {
                if !doc.issues.is_empty() {
                    limitations.push(format!(
                        "{}: {}",
                        ui::sanitize_line(path),
                        doc.issues.join("; ")
                    ));
                }
                files.push(path.clone());
                sets.push(set.clone());
                if role == SetRole::Main && base.is_none() {
                    base = Some(doc);
                } else {
                    overlays.push(doc);
                }
            }
            Err(e) => problems.push(format!("{}: {}", ui::sanitize_line(path), e.describe())),
        }
    }
    let Some(mut base) = base else {
        let why = if problems.is_empty() {
            "no src/main/AndroidManifest.xml".to_string()
        } else {
            problems.join("; ")
        };
        if !problems.is_empty() || module.kind == ModuleKind::Application {
            for rule in rules {
                out.partial.push((
                    rule,
                    format!("module {}: {why}", ui::sanitize_line(module.display_name())),
                ));
            }
        }
        return (out, info, limitations);
    };
    for p in &problems {
        for rule in rules {
            out.partial.push((rule, p.clone()));
        }
    }
    if base.root.local != "manifest" {
        for rule in rules {
            out.partial.push((
                rule,
                format!(
                    "{}: the root element is not <manifest>",
                    ui::sanitize_line(&files[0])
                ),
            ));
        }
        return (out, info, limitations);
    }
    let package_attr = base.root.plain("package").map(|a| a.value.clone());
    let package = package_attr
        .clone()
        .or_else(|| module.namespace.clone())
        .or_else(|| module.application_id.clone());
    for overlay in &overlays {
        if overlay.root.local != "manifest" {
            continue;
        }
        merge_attrs(&mut base.root, &overlay.root);
        merge_children(&mut base.root, &overlay.root, package.as_deref());
    }
    strip_removed(&mut base.root);
    info.merged = files.clone();
    let placeholders = gradle_rules::placeholders(project, module);
    let values = module_values(project, module, &sets);
    let mut unresolved = Vec::new();
    resolve_values(&mut base.root, &placeholders, &values, &mut unresolved);
    let document = xml::to_document(&base);
    let Some(mut manifest) = apk_manifest::from_document(&document) else {
        return (out, info, limitations);
    };
    if manifest.package.is_none() {
        manifest.package = package.clone();
    }
    info.package = manifest.package.clone();

    // SDK: Gradle важнее <uses-sdk>; не узнали — допущение и partial.
    let declared_min = manifest.sdk.min_declared.then_some(manifest.sdk.min);
    let declared_target = manifest.sdk.target_declared.then_some(manifest.sdk.target);
    let (mut min, min_why) = sdk_value(&module.min_sdk, declared_min);
    let (mut target, target_why) = sdk_value(&module.target_sdk, declared_target);
    let mut sdk_notes: Vec<String> = Vec::new();
    if min.is_none()
        && let Some((v, at)) = project.convention("minSdk")
    {
        min = Some(v as i32);
        limitations.push(format!(
            "module {}: minSdk {v} taken from {at} (convention/shared Gradle code, best effort)",
            ui::sanitize_line(module.display_name())
        ));
    }
    if target.is_none()
        && let Some((v, at)) = project.convention("targetSdk")
    {
        target = Some(v as i32);
        limitations.push(format!(
            "module {}: targetSdk {v} taken from {at} (convention/shared Gradle code, best effort)",
            ui::sanitize_line(module.display_name())
        ));
    }
    // Библиотека: её манифест сливается в приложение, и действует targetSdk приложения.
    if target.is_none() && module.kind != ModuleKind::Application {
        let apps: Vec<(i32, &str)> = project
            .modules
            .iter()
            .filter(|m| m.kind == ModuleKind::Application)
            .filter_map(|m| m.target_sdk.value().map(|v| (v, m.display_name())))
            .collect();
        if let Some(&(v, app)) = apps.first()
            && apps.iter().all(|(x, _)| *x == v)
        {
            target = Some(v);
            limitations.push(format!(
                "module {}: targetSdk {v} of application module {} was used (a library's manifest is \
                 merged into the app)",
                ui::sanitize_line(module.display_name()),
                ui::sanitize_line(app)
            ));
        }
    }
    // Ничего не задано и модуль на стандартном плагине: значения по умолчанию AGP (min 1, target = min).
    let plain_defaults = !module.convention
        && !module.sdk_mentioned
        && matches!(&module.min_sdk, SdkValue::Unknown(r) if r == "not set")
        && matches!(&module.target_sdk, SdkValue::Unknown(r) if r == "not set");
    let (min_value, target_value) = match (min, target) {
        (Some(m), Some(t)) => (m, t),
        (Some(m), None) if plain_defaults => (m, m),
        (None, None) if plain_defaults => (1, 1),
        (m, t) => {
            if m.is_none() {
                sdk_notes.push(format!(
                    "minSdk is unknown ({}); assumed {ASSUMED_MIN}",
                    ui::sanitize_line(min_why.as_deref().unwrap_or("not set"))
                ));
            }
            if t.is_none() {
                sdk_notes.push(format!(
                    "targetSdk is unknown ({}); assumed {ASSUMED_TARGET}",
                    ui::sanitize_line(target_why.as_deref().unwrap_or("not set"))
                ));
            }
            (m.unwrap_or(ASSUMED_MIN), t.unwrap_or(ASSUMED_TARGET))
        }
    };
    let target_unknown = target.is_none() && !plain_defaults;
    let min_unknown = min.is_none() && !plain_defaults;
    manifest.sdk = apk_manifest::Sdk {
        min: min_value,
        target: target_value,
        min_declared: true,
        target_declared: true,
        unresolved: false,
    };
    info.min_sdk = (!min_unknown).then_some(min_value);
    info.target_sdk = (!target_unknown).then_some(target_value);

    let locator = Locator {
        root: &base.root,
        files: &files,
        package: manifest.package.as_deref(),
    };
    let label = ui::sanitize_line(module.display_name());

    let run = |apk_rule: &'static str,
               result: ApkOutput,
               configs: &[(net::NetworkConfig, XmlDoc)],
               nsc: Option<&str>,
               out: &mut RuleOutput| {
        let rule = rule_for(apk_rule);
        for reason in result.partial {
            out.partial.push((
                rule,
                format!("module {label}: {}", rewrite_reason(&reason, nsc)),
            ));
        }
        for mut f in result.findings {
            let entry = f.location.archive_entry.clone().unwrap_or_default();
            let component = f.location.component.clone().unwrap_or_default();
            // Библиотека: сводный список runtime-разрешений решает приложение (шум по модулям).
            if apk_rule == mr::PERMS_ID
                && module.kind != ModuleKind::Application
                && f.title.starts_with("Requests ")
                && f.title.contains("runtime")
            {
                continue;
            }
            // `tools:ignore="ExportedService"` и т. п.: разработчик подтвердил, что экспорт намеренный.
            if apk_rule == mr::EXPORT_ID
                && let Some(lint) = locator.lint_ignored_export(&component)
            {
                f.severity = crate::apk_audit::types::Severity::Info;
                f.confidence = crate::apk_audit::types::Confidence::NeedsReview;
                f.explanation.push_str(&format!(
                    " The manifest suppresses Android lint's warning for it (tools:ignore=\"{}\"), so \
                     the export is deliberate; what remains is to review how it handles input.",
                    ui::sanitize_line(&lint)
                ));
                f.tags.push("lint:suppressed".to_string());
            }
            let (path, pos, note) = match configs.iter().find(|(c, _)| c.entry == entry) {
                Some((_, doc)) => (entry.clone(), locate_config(doc, &component), None),
                None => {
                    let (pos, note) = locator.locate(apk_rule, &component);
                    (locator.file(pos), pos, note)
                }
            };
            out.findings.push(convert(f, path, pos, note, module));
        }
    };

    // Неразрешённый плейсхолдер мешает правилу, только если это атрибут, от которого оно зависит.
    let unresolved_reason = |out: &mut RuleOutput, rule: &'static str| {
        let relevant: &[&str] = match rule {
            DEBUG_ID => &["debuggable"],
            NET_ID => &[
                "usesCleartextTraffic",
                "networkSecurityConfig",
                "debuggable",
                "minSdkVersion",
                "targetSdkVersion",
            ],
            BACKUP_ID => &[
                "allowBackup",
                "fullBackupContent",
                "dataExtractionRules",
                "debuggable",
                "targetSdkVersion",
            ],
            EXPORT_ID => &[
                "exported",
                "enabled",
                "permission",
                "readPermission",
                "writePermission",
                "protectionLevel",
                "grantUriPermissions",
                "targetSdkVersion",
            ],
            _ => &[],
        };
        let mut shown = 0;
        for (attr, u) in &unresolved {
            if !relevant.contains(&attr.as_str()) {
                continue;
            }
            shown += 1;
            if shown > 5 {
                break;
            }
            out.partial.push((rule, format!("module {label}: {u}")));
        }
    };

    // DEBUG-002: литерал манифеста; затем учитываем Gradle для последствий (NET/BACKUP).
    if rules.contains(&DEBUG_ID) {
        run(mr::DEBUG_ID, mr::debuggable(&manifest), &[], None, &mut out);
        if let Some((_, Ok(true))) = gradle_rules::release_debuggable(project, module)
            && let Some(app) = manifest.application.as_mut()
        {
            app.debuggable = Flag::True;
        }
    }
    if rules.contains(&EXPORT_ID) {
        run(mr::EXPORT_ID, mr::exported(&manifest), &[], None, &mut out);
        if target_unknown {
            out.partial.push((
                EXPORT_ID,
                format!("module {label}: {}", sdk_notes.join("; ")),
            ));
        }
        if !matches!(module.kind, ModuleKind::Application) {
            limitations.push(format!(
                "module {label} is a {}: its manifest was checked on its own with the app's SDK \
                 assumptions; components an app removes with tools:node=\"remove\" are not known here",
                module.kind.label()
            ));
        }
    }
    if rules.contains(&NET_ID) {
        let nsc = locator
            .application()
            .and_then(|a| a.android("networkSecurityConfig"))
            .map(|a| a.value.clone());
        let mut configs: Vec<(net::NetworkConfig, XmlDoc)> = Vec::new();
        if let Some(name) = nsc.as_deref().and_then(|v| v.strip_prefix("@xml/")) {
            // Наборы в обратном порядке: release/flavor перекрывают main.
            for set in sets.iter().rev() {
                let path = module.path(&format!("src/{set}/res/xml/{name}.xml"));
                let Some(text) = project.texts.get(&path) else {
                    continue;
                };
                match xml::parse(text, 0, &xml::Limits::default()) {
                    Ok(doc) => {
                        if let Some(cfg) = net::parse_config(&path, &xml::to_document(&doc)) {
                            info.network_config = Some(path.clone());
                            configs.push((cfg, doc));
                        }
                    }
                    Err(e) => out.partial.push((
                        NET_ID,
                        format!("{}: {}", ui::sanitize_line(&path), e.describe()),
                    )),
                }
                break;
            }
        }
        let only: Vec<net::NetworkConfig> = configs.iter().map(|(c, _)| c.clone()).collect();
        run(
            net::NET_ID,
            net::check(&manifest, &only),
            &configs,
            nsc.as_deref(),
            &mut out,
        );
        unresolved_reason(&mut out, NET_ID);
        if !sdk_notes.is_empty() && (target_unknown || (min_unknown && !configs.is_empty())) {
            out.partial
                .push((NET_ID, format!("module {label}: {}", sdk_notes.join("; "))));
        }
    }
    if rules.contains(&BACKUP_ID) {
        run(mr::BACKUP_ID, mr::backup(&manifest), &[], None, &mut out);
        unresolved_reason(&mut out, BACKUP_ID);
        if target_unknown {
            out.partial.push((
                BACKUP_ID,
                format!("module {label}: {}", sdk_notes.join("; ")),
            ));
        }
    }
    if rules.contains(&PERMS_ID) {
        run(
            mr::PERMS_ID,
            mr::permissions(&manifest),
            &[],
            None,
            &mut out,
        );
    }
    if rules.contains(&DEBUG_ID) {
        unresolved_reason(&mut out, DEBUG_ID);
    }
    if rules.contains(&EXPORT_ID) {
        unresolved_reason(&mut out, EXPORT_ID);
    }
    // Дедуп одинаковых причин.
    let mut seen = HashSet::new();
    out.partial.retain(|p| seen.insert(p.clone()));
    (out, info, limitations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_roles() {
        assert_eq!(set_role("main"), SetRole::Main);
        assert_eq!(set_role("release"), SetRole::Overlay);
        assert_eq!(set_role("fdroid"), SetRole::Overlay);
        assert_eq!(set_role("freeDebug"), SetRole::Debug);
        assert_eq!(set_role("androidTest"), SetRole::Test);
        assert_eq!(set_role("testDebug"), SetRole::Test);
    }

    #[test]
    fn reasons_are_rewritten_for_sources() {
        assert_eq!(
            rewrite_reason(
                "android:debuggable is a resource reference (resources.arsc is not parsed)",
                None
            ),
            "android:debuggable is not a literal (an unresolved resource reference or manifest placeholder)"
        );
        assert!(
            rewrite_reason(
                "the manifest references a network security config, but …",
                Some("@xml/n")
            )
            .contains("@xml/n")
        );
    }
}
