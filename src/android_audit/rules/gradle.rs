//! Правила по Gradle-скриптам: ANDROID-DEBUG-002 (release `debuggable`), ANDROID-MINIFY-007
//! (release без R8), ANDROID-SIGNING-008 (пароли подписи литералами) и данные для правил
//! манифеста (плейсхолдеры `manifestPlaceholders` release-сборки).
//!
//! Что такое «release»: блок `buildTypes { release { … } }` (`getByName("release")`, `named("release")`)
//! и блоки для всех типов сборки (`all { }`, `configureEach { }`). Операторы модуля важнее операторов
//! convention-плагинов (`build-logic`, `buildSrc`), корня (`subprojects { }`) и подключаемых скриптов.
//! Значение — только литерал; иначе — `partial`, а не догадка.

use super::{DEBUG_ID, MINIFY_ID, New, REF_MASVS, RuleOutput, SIGNING_ID};
use crate::android_audit::gradle::{Arg, GValue, Stmt};
use crate::android_audit::project::{Module, ModuleKind, Project, line_of};
use crate::android_audit::types::{Confidence, Severity};
use crate::secrets;
use crate::ui;
use std::collections::BTreeMap;

const REF_BUILD_TYPES: &str = "https://developer.android.com/build/build-variants#build-types";
const REF_SHRINK: &str = "https://developer.android.com/build/shrink-code";
const REF_SIGNING: &str =
    "https://developer.android.com/studio/publish/app-signing#secure-shared-keystore";

/// Оператор и файл, где он записан.
#[derive(Clone, Copy)]
pub struct Located<'a> {
    pub path: &'a str,
    pub stmt: &'a Stmt,
    /// Из файла модуля (а не из convention-плагина/корня).
    pub own: bool,
}

impl Located<'_> {
    pub fn position(&self, project: &Project) -> (u32, u32) {
        project
            .texts
            .get(self.path)
            .map_or((1, 1), |t| line_of(t, self.stmt.start))
    }

    pub fn at(&self, project: &Project) -> String {
        format!("{}:{}", self.path, self.position(project).0)
    }
}

fn is_release(stmt: &Stmt) -> bool {
    matches!(stmt.child_of("buildTypes"), Some("release" | "*")) && !stmt.in_block("productFlavors")
}

/// Операторы release-сборки модуля: сначала свои, потом общие.
pub fn release_stmts<'a>(project: &'a Project, module: &'a Module) -> Vec<Located<'a>> {
    let mut out = Vec::new();
    if let Some(file) = project.gradle.get(&module.build_file) {
        out.extend(
            file.stmts
                .iter()
                .filter(|s| is_release(s))
                .map(|s| Located {
                    path: &module.build_file,
                    stmt: s,
                    own: true,
                }),
        );
    }
    out.extend(
        project
            .shared_for(module)
            .into_iter()
            .filter(|(_, s)| is_release(s))
            .map(|(p, s)| Located {
                path: p,
                stmt: s,
                own: false,
            }),
    );
    out
}

/// Первое присваивание свойства из списка имён (`isMinifyEnabled`, `minifyEnabled`, `setMinifyEnabled`).
fn property<'a>(stmts: &[Located<'a>], names: &[&str]) -> Option<(Located<'a>, &'a Arg)> {
    // Свои операторы важнее общих; среди своих — последний (Gradle применяет по порядку).
    let pick = |own: bool| {
        stmts
            .iter()
            .filter(|l| {
                l.own == own
                    && names.iter().any(|n| {
                        l.stmt.target == *n
                            // AGP 9: `optimization { enable = true }`.
                            || (*n == "optimization.enable"
                                && l.stmt.target == "enable"
                                && l.stmt.directly_in("optimization"))
                    })
            })
            .filter_map(|l| l.stmt.args.first().map(|a| (*l, a)))
            .next_back()
    };
    pick(true).or_else(|| pick(false))
}

/// Значения `manifestPlaceholders` для release: defaultConfig, затем release (перекрывает).
#[derive(Clone, Debug, Default)]
pub struct Placeholders {
    /// Имя → (значение, где задано).
    pub known: BTreeMap<String, (String, String)>,
    /// Заданы не литералом (или картой-переменной) — значение неизвестно.
    pub unknown: Vec<String>,
    /// `manifestPlaceholders = someMap`: вся карта неизвестна.
    pub opaque: bool,
}

fn literal_text(arg: &Arg) -> Option<String> {
    match &arg.value {
        GValue::Str(s) => Some(s.clone()),
        GValue::Bool(b) => Some(b.to_string()),
        GValue::Int(n) => Some(n.to_string()),
        _ => None,
    }
}

impl Placeholders {
    fn set(&mut self, name: &str, arg: &Arg, at: String) {
        match literal_text(arg) {
            Some(v) => {
                self.unknown.retain(|u| u != name);
                self.known.insert(name.to_string(), (v, at));
            }
            None => {
                self.known.remove(name);
                if !self.unknown.iter().any(|u| u == name) {
                    self.unknown.push(name.to_string());
                }
            }
        }
    }

    fn apply(&mut self, stmt: &Stmt, at: String) {
        let target = stmt.target.as_str();
        let map_arg = |arg: &Arg| match &arg.value {
            GValue::Map(map) => Some(map.clone()),
            _ => None,
        };
        if target == "manifestPlaceholders" {
            if let Some(key) = &stmt.key {
                if let Some(arg) = stmt.args.first() {
                    self.set(key, arg, at);
                }
                return;
            }
            let Some(arg) = stmt.args.first() else { return };
            match map_arg(arg) {
                Some(map) => {
                    if stmt.op == crate::android_audit::gradle::Op::Assign {
                        self.known.clear();
                        self.unknown.clear();
                    }
                    for (k, v) in &map {
                        self.set(k, v, at.clone());
                    }
                }
                None => self.opaque = true,
            }
        } else if let Some(name) = target.strip_prefix("manifestPlaceholders.") {
            if name == "put" {
                if let [key, value] = stmt.args.as_slice()
                    && let Some(k) = key.as_str()
                {
                    self.set(k, value, at);
                }
            } else if name == "putAll" {
                match stmt.args.first().and_then(map_arg) {
                    Some(map) => map.iter().for_each(|(k, v)| self.set(k, v, at.clone())),
                    None => self.opaque = true,
                }
            } else if let Some(arg) = stmt.args.first() {
                self.set(name, arg, at);
            }
        } else if matches!(
            target,
            "addManifestPlaceholders" | "setManifestPlaceholders"
        ) {
            match stmt.args.first().and_then(map_arg) {
                Some(map) => map.iter().for_each(|(k, v)| self.set(k, v, at.clone())),
                None => self.opaque = true,
            }
        }
    }
}

fn is_placeholder_stmt(stmt: &Stmt) -> bool {
    stmt.target == "manifestPlaceholders"
        || stmt.target.starts_with("manifestPlaceholders.")
        || stmt.target == "addManifestPlaceholders"
        || stmt.target == "setManifestPlaceholders"
}

pub fn placeholders(project: &Project, module: &Module) -> Placeholders {
    let mut p = Placeholders::default();
    if let Some(id) = &module.application_id {
        p.known.insert(
            "applicationId".to_string(),
            (id.clone(), format!("{} applicationId", module.build_file)),
        );
    }
    let Some(file) = project.gradle.get(&module.build_file) else {
        return p;
    };
    let at = |s: &Stmt| {
        let line = project
            .texts
            .get(&module.build_file)
            .map_or(1, |t| line_of(t, s.start).0);
        format!("{}:{line}", module.build_file)
    };
    for stmt in file
        .stmts
        .iter()
        .filter(|s| s.in_block("defaultConfig") && is_placeholder_stmt(s))
    {
        p.apply(stmt, at(stmt));
    }
    for located in release_stmts(project, module) {
        if is_placeholder_stmt(located.stmt) {
            p.apply(located.stmt, located.at(project));
        }
    }
    p
}

/// release `debuggable`: `Some(Ok(true))` — литерал true; `Some(Err(expr))` — не литерал.
pub fn release_debuggable<'a>(
    project: &'a Project,
    module: &'a Module,
) -> Option<(Located<'a>, Result<bool, String>)> {
    let stmts = release_stmts(project, module);
    let (loc, arg) = property(&stmts, &["debuggable", "isDebuggable", "setDebuggable"])?;
    Some((loc, arg.as_bool().ok_or_else(|| arg.describe())))
}

fn excerpt(project: &Project, loc: &Located) -> String {
    let text = project
        .texts
        .get(loc.path)
        .map(String::as_str)
        .unwrap_or("");
    let end = loc.stmt.end.min(text.len());
    let start = loc.stmt.start.min(end);
    let raw = text.get(start..end).unwrap_or("");
    // Значения строк в фрагменте не показываем (`"…"`), кроме true/false и чисел.
    redact_strings(raw)
}

/// Заменяет содержимое строковых литералов на `…` (для фрагментов из Gradle).
pub fn redact_strings(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' || c == '\'' {
            out.push(c);
            out.push('…');
            let mut escaped = false;
            for d in chars.by_ref() {
                if escaped {
                    escaped = false;
                    continue;
                }
                if d == '\\' {
                    escaped = true;
                    continue;
                }
                if d == c {
                    break;
                }
            }
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out
}

/// ANDROID-DEBUG-002 (Gradle): release-сборка `debuggable true`.
pub fn debug(project: &Project, module: &Module) -> RuleOutput {
    let mut out = RuleOutput::default();
    if module.kind != ModuleKind::Application {
        return out;
    }
    let Some((loc, value)) = release_debuggable(project, module) else {
        return out;
    };
    match value {
        Ok(true) => {
            let (line, column) = loc.position(project);
            let block = loc.stmt.child_of("buildTypes").unwrap_or("release");
            out.findings.push(
                New {
                    rule: DEBUG_ID,
                    category: "debug_build",
                    title: "Release build type is debuggable".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::Potential,
                    path: loc.path,
                    line: Some(line),
                    column: Some(column),
                    component: Some(format!("buildTypes.{block}")),
                    excerpt: Some(excerpt(project, &loc)),
                    fingerprint: None,
                    key: format!("buildTypes.{block}\0{}", loc.stmt.target),
                    explanation: format!(
                        "The {} build type sets {} = true, so Gradle marks the release APK as \
                         android:debuggable=\"true\": a debugger can attach on any device, `run-as` \
                         gives a shell with the app's data and debug-overrides of the network security \
                         config take effect.{} Potential: check whether this build is really shipped.",
                        if block == "*" { "every" } else { "release" },
                        loc.stmt.target,
                        if loc.own {
                            String::new()
                        } else {
                            format!(
                                " (set outside the module, for module {})",
                                ui::sanitize_line(module.display_name())
                            )
                        }
                    ),
                    remediation: "remove-debuggable",
                    references: vec![
                        REF_BUILD_TYPES,
                        "https://cwe.mitre.org/data/definitions/489.html",
                        REF_MASVS,
                    ],
                    cwe_ids: vec!["CWE-489"],
                    tags: vec![
                        "masvs:MASVS-RESILIENCE".into(),
                        format!("module:{}", module.display_name()),
                        "source:gradle".into(),
                    ],
                }
                .build(),
            );
        }
        Ok(false) => {}
        Err(expr) => out.partial.push((
            DEBUG_ID,
            format!(
                "{}: release {} = {} is not a literal",
                loc.at(project),
                loc.stmt.target,
                ui::sanitize_line(&expr)
            ),
        )),
    }
    out
}

/// ANDROID-MINIFY-007: release-сборка приложения без R8 (`minifyEnabled`/`isMinifyEnabled`).
pub fn minify(project: &Project, module: &Module) -> RuleOutput {
    let mut out = RuleOutput::default();
    if module.kind != ModuleKind::Application {
        return out;
    }
    let stmts = release_stmts(project, module);
    let found = property(
        &stmts,
        &[
            "minifyEnabled",
            "isMinifyEnabled",
            "setMinifyEnabled",
            "optimization.enable",
        ],
    );
    let file = project.gradle.get(&module.build_file);
    let text = project
        .texts
        .get(&module.build_file)
        .map(String::as_str)
        .unwrap_or("");
    let (path, line, column, how, excerpt_text) = match found {
        Some((loc, arg)) => match arg.as_bool() {
            Some(true) => return out,
            Some(false) => {
                let (line, column) = loc.position(project);
                (
                    loc.path,
                    line,
                    column,
                    format!("{} = false", loc.stmt.target),
                    Some(excerpt(project, &loc)),
                )
            }
            None => {
                out.partial.push((
                    MINIFY_ID,
                    format!(
                        "{}: release {} = {} is not a literal",
                        loc.at(project),
                        loc.stmt.target,
                        ui::sanitize_line(&arg.describe())
                    ),
                ));
                return out;
            }
        },
        None => {
            if module.convention {
                out.partial.push((
                    MINIFY_ID,
                    format!(
                        "module {} uses a convention plugin and no release minifyEnabled was found in \
                         build-logic/buildSrc; the release build type may be configured elsewhere",
                        ui::sanitize_line(module.display_name())
                    ),
                ));
                return out;
            }
            // Нет оператора — по умолчанию false. Место: блок release, иначе buildTypes, иначе android.
            let block = file.and_then(|f| {
                ["release", "buildTypes", "android"]
                    .iter()
                    .find_map(|name| {
                        f.blocks
                            .iter()
                            .find(|b| b.path.last().is_some_and(|l| l == name))
                    })
            });
            let (line, column) = block.map_or((1, 1), |b| line_of(text, b.start));
            (
                module.build_file.as_str(),
                line,
                column,
                "minifyEnabled is not set for the release build type (the default is false)"
                    .to_string(),
                None,
            )
        }
    };
    out.findings.push(
        New {
            rule: MINIFY_ID,
            category: "resilience",
            title: "Release build is not minified or obfuscated (R8 off)".to_string(),
            severity: Severity::Low,
            confidence: Confidence::NeedsReview,
            path,
            line: Some(line),
            column: Some(column),
            component: Some("buildTypes.release".to_string()),
            excerpt: excerpt_text,
            fingerprint: None,
            key: "buildTypes.release\0minify".to_string(),
            explanation: format!(
                "{how}. Without R8 the release APK keeps original class/method names and unused code, \
                 which makes reverse engineering and repackaging easier and ships debug-only code. \
                 Minification is not a security control by itself and is sometimes off on purpose \
                 (e.g. F-Droid reproducible builds); enable it if nothing prevents it."
            ),
            remediation: "enable-r8",
            references: vec![REF_SHRINK, REF_MASVS],
            cwe_ids: Vec::new(),
            tags: vec![
                "masvs:MASVS-RESILIENCE".into(),
                format!("module:{}", module.display_name()),
                "source:gradle".into(),
            ],
        }
        .build(),
    );
    out
}

/// Пароль по умолчанию отладочного keystore Android — публичен.
const DEBUG_KEYSTORE_PASSWORD: &str = "android";

/// ANDROID-SIGNING-008 (Gradle): `storePassword`/`keyPassword` литералами в `signingConfigs`.
/// Возвращает и пути `storeFile` конфигов с литеральными паролями (для KEYSTORE-009).
pub fn signing(project: &Project) -> (RuleOutput, Vec<String>) {
    let mut out = RuleOutput::default();
    let mut keystores_with_passwords = Vec::new();
    for (path, file) in &project.gradle {
        let text = project.texts.get(path).map(String::as_str).unwrap_or("");
        let base_dir = path.rsplit_once('/').map_or("", |(d, _)| d);
        // storeFile каждого конфига (для связи с хранилищем ключей).
        let mut store_files: BTreeMap<String, String> = BTreeMap::new();
        for stmt in &file.stmts {
            let Some(config) = stmt.child_of("signingConfigs") else {
                continue;
            };
            if matches!(stmt.target.as_str(), "storeFile" | "setStoreFile")
                && let Some(arg) = stmt.args.first()
                && let GValue::Expr(tokens) = &arg.value
                && let Some(name) = tokens.iter().find_map(|t| t.literal_str())
            {
                let joined =
                    if base_dir.is_empty() || tokens.iter().any(|t| t.is_ident("rootProject")) {
                        name.to_string()
                    } else {
                        format!("{base_dir}/{name}")
                    };
                store_files.insert(config.to_string(), joined);
            }
        }
        for stmt in &file.stmts {
            let Some(config) = stmt.child_of("signingConfigs") else {
                continue;
            };
            let field = match stmt.target.as_str() {
                "storePassword" | "setStorePassword" => "storePassword",
                "keyPassword" | "setKeyPassword" => "keyPassword",
                _ => continue,
            };
            let Some(arg) = stmt.args.first() else {
                continue;
            };
            let Some(value) = arg.as_str() else {
                continue;
            };
            if value.is_empty() || secrets::rules::is_placeholder(value) {
                continue;
            }
            let default_debug = value == DEBUG_KEYSTORE_PASSWORD;
            if default_debug && config == "debug" {
                continue;
            }
            let (line, column) = line_of(text, arg.start);
            let masked = secrets::mask(value);
            let fingerprint = secrets::fingerprint(value);
            if let Some(store) = store_files.get(config)
                && !default_debug
            {
                keystores_with_passwords.push(store.clone());
            }
            let (severity, confidence, detail) = if default_debug {
                (
                    Severity::Low,
                    Confidence::NeedsReview,
                    " The value is the well-known password of Android's default debug keystore, so \
                     this config is probably a debug-only one: make sure release builds do not use it."
                        .to_string(),
                )
            } else {
                (
                    Severity::High,
                    Confidence::Potential,
                    " Anyone with the repository (and the keystore file, if it is committed too) can \
                     sign APKs as you, including updates that devices accept for your package."
                        .to_string(),
                )
            };
            out.findings.push(
                New {
                    rule: SIGNING_ID,
                    category: "secret_exposure",
                    title: format!("Signing {field} is hardcoded in a Gradle script"),
                    severity,
                    confidence,
                    path,
                    line: Some(line),
                    column: Some(column),
                    component: Some(format!("signingConfigs.{config}")),
                    excerpt: Some(format!("{} = {masked}", stmt.target)),
                    fingerprint: Some(fingerprint),
                    key: String::new(),
                    explanation: format!(
                        "signingConfigs.{} sets {field} to a literal value.{detail} Potential: whether \
                         the password is real and current is not checked. Load it from an environment \
                         variable or a git-ignored keystore.properties instead, and rotate the upload key \
                         if this file was ever pushed.",
                        ui::sanitize_line(config)
                    ),
                    remediation: "move-signing-secrets",
                    references: vec![
                        REF_SIGNING,
                        "https://cwe.mitre.org/data/definitions/798.html",
                        REF_MASVS,
                    ],
                    cwe_ids: vec!["CWE-798"],
                    tags: vec!["source:gradle".into(), format!("field:{field}")],
                }
                .build(),
            );
        }
    }
    keystores_with_passwords.sort();
    keystores_with_passwords.dedup();
    (out, keystores_with_passwords)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_redacted_in_excerpts() {
        assert_eq!(
            redact_strings(r#"buildConfigField("String", "K", "\"v\"")"#),
            r#"buildConfigField("…", "…", "…")"#
        );
        assert_eq!(redact_strings("minifyEnabled false"), "minifyEnabled false");
    }
}
