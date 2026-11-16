//! Структура iOS-проекта: `*.xcodeproj/project.pbxproj` (ASCII plist) → цели, конфигурации сборки и их
//! настройки; `*.xcconfig` (best effort: `KEY = value`, `#include`, без условий `[sdk=…]`); куда
//! указывают `INFOPLIST_FILE` и `CODE_SIGN_ENTITLEMENTS`. Только литералы: переменные, которых нет в
//! известных настройках, не вычисляются (путь становится «не разрешён», это отмечается).
//!
//! Без `project.pbxproj` (Swift Package, XcodeGen `project.yml`, Tuist `Project.swift`, папка только с
//! Info.plist) Info.plist и `.entitlements` находятся по имени файла, а конфигурация, в которую они
//! попадают, неизвестна.

use super::plist::{self, Node};
use super::walk::{Entry, FileKind};
use crate::ui;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub name: String,
    /// Debug-подобная: имя содержит `debug`, или `DEBUG` в условиях компиляции.
    pub debug: bool,
    /// Итоговые настройки (xcconfig проекта < проект < xcconfig цели < цель).
    pub settings: BTreeMap<String, String>,
    /// Путь к Info.plist от корня скана (`None` — не задан или не разрешён).
    pub info_plist: Option<String>,
    pub entitlements: Option<String>,
    /// `IPHONEOS_DEPLOYMENT_TARGET` (или macOS/tvOS/watchOS), как написано.
    pub deployment_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    pub product_type: Option<String>,
    pub configs: Vec<Config>,
}

impl Target {
    /// Цель тестов (unit/UI) — её Info.plist и entitlements не проверяются.
    pub fn is_test(&self) -> bool {
        self.product_type
            .as_deref()
            .is_some_and(|p| p.contains("test"))
            || self.name.ends_with("Tests")
            || self.name.ends_with("UITests")
    }

    /// Короткое имя вида продукта (`application`, `app-extension`, `unit-test`, …).
    pub fn kind(&self) -> &str {
        self.product_type
            .as_deref()
            .and_then(|p| p.strip_prefix("com.apple.product-type."))
            .unwrap_or("other")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XcodeProject {
    /// Путь к `project.pbxproj`.
    pub path: String,
    /// `SRCROOT`: каталог, где лежит `.xcodeproj` (`""` — корень скана).
    pub dir: String,
    /// Имя `.xcodeproj` без расширения.
    pub name: String,
    pub targets: Vec<Target>,
    /// Что не удалось разобрать/разрешить (идут в причины `partial` / ограничения).
    pub issues: Vec<String>,
}

/// Где используется файл (Info.plist / entitlements).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Usage {
    pub project: String,
    pub target: String,
    pub config: String,
    pub debug: bool,
    pub test: bool,
    pub deployment_target: Option<String>,
}

#[derive(Debug, Default)]
pub struct Project {
    pub entries: Vec<Entry>,
    pub texts: BTreeMap<String, String>,
    pub projects: Vec<XcodeProject>,
    /// pbxproj, которые не разобрались: (путь, причина).
    pub broken: Vec<(String, String)>,
    pub info_usage: BTreeMap<String, Vec<Usage>>,
    pub entitlements_usage: BTreeMap<String, Vec<Usage>>,
    pub has_package_swift: bool,
    /// Генераторы проектов, которые не разбираются: (путь, что это).
    pub generators: Vec<(String, &'static str)>,
}

/// Файлы, которые читаются на шаге структуры.
pub fn needs_structure_text(e: &Entry) -> bool {
    matches!(
        e.kind,
        FileKind::Pbxproj | FileKind::XcConfig | FileKind::GitIgnore
    )
}

/// Нормализует `a/./b/../c` относительно корня скана. `None` — путь выходит за корень или абсолютный.
pub fn normalize(path: &str) -> Option<String> {
    if path.starts_with('/') || path.contains(':') || path.starts_with('\\') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

fn join(dir: &str, rel: &str) -> Option<String> {
    if dir.is_empty() {
        normalize(rel)
    } else {
        normalize(&format!("{dir}/{rel}"))
    }
}

/// Значение настройки сборки строкой: список (`( "$(inherited)", DEBUG )`) — через пробел.
fn setting_text(n: &Node) -> String {
    match &n.value {
        plist::Value::Str(s) => s.clone(),
        plist::Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

/// `$(inherited)` в новом значении заменяется предыдущим.
fn merge(into: &mut BTreeMap<String, String>, from: &BTreeMap<String, String>) {
    for (k, v) in from {
        let prev = into.get(k).cloned().unwrap_or_default();
        let value = v
            .replace("$(inherited)", &prev)
            .replace("${inherited}", &prev)
            .trim()
            .to_string();
        into.insert(k.clone(), value);
    }
}

/// `xcconfig`: `KEY = value` без условий; `//` — комментарий (так считает и Xcode); `#include`.
pub fn parse_xcconfig(
    path: &str,
    texts: &BTreeMap<String, String>,
    depth: usize,
    issues: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(text) = texts.get(path) else {
        issues.push(format!("xcconfig {} was not read", ui::sanitize_line(path)));
        return out;
    };
    if depth > 8 {
        issues.push(format!(
            "xcconfig includes nest too deeply at {}",
            ui::sanitize_line(path)
        ));
        return out;
    }
    let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
    for raw in text.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if let Some(rest) = line
            .strip_prefix("#include?")
            .or_else(|| line.strip_prefix("#include"))
        {
            let optional = line.starts_with("#include?");
            let target = rest.trim().trim_matches('"');
            match join(dir, target).filter(|p| texts.contains_key(p)) {
                Some(p) => {
                    let inner = parse_xcconfig(&p, texts, depth + 1, issues);
                    merge(&mut out, &inner);
                }
                None if optional => {}
                None => issues.push(format!(
                    "xcconfig include {} from {} was not found",
                    ui::sanitize_line(target),
                    ui::sanitize_line(path)
                )),
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains('[') || key.contains(' ') {
            continue;
        }
        let mut one = BTreeMap::new();
        one.insert(key.to_string(), value.trim().to_string());
        merge(&mut out, &one);
    }
    out
}

/// `KEY = value` с позициями (для правил ключей): (ключ, значение, строка, колонка значения).
pub fn xcconfig_assignments(text: &str) -> Vec<(String, String, u32, u32)> {
    let mut out = Vec::new();
    for (i, raw) in text.split('\n').enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let line = raw.split("//").next().unwrap_or("");
        if line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let key = key.split('[').next().unwrap_or(key).trim();
        if key.is_empty() || key.contains(' ') {
            continue;
        }
        let lead = value.len() - value.trim_start().len();
        let value_byte = line.find('=').map_or(0, |e| e + 1 + lead);
        let column = raw[..value_byte.min(raw.len())].chars().count() as u32 + 1;
        out.push((
            key.to_string(),
            value.trim().to_string(),
            u32::try_from(i + 1).unwrap_or(u32::MAX),
            column,
        ));
    }
    out
}

struct Pbx<'a> {
    objects: &'a Node,
    /// Родитель каждого элемента дерева групп.
    parents: HashMap<&'a str, &'a str>,
}

impl<'a> Pbx<'a> {
    fn obj(&self, id: &str) -> Option<&'a Node> {
        self.objects.get(id)
    }

    fn isa(&self, id: &str) -> Option<&'a str> {
        self.obj(id)?.get("isa")?.as_str()
    }

    /// Путь файла из дерева групп относительно `SRCROOT`. `None` — абсолютный/вне проекта/SDK.
    fn file_path(&self, id: &str) -> Option<String> {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = id;
        for _ in 0..64 {
            let node = self.obj(cur)?;
            let tree = node
                .get("sourceTree")
                .and_then(Node::as_str)
                .unwrap_or("<group>");
            if let Some(p) = node.get("path").and_then(Node::as_str) {
                parts.push(p);
            }
            match tree {
                "<group>" => match self.parents.get(cur) {
                    Some(parent) => cur = parent,
                    None => break,
                },
                "SOURCE_ROOT" => break,
                _ => return None,
            }
        }
        parts.reverse();
        normalize(&parts.join("/"))
    }

    fn configs(
        &self,
        list_id: Option<&str>,
    ) -> Vec<(String, BTreeMap<String, String>, Option<String>)> {
        let mut out = Vec::new();
        let Some(list) = list_id.and_then(|id| self.obj(id)) else {
            return out;
        };
        for id in list
            .get("buildConfigurations")
            .map(Node::items)
            .unwrap_or_default()
            .iter()
            .filter_map(Node::as_str)
        {
            let Some(cfg) = self.obj(id) else { continue };
            let name = cfg
                .get("name")
                .and_then(Node::as_str)
                .unwrap_or("")
                .to_string();
            let settings = cfg
                .get("buildSettings")
                .map(|s| {
                    s.entries()
                        .iter()
                        .filter(|(k, _)| !k.name.contains('['))
                        .map(|(k, v)| (k.name.clone(), setting_text(v)))
                        .collect()
                })
                .unwrap_or_default();
            // Xcode 16: `baseConfigurationReferenceAnchor` (синхронизированная папка) +
            // `baseConfigurationReferenceRelativePath`.
            let anchored = || {
                let anchor = cfg.get("baseConfigurationReferenceAnchor")?.as_str()?;
                let rel = cfg
                    .get("baseConfigurationReferenceRelativePath")?
                    .as_str()?;
                let dir = self.file_path(anchor)?;
                join(&dir, rel)
            };
            let base = cfg
                .get("baseConfigurationReference")
                .and_then(Node::as_str)
                .and_then(|r| self.file_path(r))
                .or_else(anchored);
            out.push((name, settings, base));
        }
        out
    }
}

/// Раскрывает `$(VAR)` / `${VAR}` по известным настройкам. `None` — осталась неизвестная переменная.
pub fn expand(value: &str, vars: &BTreeMap<String, String>, depth: usize) -> Option<String> {
    if depth > 6 {
        return None;
    }
    let mut out = String::new();
    let mut rest = value;
    loop {
        let open = match (rest.find("$("), rest.find("${")) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => break,
        };
        out.push_str(&rest[..open]);
        let close_char = if rest[open + 1..].starts_with('(') {
            ')'
        } else {
            '}'
        };
        let after = &rest[open + 2..];
        let close = after.find(close_char)?;
        let name = &after[..close];
        // Модификаторы `$(PRODUCT_NAME:c99extidentifier)` — берём имя.
        let base = name.split(':').next().unwrap_or(name);
        let v = vars.get(base)?;
        out.push_str(&expand(v, vars, depth + 1)?);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn is_debug_config(name: &str, settings: &BTreeMap<String, String>) -> bool {
    if name.to_ascii_lowercase().contains("debug") {
        return true;
    }
    let conditions = settings
        .get("SWIFT_ACTIVE_COMPILATION_CONDITIONS")
        .map(String::as_str)
        .unwrap_or("");
    let defines = settings
        .get("GCC_PREPROCESSOR_DEFINITIONS")
        .map(String::as_str)
        .unwrap_or("");
    conditions.split_whitespace().any(|c| c == "DEBUG")
        || defines
            .split_whitespace()
            .any(|d| d == "DEBUG" || d == "DEBUG=1")
}

fn parse_project(
    path: &str,
    text: &str,
    texts: &BTreeMap<String, String>,
) -> Result<XcodeProject, String> {
    let parsed = plist::parse(text).map_err(|e| e.describe())?;
    let root = &parsed.root;
    let objects = root
        .get("objects")
        .ok_or("project.pbxproj has no 'objects' dictionary")?;
    let mut parents = HashMap::new();
    for (key, node) in objects.entries() {
        for child in node
            .get("children")
            .map(Node::items)
            .unwrap_or_default()
            .iter()
            .filter_map(Node::as_str)
        {
            parents.insert(child, key.name.as_str());
        }
    }
    let pbx = Pbx { objects, parents };
    let xcodeproj_dir = path.rsplit_once('/').map_or("", |(d, _)| d);
    let dir = xcodeproj_dir
        .rsplit_once('/')
        .map_or("", |(d, _)| d)
        .to_string();
    let name = xcodeproj_dir
        .rsplit('/')
        .next()
        .unwrap_or(xcodeproj_dir)
        .trim_end_matches(".xcodeproj")
        .to_string();
    let mut issues = Vec::new();
    let root_id = root
        .get("rootObject")
        .and_then(Node::as_str)
        .ok_or("project.pbxproj has no rootObject")?;
    let proj = pbx.obj(root_id).ok_or("rootObject is not in 'objects'")?;
    let project_dir = proj
        .get("projectDirPath")
        .and_then(Node::as_str)
        .filter(|p| !p.is_empty())
        .and_then(|p| join(&dir, p))
        .unwrap_or_else(|| dir.clone());
    let read_base = |base: &Option<String>, issues: &mut Vec<String>| -> BTreeMap<String, String> {
        match base {
            Some(rel) => match join(&project_dir, rel) {
                Some(p) => parse_xcconfig(&p, texts, 0, issues),
                None => BTreeMap::new(),
            },
            None => BTreeMap::new(),
        }
    };
    let project_configs = pbx.configs(proj.get("buildConfigurationList").and_then(Node::as_str));
    let mut targets = Vec::new();
    for tid in proj
        .get("targets")
        .map(Node::items)
        .unwrap_or_default()
        .iter()
        .filter_map(Node::as_str)
    {
        let Some(t) = pbx.obj(tid) else { continue };
        if !matches!(
            pbx.isa(tid),
            Some("PBXNativeTarget" | "PBXAggregateTarget" | "PBXLegacyTarget")
        ) {
            continue;
        }
        let tname = t
            .get("name")
            .and_then(Node::as_str)
            .unwrap_or("")
            .to_string();
        let product_type = t
            .get("productType")
            .and_then(Node::as_str)
            .map(str::to_string);
        let test_target = Target {
            name: tname.clone(),
            product_type: product_type.clone(),
            configs: Vec::new(),
        }
        .is_test();
        let mut configs = Vec::new();
        for (cname, tsettings, tbase) in
            pbx.configs(t.get("buildConfigurationList").and_then(Node::as_str))
        {
            let mut settings = BTreeMap::new();
            if let Some((_, psettings, pbase)) =
                project_configs.iter().find(|(n, _, _)| *n == cname)
            {
                merge(&mut settings, &read_base(pbase, &mut issues));
                merge(&mut settings, psettings);
            }
            merge(&mut settings, &read_base(&tbase, &mut issues));
            merge(&mut settings, &tsettings);
            let mut vars = settings.clone();
            for (k, v) in [
                ("SRCROOT", project_dir.clone()),
                ("PROJECT_DIR", project_dir.clone()),
                ("SOURCE_ROOT", project_dir.clone()),
                ("TARGET_NAME", tname.clone()),
                ("PROJECT_NAME", name.clone()),
                ("CONFIGURATION", cname.clone()),
            ] {
                vars.insert(k.to_string(), v);
            }
            vars.entry("PRODUCT_NAME".to_string())
                .or_insert_with(|| tname.clone());
            let mut resolve = |key: &str| -> Option<String> {
                let raw = settings.get(key)?.trim().trim_matches('"').to_string();
                if raw.is_empty() {
                    return None;
                }
                // Переменные SRCROOT/PROJECT_DIR дают путь от корня скана; прочие пути — от SRCROOT.
                let rooted = raw.starts_with("$(SRCROOT)")
                    || raw.starts_with("${SRCROOT}")
                    || raw.starts_with("$(PROJECT_DIR)")
                    || raw.starts_with("${PROJECT_DIR}")
                    || raw.starts_with("$(SOURCE_ROOT)");
                match expand(&raw, &vars, 0) {
                    // `$(SRCROOT)` = корень скана раскрывается в `""`: `/App/Info.plist` → `App/Info.plist`.
                    Some(v) if rooted && project_dir.is_empty() => {
                        normalize(v.trim_start_matches('/'))
                    }
                    Some(v) if rooted => normalize(&v),
                    Some(v) => join(&project_dir, &v),
                    None if test_target => None,
                    None => {
                        issues.push(format!(
                            "{}: target {} ({}): {key} = {} uses a build setting that is not a literal",
                            ui::sanitize_line(path),
                            ui::sanitize_line(&tname),
                            ui::sanitize_line(&cname),
                            ui::sanitize_line(&raw)
                        ));
                        None
                    }
                }
            };
            let info_plist = resolve("INFOPLIST_FILE");
            let entitlements = resolve("CODE_SIGN_ENTITLEMENTS");
            let deployment_target = [
                "IPHONEOS_DEPLOYMENT_TARGET",
                "MACOSX_DEPLOYMENT_TARGET",
                "TVOS_DEPLOYMENT_TARGET",
                "WATCHOS_DEPLOYMENT_TARGET",
            ]
            .iter()
            .find_map(|k| settings.get(*k).filter(|v| !v.contains('$')).cloned());
            configs.push(Config {
                debug: is_debug_config(&cname, &settings),
                name: cname,
                settings,
                info_plist,
                entitlements,
                deployment_target,
            });
        }
        targets.push(Target {
            name: tname,
            product_type,
            configs,
        });
    }
    issues.sort();
    issues.dedup();
    Ok(XcodeProject {
        path: path.to_string(),
        dir,
        name,
        targets,
        issues,
    })
}

impl Project {
    pub fn build(entries: Vec<Entry>, texts: BTreeMap<String, String>) -> Project {
        let mut project = Project {
            entries,
            texts,
            ..Project::default()
        };
        for e in &project.entries {
            let lower = e.name().to_ascii_lowercase();
            if lower == "package.swift" {
                project.has_package_swift = true;
            }
            let generator = match lower.as_str() {
                "project.yml" | "project.yaml" => Some("XcodeGen spec"),
                "project.swift" | "workspace.swift" => Some("Tuist manifest"),
                _ => None,
            };
            if let Some(g) = generator {
                project.generators.push((e.relative_path.clone(), g));
            }
        }
        let pbx: Vec<String> = project
            .entries
            .iter()
            .filter(|e| e.kind == FileKind::Pbxproj)
            .map(|e| e.relative_path.clone())
            .collect();
        for path in pbx {
            let Some(text) = project.texts.get(&path) else {
                continue;
            };
            match parse_project(&path, text, &project.texts) {
                Ok(p) => project.projects.push(p),
                Err(e) => project.broken.push((path, e)),
            }
        }
        for p in &project.projects {
            for t in &p.targets {
                for c in &t.configs {
                    let usage = Usage {
                        project: p.name.clone(),
                        target: t.name.clone(),
                        config: c.name.clone(),
                        debug: c.debug,
                        test: t.is_test(),
                        deployment_target: c.deployment_target.clone(),
                    };
                    if let Some(path) = &c.info_plist {
                        project
                            .info_usage
                            .entry(path.clone())
                            .or_default()
                            .push(usage.clone());
                    }
                    if let Some(path) = &c.entitlements {
                        project
                            .entitlements_usage
                            .entry(path.clone())
                            .or_default()
                            .push(usage);
                    }
                }
            }
        }
        project
    }

    pub fn entries_of(&self, kind: FileKind) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |e| e.kind == kind)
    }

    /// Info.plist цели: упомянут в `INFOPLIST_FILE` или назван `Info.plist` / `*-Info.plist`
    /// (кроме `GoogleService-Info.plist`).
    pub fn is_info_plist(&self, path: &str) -> bool {
        if self.info_usage.contains_key(path) {
            return true;
        }
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        name.ends_with("info.plist") && !name.starts_with("googleservice")
    }
}

/// Каталог (или имя файла) — тестовый: `*Tests`, `*UITests`, `Tests`, `Specs`, `Mocks`, `Fixtures`, ….
pub fn is_test_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').collect();
    let dirs = &segs[..segs.len().saturating_sub(1)];
    let test_dir = |s: &&str| {
        let l = s.to_ascii_lowercase();
        s.ends_with("Tests")
            || s.ends_with("Test")
            || s.ends_with("Specs")
            || s.ends_with("TestSupport")
            || s.ends_with("TestHelpers")
            || s.ends_with("TestUtils")
            || s.ends_with("Mocks")
            || matches!(
                l.as_str(),
                "test"
                    | "tests"
                    | "uitests"
                    | "testing"
                    | "spec"
                    | "specs"
                    | "mocks"
                    | "fixtures"
                    | "testdata"
                    | "test-data"
                    | "testfixtures"
                    | "testhelpers"
                    | "testsupport"
                    | "testutils"
                    | "test-utils"
                    | "__snapshots__"
            )
    };
    if dirs.iter().any(test_dir) {
        return true;
    }
    let name = segs.last().copied().unwrap_or("");
    let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
    stem.ends_with("Tests")
        || stem.ends_with("Test")
        || stem.ends_with("Spec")
        || stem.ends_with("Mock")
}

/// Файл инструментов сборки/CI, а не приложения (`fastlane/`, `scripts/`, `.github/`, `Package.swift`).
pub fn is_tooling_path(path: &str) -> bool {
    let segs: Vec<&str> = path.split('/').collect();
    let name = segs.last().copied().unwrap_or("").to_ascii_lowercase();
    if name == "package.swift" || name == "project.swift" || name == "dangerfile.swift" {
        return true;
    }
    segs[..segs.len().saturating_sub(1)].iter().any(|s| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "fastlane"
                | "scripts"
                | "script"
                | "bin"
                | ".github"
                | ".circleci"
                | "ci"
                | "tools"
                | "buildtools"
                | "build-tools"
                | "tuist"
                | "plugins"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PBX: &str = r#"// !$*UTF8*$!
{
	archiveVersion = 1;
	objectVersion = 56;
	objects = {
		G0 = {isa = PBXGroup; children = (G1, F9, ); sourceTree = "<group>"; };
		G1 = {isa = PBXGroup; children = (F1, ); path = Config; sourceTree = "<group>"; };
		F1 /* Release.xcconfig */ = {isa = PBXFileReference; path = Release.xcconfig; sourceTree = "<group>"; };
		F9 = {isa = PBXFileReference; path = /usr/x.xcconfig; sourceTree = "<absolute>"; };
		P1 = {isa = PBXProject; buildConfigurationList = L0; mainGroup = G0; targets = (T1, T2, ); };
		L0 = {isa = XCConfigurationList; buildConfigurations = (PD, PR, ); };
		PD = {isa = XCBuildConfiguration; buildSettings = {IPHONEOS_DEPLOYMENT_TARGET = 15.0; SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG; }; name = Debug; };
		PR = {isa = XCBuildConfiguration; baseConfigurationReference = F1; buildSettings = {IPHONEOS_DEPLOYMENT_TARGET = 15.0; }; name = Release; };
		T1 = {isa = PBXNativeTarget; buildConfigurationList = L1; name = App; productType = "com.apple.product-type.application"; };
		L1 = {isa = XCConfigurationList; buildConfigurations = (D1, R1, ); };
		D1 = {isa = XCBuildConfiguration; buildSettings = {CODE_SIGN_ENTITLEMENTS = App/AppDebug.entitlements; INFOPLIST_FILE = "$(SRCROOT)/App/Info.plist"; }; name = Debug; };
		R1 = {isa = XCBuildConfiguration; buildSettings = {CODE_SIGN_ENTITLEMENTS = "$(TARGET_NAME)/$(TARGET_NAME).entitlements"; INFOPLIST_FILE = App/Info.plist; "OTHER[sdk=iphoneos*]" = x; }; name = Release; };
		T2 = {isa = PBXNativeTarget; buildConfigurationList = L2; name = AppTests; productType = "com.apple.product-type.bundle.unit-test"; };
		L2 = {isa = XCConfigurationList; buildConfigurations = (D2, ); };
		D2 = {isa = XCBuildConfiguration; buildSettings = {INFOPLIST_FILE = "$(UNKNOWN_DIR)/Info.plist"; }; name = Debug; };
	};
	rootObject = P1;
}
"#;

    fn texts() -> BTreeMap<String, String> {
        let mut t = BTreeMap::new();
        t.insert(
            "ios/App.xcodeproj/project.pbxproj".to_string(),
            PBX.to_string(),
        );
        t.insert(
            "ios/Config/Release.xcconfig".to_string(),
            "#include \"Shared.xcconfig\"\nIPHONEOS_DEPLOYMENT_TARGET = 14.0 // comment\nSWIFT_ACTIVE_COMPILATION_CONDITIONS = $(inherited) PROD\nAPI_URL = https:/$()/x\n".to_string(),
        );
        t.insert(
            "ios/Config/Shared.xcconfig".to_string(),
            "SWIFT_ACTIVE_COMPILATION_CONDITIONS = SHARED\n".to_string(),
        );
        t
    }

    #[test]
    fn pbxproj_targets_configs_and_paths() {
        let texts = texts();
        let p = parse_project(
            "ios/App.xcodeproj/project.pbxproj",
            &texts["ios/App.xcodeproj/project.pbxproj"],
            &texts,
        )
        .unwrap();
        assert_eq!((p.dir.as_str(), p.name.as_str()), ("ios", "App"));
        assert_eq!(p.targets.len(), 2);
        let app = &p.targets[0];
        assert_eq!(app.kind(), "application");
        assert!(!app.is_test());
        let debug = &app.configs[0];
        assert!(debug.debug);
        assert_eq!(debug.info_plist.as_deref(), Some("ios/App/Info.plist"));
        assert_eq!(
            debug.entitlements.as_deref(),
            Some("ios/App/AppDebug.entitlements")
        );
        let release = &app.configs[1];
        assert!(!release.debug);
        assert_eq!(release.info_plist.as_deref(), Some("ios/App/Info.plist"));
        assert_eq!(
            release.entitlements.as_deref(),
            Some("ios/App/App.entitlements")
        );
        // Проект важнее xcconfig проекта; `$(inherited)` склеивается с include.
        assert_eq!(release.deployment_target.as_deref(), Some("15.0"));
        assert_eq!(
            release.settings["SWIFT_ACTIVE_COMPILATION_CONDITIONS"],
            "SHARED PROD"
        );
        assert!(!release.settings.contains_key("OTHER"));
        let tests = &p.targets[1];
        assert!(tests.is_test());
        assert_eq!(tests.configs[0].info_plist, None);
        // Неразрешённая переменная в цели тестов не делает проект неполным.
        assert!(p.issues.is_empty(), "{:?}", p.issues);
    }

    #[test]
    fn project_build_maps_usage() {
        let texts = texts();
        let entries = vec![Entry {
            relative_path: "ios/App.xcodeproj/project.pbxproj".into(),
            kind: FileKind::Pbxproj,
            len: 1,
        }];
        let p = Project::build(entries, texts);
        let usage = &p.entitlements_usage["ios/App/App.entitlements"];
        assert_eq!(usage.len(), 1);
        assert!(!usage[0].debug);
        assert_eq!(p.info_usage["ios/App/Info.plist"].len(), 2);
        assert!(p.is_info_plist("ios/App/Info.plist"));
        assert!(p.is_info_plist("Other/Share-Info.plist"));
        assert!(!p.is_info_plist("App/GoogleService-Info.plist"));
        assert!(!p.is_info_plist("App/Settings.plist"));
    }

    #[test]
    fn broken_pbxproj_is_reported() {
        let mut texts = BTreeMap::new();
        texts.insert(
            "A.xcodeproj/project.pbxproj".to_string(),
            "{ objects = {".to_string(),
        );
        let entries = vec![Entry {
            relative_path: "A.xcodeproj/project.pbxproj".into(),
            kind: FileKind::Pbxproj,
            len: 1,
        }];
        let p = Project::build(entries, texts);
        assert_eq!(p.broken.len(), 1);
        assert!(p.broken[0].1.contains("malformed"));
    }

    #[test]
    fn paths_and_expansion() {
        assert_eq!(normalize("a/./b/../c").as_deref(), Some("a/c"));
        assert_eq!(normalize("../x"), None);
        assert_eq!(normalize("/abs"), None);
        let mut vars = BTreeMap::new();
        vars.insert("A".to_string(), "x$(B)".to_string());
        vars.insert("B".to_string(), "y".to_string());
        assert_eq!(expand("$(A)/${B}", &vars, 0).as_deref(), Some("xy/y"));
        assert_eq!(expand("$(C)", &vars, 0), None);
        assert_eq!(
            expand("$(B:rfc1034identifier)", &vars, 0).as_deref(),
            Some("y")
        );
    }

    #[test]
    fn field_test_project_patterns() {
        // Signal: проект в корне скана, `INFOPLIST_FILE = "$(SRCROOT)/Signal/Signal-Info.plist"`.
        // NetNewsWire (Xcode 16): xcconfig через `baseConfigurationReferenceAnchor` + `…RelativePath`.
        let pbx = "{ objects = { G0 = {isa = PBXGroup; children = (X); sourceTree = \"<group>\"; }; X = {isa = PBXFileSystemSynchronizedRootGroup; path = xcconfig; sourceTree = \"<group>\"; }; P = {isa = PBXProject; buildConfigurationList = L; mainGroup = G0; targets = (T); }; L = {isa = XCConfigurationList; buildConfigurations = (C); }; T = {isa = PBXNativeTarget; name = App; buildConfigurationList = L2; }; L2 = {isa = XCConfigurationList; buildConfigurations = (R); }; C = {isa = XCBuildConfiguration; name = Release; buildSettings = {}; }; R = {isa = XCBuildConfiguration; name = Release; baseConfigurationReferenceAnchor = X; baseConfigurationReferenceRelativePath = app.xcconfig; buildSettings = {INFOPLIST_FILE = \"$(SRCROOT)/App/App-Info.plist\"; }; }; }; rootObject = P; }";
        let mut texts = BTreeMap::new();
        texts.insert("App.xcodeproj/project.pbxproj".to_string(), pbx.to_string());
        texts.insert(
            "xcconfig/app.xcconfig".to_string(),
            "CODE_SIGN_ENTITLEMENTS = App/App.entitlements\n".to_string(),
        );
        let p = parse_project("App.xcodeproj/project.pbxproj", pbx, &texts).unwrap();
        let c = &p.targets[0].configs[0];
        assert_eq!(c.info_plist.as_deref(), Some("App/App-Info.plist"));
        assert_eq!(c.entitlements.as_deref(), Some("App/App.entitlements"));
        assert!(p.issues.is_empty(), "{:?}", p.issues);
    }

    #[test]
    fn xcconfig_positions() {
        let a = xcconfig_assignments(
            "// c\nAPI_SECRET = abc // x\nKEY[sdk=iphoneos*] = v\n#include \"a\"\n",
        );
        assert_eq!(a.len(), 2);
        assert_eq!(a[0], ("API_SECRET".to_string(), "abc".to_string(), 2, 14));
        assert_eq!(a[1].0, "KEY");
    }

    #[test]
    fn test_and_tooling_paths() {
        for yes in [
            "AppTests/LoginTests.swift",
            "Modules/Core/Tests/CoreTests/A.swift",
            "App/Mocks/MockAPI.swift",
            "App/LoginSpec.swift",
            "AppUITests/Info.plist",
        ] {
            assert!(is_test_path(yes), "{yes}");
        }
        for no in ["App/Login.swift", "App/Latest/A.swift", "App/Info.plist"] {
            assert!(!is_test_path(no), "{no}");
        }
        assert!(is_tooling_path("fastlane/Fastfile"));
        assert!(is_tooling_path("Package.swift"));
        assert!(!is_tooling_path("App/AppDelegate.swift"));
    }
}
