//! Структура Gradle-проекта: модули, их тип (application / library / …), SDK и где лежит конфигурация.
//!
//! Модуль — каталог с `build.gradle` / `build.gradle.kts`. Тип — по плагинам (`com.android.application`,
//! `com.android.library`, `com.android.dynamic-feature`, `com.android.test`, а также алиасы каталога
//! версий и convention-плагины, в имени которых есть `android` + `application`/`library`), иначе по
//! `applicationId` в `defaultConfig`. `settings.gradle(.kts)` читается для отчёта (включённые модули).
//!
//! SDK (`minSdk`/`targetSdk`/`compileSdk` и старые `*SdkVersion`) — только литералы. Best effort:
//! `libs.versions.<имя>` из `*.versions.toml`, `gradle.properties`, переменные `ext`/`extra`/`val`/`def`
//! и `const val` из `buildSrc`/`build-logic` — если значение одно и литеральное. Иначе — `Unknown`
//! с причиной: правила, которым SDK важен, честно становятся `partial`.

use super::gradle::{self, Arg, GValue, GradleFile, Stmt};
use super::lex::Kind;
use super::walk::{Entry, FileKind};
use crate::web_audit::location::LineIndex;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Application,
    Library,
    DynamicFeature,
    Test,
    /// Не Android-модуль (Kotlin/JVM) или тип не определён.
    Other,
}

impl ModuleKind {
    pub fn label(self) -> &'static str {
        match self {
            ModuleKind::Application => "application",
            ModuleKind::Library => "library",
            ModuleKind::DynamicFeature => "dynamic-feature",
            ModuleKind::Test => "test",
            ModuleKind::Other => "other",
        }
    }

    pub fn is_android(self) -> bool {
        !matches!(self, ModuleKind::Other)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdkValue {
    Known {
        value: i32,
        /// `app/build.gradle:12` или «AndroidManifest.xml uses-sdk».
        source: String,
        /// Не литерал на месте, а разрешённое значение (как именно — для отчёта).
        best_effort: Option<String>,
    },
    Unknown(String),
}

impl SdkValue {
    pub fn value(&self) -> Option<i32> {
        match self {
            SdkValue::Known { value, .. } => Some(*value),
            SdkValue::Unknown(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Каталог модуля от корня (`""` — корень).
    pub dir: String,
    pub build_file: String,
    pub kind: ModuleKind,
    pub namespace: Option<String>,
    pub application_id: Option<String>,
    pub min_sdk: SdkValue,
    pub target_sdk: SdkValue,
    pub compile_sdk: SdkValue,
    /// Плагин не стандартный (convention-плагин `build-logic` / `buildSrc`): часть конфигурации
    /// (типы сборки, SDK) может жить вне файла модуля.
    pub convention: bool,
    /// Скрипты convention-плагинов (`build-logic/**/<id>.gradle.kts`), применённые к модулю
    /// (транзитивно), и скрипты `apply from:`.
    pub applied: Vec<String>,
    /// В файле модуля или его скриптах вообще упоминается min/target SDK.
    pub sdk_mentioned: bool,
}

impl Module {
    pub fn display_name(&self) -> &str {
        if self.dir.is_empty() { "." } else { &self.dir }
    }

    /// Путь внутри модуля.
    pub fn path(&self, rest: &str) -> String {
        if self.dir.is_empty() {
            rest.to_string()
        } else {
            format!("{}/{rest}", self.dir)
        }
    }
}

/// Литеральные значения переменных, каталога версий и `gradle.properties` (для best effort).
#[derive(Clone, Debug, Default)]
pub struct Symbols {
    /// Нормализованное имя → (значение, где).
    pub ints: HashMap<String, Vec<(i64, String)>>,
    pub toml_versions: HashMap<String, (String, String)>,
    /// Алиас плагина каталога версий (нормализован) → id плагина.
    pub toml_plugins: HashMap<String, String>,
    pub properties: HashMap<String, (String, String)>,
    /// Строковые константы: полное имя (`ThunderbirdPlugins.App.android`) и короткое → значение;
    /// `None` — неоднозначно.
    pub strings: HashMap<String, Option<String>>,
}

/// `targetSdk` == `TARGET_SDK` == `target-sdk`: регистр и разделители не важны.
pub fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | '.'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub struct Project {
    pub entries: Vec<Entry>,
    /// Прочитанные на шаге структуры тексты (Gradle, каталоги версий, properties, манифесты, res/xml,
    /// res/values, `buildSrc`/`build-logic`).
    pub texts: BTreeMap<String, String>,
    pub gradle: BTreeMap<String, GradleFile>,
    pub symbols: Symbols,
    pub modules: Vec<Module>,
    /// Модули из `settings.gradle(.kts)` (`:app`, `:core:data`).
    pub included: Vec<String>,
    pub has_settings: bool,
    /// Значения из convention-плагинов / `subprojects {}`: поле → (значение, где).
    pub conventions: HashMap<&'static str, Vec<(i64, String)>>,
    /// Операторы `buildTypes` из корня (`subprojects {}` / `allprojects {}`) — для всех модулей.
    pub root_shared: Vec<(String, Stmt)>,
    /// Скрипты convention-плагинов: id плагина (имя файла без `.gradle.kts`) → путь.
    pub scripts: HashMap<String, String>,
}

/// Каталоги исходников сборки: `buildSrc`, `build-logic`, `*-conventions`, `gradle/plugins`.
pub fn is_build_logic(path: &str) -> bool {
    path.split('/').any(|seg| {
        let lower = seg.to_ascii_lowercase();
        lower == "buildsrc"
            || lower.contains("build-logic")
            || lower.starts_with("build-plugin")
            || lower == "gradle-plugins"
            || lower.contains("build-conventions")
            || lower == "convention"
            || lower == "conventions"
    })
}

pub fn needs_structure_text(entry: &Entry) -> bool {
    match entry.kind {
        FileKind::Gradle
        | FileKind::VersionCatalog
        | FileKind::Properties
        | FileKind::Manifest
        | FileKind::GitIgnore => true,
        FileKind::Xml => entry.relative_path.contains("/res/"),
        FileKind::Kotlin | FileKind::Java => is_build_logic(&entry.relative_path),
        _ => false,
    }
}

const SDK_FIELDS: &[(&str, &[&str])] = &[
    ("minSdk", &["minSdk", "minSdkVersion", "setMinSdkVersion"]),
    (
        "targetSdk",
        &["targetSdk", "targetSdkVersion", "setTargetSdkVersion"],
    ),
    (
        "compileSdk",
        &["compileSdk", "compileSdkVersion", "setCompileSdkVersion"],
    ),
];

/// Блоки, чьи операторы — настройка модуля, а не переменные.
const CONFIG_BLOCKS: &[&str] = &[
    "android",
    "defaultConfig",
    "buildTypes",
    "productFlavors",
    "signingConfigs",
    "dependencies",
    "plugins",
    "repositories",
    "sourceSets",
    "kotlinOptions",
    "compileOptions",
];

pub fn line_of(text: &str, byte: usize) -> (u32, u32) {
    LineIndex::new(text).line_col(text, byte).unwrap_or((1, 1))
}

impl Project {
    pub fn build(entries: Vec<Entry>, texts: BTreeMap<String, String>) -> Project {
        let mut gradle = BTreeMap::new();
        for (path, text) in &texts {
            let lower = path.to_ascii_lowercase();
            let is_gradle = lower.ends_with(".gradle") || lower.ends_with(".gradle.kts");
            let is_logic_src =
                (lower.ends_with(".kt") || lower.ends_with(".java")) && is_build_logic(path);
            if is_gradle || is_logic_src {
                gradle.insert(path.clone(), gradle::parse(text, gradle::lang_for(&lower)));
            }
        }
        let mut project = Project {
            entries,
            texts,
            gradle,
            symbols: Symbols::default(),
            modules: Vec::new(),
            included: Vec::new(),
            has_settings: false,
            conventions: HashMap::new(),
            root_shared: Vec::new(),
            scripts: HashMap::new(),
        };
        project.collect_symbols();
        project.collect_settings();
        project.collect_conventions();
        project.collect_modules();
        project
    }

    pub fn where_(&self, path: &str, byte: usize) -> String {
        let (line, _) = self.texts.get(path).map_or((1, 1), |t| line_of(t, byte));
        format!("{path}:{line}")
    }

    fn collect_symbols(&mut self) {
        let mut ints: HashMap<String, Vec<(i64, String)>> = HashMap::new();
        let mut strings: HashMap<String, Option<String>> = HashMap::new();
        for (path, file) in &self.gradle {
            for stmt in &file.stmts {
                if stmt
                    .path
                    .iter()
                    .any(|p| CONFIG_BLOCKS.contains(&p.as_str()))
                {
                    continue;
                }
                if stmt.op == gradle::Op::Assign
                    && let [arg] = stmt.args.as_slice()
                    && let Some(value) = arg.as_str()
                {
                    let mut full: Vec<&str> = stmt.path.iter().map(String::as_str).collect();
                    full.push(&stmt.target);
                    for key in [full.join("."), stmt.target.clone()] {
                        let slot = strings
                            .entry(key)
                            .or_insert_with(|| Some(value.to_string()));
                        if slot.as_deref() != Some(value) {
                            *slot = None;
                        }
                    }
                }
                let (name, arg) = match (stmt.op, stmt.args.as_slice()) {
                    (gradle::Op::Assign, [arg]) => {
                        let name = stmt.key.clone().unwrap_or_else(|| {
                            stmt.target.rsplit('.').next().unwrap_or("").to_string()
                        });
                        (name, arg)
                    }
                    (gradle::Op::Call, [key, arg]) if stmt.target.ends_with("set") => {
                        let Some(name) = key.as_str() else { continue };
                        (name.to_string(), arg)
                    }
                    _ => continue,
                };
                let value = match &arg.value {
                    GValue::Int(n) => *n,
                    GValue::Str(s) => match s.trim().parse() {
                        Ok(n) => n,
                        Err(_) => continue,
                    },
                    _ => continue,
                };
                let line = self.texts.get(path).map_or(1, |t| line_of(t, stmt.start).0);
                ints.entry(normalize(&name))
                    .or_default()
                    .push((value, format!("{path}:{line}")));
            }
        }
        let mut toml = HashMap::new();
        let mut plugins = HashMap::new();
        let mut props = HashMap::new();
        for (path, text) in &self.texts {
            let lower = path.to_ascii_lowercase();
            if lower.ends_with(".versions.toml") {
                for (key, value, line) in toml_versions(text) {
                    toml.insert(normalize(&key), (value, format!("{path}:{line}")));
                }
                for (key, id, _) in toml_plugins(text) {
                    plugins.insert(normalize(&key), id);
                }
            } else if lower == "gradle.properties" || lower.ends_with("/gradle.properties") {
                for p in properties(text) {
                    props
                        .entry(p.key.clone())
                        .or_insert((p.value.clone(), format!("{path}:{}", p.line)));
                }
            }
        }
        self.symbols = Symbols {
            ints,
            toml_versions: toml,
            toml_plugins: plugins,
            properties: props,
            strings,
        };
    }

    fn collect_settings(&mut self) {
        for (path, file) in &self.gradle {
            let name = path.rsplit('/').next().unwrap_or(path);
            if path.contains('/') || !name.starts_with("settings.gradle") {
                continue;
            }
            self.has_settings = true;
            for stmt in &file.stmts {
                if stmt.target != "include" {
                    continue;
                }
                for arg in &stmt.args {
                    if let Some(s) = arg.as_str() {
                        self.included.push(s.to_string());
                    }
                }
            }
        }
    }

    fn collect_conventions(&mut self) {
        let mut conventions: HashMap<&'static str, Vec<(i64, String)>> = HashMap::new();
        let mut shared = Vec::new();
        let mut scripts = HashMap::new();
        for (path, file) in &self.gradle {
            let name = path.rsplit('/').next().unwrap_or(path);
            let module_file = name == "build.gradle" || name == "build.gradle.kts";
            let root_file = module_file && !path.contains('/');
            let logic = is_build_logic(path);
            if logic && !module_file && !name.starts_with("settings.gradle") {
                let id = name
                    .strip_suffix(".gradle.kts")
                    .or_else(|| name.strip_suffix(".gradle"));
                if let Some(id) = id {
                    scripts.insert(id.to_string(), path.clone());
                }
            }
            for stmt in &file.stmts {
                let root_scope = root_file
                    && (stmt.in_block("subprojects")
                        || stmt.in_block("allprojects")
                        || stmt.in_block("configure"));
                if root_scope && stmt.in_block("buildTypes") {
                    shared.push((path.clone(), stmt.clone()));
                }
                // Глобальный best effort (классы convention-плагинов, которые не сопоставить с
                // модулем): используется, только если значение одно на весь проект.
                if !(logic || root_scope) {
                    continue;
                }
                for (field, names) in SDK_FIELDS {
                    if !names.contains(&stmt.target.as_str()) || stmt.args.len() != 1 {
                        continue;
                    }
                    if let Ok((value, _)) = resolve_int(&stmt.args[0], &self.symbols) {
                        let line = self.texts.get(path).map_or(1, |t| line_of(t, stmt.start).0);
                        conventions
                            .entry(field)
                            .or_default()
                            .push((value, format!("{path}:{line}")));
                    }
                }
            }
        }
        self.conventions = conventions;
        self.root_shared = shared;
        self.scripts = scripts;
    }

    /// id плагинов оператора `plugins { … }` / `apply plugin:`: строки, алиасы каталога версий,
    /// константы (`id(ThunderbirdPlugins.App.android)`). `apply false` — не применяется (`None`).
    fn plugin_ids(&self, stmt: &Stmt) -> Option<Vec<String>> {
        let t = &stmt.tokens;
        if t.windows(2)
            .any(|w| w[0].is_ident("apply") && w[1].is_ident("false"))
        {
            return None;
        }
        let mut ids: Vec<String> = t
            .iter()
            .filter_map(|x| x.literal_str().map(str::to_string))
            .collect();
        if let Some(at) = t
            .windows(3)
            .position(|w| w[0].is_ident("libs") && w[1].is_punct(".") && w[2].is_ident("plugins"))
        {
            let mut parts = Vec::new();
            let mut k = at + 3;
            while k + 1 < t.len() && t[k].is_punct(".") && t[k + 1].kind == Kind::Ident {
                parts.push(t[k + 1].text.clone());
                k += 2;
            }
            if let Some(id) = self.symbols.toml_plugins.get(&normalize(&parts.join("."))) {
                ids.push(id.clone());
            }
        } else if let Some(open) = t.iter().position(|x| x.is_punct("(")) {
            // `id(Const.Path)`: цепочка идентификаторов в скобках.
            let mut chain = Vec::new();
            let mut k = open + 1;
            while let Some(x) = t.get(k) {
                if x.kind == Kind::Ident {
                    chain.push(x.text.as_str());
                } else if !x.is_punct(".") {
                    break;
                }
                k += 1;
            }
            if !chain.is_empty() {
                let full = chain.join(".");
                let last = chain.last().copied().unwrap_or("");
                let found = self
                    .symbols
                    .strings
                    .get(&full)
                    .or_else(|| self.symbols.strings.get(last));
                if let Some(Some(v)) = found {
                    ids.push(v.clone());
                }
            }
        }
        Some(ids)
    }

    /// Плагины файла: (текст оператора с разрешёнными id — для эвристик, id).
    fn plugins_of(&self, file: &GradleFile) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for stmt in &file.stmts {
            let plugin = stmt.directly_in("plugins")
                || (stmt.path.is_empty() && stmt.target.starts_with("apply"));
            if !plugin {
                continue;
            }
            let Some(ids) = self.plugin_ids(stmt) else {
                continue;
            };
            let mut text = gradle::stmt_text(stmt).to_ascii_lowercase();
            for id in &ids {
                text.push(' ');
                text.push_str(&id.to_ascii_lowercase());
            }
            out.push((text, ids));
        }
        out
    }

    /// Скрипты convention-плагинов, применённые к модулю (транзитивно), и `apply from:`.
    fn applied_scripts(&self, file: &GradleFile) -> Vec<String> {
        let mut applied: Vec<String> = Vec::new();
        // `apply from: "…/signing.gradle"` / `apply(from = "…")`.
        for stmt in file.stmts.iter().filter(|s| s.target == "apply") {
            for tok in &stmt.tokens {
                let Some(v) = tok.literal_str() else { continue };
                let base = v.rsplit('/').next().unwrap_or(v);
                if !base.contains(".gradle") {
                    continue;
                }
                if let Some((p, _)) = self
                    .gradle
                    .iter()
                    .find(|(p, _)| p.rsplit('/').next() == Some(base))
                    && !applied.contains(p)
                {
                    applied.push(p.clone());
                }
            }
        }
        let first: Vec<String> = self
            .plugins_of(file)
            .into_iter()
            .flat_map(|(_, ids)| ids)
            .collect();
        let mut work = vec![first];
        while let Some(ids) = work.pop() {
            for id in ids {
                let Some(path) = self.scripts.get(&id) else {
                    continue;
                };
                if applied.contains(path) || applied.len() > 64 {
                    continue;
                }
                applied.push(path.clone());
                if let Some(script) = self.gradle.get(path) {
                    work.push(
                        self.plugins_of(script)
                            .into_iter()
                            .flat_map(|(_, ids)| ids)
                            .collect(),
                    );
                }
            }
        }
        applied
    }

    /// Операторы `buildTypes` вне файла модуля, которые к нему относятся: применённые скрипты
    /// convention-плагинов, `apply from:`, корневые `subprojects {}`/`allprojects {}`.
    pub fn shared_for<'a>(&'a self, module: &'a Module) -> Vec<(&'a str, &'a Stmt)> {
        let mut out = Vec::new();
        for path in &module.applied {
            if let Some(file) = self.gradle.get(path) {
                out.extend(
                    file.stmts
                        .iter()
                        .filter(|s| s.in_block("buildTypes"))
                        .map(|s| (path.as_str(), s)),
                );
            }
        }
        out.extend(self.root_shared.iter().map(|(p, s)| (p.as_str(), s)));
        out
    }

    fn collect_modules(&mut self) {
        let mut modules = Vec::new();
        for (path, file) in &self.gradle {
            let name = path.rsplit('/').next().unwrap_or(path);
            if name != "build.gradle" && name != "build.gradle.kts" || is_build_logic(path) {
                continue;
            }
            let dir = path.rsplit_once('/').map_or("", |(d, _)| d).to_string();
            modules.push(self.module(dir, path, file));
        }
        self.modules = modules;
    }

    fn module(&self, dir: String, path: &str, file: &GradleFile) -> Module {
        let mut app = false;
        let mut lib = false;
        let mut dynamic = false;
        let mut test = false;
        let mut standard = false;
        let applied = self.applied_scripts(file);
        let mut texts: Vec<(String, bool)> = self
            .plugins_of(file)
            .into_iter()
            .map(|(t, _)| (t, true))
            .collect();
        for path in &applied {
            if let Some(script) = self.gradle.get(path) {
                texts.extend(self.plugins_of(script).into_iter().map(|(t, _)| (t, false)));
            }
        }
        for (text, own) in texts {
            let words: Vec<&str> = text
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .collect();
            let android = text.contains("android");
            if text.contains("com.android.application") {
                app = true;
                standard |= own;
            } else if text.contains("com.android.library") {
                lib = true;
                standard |= own;
            } else if text.contains("com.android.dynamic-feature") {
                dynamic = true;
                standard |= own;
            } else if text.contains("com.android.test") {
                test = true;
                standard |= own;
            } else if !own {
                // Внутри convention-скрипта учитываются только стандартные id.
            } else if android
                && (words.contains(&"application")
                    || words.contains(&"app")
                    || words.iter().any(|w| w.starts_with("application")))
            {
                app = true;
            } else if android && words.iter().any(|w| w.contains("library") || *w == "lib") {
                lib = true;
            } else if android && words.iter().any(|w| w.contains("dynamicfeature")) {
                dynamic = true;
            }
        }
        let has_app_id = file
            .stmts
            .iter()
            .any(|s| s.target == "applicationId" && s.in_block("defaultConfig"));
        let has_android = file.blocks.iter().any(|b| b.path == ["android"]);
        let kind = if app || (!lib && !dynamic && !test && has_app_id) {
            ModuleKind::Application
        } else if dynamic {
            ModuleKind::DynamicFeature
        } else if lib {
            ModuleKind::Library
        } else if test {
            ModuleKind::Test
        } else if has_android {
            ModuleKind::Library
        } else {
            ModuleKind::Other
        };
        let literal = |target: &str, block: Option<&str>| -> Option<String> {
            file.stmts
                .iter()
                .filter(|s| s.target == target && block.is_none_or(|b| s.in_block(b)))
                .find_map(|s| s.args.first().and_then(Arg::as_str).map(str::to_string))
        };
        let mut sdk = [
            SdkValue::Unknown("not set".into()),
            SdkValue::Unknown("not set".into()),
            SdkValue::Unknown("not set".into()),
        ];
        let is_sdk = |s: &Stmt, names: &[&str]| {
            let direct = names.contains(&s.target.as_str());
            // AGP 9: `minSdk { version = release(23) }`.
            let block =
                s.target == "version" && s.path.last().is_some_and(|l| names.contains(&l.as_str()));
            (direct || block)
                && s.args.len() == 1
                && !["productFlavors", "buildTypes", "lint", "testOptions"]
                    .iter()
                    .any(|b| s.in_block(b))
        };
        let mentions = |f: &GradleFile| {
            f.stmts.iter().any(|s| {
                SDK_FIELDS[..2]
                    .iter()
                    .any(|(_, names)| s.tokens.iter().any(|t| names.contains(&t.text.as_str())))
            })
        };
        let sdk_mentioned = mentions(file)
            || applied
                .iter()
                .any(|p| self.gradle.get(p).is_some_and(mentions));
        for (i, (_, names)) in SDK_FIELDS.iter().enumerate() {
            let own = file
                .stmts
                .iter()
                .find(|s| is_sdk(s, names))
                .map(|s| (path, s, false));
            let found = own.or_else(|| {
                applied.iter().find_map(|p| {
                    self.gradle
                        .get(p)?
                        .stmts
                        .iter()
                        .find(|s| is_sdk(s, names))
                        .map(|s| (p.as_str(), s, true))
                })
            });
            if let Some((stmt_path, stmt, from_script)) = found {
                let at = self.where_(stmt_path, stmt.start);
                sdk[i] = match resolve_int(&stmt.args[0], &self.symbols) {
                    Ok((value, how)) => SdkValue::Known {
                        value: value as i32,
                        best_effort: match (how, from_script) {
                            (Some(h), true) => {
                                Some(format!("{h}, set by a convention plugin at {at}"))
                            }
                            (None, true) => Some(format!("set by a convention plugin at {at}")),
                            (h, false) => h,
                        },
                        source: at,
                    },
                    Err(expr) => SdkValue::Unknown(format!(
                        "{} = {} at {at} is not a literal and could not be resolved",
                        stmt.target,
                        crate::ui::sanitize_line(&expr)
                    )),
                };
            }
        }
        let [min_sdk, target_sdk, compile_sdk] = sdk;
        Module {
            dir,
            build_file: path.to_string(),
            kind,
            namespace: literal("namespace", None),
            application_id: literal("applicationId", Some("defaultConfig")),
            min_sdk,
            target_sdk,
            compile_sdk,
            convention: kind.is_android() && !standard,
            applied,
            sdk_mentioned,
        }
    }

    /// Значение из convention-плагинов, если оно одно.
    pub fn convention(&self, field: &str) -> Option<(i64, String)> {
        let values = self.conventions.get(field)?;
        let first = values.first()?;
        values
            .iter()
            .all(|(v, _)| *v == first.0)
            .then(|| first.clone())
    }

    pub fn entries_of(&self, kind: FileKind) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |e| e.kind == kind)
    }
}

/// Слова-функции в выражениях (`libs.versions.x.get().toInt()`), не имена переменных.
const FUNC_WORDS: &[&str] = &[
    "get",
    "toInt",
    "toInteger",
    "toString",
    "as",
    "Int",
    "Integer",
    "String",
    "orNull",
    "parseInt",
    "valueOf",
    "rootProject",
    "project",
    "ext",
    "extra",
    "properties",
    "property",
    "findProperty",
    "providers",
    "gradleProperty",
    "it",
    "this",
    "release",
    "preview",
];

/// Литеральное значение аргумента или best effort по символам. `Err` — текст выражения.
pub fn resolve_int(arg: &Arg, symbols: &Symbols) -> Result<(i64, Option<String>), String> {
    let tokens = match &arg.value {
        GValue::Int(n) => return Ok((*n, None)),
        GValue::Str(s) => {
            return s
                .trim()
                .parse()
                .map(|n| (n, None))
                .map_err(|_| arg.describe());
        }
        GValue::Expr(tokens) => tokens,
        _ => return Err(arg.describe()),
    };
    let expr = arg.describe();
    let unique = |values: &[(i64, String)]| -> Option<(i64, String)> {
        let first = values.first()?;
        values
            .iter()
            .all(|(v, _)| *v == first.0)
            .then(|| first.clone())
    };
    // `libs.versions.<a>.<b>…`
    if let Some(at) = tokens
        .windows(3)
        .position(|w| w[0].is_ident("libs") && w[1].is_punct(".") && w[2].is_ident("versions"))
    {
        let mut parts = Vec::new();
        let mut k = at + 3;
        while k + 1 < tokens.len() && tokens[k].is_punct(".") && tokens[k + 1].kind == Kind::Ident {
            let name = &tokens[k + 1].text;
            if FUNC_WORDS.contains(&name.as_str()) {
                break;
            }
            parts.push(name.clone());
            k += 2;
        }
        if !parts.is_empty()
            && let Some((value, at)) = symbols.toml_versions.get(&normalize(&parts.join(".")))
            && let Ok(n) = value.trim().parse::<i64>()
        {
            return Ok((n, Some(format!("{expr} = {n} from {at}"))));
        }
        return Err(expr);
    }
    // `release(36)`: одно число, остальное — служебные слова.
    let numbers: Vec<i64> = tokens
        .iter()
        .filter(|t| t.kind == Kind::Num)
        .filter_map(|t| gradle::parse_int(&t.text))
        .collect();
    if let [n] = numbers.as_slice()
        && tokens
            .iter()
            .filter(|t| t.kind == Kind::Ident)
            .all(|t| FUNC_WORDS.contains(&t.text.as_str()))
    {
        return Ok((*n, None));
    }
    // Литерал в выражении: `"34".toInt()`, `property("targetSdk")`, `extra["targetSdk"]`.
    let strings: Vec<&str> = tokens.iter().filter_map(|t| t.literal_str()).collect();
    if let [single] = strings.as_slice() {
        if let Ok(n) = single.trim().parse::<i64>() {
            return Ok((n, Some(format!("{expr} = {n}"))));
        }
        if let Some((value, at)) = symbols.properties.get(*single)
            && let Ok(n) = value.trim().parse::<i64>()
        {
            return Ok((n, Some(format!("{expr} = {n} from {at}"))));
        }
        if let Some((n, at)) = symbols.ints.get(&normalize(single)).and_then(|v| unique(v)) {
            return Ok((n, Some(format!("{expr} = {n} from {at}"))));
        }
        return Err(expr);
    }
    let name = tokens
        .iter()
        .rev()
        .filter(|t| t.kind == Kind::Ident && !FUNC_WORDS.contains(&t.text.as_str()))
        .map(|t| t.text.as_str())
        .next();
    if let Some(name) = name {
        if let Some((n, at)) = symbols.ints.get(&normalize(name)).and_then(|v| unique(v)) {
            return Ok((n, Some(format!("{expr} = {n} from {at}"))));
        }
        if let Some((value, at)) = symbols.properties.get(name)
            && let Ok(n) = value.trim().parse::<i64>()
        {
            return Ok((n, Some(format!("{expr} = {n} from {at}"))));
        }
    }
    Err(expr)
}

/// `[versions]` каталога версий: (ключ, значение, строка). Значение — первая строка в кавычках
/// (`"34"` или `{ strictly = "34" }`).
pub fn toml_versions(text: &str) -> Vec<(String, String, u32)> {
    toml_section(text, "[versions]")
}

/// `[plugins]` каталога версий: (алиас, id плагина, строка). `"id:version"` и `{ id = "…" }`.
pub fn toml_plugins(text: &str) -> Vec<(String, String, u32)> {
    toml_section(text, "[plugins]")
        .into_iter()
        .map(|(k, v, l)| (k, v.split(':').next().unwrap_or("").to_string(), l))
        .collect()
}

fn toml_section(text: &str, section: &str) -> Vec<(String, String, u32)> {
    let mut out = Vec::new();
    let mut in_versions = false;
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_versions = line == section;
            continue;
        }
        if !in_versions {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_matches('"').to_string();
        let Some(open) = value.find('"') else {
            continue;
        };
        let rest = &value[open + 1..];
        let Some(close) = rest.find('"') else {
            continue;
        };
        out.push((key, rest[..close].to_string(), (i + 1) as u32));
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Property {
    pub key: String,
    pub value: String,
    pub line: u32,
    /// Колонка начала значения (в символах, с 1).
    pub value_column: u32,
    /// Байтовое смещение значения в тексте.
    pub value_start: usize,
}

/// `*.properties`: `key=value`, `key: value`, `key value`; комментарии `#`/`!`.
/// Продолжения строк `\` не склеиваются (значение — первая физическая строка).
pub fn properties(text: &str) -> Vec<Property> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for (i, raw) in text.split('\n').enumerate() {
        let line_start = offset;
        offset += raw.len() + 1;
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('!') {
            continue;
        }
        let lead = line.len() - trimmed.len();
        let sep = trimmed
            .char_indices()
            .find(|(_, c)| matches!(c, '=' | ':') || c.is_whitespace());
        let Some((at, _)) = sep else {
            continue;
        };
        let key = trimmed[..at].trim().to_string();
        let mut rest_at = at;
        let bytes = trimmed.as_bytes();
        while rest_at < bytes.len() && bytes[rest_at].is_ascii_whitespace() {
            rest_at += 1;
        }
        if rest_at < bytes.len() && matches!(bytes[rest_at], b'=' | b':') {
            rest_at += 1;
        }
        while rest_at < bytes.len() && bytes[rest_at].is_ascii_whitespace() {
            rest_at += 1;
        }
        let value = trimmed[rest_at..].trim_end().to_string();
        let value_start = line_start + lead + rest_at;
        let value_column = line[..lead + rest_at].chars().count() as u32 + 1;
        out.push(Property {
            key,
            value,
            line: (i + 1) as u32,
            value_column,
            value_start,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(files: &[(&str, &str)]) -> Project {
        let texts: BTreeMap<String, String> = files
            .iter()
            .map(|(p, t)| (p.to_string(), t.to_string()))
            .collect();
        Project::build(Vec::new(), texts)
    }

    #[test]
    fn module_kinds_from_plugins_and_app_id() {
        let p = project(&[
            (
                "settings.gradle",
                "include ':app', ':lib'\ninclude(':conv')",
            ),
            (
                "app/build.gradle",
                "plugins { id 'com.android.application' }",
            ),
            (
                "lib/build.gradle.kts",
                "plugins { id(\"com.android.library\") }",
            ),
            (
                "conv/build.gradle.kts",
                "plugins { alias(libs.plugins.nowinandroid.android.application) }",
            ),
            (
                "old/build.gradle",
                "apply plugin: 'com.android.dynamic-feature'",
            ),
            (
                "guess/build.gradle",
                "android { defaultConfig { applicationId 'x' } }",
            ),
            ("jvm/build.gradle.kts", "plugins { kotlin(\"jvm\") }"),
            (
                "build-logic/convention/build.gradle.kts",
                "plugins { `kotlin-dsl` }",
            ),
        ]);
        let kinds: Vec<(&str, ModuleKind, bool)> = p
            .modules
            .iter()
            .map(|m| (m.dir.as_str(), m.kind, m.convention))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("app", ModuleKind::Application, false),
                ("conv", ModuleKind::Application, true),
                ("guess", ModuleKind::Application, true),
                ("jvm", ModuleKind::Other, false),
                ("lib", ModuleKind::Library, false),
                ("old", ModuleKind::DynamicFeature, false),
            ]
        );
        assert!(p.has_settings);
        assert_eq!(p.included, vec![":app", ":lib", ":conv"]);
    }

    #[test]
    fn sdk_literals_and_best_effort() {
        let p = project(&[
            (
                "gradle/libs.versions.toml",
                "[versions]\nandroid-targetSdk = \"34\" # comment\nminSdk = { strictly = \"23\" }\n[libraries]\nx = \"y\"",
            ),
            (
                "gradle.properties",
                "compile.sdk=35\norg.gradle.jvmargs=-Xmx2g",
            ),
            (
                "build.gradle",
                "ext {\n  legacyMin = 19\n}\nsubprojects { android { defaultConfig { targetSdkVersion 30 } } }",
            ),
            (
                "a/build.gradle.kts",
                "plugins { id(\"com.android.application\") }\nandroid {\n compileSdk = providers.gradleProperty(\"compile.sdk\").get().toInt()\n defaultConfig {\n  minSdk = libs.versions.minSdk.get().toInt()\n  targetSdk = libs.versions.android.targetSdk.get().toInt()\n }\n}",
            ),
            (
                "b/build.gradle",
                "apply plugin: 'com.android.application'\nandroid {\n defaultConfig {\n  minSdkVersion rootProject.ext.legacyMin\n  targetSdkVersion 33\n }\n}",
            ),
            (
                "c/build.gradle.kts",
                "plugins { id(\"com.android.library\") }\nandroid { defaultConfig { minSdk = someUnknown } }",
            ),
        ]);
        let m = |dir: &str| p.modules.iter().find(|m| m.dir == dir).unwrap();
        let a = m("a");
        assert_eq!(a.target_sdk.value(), Some(34));
        assert_eq!(a.min_sdk.value(), Some(23));
        assert_eq!(a.compile_sdk.value(), Some(35));
        let SdkValue::Known { best_effort, .. } = &a.target_sdk else {
            panic!()
        };
        assert!(
            best_effort
                .as_deref()
                .unwrap()
                .contains("libs.versions.toml:2")
        );
        let b = m("b");
        assert_eq!(b.min_sdk.value(), Some(19));
        let SdkValue::Known {
            source,
            best_effort,
            ..
        } = &b.target_sdk
        else {
            panic!()
        };
        assert_eq!(source, "b/build.gradle:5");
        assert!(best_effort.is_none());
        let c = m("c");
        assert_eq!(m("").kind, ModuleKind::Other);
        assert!(matches!(&c.min_sdk, SdkValue::Unknown(r) if r.contains("someUnknown")));
        assert!(matches!(&c.target_sdk, SdkValue::Unknown(r) if r == "not set"));
        assert_eq!(p.convention("targetSdk").map(|v| v.0), Some(30));
    }

    #[test]
    fn ambiguous_symbols_are_not_guessed() {
        let p = project(&[
            ("x.gradle", "ext.target = 30"),
            ("y.gradle", "ext.target = 31"),
            (
                "app/build.gradle",
                "apply plugin: 'com.android.application'\nandroid { defaultConfig { targetSdkVersion target } }",
            ),
        ]);
        let app = p.modules.iter().find(|m| m.dir == "app").unwrap();
        assert!(app.target_sdk.value().is_none());
    }

    #[test]
    fn properties_parsing() {
        let props = properties("# c\n! c\na=1\nb : two words\nc three\n  d.e=  x=y \r\nempty=\n");
        let got: Vec<(&str, &str, u32, u32)> = props
            .iter()
            .map(|p| (p.key.as_str(), p.value.as_str(), p.line, p.value_column))
            .collect();
        assert_eq!(
            got,
            vec![
                ("a", "1", 3, 3),
                ("b", "two words", 4, 5),
                ("c", "three", 5, 3),
                ("d.e", "x=y", 6, 9),
                ("empty", "", 7, 7),
            ]
        );
        let text = "k=v";
        assert_eq!(&text[props_value_start(text)..], "v");
    }

    fn props_value_start(text: &str) -> usize {
        properties(text)[0].value_start
    }
}
