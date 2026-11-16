//! Чтение Gradle-скриптов (Groovy `build.gradle` и Kotlin DSL `build.gradle.kts`) без исполнения.
//!
//! Из токенов (`lex`) собираются блоки (`android { buildTypes { release { … } } }`, в т. ч.
//! `getByName("release") {`, `create("staging") {`, `named("release") {`) и операторы внутри них:
//! присваивание (`isMinifyEnabled = true`, `minifyEnabled = true`), вызов (`minifyEnabled(true)`,
//! `buildConfigField("String", "K", "\"v\"")`), командный синтаксис Groovy (`minifyEnabled true`),
//! добавление (`manifestPlaceholders += mapOf(…)`), индекс (`manifestPlaceholders["k"] = "v"`).
//!
//! Значение известно, только если это литерал: `true`/`false`, число, строка без шаблонов,
//! карта литералов (`[k: "v"]`, `mapOf("k" to "v")`). Всё остальное (переменные, `libs.versions…`,
//! `System.getenv(…)`, шаблоны) — `Expr`: его не вычисляем (разрешение версий SDK — best effort в
//! `project.rs`). Блоки `all { }` / `configureEach { }` / `each { }` внутри `buildTypes` получают
//! имя `*` — они относятся ко всем типам сборки, включая release.

use super::lex::{self, Kind, Lang, Token};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Assign,
    Call,
    Append,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GValue {
    Bool(bool),
    Int(i64),
    Str(String),
    /// Карта литеральных ключей; значения — любые.
    Map(Vec<(String, Arg)>),
    /// Не литерал: токены выражения как есть.
    Expr(Vec<Token>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arg {
    pub value: GValue,
    /// Байтовый диапазон значения в тексте.
    pub start: usize,
    pub end: usize,
}

impl Arg {
    pub fn as_bool(&self) -> Option<bool> {
        match self.value {
            GValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match &self.value {
            GValue::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Текст выражения для отчёта (без значений строк).
    pub fn describe(&self) -> String {
        match &self.value {
            GValue::Bool(b) => b.to_string(),
            GValue::Int(i) => i.to_string(),
            GValue::Str(_) => "\"…\"".to_string(),
            GValue::Map(_) => "[…]".to_string(),
            GValue::Expr(tokens) => tokens
                .iter()
                .map(|t| match t.kind {
                    Kind::Str | Kind::Char => "\"…\"".to_string(),
                    _ => t.text.clone(),
                })
                .collect::<Vec<_>>()
                .join(""),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Stmt {
    /// Имена объемлющих блоков (`["android", "buildTypes", "release"]`).
    pub path: Vec<String>,
    /// Цель без модификаторов (`isMinifyEnabled`, `manifestPlaceholders`, `rootProject.ext.x`).
    pub target: String,
    /// `target["key"]`.
    pub key: Option<String>,
    pub op: Op,
    pub args: Vec<Arg>,
    /// Байтовый диапазон всего оператора.
    pub start: usize,
    pub end: usize,
    /// Все токены оператора (для `plugins { … }` и разрешения выражений).
    pub tokens: Vec<Token>,
}

impl Stmt {
    pub fn in_block(&self, name: &str) -> bool {
        self.path.iter().any(|p| p == name)
    }

    /// Имя блока сразу после `parent` (`buildTypes` → `release`).
    pub fn child_of(&self, parent: &str) -> Option<&str> {
        let at = self.path.iter().rposition(|p| p == parent)?;
        self.path.get(at + 1).map(String::as_str)
    }

    /// Оператор лежит прямо в блоке `name` (последний в пути).
    pub fn directly_in(&self, name: &str) -> bool {
        self.path.last().is_some_and(|p| p == name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub path: Vec<String>,
    /// Байт начала заголовка блока.
    pub start: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct GradleFile {
    pub stmts: Vec<Stmt>,
    pub blocks: Vec<Block>,
    /// Незакрытые строки/комментарии, лишние `}` — разбор приблизительный.
    pub recoveries: usize,
}

const MODIFIERS: &[&str] = &[
    "val",
    "var",
    "def",
    "const",
    "private",
    "internal",
    "public",
    "protected",
    "final",
    "static",
    "override",
    "lateinit",
];

/// Функции-селекторы именованных элементов контейнера: `getByName("release") {`.
const NAMED: &[&str] = &[
    "getByName",
    "create",
    "named",
    "register",
    "maybeCreate",
    "getAt",
];

/// Блоки, относящиеся ко всем элементам контейнера.
const ALL: &[&str] = &["all", "configureEach", "each", "forEach", "configure"];

pub fn lang_for(path: &str) -> Lang {
    if path.ends_with(".kts") || path.ends_with(".kt") {
        Lang::Kotlin
    } else if path.ends_with(".java") {
        Lang::Java
    } else {
        Lang::Groovy
    }
}

pub fn parse(text: &str, lang: Lang) -> GradleFile {
    let lexed = lex::lex(text, lang);
    let toks = &lexed.tokens;
    let mut file = GradleFile {
        recoveries: lexed.unterminated,
        ..GradleFile::default()
    };
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0usize;
    let n = toks.len();
    while i < n {
        let t = &toks[i];
        if t.kind == Kind::Newline || t.is_punct(";") {
            i += 1;
            continue;
        }
        if t.is_punct("}") {
            if stack.pop().is_none() {
                file.recoveries += 1;
            }
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 0usize;
        let mut j = i;
        let mut opens_block = false;
        while j < n {
            let t = &toks[j];
            if t.is_punct("(") || t.is_punct("[") {
                depth += 1;
            } else if t.is_punct(")") || t.is_punct("]") {
                depth = depth.saturating_sub(1);
            } else if t.is_punct("{") {
                if depth == 0 {
                    opens_block = true;
                    break;
                }
                j = skip_braces(toks, j);
                continue;
            } else if depth == 0 {
                if t.is_punct("}") || t.is_punct(";") {
                    break;
                }
                if t.kind == Kind::Newline {
                    if continues(toks, start, j) {
                        j += 1;
                        continue;
                    }
                    break;
                }
            }
            j += 1;
        }
        let header = &toks[start..j];
        if opens_block {
            let name = block_name(header, &stack);
            stack.push(name);
            file.blocks.push(Block {
                path: stack.clone(),
                start: toks[start].start,
            });
            i = j + 1;
            continue;
        }
        if let Some(stmt) = statement(header, &stack) {
            file.stmts.push(stmt);
        }
        i = j.max(start + 1);
    }
    file
}

/// Индекс токена после парной `}` для `{` в `at`.
fn skip_braces(toks: &[Token], at: usize) -> usize {
    let mut depth = 0usize;
    let mut j = at;
    while j < toks.len() {
        if toks[j].is_punct("{") {
            depth += 1;
        } else if toks[j].is_punct("}") {
            depth -= 1;
            if depth == 0 {
                return j + 1;
            }
        }
        j += 1;
    }
    toks.len()
}

/// Перевод строки внутри оператора: предыдущий значимый токен — оператор/запятая, или следующий
/// начинается с `.`/`?.`/`?:` (цепочка вызовов на новой строке).
fn continues(toks: &[Token], start: usize, newline: usize) -> bool {
    let prev = toks[start..newline]
        .iter()
        .rev()
        .find(|t| t.kind != Kind::Newline);
    if let Some(p) = prev
        && p.kind == Kind::Punct
        && matches!(
            p.text.as_str(),
            "=" | "," | "+" | "-" | "*" | "+=" | "?:" | "." | "?." | "&&" | "||" | "->" | ":"
        )
    {
        return true;
    }
    let next = toks[newline..].iter().find(|t| t.kind != Kind::Newline);
    next.is_some_and(|t| t.kind == Kind::Punct && matches!(t.text.as_str(), "." | "?." | "?:"))
}

fn block_name(header: &[Token], stack: &[String]) -> String {
    let sig: Vec<&Token> = header.iter().filter(|t| t.kind != Kind::Newline).collect();
    let Some(last) = sig.last() else {
        return String::new();
    };
    let in_container = stack.last().is_some_and(|p| {
        matches!(
            p.as_str(),
            "buildTypes" | "signingConfigs" | "productFlavors"
        )
    });
    if last.is_punct(")") {
        // Парная `(`.
        let mut depth = 0usize;
        let mut open = None;
        for (k, t) in sig.iter().enumerate().rev() {
            if t.is_punct(")") {
                depth += 1;
            } else if t.is_punct("(") {
                depth -= 1;
                if depth == 0 {
                    open = Some(k);
                    break;
                }
            }
        }
        let Some(open) = open else {
            return String::new();
        };
        // `named<ApplicationBuildType>("release")`: пропускаем `<…>`.
        let mut f = open;
        if f > 0 && sig[f - 1].is_punct(">") {
            while f > 0 && !sig[f - 1].is_punct("<") {
                f -= 1;
            }
            f = f.saturating_sub(1);
        }
        let Some(func) = f.checked_sub(1).map(|k| sig[k]) else {
            return String::new();
        };
        if func.kind != Kind::Ident {
            return String::new();
        }
        if NAMED.contains(&func.text.as_str())
            && let Some(arg) = sig.get(open + 1).and_then(|t| t.literal_str())
        {
            return arg.to_string();
        }
        if in_container && ALL.contains(&func.text.as_str()) {
            return "*".to_string();
        }
        return func.text.clone();
    }
    if last.kind == Kind::Ident {
        if in_container && ALL.contains(&last.text.as_str()) {
            return "*".to_string();
        }
        return last.text.clone();
    }
    String::new()
}

fn statement(header: &[Token], stack: &[String]) -> Option<Stmt> {
    let toks: Vec<&Token> = header.iter().filter(|t| t.kind != Kind::Newline).collect();
    let mut k = 0;
    while k < toks.len()
        && toks[k].kind == Kind::Ident
        && MODIFIERS.contains(&toks[k].text.as_str())
    {
        k += 1;
    }
    let first = *toks.get(k)?;
    if first.kind != Kind::Ident {
        return None;
    }
    let mut target = first.text.clone();
    k += 1;
    while k + 1 < toks.len()
        && (toks[k].is_punct(".") || toks[k].is_punct("?."))
        && toks[k + 1].kind == Kind::Ident
    {
        target.push('.');
        target.push_str(&toks[k + 1].text);
        k += 2;
    }
    // Тип в объявлении Kotlin: `val x: Int = 34`.
    if k + 1 < toks.len() && toks[k].is_punct(":") && toks[k + 1].kind == Kind::Ident {
        k += 2;
    }
    let mut key = None;
    if k + 2 < toks.len()
        && toks[k].is_punct("[")
        && toks[k + 2].is_punct("]")
        && let Some(s) = toks[k + 1].literal_str()
    {
        key = Some(s.to_string());
        k += 3;
    }
    let start = header.first()?.start;
    let end = header.last()?.end;
    let (op, args) = match toks.get(k) {
        None => (Op::Call, Vec::new()),
        Some(t) if t.is_punct("=") => (Op::Assign, vec![value(&toks[k + 1..])?]),
        Some(t) if t.is_punct("+=") => (Op::Append, vec![value(&toks[k + 1..])?]),
        Some(t) if t.is_punct("(") => {
            let close = matching(&toks, k)?;
            (Op::Call, split_args(&toks[k + 1..close]))
        }
        Some(t) if t.kind == Kind::Punct && !matches!(t.text.as_str(), "[" | "-") => {
            return None;
        }
        Some(_) => (Op::Call, split_args(&toks[k..])),
    };
    Some(Stmt {
        path: stack.to_vec(),
        target,
        key,
        op,
        args,
        start,
        end,
        tokens: header.to_vec(),
    })
}

/// Индекс парной закрывающей скобки для `(`/`[` в `open`.
fn matching(toks: &[&Token], open: usize) -> Option<usize> {
    let (o, c) = if toks[open].is_punct("[") {
        ("[", "]")
    } else {
        ("(", ")")
    };
    let mut depth = 0usize;
    for (k, t) in toks.iter().enumerate().skip(open) {
        if t.is_punct(o) {
            depth += 1;
        } else if t.is_punct(c) {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

fn split_args(toks: &[&Token]) -> Vec<Arg> {
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut from = 0;
    for (k, t) in toks.iter().enumerate() {
        if t.is_punct("(") || t.is_punct("[") || t.is_punct("{") {
            depth += 1;
        } else if t.is_punct(")") || t.is_punct("]") || t.is_punct("}") {
            depth = depth.saturating_sub(1);
        } else if t.is_punct(",") && depth == 0 {
            if let Some(v) = value(&toks[from..k]) {
                args.push(v);
            }
            from = k + 1;
        }
    }
    if from < toks.len()
        && let Some(v) = value(&toks[from..])
    {
        args.push(v);
    }
    // Именованные аргументы Groovy (`plugin: 'x'`) — одна карта.
    args
}

fn value(toks: &[&Token]) -> Option<Arg> {
    let first = toks.first()?;
    let last = toks.last()?;
    let (start, end) = (first.start, last.end);
    let arg = |value| Some(Arg { value, start, end });
    if toks.len() == 1 {
        let t = first;
        match t.kind {
            Kind::Ident if t.text == "true" => return arg(GValue::Bool(true)),
            Kind::Ident if t.text == "false" => return arg(GValue::Bool(false)),
            Kind::Num => {
                if let Some(n) = parse_int(&t.text) {
                    return arg(GValue::Int(n));
                }
            }
            Kind::Str | Kind::Char if t.templates.is_empty() => {
                return arg(GValue::Str(t.text.clone()));
            }
            _ => {}
        }
    }
    if toks.len() == 2
        && first.is_punct("-")
        && toks[1].kind == Kind::Num
        && let Some(n) = parse_int(&toks[1].text)
    {
        return arg(GValue::Int(-n));
    }
    // Groovy `[k: v, …]`.
    if first.is_punct("[") && last.is_punct("]") && toks.len() > 2 {
        let inner = &toks[1..toks.len() - 1];
        if let Some(map) = map_entries(inner, ":") {
            return arg(GValue::Map(map));
        }
    }
    // Kotlin `mapOf("k" to v, …)`.
    if first.kind == Kind::Ident
        && matches!(
            first.text.as_str(),
            "mapOf" | "hashMapOf" | "mutableMapOf" | "linkedMapOf"
        )
        && toks.len() >= 3
        && toks[1].is_punct("(")
        && last.is_punct(")")
        && let Some(map) = map_entries(&toks[2..toks.len() - 1], "to")
    {
        return arg(GValue::Map(map));
    }
    // Groovy именованный аргумент `key: value` как карта из одного элемента.
    if toks.len() >= 3 && toks[1].is_punct(":") && first.kind == Kind::Ident {
        let v = value(&toks[2..])?;
        return arg(GValue::Map(vec![(first.text.clone(), v)]));
    }
    arg(GValue::Expr(toks.iter().map(|t| (*t).clone()).collect()))
}

fn map_entries(toks: &[&Token], sep: &str) -> Option<Vec<(String, Arg)>> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut from = 0;
    let mut parts: Vec<&[&Token]> = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if t.is_punct("(") || t.is_punct("[") {
            depth += 1;
        } else if t.is_punct(")") || t.is_punct("]") {
            depth = depth.saturating_sub(1);
        } else if t.is_punct(",") && depth == 0 {
            parts.push(&toks[from..k]);
            from = k + 1;
        }
    }
    if from < toks.len() {
        parts.push(&toks[from..]);
    }
    for part in parts {
        if part.len() < 3 {
            return None;
        }
        let is_sep = if sep == "to" {
            part[1].is_ident("to")
        } else {
            part[1].is_punct(sep)
        };
        if !is_sep {
            return None;
        }
        let key = match part[0].kind {
            Kind::Ident => part[0].text.clone(),
            Kind::Str if part[0].templates.is_empty() => part[0].text.clone(),
            _ => return None,
        };
        out.push((key, value(&part[2..])?));
    }
    Some(out)
}

pub fn parse_int(text: &str) -> Option<i64> {
    let clean: String = text
        .trim_end_matches(['L', 'l'])
        .chars()
        .filter(|c| *c != '_')
        .collect();
    if let Some(hex) = clean
        .strip_prefix("0x")
        .or_else(|| clean.strip_prefix("0X"))
    {
        return i64::from_str_radix(hex, 16).ok();
    }
    clean.parse().ok()
}

/// Нормализованный текст оператора (для `plugins { … }`): строки — значениями, остальное — как есть.
pub fn stmt_text(stmt: &Stmt) -> String {
    stmt.tokens
        .iter()
        .filter(|t| t.kind != Kind::Newline)
        .map(|t| t.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stmts(text: &str, lang: Lang) -> Vec<Stmt> {
        parse(text, lang).stmts
    }

    fn find<'a>(s: &'a [Stmt], target: &str) -> &'a Stmt {
        s.iter()
            .find(|s| s.target == target)
            .unwrap_or_else(|| panic!("no {target}"))
    }

    #[test]
    fn groovy_build_types_and_command_syntax() {
        let text = "android {\n  compileSdkVersion 34\n  defaultConfig {\n    minSdkVersion 21\n    targetSdkVersion(34)\n  }\n  buildTypes {\n    release {\n      minifyEnabled false\n      debuggable = true\n      manifestPlaceholders = [cleartext: \"true\", other: someVar]\n    }\n  }\n}\n";
        let s = stmts(text, Lang::Groovy);
        let compile = find(&s, "compileSdkVersion");
        assert_eq!(compile.path, vec!["android"]);
        assert_eq!(compile.args[0].value, GValue::Int(34));
        assert_eq!(find(&s, "targetSdkVersion").args[0].value, GValue::Int(34));
        let minify = find(&s, "minifyEnabled");
        assert_eq!(minify.path, vec!["android", "buildTypes", "release"]);
        assert_eq!(minify.args[0].as_bool(), Some(false));
        assert_eq!(find(&s, "debuggable").op, Op::Assign);
        let GValue::Map(map) = &find(&s, "manifestPlaceholders").args[0].value else {
            panic!("map");
        };
        assert_eq!(map[0].0, "cleartext");
        assert_eq!(map[0].1.as_str(), Some("true"));
        assert!(matches!(map[1].1.value, GValue::Expr(_)));
    }

    #[test]
    fn kotlin_dsl_named_blocks_index_and_map_of() {
        let text = r#"
android {
    namespace = "com.example.app"
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isDebuggable = false
            manifestPlaceholders["cleartext"] = "false"
            manifestPlaceholders += mapOf("a" to "1", "b" to true)
            buildConfigField("String", "API", "\"x\"")
        }
        named<ApplicationBuildType>("staging") { isDebuggable = true }
        all { signingConfig = signingConfigs.getByName("release") }
    }
}
"#;
        let s = stmts(text, Lang::Kotlin);
        assert_eq!(
            find(&s, "namespace").args[0].as_str(),
            Some("com.example.app")
        );
        let minify = find(&s, "isMinifyEnabled");
        assert_eq!(minify.child_of("buildTypes"), Some("release"));
        let idx = s
            .iter()
            .find(|s| s.key.as_deref() == Some("cleartext"))
            .unwrap();
        assert_eq!(idx.args[0].as_str(), Some("false"));
        let append = s.iter().find(|s| s.op == Op::Append).unwrap();
        let GValue::Map(map) = &append.args[0].value else {
            panic!("map");
        };
        assert_eq!(map.len(), 2);
        assert_eq!(map[1].1.as_bool(), Some(true));
        let field = find(&s, "buildConfigField");
        assert_eq!(field.args.len(), 3);
        assert_eq!(field.args[2].as_str(), Some("\"x\""));
        let staging = s
            .iter()
            .find(|s| s.target == "isDebuggable" && s.child_of("buildTypes") == Some("staging"));
        assert!(staging.is_some());
        let all = find(&s, "signingConfig");
        assert_eq!(all.child_of("buildTypes"), Some("*"));
    }

    #[test]
    fn non_literals_stay_expressions() {
        let text = "android {\n defaultConfig {\n  targetSdk = libs.versions.targetSdk.get().toInt()\n  minSdk = rootProject.extra[\"minSdk\"] as Int\n }\n signingConfigs { create(\"release\") { storePassword = System.getenv(\"PW\") ?: \"\"\n keyPassword = \"$pw\" } }\n}";
        let s = stmts(text, Lang::Kotlin);
        assert!(matches!(
            find(&s, "targetSdk").args[0].value,
            GValue::Expr(_)
        ));
        assert!(matches!(find(&s, "minSdk").args[0].value, GValue::Expr(_)));
        assert!(matches!(
            find(&s, "storePassword").args[0].value,
            GValue::Expr(_)
        ));
        assert!(matches!(
            find(&s, "keyPassword").args[0].value,
            GValue::Expr(_)
        ));
        assert_eq!(
            find(&s, "storePassword").child_of("signingConfigs"),
            Some("release")
        );
    }

    #[test]
    fn chained_calls_across_lines_and_declarations() {
        let text = "val targetSdkVersion = 34\nval x = foo\n    .bar()\next.minSdk = 21\ndef compile = 33\nval y: Int = 7";
        let s = stmts(text, Lang::Kotlin);
        assert_eq!(find(&s, "targetSdkVersion").args[0].value, GValue::Int(34));
        assert!(matches!(find(&s, "x").args[0].value, GValue::Expr(_)));
        assert_eq!(find(&s, "ext.minSdk").args[0].value, GValue::Int(21));
        assert_eq!(find(&s, "compile").args[0].value, GValue::Int(33));
        assert_eq!(find(&s, "y").args[0].value, GValue::Int(7));
    }

    #[test]
    fn plugins_and_apply() {
        let text = "plugins {\n  id 'com.android.application'\n  alias(libs.plugins.kotlin.android)\n}\napply plugin: 'com.android.library'\n";
        let s = stmts(text, Lang::Groovy);
        let in_plugins: Vec<String> = s
            .iter()
            .filter(|s| s.directly_in("plugins"))
            .map(stmt_text)
            .collect();
        assert_eq!(in_plugins.len(), 2);
        assert!(in_plugins[0].contains("com.android.application"));
        let apply = find(&s, "apply");
        let GValue::Map(map) = &apply.args[0].value else {
            panic!("map");
        };
        assert_eq!(map[0].1.as_str(), Some("com.android.library"));
    }

    #[test]
    fn lambdas_inside_arguments_do_not_open_blocks() {
        let text = "android {\n  foo(listOf(1).map { it })\n  release { minifyEnabled true }\n}\nafter = 1";
        let f = parse(text, Lang::Groovy);
        assert_eq!(find(&f.stmts, "after").path, Vec::<String>::new());
        assert!(
            f.blocks
                .iter()
                .any(|b| b.path == vec!["android", "release"])
        );
    }

    #[test]
    fn stray_braces_are_recoveries_not_panics() {
        let f = parse("}}\nandroid {", Lang::Groovy);
        assert_eq!(f.recoveries, 2);
        for text in [
            "a(", "a = ", "a[", "[", "a = [x:", "mapOf(", "a.b.", "x = -", "{{{",
        ] {
            let _ = parse(text, Lang::Kotlin);
            let _ = parse(text, Lang::Groovy);
        }
    }

    #[test]
    fn ints() {
        assert_eq!(parse_int("34"), Some(34));
        assert_eq!(parse_int("1_000L"), Some(1000));
        assert_eq!(parse_int("0x1F"), Some(31));
        assert_eq!(parse_int("3.4"), None);
    }
}
