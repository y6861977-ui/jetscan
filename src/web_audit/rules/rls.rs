//! WEB-RLS-009: Row Level Security Supabase по SQL-схеме из репозитория.
//!
//! Публичный anon/publishable-ключ в браузере — норма; данные защищает только RLS. Проверяем это
//! по SQL, который лежит в проекте (`supabase/migrations/*.sql`, `supabase/schema.sql`, дампы,
//! декларативные схемы; при Supabase — ещё `prisma/migrations/**/migration.sql` и `drizzle/**.sql`).
//! **Никуда не подключаемся**: что сделано в панели Supabase руками, мы не видим, и говорим это.
//!
//! Модель: операторы применяются по порядку файлов (миграции — по имени, как их применяет
//! `supabase db push`, затем прочие файлы). Учитываются CREATE/ALTER/DROP TABLE (RLS, имена,
//! столбцы), CREATE/ALTER/DROP POLICY, GRANT/REVOKE и ALTER DEFAULT PRIVILEGES для `anon`/
//! `authenticated`, функции `SECURITY DEFINER`, представления, публичные бакеты Storage. Прочие
//! известные операторы игнорируются; неизвестные — считаются и попадают в `limitations`.
//!
//! Находки (никогда не `confirmed`: это схема из файлов, а не живая база):
//! - таблица в открытой схеме без `ENABLE ROW LEVEL SECURITY` → high/potential;
//! - RLS включён, политик нет → info (таблица закрыта для anon/authenticated — не утечка);
//! - политика `USING (true)`/`WITH CHECK (true)` для anon/authenticated → по команде и таблице;
//! - политика опирается на `user_metadata` (его меняет сам пользователь) → high/potential;
//! - изменяющая политика без проверки личности (`auth.uid()` и т. п.) → medium/needs_review;
//! - `SECURITY DEFINER` в открытой схеме без `SET search_path` → medium (триггерная — low)/needs_review;
//! - представление без `security_invoker` в открытой схеме → medium/needs_review;
//! - бакет Storage `public = true` → info/needs_review.

use crate::secrets;
use crate::ui;
use crate::web_audit::location::{EXCERPT_MAX_CHARS, LineIndex};
use crate::web_audit::sql::{self, Kind, Token};
use crate::web_audit::types::{
    Confidence, Evidence, Severity, SourceLocation, WebFinding, finding_id,
};
use std::collections::{BTreeMap, BTreeSet};

pub const RULE_ID: &str = "WEB-RLS-009";

pub const REFERENCES: &[&str] = &[
    "https://supabase.com/docs/guides/database/postgres/row-level-security",
    "https://supabase.com/docs/guides/api/securing-your-api",
    "https://supabase.com/docs/guides/database/database-linter",
];

/// Команда, которой подсказываем выгрузить схему, когда SQL в проекте нет.
pub const DUMP_HINT: &str = "supabase db dump --schema public -f supabase/schema.sql";

/// Откуда SQL: определяет группу (одна база) и нужен ли Supabase в зависимостях.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    Supabase,
    Prisma,
    Drizzle,
}

/// Группа файла (каталог `supabase`/`prisma`/`drizzle` от корня) и источник. `None` — не наш SQL.
pub fn sql_group(relative: &str) -> Option<(String, Source)> {
    let lower = relative.to_ascii_lowercase();
    if !lower.ends_with(".sql") {
        return None;
    }
    let parts: Vec<&str> = lower.split('/').collect();
    let originals: Vec<&str> = relative.split('/').collect();
    let prefix = |i: usize| originals[..=i].join("/");
    if let Some(i) = parts.iter().position(|p| *p == "supabase") {
        // Тесты pgTAP, edge-функции и служебные каталоги CLI — не схема.
        let skip = [
            "tests",
            "test",
            "functions",
            ".temp",
            ".branches",
            "snippets",
        ];
        if parts.get(i + 1).is_some_and(|next| skip.contains(next)) || i + 1 == parts.len() {
            return None;
        }
        return Some((prefix(i), Source::Supabase));
    }
    if let Some(i) = parts.iter().position(|p| *p == "prisma")
        && parts.get(i + 1) == Some(&"migrations")
        && parts.last() == Some(&"migration.sql")
    {
        return Some((prefix(i), Source::Prisma));
    }
    if let Some(i) = parts.iter().position(|p| *p == "drizzle")
        && i + 1 < parts.len()
    {
        return Some((prefix(i), Source::Drizzle));
    }
    None
}

/// `supabase/config.toml` (каталог группы `supabase`).
pub fn is_supabase_config(relative: &str) -> bool {
    let lower = relative.to_ascii_lowercase();
    lower == "supabase/config.toml" || lower.ends_with("/supabase/config.toml")
}

type Key = (String, String);

fn key_label(k: &Key) -> String {
    format!("{}.{}", k.0, k.1)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Anon,
    Authenticated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Priv {
    Select,
    Insert,
    Update,
    Delete,
}

const ALL_PRIVS: [Priv; 4] = [Priv::Select, Priv::Insert, Priv::Update, Priv::Delete];
const API_ROLES: [Role; 2] = [Role::Anon, Role::Authenticated];

/// Место оператора: для находки и `jetscan:ignore`.
#[derive(Clone, Debug)]
struct Site {
    path: String,
    line: u32,
    col: u32,
    excerpt: String,
    ignored: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelKind {
    Table,
    View,
    MatView,
}

#[derive(Clone, Debug)]
struct Relation {
    kind: RelKind,
    columns: Vec<String>,
    /// `Some(false)` — создана в файлах без RLS; `None` — создана не здесь (RLS неизвестен).
    rls: Option<bool>,
    /// Где RLS оказался выключен/включён (создание или ALTER).
    site: Option<Site>,
    privs: BTreeSet<(Role, Priv)>,
    /// Представление с `security_invoker`.
    invoker: bool,
    /// ALTER POLICY / политика, о которой мы знаем только по имени.
    external_policy: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmd {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

impl Cmd {
    fn label(self) -> &'static str {
        match self {
            Cmd::All => "ALL",
            Cmd::Select => "SELECT",
            Cmd::Insert => "INSERT",
            Cmd::Update => "UPDATE",
            Cmd::Delete => "DELETE",
        }
    }

    fn covers(self, other: Cmd) -> bool {
        self == Cmd::All || other == Cmd::All || self == other
    }
}

/// Нормализованный токен выражения: вид и значение.
type ExprTok = (Kind, String);

#[derive(Clone, Debug)]
struct Policy {
    name: String,
    table: Key,
    cmd: Cmd,
    /// Пусто — `TO PUBLIC` по умолчанию.
    roles: Vec<String>,
    permissive: bool,
    using: Option<Vec<ExprTok>>,
    check: Option<Vec<ExprTok>>,
    site: Site,
}

#[derive(Clone, Debug)]
struct Function {
    definer: bool,
    search_path: bool,
    trigger: bool,
    site: Site,
}

#[derive(Clone, Debug)]
struct Bucket {
    public: bool,
    site: Site,
}

/// Состояние схемы одной базы после применения файлов по порядку.
#[derive(Default)]
struct Model {
    rels: BTreeMap<Key, Relation>,
    policies: BTreeMap<(Key, String), Policy>,
    functions: BTreeMap<Key, Function>,
    buckets: BTreeMap<String, Bucket>,
    /// (схема или `*`, роль, право), отозванные через ALTER DEFAULT PRIVILEGES.
    default_revoked: BTreeSet<(String, Role, Priv)>,
    /// В DO-блоке, теле функции или event trigger упоминается RLS: его могут включать динамически.
    dynamic_rls: bool,
    statements: usize,
    unknown: BTreeMap<String, usize>,
}

/// Итог по всем SQL-файлам.
#[derive(Default)]
pub struct RlsOutcome {
    pub findings: Vec<WebFinding>,
    pub files: usize,
    pub statements: usize,
    pub unterminated: Vec<String>,
    /// Неизвестные операторы: (первые слова, сколько).
    pub unknown: BTreeMap<String, usize>,
    pub dynamic_rls: bool,
    pub ignored_inline: usize,
    /// Схемы, открытые через Data API (по `config.toml` или по умолчанию).
    pub exposed: Vec<String>,
}

#[derive(Default)]
pub struct RlsCollector {
    files: BTreeMap<String, Vec<(String, String)>>,
    sources: BTreeMap<String, Source>,
    configs: BTreeMap<String, String>,
}

impl RlsCollector {
    /// SQL-файл (путь уже прошёл `sql_group`).
    pub fn sql_file(&mut self, path: &str, text: &str) {
        if let Some((group, source)) = sql_group(path) {
            self.sources.insert(group.clone(), source);
            self.files
                .entry(group)
                .or_default()
                .push((path.to_string(), text.to_string()));
        }
    }

    /// `supabase/config.toml`.
    pub fn config_file(&mut self, path: &str, text: &str) {
        let dir = path.rsplit_once('/').map_or("", |(d, _)| d).to_string();
        self.configs.insert(dir, text.to_string());
    }

    /// `uses_supabase` — Supabase в зависимостях корня: только тогда читаем SQL Prisma/Drizzle.
    pub fn finish(self, uses_supabase: bool) -> RlsOutcome {
        let mut out = RlsOutcome::default();
        let mut exposed_all = BTreeSet::new();
        for (group, mut files) in self.files {
            let source = self.sources[&group];
            if source != Source::Supabase && !uses_supabase {
                continue;
            }
            // Миграции — первыми и по имени (так их применяет CLI), затем прочие файлы группы.
            files.sort_by(|a, b| {
                let m = |p: &str| !p.to_ascii_lowercase().contains("/migrations/");
                (m(&a.0), &a.0).cmp(&(m(&b.0), &b.0))
            });
            let exposed = match self.configs.get(&group) {
                Some(cfg) if source == Source::Supabase => exposed_schemas(cfg),
                _ => vec!["public".to_string()],
            };
            exposed_all.extend(exposed.iter().cloned());
            let mut model = Model::default();
            for (path, text) in &files {
                let parsed = sql::parse(text);
                if parsed.unterminated {
                    out.unterminated.push(ui::sanitize_line(path));
                }
                let index = LineIndex::new(text);
                for st in &parsed.statements {
                    let s = Stmt {
                        text,
                        toks: &st.tokens,
                        path,
                        index: &index,
                    };
                    model.apply(&s);
                }
                out.files += 1;
            }
            out.statements += model.statements;
            out.dynamic_rls |= model.dynamic_rls;
            for (k, n) in &model.unknown {
                *out.unknown.entry(k.clone()).or_default() += n;
            }
            model.report(&exposed, &mut out);
        }
        out.exposed = exposed_all.into_iter().collect();
        out
    }
}

/// `[api] schemas = [...]` и `enabled = false` из `supabase/config.toml` (простой разбор TOML:
/// только эти два ключа). Data API выключен — открытых схем нет.
fn exposed_schemas(config: &str) -> Vec<String> {
    let mut section = String::new();
    let mut schemas: Option<Vec<String>> = None;
    let mut enabled = true;
    let mut pending = String::new();
    for raw in config.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if !pending.is_empty() {
            pending.push_str(line);
            if line.contains(']') {
                schemas = Some(toml_strings(&pending));
                pending.clear();
            }
            continue;
        }
        if line.starts_with('[') {
            section = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
            continue;
        }
        if section != "api" {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "schemas" => {
                    let v = v.trim();
                    if v.contains(']') {
                        schemas = Some(toml_strings(v));
                    } else {
                        pending = v.to_string();
                    }
                }
                "enabled" => enabled = v.trim() != "false",
                _ => {}
            }
        }
    }
    if !enabled {
        return Vec::new();
    }
    schemas.unwrap_or_else(|| vec!["public".to_string()])
}

fn toml_strings(v: &str) -> Vec<String> {
    v.split(['"', '\''])
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_string())
        .collect()
}

/// Оператор с доступом к тексту.
struct Stmt<'a> {
    text: &'a str,
    toks: &'a [Token],
    path: &'a str,
    index: &'a LineIndex,
}

impl Stmt<'_> {
    fn word(&self, i: usize) -> Option<String> {
        let t = self.toks.get(i)?;
        (t.kind == Kind::Word).then(|| sql::value(self.text, t))
    }

    fn is(&self, i: usize, w: &str) -> bool {
        self.toks.get(i).is_some_and(|t| {
            t.kind == Kind::Word && self.text[t.start..t.end].eq_ignore_ascii_case(w)
        })
    }

    fn seq(&self, i: usize, words: &[&str]) -> bool {
        words.iter().enumerate().all(|(n, w)| self.is(i + n, w))
    }

    fn punct(&self, i: usize, p: &str) -> bool {
        self.toks.get(i).is_some_and(|t| {
            matches!(t.kind, Kind::Punct | Kind::Op) && &self.text[t.start..t.end] == p
        })
    }

    fn ident(&self, i: usize) -> Option<String> {
        let t = self.toks.get(i)?;
        matches!(t.kind, Kind::Word | Kind::Quoted).then(|| sql::value(self.text, t))
    }

    /// `[схема.]имя` с позиции `i`: (ключ, следующая позиция). Без схемы — `public`.
    fn name(&self, i: usize) -> Option<(Key, usize)> {
        let first = self.ident(i)?;
        if self.punct(i + 1, ".")
            && let Some(second) = self.ident(i + 2)
        {
            return Some(((first, second), i + 3));
        }
        Some((("public".to_string(), first), i + 1))
    }

    /// Позиция сразу за парной `)` для `(` на `i`.
    fn group_end(&self, i: usize) -> Option<usize> {
        if !self.punct(i, "(") {
            return None;
        }
        let mut depth = 0usize;
        for (n, t) in self.toks.iter().enumerate().skip(i) {
            if t.kind == Kind::Punct {
                match &self.text[t.start..t.end] {
                    "(" => depth += 1,
                    ")" => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(n + 1);
                        }
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn find(&self, from: usize, words: &[&str]) -> Option<usize> {
        (from..self.toks.len()).find(|&i| self.seq(i, words))
    }

    fn expr(&self, from: usize, to: usize) -> Vec<ExprTok> {
        self.toks[from..to]
            .iter()
            .map(|t| (t.kind, sql::value(self.text, t)))
            .collect()
    }

    /// Текст оператора в нижнем регистре (для поиска упоминаний RLS в телах).
    fn lower(&self) -> String {
        match (self.toks.first(), self.toks.last()) {
            (Some(a), Some(b)) => self.text[a.start..b.end].to_ascii_lowercase(),
            _ => String::new(),
        }
    }

    fn site(&self) -> Site {
        let first = self.toks[0];
        let last = self.toks[self.toks.len() - 1];
        let (line, col) = self
            .index
            .line_col(self.text, first.start)
            .unwrap_or((1, 1));
        let (end_line, _) = self
            .index
            .line_col(self.text, last.end)
            .unwrap_or((line, 1));
        let ignored = (line..=end_line).any(|l| {
            self.index
                .line_range(self.text, l as usize)
                .is_some_and(|(s, e)| self.text[s..e].contains(secrets::scan::INLINE_IGNORE))
        });
        Site {
            path: self.path.to_string(),
            line,
            col,
            excerpt: self.excerpt(),
            ignored,
        }
    }

    /// Фрагмент оператора: строковые значения — `'…'` (кроме коротких имён вроде ролей и бакетов,
    /// не похожих на ключи), тела `$$…$$` выброшены, ≤160 символов.
    fn excerpt(&self) -> String {
        let mut out = String::new();
        let mut prev = "";
        for t in self.toks {
            let raw = &self.text[t.start..t.end];
            let piece = match t.kind {
                Kind::Str => {
                    let v = sql::value(self.text, t);
                    if is_plain_name(&v) {
                        format!("'{v}'")
                    } else {
                        "'…'".to_string()
                    }
                }
                Kind::Dollar => "$$…$$".to_string(),
                _ => raw.to_string(),
            };
            let tight = matches!(raw, ")" | "," | "." | "]")
                || matches!(prev, "(" | "." | "[")
                || (raw == "(" && t.kind == Kind::Punct && !prev.is_empty() && is_callable(prev));
            if !out.is_empty() && !tight {
                out.push(' ');
            }
            out.push_str(&piece);
            prev = raw;
            if out.chars().count() > EXCERPT_MAX_CHARS {
                break;
            }
        }
        let clean = ui::sanitize_line(&out);
        if clean.chars().count() > EXCERPT_MAX_CHARS {
            let cut: String = clean.chars().take(EXCERPT_MAX_CHARS - 1).collect();
            format!("{cut}…")
        } else {
            clean
        }
    }
}

fn is_callable(prev: &str) -> bool {
    prev.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '"')
        && !matches!(
            prev.to_ascii_lowercase().as_str(),
            "using" | "check" | "on" | "values" | "in" | "and" | "or" | "not" | "exists" | "table"
        )
}

/// Короткое имя (роль, бакет, значение-метка): показываем как есть. Похожее на ключ — нет.
pub(crate) fn is_plain_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 40
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && secrets::scan_text(secrets::rules::all(), v).is_empty()
}

fn parse_cmd(word: &str) -> Option<Cmd> {
    Some(match word {
        "all" => Cmd::All,
        "select" => Cmd::Select,
        "insert" => Cmd::Insert,
        "update" => Cmd::Update,
        "delete" => Cmd::Delete,
        _ => return None,
    })
}

fn role_set(name: &str) -> &'static [Role] {
    match name {
        "anon" => &[Role::Anon],
        "authenticated" => &[Role::Authenticated],
        "public" => &API_ROLES,
        _ => &[],
    }
}

/// Слова, с которых начинаются операторы, не влияющие на RLS (или влияющие так, что мы
/// это не моделируем и не обязаны: индексы, типы, комментарии, данные).
const KNOWN_LEADING: &[&str] = &[
    "select",
    "with",
    "set",
    "reset",
    "comment",
    "begin",
    "commit",
    "end",
    "rollback",
    "abort",
    "start",
    "savepoint",
    "release",
    "truncate",
    "delete",
    "copy",
    "lock",
    "analyze",
    "analyse",
    "vacuum",
    "notify",
    "listen",
    "unlisten",
    "security",
    "reindex",
    "refresh",
    "call",
    "cluster",
    "discard",
    "checkpoint",
    "explain",
    "prepare",
    "execute",
    "deallocate",
    "import",
    "load",
    "reassign",
    "show",
    "values",
    "merge",
    "declare",
    "fetch",
    "close",
    "move",
    "insert",
    "update",
];

const KNOWN_CREATE: &[&str] = &[
    "index",
    "unique",
    "trigger",
    "constraint",
    "extension",
    "schema",
    "type",
    "domain",
    "sequence",
    "publication",
    "subscription",
    "role",
    "user",
    "group",
    "aggregate",
    "operator",
    "cast",
    "collation",
    "conversion",
    "foreign",
    "server",
    "statistics",
    "text",
    "language",
    "transform",
    "access",
    "tablespace",
    "database",
    "trusted",
    "procedural",
    "default",
];

impl Model {
    fn unknown(&mut self, s: &Stmt) {
        let words: Vec<String> = (0..2).filter_map(|i| s.word(i)).collect();
        let label = ui::sanitize_line(&words.join(" "));
        *self.unknown.entry(label).or_default() += 1;
    }

    fn apply(&mut self, s: &Stmt) {
        if s.toks.is_empty() {
            return;
        }
        self.statements += 1;
        let Some(first) = s.word(0) else {
            self.unknown(s);
            return;
        };
        match first.as_str() {
            "create" => self.create(s),
            "alter" => self.alter(s),
            "drop" => self.drop(s),
            "grant" | "revoke" => self.grant(s, 0),
            "do" => {
                if mentions_rls(&s.lower()) {
                    self.dynamic_rls = true;
                }
            }
            "insert" => self.insert_bucket(s),
            "update" => self.update_bucket(s),
            w if KNOWN_LEADING.contains(&w) => {}
            _ => self.unknown(s),
        }
    }

    fn create(&mut self, s: &Stmt) {
        let mut i = 1;
        if s.seq(i, &["or", "replace"]) {
            i += 2;
        }
        let mut temp = false;
        while let Some(w) = s.word(i) {
            match w.as_str() {
                "temp" | "temporary" => temp = true,
                "global" | "local" | "unlogged" | "recursive" => {}
                _ => break,
            }
            i += 1;
        }
        let Some(what) = s.word(i) else {
            self.unknown(s);
            return;
        };
        match what.as_str() {
            "table" if !temp => self.create_table(s, i + 1),
            "table" => {}
            "policy" => self.create_policy(s, i + 1),
            "function" | "procedure" => self.create_function(s, i + 1),
            "view" if !temp => self.create_view(s, i + 1, RelKind::View),
            "view" => {}
            "materialized" if s.is(i + 1, "view") => self.create_view(s, i + 2, RelKind::MatView),
            "event" => {
                if mentions_rls(&s.lower()) {
                    self.dynamic_rls = true;
                }
            }
            w if KNOWN_CREATE.contains(&w) => {}
            _ => self.unknown(s),
        }
    }

    fn initial_privs(&self, schema: &str) -> BTreeSet<(Role, Priv)> {
        let mut set = BTreeSet::new();
        for role in API_ROLES {
            for p in ALL_PRIVS {
                let revoked = self
                    .default_revoked
                    .contains(&(schema.to_string(), role, p))
                    || self.default_revoked.contains(&("*".to_string(), role, p));
                if !revoked {
                    set.insert((role, p));
                }
            }
        }
        set
    }

    fn create_table(&mut self, s: &Stmt, mut i: usize) {
        if s.seq(i, &["if", "not", "exists"]) {
            i += 3;
        }
        let Some((key, next)) = s.name(i) else {
            self.unknown(s);
            return;
        };
        let columns = s
            .group_end(next)
            .map_or_else(Vec::new, |end| columns(s, next, end));
        if let Some(existing) = self.rels.get_mut(&key) {
            // Повторное создание (дамп поверх миграций, IF NOT EXISTS): состояние сохраняем.
            if existing.columns.is_empty() {
                existing.columns = columns;
            }
            if existing.rls.is_none() {
                existing.rls = Some(false);
                existing.site = Some(s.site());
            }
            return;
        }
        let privs = self.initial_privs(&key.0);
        self.rels.insert(
            key,
            Relation {
                kind: RelKind::Table,
                columns,
                rls: Some(false),
                site: Some(s.site()),
                privs,
                invoker: false,
                external_policy: false,
            },
        );
    }

    fn create_view(&mut self, s: &Stmt, mut i: usize, kind: RelKind) {
        if s.seq(i, &["if", "not", "exists"]) {
            i += 3;
        }
        let Some((key, mut next)) = s.name(i) else {
            self.unknown(s);
            return;
        };
        if let Some(end) = s.group_end(next) {
            next = end;
        }
        let mut invoker = false;
        if s.is(next, "with")
            && let Some(end) = s.group_end(next + 1)
        {
            invoker = security_invoker_option(s, next + 2, end - 1);
        }
        let privs = self
            .rels
            .get(&key)
            .map_or_else(|| self.initial_privs(&key.0), |r| r.privs.clone());
        self.rels.insert(
            key,
            Relation {
                kind,
                columns: Vec::new(),
                rls: None,
                site: Some(s.site()),
                privs,
                invoker,
                external_policy: false,
            },
        );
    }

    fn create_policy(&mut self, s: &Stmt, i: usize) {
        let Some(name) = s.ident(i) else {
            self.unknown(s);
            return;
        };
        if !s.is(i + 1, "on") {
            self.unknown(s);
            return;
        }
        let Some((table, mut j)) = s.name(i + 2) else {
            self.unknown(s);
            return;
        };
        let mut policy = Policy {
            name: name.clone(),
            table: table.clone(),
            cmd: Cmd::All,
            roles: Vec::new(),
            permissive: true,
            using: None,
            check: None,
            site: s.site(),
        };
        while j < s.toks.len() {
            if s.is(j, "as") {
                policy.permissive = !s.is(j + 1, "restrictive");
                j += 2;
            } else if s.is(j, "for") {
                if let Some(cmd) = s.word(j + 1).as_deref().and_then(parse_cmd) {
                    policy.cmd = cmd;
                }
                j += 2;
            } else if s.is(j, "to") {
                j = roles(s, j + 1, &mut policy.roles);
            } else if s.is(j, "using") {
                let Some(end) = s.group_end(j + 1) else { break };
                policy.using = Some(s.expr(j + 2, end - 1));
                j = end;
            } else if s.seq(j, &["with", "check"]) {
                let Some(end) = s.group_end(j + 2) else { break };
                policy.check = Some(s.expr(j + 3, end - 1));
                j = end;
            } else {
                j += 1;
            }
        }
        self.policies.insert((table, name), policy);
    }

    fn create_function(&mut self, s: &Stmt, i: usize) {
        let Some((key, next)) = s.name(i) else {
            self.unknown(s);
            return;
        };
        let after_args = s.group_end(next).unwrap_or(next);
        let mut f = Function {
            definer: false,
            search_path: false,
            trigger: false,
            site: s.site(),
        };
        let mut j = after_args;
        while j < s.toks.len() {
            if s.is(j, "returns") && (s.is(j + 1, "trigger") || s.is(j + 1, "event_trigger")) {
                f.trigger = true;
            } else if s.seq(j, &["security", "definer"]) {
                f.definer = true;
            } else if s.seq(j, &["security", "invoker"]) {
                f.definer = false;
            } else if s.seq(j, &["set", "search_path"]) {
                f.search_path = true;
            } else if matches!(s.toks[j].kind, Kind::Dollar | Kind::Str)
                && j > 0
                && s.is(j - 1, "as")
                && mentions_rls(&sql::value(s.text, &s.toks[j]).to_ascii_lowercase())
            {
                self.dynamic_rls = true;
            }
            j += 1;
        }
        if s.text[s.toks[0].start..s.toks[s.toks.len() - 1].end]
            .to_ascii_lowercase()
            .contains("begin atomic")
            && mentions_rls(&s.lower())
        {
            self.dynamic_rls = true;
        }
        self.functions.insert(key, f);
    }

    fn alter(&mut self, s: &Stmt) {
        let Some(what) = s.word(1) else {
            self.unknown(s);
            return;
        };
        match what.as_str() {
            "table" => self.alter_table(s),
            "policy" => self.alter_policy(s),
            "function" | "procedure" | "routine" => self.alter_function(s),
            "view" => self.alter_view(s, 2),
            "materialized" if s.is(2, "view") => self.alter_view(s, 3),
            "default" if s.is(2, "privileges") => self.default_privileges(s),
            _ => {}
        }
    }

    fn alter_table(&mut self, s: &Stmt) {
        let mut i = 2;
        if s.seq(i, &["if", "exists"]) {
            i += 2;
        }
        if s.is(i, "only") {
            i += 1;
        }
        if s.is(i, "all") {
            return; // ALTER TABLE ALL IN TABLESPACE
        }
        let Some((key, mut next)) = s.name(i) else {
            self.unknown(s);
            return;
        };
        if s.punct(next, "*") {
            next += 1;
        }
        if s.seq(next, &["rename", "to"]) {
            if let Some(new) = s.ident(next + 2) {
                self.rename(&key, (key.0.clone(), new));
            }
            return;
        }
        if s.seq(next, &["set", "schema"]) {
            if let Some(schema) = s.ident(next + 2) {
                self.rename(&key, (schema, key.1.clone()));
            }
            return;
        }
        let enable = s.find(next, &["enable", "row", "level", "security"]);
        let disable = s.find(next, &["disable", "row", "level", "security"]);
        let mut added = Vec::new();
        let mut j = next;
        while j < s.toks.len() {
            if s.is(j, "add") {
                let mut k = j + 1;
                if s.is(k, "column") {
                    k += 1;
                }
                if s.seq(k, &["if", "not", "exists"]) {
                    k += 3;
                }
                let constraint = s.word(k).is_some_and(|w| {
                    matches!(
                        w.as_str(),
                        "constraint" | "primary" | "unique" | "foreign" | "check" | "exclude"
                    )
                });
                if !constraint && let Some(col) = s.ident(k) {
                    added.push(col);
                }
            }
            j += 1;
        }
        if enable.is_none() && disable.is_none() && added.is_empty() {
            return;
        }
        let site = s.site();
        let rel = self.rels.entry(key.clone()).or_insert_with(|| Relation {
            kind: RelKind::Table,
            columns: Vec::new(),
            rls: None,
            site: None,
            privs: API_ROLES
                .iter()
                .flat_map(|r| ALL_PRIVS.iter().map(move |p| (*r, *p)))
                .collect(),
            invoker: false,
            external_policy: false,
        });
        rel.columns.extend(added);
        // Последнее по тексту действие побеждает.
        match (enable, disable) {
            (Some(e), Some(d)) => {
                rel.rls = Some(e > d);
                rel.site = Some(site);
            }
            (Some(_), None) => {
                rel.rls = Some(true);
                rel.site = Some(site);
            }
            (None, Some(_)) => {
                rel.rls = Some(false);
                rel.site = Some(site);
            }
            (None, None) => {}
        }
    }

    fn rename(&mut self, from: &Key, to: Key) {
        if let Some(rel) = self.rels.remove(from) {
            self.rels.insert(to.clone(), rel);
        }
        let moved: Vec<(Key, String)> = self
            .policies
            .keys()
            .filter(|(t, _)| t == from)
            .cloned()
            .collect();
        for k in moved {
            if let Some(mut p) = self.policies.remove(&k) {
                p.table = to.clone();
                self.policies.insert((to.clone(), k.1), p);
            }
        }
    }

    fn alter_policy(&mut self, s: &Stmt) {
        let Some(name) = s.ident(2) else {
            self.unknown(s);
            return;
        };
        if !s.is(3, "on") {
            self.unknown(s);
            return;
        }
        let Some((table, mut j)) = s.name(4) else {
            self.unknown(s);
            return;
        };
        let pk = (table.clone(), name);
        if s.seq(j, &["rename", "to"]) {
            if let (Some(new), Some(mut p)) = (s.ident(j + 2), self.policies.remove(&pk)) {
                p.name = new.clone();
                self.policies.insert((table, new), p);
            }
            return;
        }
        let Some(policy) = self.policies.get_mut(&pk) else {
            // Политика создана не в этих файлах: команда неизвестна, но политики у таблицы есть.
            if let Some(rel) = self.rels.get_mut(&table) {
                rel.external_policy = true;
            }
            return;
        };
        policy.site = s.site();
        while j < s.toks.len() {
            if s.is(j, "to") {
                policy.roles.clear();
                j = roles(s, j + 1, &mut policy.roles);
            } else if s.is(j, "using") {
                let Some(end) = s.group_end(j + 1) else { break };
                policy.using = Some(s.expr(j + 2, end - 1));
                j = end;
            } else if s.seq(j, &["with", "check"]) {
                let Some(end) = s.group_end(j + 2) else { break };
                policy.check = Some(s.expr(j + 3, end - 1));
                j = end;
            } else {
                j += 1;
            }
        }
    }

    fn alter_function(&mut self, s: &Stmt) {
        let Some((key, next)) = s.name(2) else {
            return;
        };
        let j = s.group_end(next).unwrap_or(next);
        if s.seq(j, &["rename", "to"]) {
            if let (Some(new), Some(f)) = (s.ident(j + 2), self.functions.remove(&key)) {
                self.functions.insert((key.0.clone(), new), f);
            }
            return;
        }
        if s.seq(j, &["set", "schema"]) {
            if let (Some(schema), Some(f)) = (s.ident(j + 2), self.functions.remove(&key)) {
                self.functions.insert((schema, key.1.clone()), f);
            }
            return;
        }
        let Some(f) = self.functions.get_mut(&key) else {
            return;
        };
        for k in j..s.toks.len() {
            if s.seq(k, &["security", "definer"]) {
                f.definer = true;
            } else if s.seq(k, &["security", "invoker"]) {
                f.definer = false;
            } else if s.seq(k, &["set", "search_path"]) {
                f.search_path = true;
            } else if s.seq(k, &["reset", "search_path"]) || s.seq(k, &["reset", "all"]) {
                f.search_path = false;
            }
        }
    }

    fn alter_view(&mut self, s: &Stmt, i: usize) {
        let mut i = i;
        if s.seq(i, &["if", "exists"]) {
            i += 2;
        }
        let Some((key, next)) = s.name(i) else {
            return;
        };
        if s.seq(next, &["rename", "to"]) {
            if let Some(new) = s.ident(next + 2) {
                self.rename(&key, (key.0.clone(), new));
            }
            return;
        }
        if s.seq(next, &["set", "schema"]) {
            if let Some(schema) = s.ident(next + 2) {
                self.rename(&key, (schema, key.1.clone()));
            }
            return;
        }
        let Some(rel) = self.rels.get_mut(&key) else {
            return;
        };
        if s.is(next, "set")
            && let Some(end) = s.group_end(next + 1)
            && (next + 2..end).any(|k| s.is(k, "security_invoker"))
        {
            rel.invoker = security_invoker_option(s, next + 2, end - 1);
        } else if s.is(next, "reset")
            && let Some(end) = s.group_end(next + 1)
            && (next + 2..end).any(|k| s.is(k, "security_invoker"))
        {
            rel.invoker = false;
        }
    }

    fn drop(&mut self, s: &Stmt) {
        let Some(what) = s.word(1) else {
            self.unknown(s);
            return;
        };
        let (mut i, kind) = match what.as_str() {
            "table" | "view" | "function" | "procedure" | "routine" => (2, what.clone()),
            "materialized" if s.is(2, "view") => (3, "view".to_string()),
            "policy" => {
                let mut i = 2;
                if s.seq(i, &["if", "exists"]) {
                    i += 2;
                }
                if let Some(name) = s.ident(i)
                    && s.is(i + 1, "on")
                    && let Some((table, _)) = s.name(i + 2)
                {
                    self.policies.remove(&(table, name));
                }
                return;
            }
            _ => return,
        };
        if s.seq(i, &["if", "exists"]) {
            i += 2;
        }
        loop {
            let Some((key, mut next)) = s.name(i) else {
                return;
            };
            if let Some(end) = s.group_end(next) {
                next = end;
            }
            match kind.as_str() {
                "table" | "view" => {
                    self.rels.remove(&key);
                    self.policies.retain(|(t, _), _| *t != key);
                }
                _ => {
                    self.functions.remove(&key);
                }
            }
            if !s.punct(next, ",") {
                return;
            }
            i = next + 1;
        }
    }

    /// GRANT/REVOKE (с позиции `i`), в том числе внутри ALTER DEFAULT PRIVILEGES (`default`).
    fn grant(&mut self, s: &Stmt, i: usize) {
        let grant = s.is(i, "grant");
        let mut j = i + 1;
        if s.seq(j, &["grant", "option", "for"]) {
            return; // отзыв только права передачи: доступ не меняется
        }
        let mut privs = BTreeSet::new();
        while j < s.toks.len() && !s.is(j, "on") {
            match s.word(j).as_deref() {
                Some("all") => privs.extend(ALL_PRIVS),
                Some("select") => {
                    privs.insert(Priv::Select);
                }
                Some("insert") => {
                    privs.insert(Priv::Insert);
                }
                Some("update") => {
                    privs.insert(Priv::Update);
                }
                Some("delete") => {
                    privs.insert(Priv::Delete);
                }
                _ => {}
            }
            j = s.group_end(j).unwrap_or(j + 1);
        }
        if !s.is(j, "on") {
            return; // GRANT role TO role
        }
        j += 1;
        // Объекты.
        enum Target {
            Tables(Vec<Key>),
            Schemas(Vec<String>),
        }
        let target = if s.seq(j, &["all", "tables", "in", "schema"]) {
            let mut schemas = Vec::new();
            let mut k = j + 4;
            while let Some(name) = s.ident(k) {
                if matches!(name.as_str(), "to" | "from") && s.toks[k].kind == Kind::Word {
                    break;
                }
                schemas.push(name);
                k += 1;
                if s.punct(k, ",") {
                    k += 1;
                }
            }
            j = k;
            Target::Schemas(schemas)
        } else {
            if s.is(j, "table") {
                j += 1;
            } else if s.word(j).is_some_and(|w| {
                matches!(
                    w.as_str(),
                    "function"
                        | "functions"
                        | "sequence"
                        | "sequences"
                        | "schema"
                        | "database"
                        | "type"
                        | "domain"
                        | "language"
                        | "large"
                        | "foreign"
                        | "procedure"
                        | "procedures"
                        | "routine"
                        | "routines"
                        | "all"
                        | "tablespace"
                        | "parameter"
                        | "tables"
                )
            }) {
                if s.is(j, "tables") && i > 0 {
                    // ALTER DEFAULT PRIVILEGES … ON TABLES: обрабатывает вызывающий.
                } else {
                    return;
                }
            }
            let mut tables = Vec::new();
            while let Some((key, next)) = s.name(j) {
                if s.toks[j].kind == Kind::Word && (s.is(j, "to") || s.is(j, "from")) {
                    break;
                }
                tables.push(key);
                j = next;
                if s.punct(j, ",") {
                    j += 1;
                } else {
                    break;
                }
            }
            Target::Tables(tables)
        };
        if !(s.is(j, "to") || s.is(j, "from")) {
            return;
        }
        let mut names = Vec::new();
        roles(s, j + 1, &mut names);
        let roles: BTreeSet<Role> = names.iter().flat_map(|n| role_set(n)).copied().collect();
        if roles.is_empty() || privs.is_empty() {
            return;
        }
        let apply = |rel: &mut Relation| {
            for r in &roles {
                for p in &privs {
                    if grant {
                        rel.privs.insert((*r, *p));
                    } else {
                        rel.privs.remove(&(*r, *p));
                    }
                }
            }
        };
        match target {
            Target::Tables(tables) => {
                for key in tables {
                    if let Some(rel) = self.rels.get_mut(&key) {
                        apply(rel);
                    }
                }
            }
            Target::Schemas(schemas) => {
                for (key, rel) in self.rels.iter_mut() {
                    if schemas.contains(&key.0) {
                        apply(rel);
                    }
                }
            }
        }
    }

    fn default_privileges(&mut self, s: &Stmt) {
        let mut schemas = Vec::new();
        let mut j = 3;
        while j < s.toks.len() && !(s.is(j, "grant") || s.is(j, "revoke")) {
            if s.seq(j, &["in", "schema"]) {
                j += 2;
                while let Some(name) = s.ident(j) {
                    if s.toks[j].kind == Kind::Word && (s.is(j, "grant") || s.is(j, "revoke")) {
                        break;
                    }
                    schemas.push(name);
                    j += 1;
                    if s.punct(j, ",") {
                        j += 1;
                    } else {
                        break;
                    }
                }
                continue;
            }
            j += 1;
        }
        let grant = s.is(j, "grant");
        let Some(on) = s.find(j, &["on"]) else {
            return;
        };
        if !s.is(on + 1, "tables") {
            return;
        }
        let mut privs = BTreeSet::new();
        for k in j + 1..on {
            match s.word(k).as_deref() {
                Some("all") => privs.extend(ALL_PRIVS),
                Some(w) => {
                    if let Some(p) = match w {
                        "select" => Some(Priv::Select),
                        "insert" => Some(Priv::Insert),
                        "update" => Some(Priv::Update),
                        "delete" => Some(Priv::Delete),
                        _ => None,
                    } {
                        privs.insert(p);
                    }
                }
                None => {}
            }
        }
        let mut names = Vec::new();
        roles(s, on + 3, &mut names);
        if schemas.is_empty() {
            schemas.push("*".to_string());
        }
        for name in names {
            for role in role_set(&name) {
                for p in &privs {
                    for schema in &schemas {
                        let k = (schema.clone(), *role, *p);
                        if grant {
                            self.default_revoked.remove(&k);
                        } else {
                            self.default_revoked.insert(k);
                        }
                    }
                }
            }
        }
    }

    fn insert_bucket(&mut self, s: &Stmt) {
        if !s.is(1, "into") {
            return;
        }
        let Some((key, next)) = s.name(2) else {
            return;
        };
        if key != ("storage".to_string(), "buckets".to_string()) {
            return;
        }
        let Some(cols_end) = s.group_end(next) else {
            return;
        };
        let cols: Vec<String> = split_commas(s, next + 1, cols_end - 1)
            .into_iter()
            .filter_map(|(a, _)| s.ident(a))
            .collect();
        let (Some(id_col), Some(public_col)) = (
            cols.iter()
                .position(|c| c == "id")
                .or_else(|| cols.iter().position(|c| c == "name")),
            cols.iter().position(|c| c == "public"),
        ) else {
            return;
        };
        if !s.is(cols_end, "values") {
            return;
        }
        let mut j = cols_end + 1;
        while let Some(end) = s.group_end(j) {
            let values = split_commas(s, j + 1, end - 1);
            if let (Some(&(ia, ib)), Some(&(pa, pb))) = (values.get(id_col), values.get(public_col))
                && ib == ia + 1
                && s.toks[ia].kind == Kind::Str
            {
                let id = sql::value(s.text, &s.toks[ia]);
                let public = pb == pa + 1 && is_true_literal(s, pa);
                self.buckets.insert(
                    id,
                    Bucket {
                        public,
                        site: s.site(),
                    },
                );
            }
            j = end;
            if s.punct(j, ",") {
                j += 1;
            } else {
                break;
            }
        }
    }

    fn update_bucket(&mut self, s: &Stmt) {
        let Some((key, next)) = s.name(1) else {
            return;
        };
        if key != ("storage".to_string(), "buckets".to_string()) || !s.is(next, "set") {
            return;
        }
        let Some(p) = (next..s.toks.len()).find(|&k| s.is(k, "public") && s.punct(k + 1, "="))
        else {
            return;
        };
        let public = is_true_literal(s, p + 2);
        let Some(w) = s.find(next, &["where"]) else {
            return;
        };
        let Some(id) = (w..s.toks.len()).find_map(|k| {
            ((s.is(k, "id") || s.is(k, "name"))
                && s.punct(k + 1, "=")
                && s.toks.get(k + 2).is_some_and(|t| t.kind == Kind::Str))
            .then(|| sql::value(s.text, &s.toks[k + 2]))
        }) else {
            return;
        };
        self.buckets.insert(
            id,
            Bucket {
                public,
                site: s.site(),
            },
        );
    }
}

fn is_true_literal(s: &Stmt, i: usize) -> bool {
    let Some(t) = s.toks.get(i) else {
        return false;
    };
    let v = sql::value(s.text, t).to_ascii_lowercase();
    matches!(t.kind, Kind::Word | Kind::Str) && matches!(v.as_str(), "true" | "t" | "on" | "yes")
}

/// Участки `[a, b)` между запятыми верхнего уровня в `[from, to)`.
fn split_commas(s: &Stmt, from: usize, to: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = from;
    for k in from..to.min(s.toks.len()) {
        if s.punct(k, "(") {
            depth += 1;
        } else if s.punct(k, ")") {
            depth -= 1;
        } else if depth == 0 && s.punct(k, ",") {
            out.push((start, k));
            start = k + 1;
        }
    }
    if start < to {
        out.push((start, to));
    }
    out
}

/// Имена столбцов из `( … )` CREATE TABLE.
fn columns(s: &Stmt, open: usize, end: usize) -> Vec<String> {
    split_commas(s, open + 1, end - 1)
        .into_iter()
        .filter_map(|(a, _)| {
            let w = s.word(a);
            if w.as_deref().is_some_and(|w| {
                matches!(
                    w,
                    "constraint" | "primary" | "unique" | "check" | "foreign" | "exclude" | "like"
                )
            }) {
                return None;
            }
            s.ident(a).map(|c| c.to_ascii_lowercase())
        })
        .collect()
}

/// Список ролей с позиции `i`; возвращает позицию за ним.
fn roles(s: &Stmt, mut i: usize, out: &mut Vec<String>) -> usize {
    loop {
        if s.is(i, "group") {
            i += 1;
        }
        let Some(name) = s.ident(i) else {
            return i;
        };
        out.push(if s.toks[i].kind == Kind::Word {
            name
        } else {
            name.to_ascii_lowercase()
        });
        i += 1;
        if s.punct(i, ",") {
            i += 1;
        } else {
            return i;
        }
    }
}

/// `security_invoker [= true|on|1|yes]` внутри опций представления.
fn security_invoker_option(s: &Stmt, from: usize, to: usize) -> bool {
    for k in from..to {
        if s.is(k, "security_invoker") {
            if !s.punct(k + 1, "=") {
                return true;
            }
            let v = s
                .toks
                .get(k + 2)
                .map(|t| sql::value(s.text, t).to_ascii_lowercase())
                .unwrap_or_default();
            return matches!(v.as_str(), "true" | "on" | "1" | "yes");
        }
    }
    false
}

fn mentions_rls(lower: &str) -> bool {
    lower.contains("row level security") || lower.contains("row_level_security")
}

// ---------- Разбор выражений политик ----------

/// Выражение одной строкой: токены через пробел, строки — в кавычках, `( select auth.uid ( ) )`
/// свёрнуто до `auth.uid ( )`, внешние скобки сняты.
fn normalize(expr: &[ExprTok]) -> String {
    let mut out = String::new();
    for (kind, v) in expr {
        let piece = match kind {
            Kind::Str => format!("'{v}'"),
            Kind::Word | Kind::Quoted => v.to_ascii_lowercase(),
            _ => v.clone(),
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&piece);
    }
    let mut s = out.replace(" . ", ".");
    for f in ["uid", "jwt", "role", "email"] {
        s = s.replace(
            &format!("( select auth.{f} ( ) )"),
            &format!("auth.{f} ( )"),
        );
        s = s.replace(
            &format!("( select auth.{f} ( ) as "),
            &format!("( auth.{f} ( ) as "),
        );
    }
    while let Some(inner) = s.strip_prefix("( ").and_then(|r| r.strip_suffix(" )")) {
        // Снимаем, только если скобки — одна внешняя пара.
        let mut depth = 0i32;
        let balanced = inner.split(' ').all(|t| {
            match t {
                "(" => depth += 1,
                ")" => depth -= 1,
                _ => {}
            }
            depth >= 0
        });
        if !balanced || depth != 0 {
            break;
        }
        s = inner.to_string();
    }
    s
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Openness {
    /// `true`: всем, кому политика адресована.
    Open,
    /// Только «вошёл ли пользователь» — любой зарегистрированный.
    AnySignedIn,
    /// Опирается на `user_metadata` — его меняет сам пользователь.
    UserMetadata,
    /// Нет ни `auth.*`, ни вызова функции-помощника: личность не проверяется.
    NoIdentity,
    /// Есть проверка личности (или помощник, который мы не видим).
    Scoped,
}

const NON_IDENTITY_CALLS: &[&str] = &[
    "coalesce",
    "nullif",
    "lower",
    "upper",
    "now",
    "length",
    "char_length",
    "trim",
    "greatest",
    "least",
    "array_length",
    "cardinality",
    "concat",
    "substring",
    "position",
    "split_part",
    "foldername",
    "filename",
    "extension",
    "exists",
    "in",
    "any",
    "all",
    "some",
    "not",
    "and",
    "or",
    "cast",
    "array",
    "row",
    "values",
    "extract",
    "date_trunc",
    "to_char",
    "jsonb_array_length",
    "is",
    "using",
    "check",
    "select",
    "where",
    "from",
    "when",
    "then",
    "else",
    "case",
    "like",
    "ilike",
    "between",
    "current_date",
    "current_timestamp",
    "interval",
    "left",
    "right",
    "starts_with",
    "regexp_like",
    "abs",
    "round",
];

const AUTH_ONLY: &[&str] = &[
    "auth.uid ( ) is not null",
    "auth.role ( ) = 'authenticated'",
    "'authenticated' = auth.role ( )",
    "auth.jwt ( ) is not null",
    "auth.uid ( ) <> null",
    "auth.uid ( ) != null",
    "auth.jwt ( ) ->> 'role' = 'authenticated'",
    "( auth.jwt ( ) ->> 'role' ) = 'authenticated'",
    "current_user = 'authenticated'",
];

fn openness(expr: &[ExprTok]) -> Openness {
    let n = normalize(expr);
    if matches!(n.as_str(), "true" | "1 = 1" | "'t'" | "true = true") {
        return Openness::Open;
    }
    if expr.iter().any(|(_, v)| {
        let v = v.to_ascii_lowercase();
        v == "user_metadata" || v == "raw_user_meta_data"
    }) {
        return Openness::UserMetadata;
    }
    if AUTH_ONLY.contains(&n.as_str()) {
        return Openness::AnySignedIn;
    }
    let mut identity = false;
    for (i, (kind, v)) in expr.iter().enumerate() {
        if !matches!(kind, Kind::Word | Kind::Quoted) {
            continue;
        }
        let v = v.to_ascii_lowercase();
        if matches!(
            v.as_str(),
            "auth" | "current_user" | "session_user" | "current_role" | "current_setting"
        ) {
            identity = true;
            break;
        }
        let call = expr
            .get(i + 1)
            .is_some_and(|(k, t)| *k == Kind::Punct && t == "(");
        if call && !NON_IDENTITY_CALLS.contains(&v.as_str()) {
            identity = true; // функция-помощник (is_admin(), is_member_of(…)) — считаем проверкой
            break;
        }
    }
    if identity {
        Openness::Scoped
    } else {
        Openness::NoIdentity
    }
}

// ---------- Оценка таблиц ----------

const SENSITIVE_COLUMNS: &[&str] = &[
    "email",
    "phone",
    "mobile",
    "password",
    "passwd",
    "secret",
    "ssn",
    "iban",
    "birth",
    "salary",
    "api_key",
    "apikey",
    "private_key",
    "card_number",
    "cvv",
    "passport",
    "national_id",
    "tax_id",
    "stripe_customer",
    "access_token",
    "refresh_token",
    "auth_token",
    "api_token",
    "address",
    "diagnos",
    "medical",
];

fn sensitive_columns(columns: &[String]) -> Vec<String> {
    columns
        .iter()
        .filter(|c| c.as_str() == "token" || SENSITIVE_COLUMNS.iter().any(|s| c.contains(s)))
        .take(4)
        .cloned()
        .collect()
}

const PRIVATE_TABLES: &[&str] = &[
    "user",
    "account",
    "customer",
    "order",
    "payment",
    "invoice",
    "transaction",
    "message",
    "chat",
    "conversation",
    "subscription",
    "session",
    "token",
    "api_key",
    "secret",
    "credential",
    "notification",
    "address",
    "booking",
    "appointment",
    "patient",
    "lead",
    "contact",
    "application",
    "submission",
    "email",
    "wallet",
    "purchase",
    "billing",
];

const PUBLIC_TABLES: &[&str] = &[
    "post",
    "article",
    "blog",
    "product",
    "category",
    "categorie",
    "tag",
    "page",
    "faq",
    "testimonial",
    "review",
    "event",
    "announcement",
    "news",
    "doc",
    "course",
    "lesson",
    "plan",
    "pricing",
    "feature",
    "menu",
    "country",
    "countrie",
    "city",
    "citie",
    "language",
    "comment",
    "listing",
    "recipe",
    "project",
    "portfolio",
    "service",
];

fn name_matches(name: &str, list: &[&str]) -> bool {
    let n = name.to_ascii_lowercase();
    let last = n.rsplit('_').next().unwrap_or(&n);
    let stem = last.strip_suffix('s').unwrap_or(last);
    list.iter().any(|w| stem == *w || last == *w)
}

pub(crate) fn is_public_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("public_") || n.ends_with("_public") || name_matches(&n, PUBLIC_TABLES)
}

pub(crate) fn is_private_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("private") || name_matches(&n, PRIVATE_TABLES)
}

fn storage_objects() -> Key {
    ("storage".to_string(), "objects".to_string())
}

struct Draft {
    key: String,
    site: Site,
    severity: Severity,
    confidence: Confidence,
    title: String,
    explanation: String,
    cwe: &'static str,
    tags: Vec<&'static str>,
}

impl Model {
    fn report(&self, exposed: &[String], out: &mut RlsOutcome) {
        let mut drafts = Vec::new();
        let is_exposed = |k: &Key| exposed.contains(&k.0);
        let has_policy = |k: &Key| self.policies.keys().any(|(t, _)| t == k);
        for (key, rel) in &self.rels {
            if !is_exposed(key) || rel.privs.is_empty() {
                continue;
            }
            let Some(site) = rel.site.clone() else {
                continue;
            };
            let label = key_label(key);
            let who = who_can(&rel.privs);
            match rel.kind {
                RelKind::Table => match rel.rls {
                    Some(false) => {
                        let sensitive = sensitive_columns(&rel.columns);
                        let cols = if sensitive.is_empty() {
                            String::new()
                        } else {
                            format!(" Columns that look sensitive: {}.", sensitive.join(", "))
                        };
                        let (confidence, dynamic) = if self.dynamic_rls {
                            (
                                Confidence::NeedsReview,
                                " A DO block, function or event trigger in the SQL mentions row \
                                 level security; it may enable RLS dynamically, which jetscan does \
                                 not evaluate.",
                            )
                        } else {
                            (Confidence::Potential, "")
                        };
                        drafts.push(Draft {
                            key: format!("no-rls|{label}"),
                            site,
                            severity: Severity::High,
                            confidence,
                            title: format!("Table {label} has no Row Level Security"),
                            explanation: format!(
                                "{label} is in an API-exposed schema and the SQL in this repository \
                                 never enables Row Level Security on it. Without RLS, {who} can \
                                 use the Data API to read, insert, update and delete every row \
                                 with the public anon key that ships in the app.{cols}{dynamic} \
                                 This is from the SQL files only: if RLS was enabled in the \
                                 dashboard, or the project revokes default grants, the table may \
                                 already be closed. Enable it with `alter table {label} enable row \
                                 level security;` and add policies scoped to auth.uid()."
                            ),
                            cwe: "CWE-862",
                            tags: vec!["rls:disabled"],
                        });
                    }
                    Some(true) if !has_policy(key) && !rel.external_policy => {
                        drafts.push(Draft {
                            key: format!("locked|{label}"),
                            site,
                            severity: Severity::Info,
                            confidence: Confidence::Potential,
                            title: format!(
                                "Table {label} has RLS enabled but no policies (closed to the API)"
                            ),
                            explanation: format!(
                                "RLS is on and no policy for {label} is defined in these SQL files, \
                                 so anon and signed-in users get no rows: this is not a leak. If \
                                 the app expects to read it from the browser, add a policy scoped \
                                 to auth.uid(); if only server code (service role) uses it, this \
                                 is the intended state."
                            ),
                            cwe: "CWE-284",
                            tags: vec!["rls:no-policies"],
                        });
                    }
                    _ => {}
                },
                RelKind::View | RelKind::MatView if !rel.invoker => {
                    let what = if rel.kind == RelKind::MatView {
                        "Materialized view"
                    } else {
                        "View"
                    };
                    let fix = if rel.kind == RelKind::MatView {
                        "Materialized views cannot use RLS: move it to a schema that is not \
                         exposed, or revoke select from anon and authenticated."
                    } else {
                        "Create it `with (security_invoker = true)` (Postgres 15+), or revoke \
                         select from anon and authenticated."
                    };
                    drafts.push(Draft {
                        key: format!("view|{label}"),
                        site,
                        severity: Severity::Medium,
                        confidence: Confidence::NeedsReview,
                        title: format!("{what} {label} bypasses Row Level Security"),
                        explanation: format!(
                            "{what} {label} is in an API-exposed schema and runs with its owner's \
                             rights, so it returns rows of the underlying tables regardless of \
                             their RLS policies; {who} can query it. Whether this leaks depends \
                             on what it selects. {fix}"
                        ),
                        cwe: "CWE-284",
                        tags: vec!["rls:view-bypass"],
                    });
                }
                _ => {}
            }
        }

        for policy in self.policies.values() {
            if let Some(d) = self.policy_draft(policy, &is_exposed) {
                drafts.push(d);
            }
        }

        for (key, f) in &self.functions {
            if !is_exposed(key) || !f.definer || f.search_path {
                continue;
            }
            let label = key_label(key);
            let (severity, callable) = if f.trigger {
                (
                    Severity::Low,
                    "It is a trigger function, so the Data API cannot call it directly.",
                )
            } else {
                (
                    Severity::Medium,
                    "Functions in an exposed schema can be called through the Data API (`rpc`) by \
                     anon and signed-in users unless EXECUTE is revoked, and this one runs with \
                     its owner's rights, which bypass RLS; check that it validates auth.uid() \
                     itself.",
                )
            };
            drafts.push(Draft {
                key: format!("definer|{label}"),
                site: f.site.clone(),
                severity,
                confidence: Confidence::NeedsReview,
                title: format!("SECURITY DEFINER function {label} has no fixed search_path"),
                explanation: format!(
                    "{label} is SECURITY DEFINER without `set search_path`, so names inside it \
                     resolve through the caller's search_path (Supabase lint \
                     function_search_path_mutable). Exploiting that needs the ability to create \
                     objects in a schema on the path, which anon usually lacks. {callable} Add \
                     `set search_path = ''` and schema-qualify names in the body."
                ),
                cwe: "CWE-426",
                tags: vec!["rls:security-definer"],
            });
        }

        for (id, b) in &self.buckets {
            if !b.public {
                continue;
            }
            let shown = if is_plain_name(id) {
                format!("'{id}'")
            } else {
                "(name hidden)".to_string()
            };
            drafts.push(Draft {
                key: format!("bucket|{id}"),
                site: b.site.clone(),
                severity: Severity::Info,
                confidence: Confidence::NeedsReview,
                title: format!("Storage bucket {shown} is public"),
                explanation: "A public bucket serves every file to anyone who has or guesses its \
                     URL, without checking policies on download. That is right for avatars and \
                     site images, wrong for user documents, invoices or exports. Uploads are still \
                     governed by storage.objects policies."
                    .to_string(),
                cwe: "CWE-284",
                tags: vec!["storage:public-bucket"],
            });
        }

        for d in drafts {
            if d.site.ignored {
                out.ignored_inline += 1;
                continue;
            }
            let mut tags = vec![
                "web".to_string(),
                "supabase".to_string(),
                "rls".to_string(),
                "sql".to_string(),
            ];
            tags.extend(d.tags.iter().map(|t| t.to_string()));
            out.findings.push(WebFinding {
                id: finding_id(RULE_ID, &d.site.path, &d.key),
                rule_id: RULE_ID,
                title: ui::sanitize_line(&d.title),
                category: "access_control",
                severity: d.severity,
                confidence: d.confidence,
                location: SourceLocation {
                    relative_path: d.site.path.clone(),
                    line: Some(d.site.line),
                    column: Some(d.site.col),
                },
                evidence: Evidence {
                    redacted_excerpt: Some(d.site.excerpt.clone()),
                    fingerprint: None,
                },
                explanation: ui::sanitize_line(&d.explanation),
                remediation_id: Some(format!("{RULE_ID}:enable-rls-and-scope-policies")),
                references: REFERENCES.to_vec(),
                cwe_ids: vec![d.cwe],
                tags,
            });
        }
    }

    fn policy_draft(&self, p: &Policy, is_exposed: &dyn Fn(&Key) -> bool) -> Option<Draft> {
        let storage = p.table == storage_objects();
        if !p.permissive || !(storage || is_exposed(&p.table)) {
            return None;
        }
        let rel = self.rels.get(&p.table);
        // RLS выключен — таблица открыта и без политики; об этом уже говорит находка no-rls.
        if rel.is_some_and(|r| r.rls == Some(false) && r.kind == RelKind::Table) {
            return None;
        }
        let anon = p.roles.is_empty() || p.roles.iter().any(|r| r == "anon" || r == "public");
        let authenticated = anon || p.roles.iter().any(|r| r == "authenticated");
        if !authenticated {
            return None; // service_role, postgres, свои роли
        }
        let expr = match p.cmd {
            Cmd::Insert => p.check.as_ref(),
            _ => p.using.as_ref().or(p.check.as_ref()),
        }?;
        let open = openness(expr);
        let label = key_label(&p.table);
        let columns = rel.map(|r| r.columns.clone()).unwrap_or_default();
        let sensitive = sensitive_columns(&columns);
        let restricted = self
            .policies
            .values()
            .any(|o| !o.permissive && o.table == p.table && o.cmd.covers(p.cmd));
        let who = if anon {
            "anyone with the public anon key"
        } else {
            "any signed-in user (sign-ups are open by default)"
        };
        let verb = match p.cmd {
            Cmd::All => "read and change",
            Cmd::Select => "read",
            Cmd::Insert => "insert into",
            Cmd::Update => "update",
            Cmd::Delete => "delete",
        };
        let target = if storage {
            "storage.objects (files in every bucket the policy covers)".to_string()
        } else {
            label.clone()
        };
        let name = ui::sanitize_line(&p.name);
        let cols = if sensitive.is_empty() {
            String::new()
        } else {
            format!(" Columns that look sensitive: {}.", sensitive.join(", "))
        };
        let writes = matches!(p.cmd, Cmd::All | Cmd::Update | Cmd::Delete);
        let (severity, confidence, title, why, tag) = match open {
            Openness::Open => {
                let (sev, conf) = match p.cmd {
                    Cmd::All | Cmd::Update | Cmd::Delete => (Severity::High, Confidence::Potential),
                    Cmd::Insert => (Severity::Medium, Confidence::NeedsReview),
                    Cmd::Select => {
                        if storage || !sensitive.is_empty() || is_private_name(&p.table.1) {
                            (Severity::High, Confidence::Potential)
                        } else if is_public_name(&p.table.1) {
                            (Severity::Low, Confidence::NeedsReview)
                        } else {
                            (Severity::Medium, Confidence::NeedsReview)
                        }
                    }
                };
                let scope = if p.cmd == Cmd::Insert {
                    "any rows"
                } else {
                    "every row"
                };
                (
                    sev,
                    conf,
                    format!(
                        "Policy \"{name}\" lets {} {verb} {scope} of {label}",
                        short(anon)
                    ),
                    format!(
                        "Policy \"{name}\" ({} on {target}) has the condition `true`, so {who} \
                         can {verb} {scope}.{cols}{}",
                        p.cmd.label(),
                        if p.cmd == Cmd::Select
                            && is_public_name(&p.table.1)
                            && sensitive.is_empty()
                        {
                            " The table name suggests public content, so this may be intended."
                        } else if p.cmd == Cmd::Insert {
                            " Public inserts are sometimes intended (contact forms, waitlists); \
                             without a user_id = auth.uid() check, rows can also be written on \
                             behalf of other users."
                        } else {
                            ""
                        }
                    ),
                    "policy:open",
                )
            }
            Openness::UserMetadata => (
                Severity::High,
                Confidence::Potential,
                format!("Policy \"{name}\" on {label} trusts user_metadata"),
                format!(
                    "Policy \"{name}\" ({} on {target}) reads user_metadata / raw_user_meta_data \
                     from the JWT. Users can change their own user_metadata with \
                     supabase.auth.updateUser(), so any user can grant themselves whatever this \
                     policy checks. Use app_metadata (only the server can set it) or a table \
                     protected by RLS.",
                    p.cmd.label()
                ),
                "policy:user-metadata",
            ),
            Openness::AnySignedIn if writes => (
                Severity::High,
                Confidence::NeedsReview,
                format!("Policy \"{name}\" lets any signed-in user {verb} every row of {label}"),
                format!(
                    "Policy \"{name}\" ({} on {target}) only checks that the caller is signed in. \
                     Sign-ups are open by default, so anyone can create an account and {verb} \
                     every row, including other users' rows. Compare the owner column with \
                     auth.uid().",
                    p.cmd.label()
                ),
                "policy:any-signed-in",
            ),
            Openness::AnySignedIn
                if p.cmd == Cmd::Select
                    && (storage || !sensitive.is_empty() || is_private_name(&p.table.1)) =>
            {
                (
                    Severity::Medium,
                    Confidence::NeedsReview,
                    format!("Policy \"{name}\" lets any signed-in user read every row of {label}"),
                    format!(
                        "Policy \"{name}\" (SELECT on {target}) only checks that the caller is \
                         signed in. Sign-ups are open by default, so anyone can create an account \
                         and read every row.{cols} If rows belong to users, compare the owner \
                         column with auth.uid()."
                    ),
                    "policy:any-signed-in",
                )
            }
            Openness::NoIdentity if writes || (storage && p.cmd == Cmd::Insert) => (
                Severity::Medium,
                Confidence::NeedsReview,
                format!(
                    "Policy \"{name}\" lets {} {verb} rows of {label} without checking who they are",
                    short(anon)
                ),
                format!(
                    "Policy \"{name}\" ({} on {target}) filters rows by their own columns only \
                     (no auth.uid(), auth.jwt() or helper function), so {who} can {verb} every \
                     row that matches. Values in those columns are often set by the same users.",
                    p.cmd.label()
                ),
                "policy:no-identity",
            ),
            _ => return None,
        };
        let (confidence, restricted_note) = if restricted {
            (
                Confidence::NeedsReview,
                " A RESTRICTIVE policy on the same table also applies and may narrow this.",
            )
        } else {
            (confidence, "")
        };
        Some(Draft {
            key: format!("policy|{label}|{}|{tag}", p.name),
            site: p.site.clone(),
            severity,
            confidence,
            title,
            explanation: format!(
                "{why}{restricted_note} Based on the SQL in this repository; policies changed in \
                 the dashboard are not seen."
            ),
            cwe: if open == Openness::UserMetadata {
                "CWE-639"
            } else {
                "CWE-862"
            },
            tags: vec![tag],
        })
    }
}

fn short(anon: bool) -> &'static str {
    if anon { "anyone" } else { "any signed-in user" }
}

fn who_can(privs: &BTreeSet<(Role, Priv)>) -> &'static str {
    if privs.iter().any(|(r, _)| *r == Role::Anon) {
        "anyone"
    } else {
        "any signed-in user"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[(&str, &str)]) -> RlsOutcome {
        let mut c = RlsCollector::default();
        for (path, text) in files {
            if is_supabase_config(path) {
                c.config_file(path, text);
            } else {
                c.sql_file(path, text);
            }
        }
        c.finish(true)
    }

    fn summary(out: &RlsOutcome) -> Vec<(String, Severity, Confidence)> {
        out.findings
            .iter()
            .map(|f| (f.title.clone(), f.severity, f.confidence))
            .collect()
    }

    const M: &str = "supabase/migrations/20240101000000_init.sql";

    #[test]
    fn groups_and_paths() {
        assert_eq!(
            sql_group("supabase/migrations/1_a.sql"),
            Some(("supabase".to_string(), Source::Supabase))
        );
        assert_eq!(
            sql_group("apps/web/supabase/schema.sql"),
            Some(("apps/web/supabase".to_string(), Source::Supabase))
        );
        assert_eq!(sql_group("supabase/tests/rls.test.sql"), None);
        assert_eq!(sql_group("supabase/functions/x/q.sql"), None);
        assert_eq!(
            sql_group("prisma/migrations/2024_init/migration.sql"),
            Some(("prisma".to_string(), Source::Prisma))
        );
        assert_eq!(sql_group("prisma/seed.sql"), None);
        assert_eq!(
            sql_group("drizzle/0000_init.sql"),
            Some(("drizzle".to_string(), Source::Drizzle))
        );
        assert_eq!(sql_group("db/schema.sql"), None);
        assert!(is_supabase_config("supabase/config.toml"));
        assert!(!is_supabase_config("config.toml"));
    }

    #[test]
    fn table_without_rls_is_high_potential() {
        let out = run(&[(
            M,
            "create table public.profiles (id uuid primary key, email text, full_name text);\n\
             create table notes (id bigint);\n\
             alter table notes enable row level security;\n\
             create policy \"own\" on notes for select to authenticated using ((select auth.uid()) = user_id);",
        )]);
        assert_eq!(
            summary(&out),
            vec![(
                "Table public.profiles has no Row Level Security".to_string(),
                Severity::High,
                Confidence::Potential
            )]
        );
        let f = &out.findings[0];
        assert!(f.explanation.contains("email"));
        assert_eq!(f.location.line, Some(1));
        assert_eq!(out.statements, 4);
    }

    #[test]
    fn rls_tracked_across_files_rename_and_drop() {
        let out = run(&[
            (
                "supabase/migrations/2_b.sql",
                "alter table public.a enable row level security;\nalter table public.c rename to d;",
            ),
            (
                "supabase/migrations/1_a.sql",
                "create table public.a (id int);\ncreate table public.b (id int);\ncreate table public.c (id int);\n\
                 create table if not exists public.e (id int); drop table if exists public.b, public.e cascade;",
            ),
        ]);
        let titles: Vec<String> = out.findings.iter().map(|f| f.title.clone()).collect();
        assert_eq!(
            titles,
            vec![
                "Table public.a has RLS enabled but no policies (closed to the API)".to_string(),
                "Table public.d has no Row Level Security".to_string(),
            ]
        );
    }

    #[test]
    fn disable_after_enable_and_quoted_names() {
        let out = run(&[(
            M,
            "CREATE TABLE \"public\".\"Orders\" (\"id\" int);\n\
             ALTER TABLE ONLY \"public\".\"Orders\" ENABLE ROW LEVEL SECURITY;\n\
             ALTER TABLE \"public\".\"Orders\" DISABLE ROW LEVEL SECURITY;",
        )]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(
            out.findings[0].title,
            "Table public.Orders has no Row Level Security"
        );
        assert_eq!(out.findings[0].location.line, Some(3));
    }

    #[test]
    fn revoked_grants_and_unexposed_schemas_are_quiet() {
        let out = run(&[(
            M,
            "create schema private;\ncreate table private.keys (id int);\n\
             create table public.audit (id int);\nrevoke all on table public.audit from anon, authenticated;\n\
             alter default privileges in schema public revoke all on tables from anon, authenticated;\n\
             create table public.later (id int);\n\
             create temp table scratch (id int);",
        )]);
        assert!(out.findings.is_empty(), "{:?}", summary(&out));
        // Частичный отзыв: authenticated остаётся.
        let out = run(&[(
            M,
            "create table public.t (id int);\nrevoke all on public.t from anon;",
        )]);
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].explanation.contains("any signed-in user"));
    }

    #[test]
    fn config_toml_exposed_schemas() {
        let out = run(&[
            (
                "supabase/config.toml",
                "[db]\nport = 1\n[api]\nenabled = true\nschemas = [\"public\", \"api\"]\n",
            ),
            (
                M,
                "create table api.items (id int);\ncreate table other.x (id int);",
            ),
        ]);
        assert_eq!(summary(&out).len(), 1);
        assert!(out.findings[0].title.contains("api.items"));
        let out = run(&[
            ("supabase/config.toml", "[api]\nenabled = false\n"),
            (M, "create table public.items (id int);"),
        ]);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn open_policies_by_command_and_table() {
        let out = run(&[(
            M,
            "create table public.posts (id int, title text);\nalter table public.posts enable row level security;\n\
             create policy \"read\" on public.posts for select using (true);\n\
             create table public.orders (id int, total int);\nalter table public.orders enable row level security;\n\
             create policy \"read\" on public.orders for select to anon using (true);\n\
             create policy \"upd\" on public.orders for update to authenticated using (true) with check (true);\n\
             create policy \"ins\" on public.orders for insert with check (true);\n\
             create table public.widgets (id int);\nalter table public.widgets enable row level security;\n\
             create policy \"w\" on public.widgets for select using ( ( true ) );\n\
             create policy \"svc\" on public.widgets for all to service_role using (true);",
        )]);
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Policy \"ins\" lets anyone insert into any rows of public.orders".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "Policy \"read\" lets anyone read every row of public.orders".to_string(),
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Policy \"upd\" lets any signed-in user update every row of public.orders"
                        .to_string(),
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Policy \"read\" lets anyone read every row of public.posts".to_string(),
                    Severity::Low,
                    Confidence::NeedsReview
                ),
                (
                    "Policy \"w\" lets anyone read every row of public.widgets".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
            ]
        );
    }

    #[test]
    fn scoped_policies_are_quiet_and_dropped_policies_forgotten() {
        let out = run(&[(
            M,
            "create table public.todos (id int, user_id uuid);\nalter table public.todos enable row level security;\n\
             create policy \"sel\" on public.todos for select to authenticated using ((select auth.uid()) = user_id);\n\
             create policy \"upd\" on public.todos for update using (auth.uid() = user_id) with check (auth.uid() = user_id);\n\
             create policy \"adm\" on public.todos for delete using (public.is_admin());\n\
             create policy \"pub\" on public.todos for select using (is_public = true);\n\
             create policy \"tmp\" on public.todos for all using (true);\n\
             drop policy if exists \"tmp\" on public.todos;",
        )]);
        assert!(out.findings.is_empty(), "{:?}", summary(&out));
    }

    #[test]
    fn signed_in_only_metadata_and_no_identity() {
        let out = run(&[(
            M,
            "create table public.messages (id int, body text);\nalter table public.messages enable row level security;\n\
             create policy \"a\" on public.messages for delete to authenticated using (auth.role() = 'authenticated');\n\
             create policy \"b\" on public.messages for select using (auth.uid() is not null);\n\
             create policy \"c\" on public.messages for update using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n\
             create policy \"d\" on public.messages for update using (status = 'draft');\n\
             create policy \"e\" on public.messages for insert to authenticated with check (auth.uid() is not null);",
        )]);
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Policy \"a\" lets any signed-in user delete every row of public.messages".to_string(),
                    Severity::High,
                    Confidence::NeedsReview
                ),
                (
                    "Policy \"b\" lets any signed-in user read every row of public.messages".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "Policy \"c\" on public.messages trusts user_metadata".to_string(),
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Policy \"d\" lets anyone update rows of public.messages without checking who they are"
                        .to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
            ]
        );
    }

    #[test]
    fn restrictive_policy_downgrades_and_alter_policy_updates() {
        let out = run(&[(
            M,
            "create table public.notes (id int);\nalter table public.notes enable row level security;\n\
             create policy \"all\" on public.notes for select using (true);\n\
             create policy \"mfa\" on public.orders as restrictive for all to authenticated using ((select auth.jwt()->>'aal') = 'aal2');",
        )]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].confidence, Confidence::NeedsReview);
        let out = run(&[(
            M,
            "create table public.notes (id int);\nalter table public.notes enable row level security;\n\
             create policy \"p\" on public.notes for update using (auth.uid() = owner);\n\
             alter policy \"p\" on public.notes using (true);",
        )]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].location.line, Some(4));
    }

    #[test]
    fn storage_policies_and_buckets() {
        let out = run(&[(
            M,
            "insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('docs', 'docs', false);\n\
             update storage.buckets set public = true where id = 'exports';\n\
             create policy \"up\" on storage.objects for insert with check (bucket_id = 'avatars');\n\
             create policy \"own\" on storage.objects for insert to authenticated with check (bucket_id = 'docs' and (storage.foldername(name))[1] = auth.uid()::text);\n\
             create policy \"r\" on storage.objects for select using (true);",
        )]);
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Policy \"r\" lets anyone read every row of storage.objects".to_string(),
                    Severity::High,
                    Confidence::Potential
                ),
                (
                    "Policy \"up\" lets anyone insert into rows of storage.objects without checking who they are"
                        .to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "Storage bucket 'avatars' is public".to_string(),
                    Severity::Info,
                    Confidence::NeedsReview
                ),
                (
                    "Storage bucket 'exports' is public".to_string(),
                    Severity::Info,
                    Confidence::NeedsReview
                ),
            ]
        );
    }

    #[test]
    fn security_definer_and_views() {
        let out = run(&[(
            M,
            "create or replace function public.get_all() returns setof text language sql security definer as $$ select 1 $$;\n\
             create function public.safe() returns int language plpgsql security definer set search_path = '' as $$ begin return 1; end $$;\n\
             create function public.handle_new_user() returns trigger language plpgsql security definer as $$ begin return new; end $$;\n\
             create function private.hidden() returns int language sql security definer as $$ select 1 $$;\n\
             create function public.fixed() returns int language sql security definer as $$ select 1 $$;\n\
             alter function public.fixed() set search_path = public;\n\
             create view public.stats as select count(*) from public.x;\n\
             create view public.ok with (security_invoker = true) as select 1;\n\
             create materialized view public.mv as select 1;\n\
             create view public.later as select 1;\nalter view public.later set (security_invoker = on);",
        )]);
        assert_eq!(
            summary(&out),
            vec![
                (
                    "Materialized view public.mv bypasses Row Level Security".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "View public.stats bypasses Row Level Security".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "SECURITY DEFINER function public.get_all has no fixed search_path".to_string(),
                    Severity::Medium,
                    Confidence::NeedsReview
                ),
                (
                    "SECURITY DEFINER function public.handle_new_user has no fixed search_path"
                        .to_string(),
                    Severity::Low,
                    Confidence::NeedsReview
                ),
            ]
        );
    }

    #[test]
    fn dynamic_rls_downgrades_and_unknown_is_counted() {
        let out = run(&[(
            M,
            "create table public.t (id int);\n\
             do $$ begin execute format('alter table %I enable row level security', 't'); end $$;\n\
             create rule r as on insert to t do nothing;\nfrobnicate everything;",
        )]);
        assert!(out.dynamic_rls);
        assert_eq!(out.findings[0].confidence, Confidence::NeedsReview);
        assert_eq!(out.unknown.get("create rule"), Some(&1));
        assert_eq!(out.unknown.get("frobnicate everything"), Some(&1));
    }

    #[test]
    fn pg_dump_style_is_understood() {
        let dump = "SET statement_timeout = 0;\nSELECT pg_catalog.set_config('search_path', '', false);\n\
            \\restrict abc\n\
            CREATE TABLE IF NOT EXISTS \"public\".\"profiles\" (\n    \"id\" \"uuid\" NOT NULL,\n    \"username\" \"text\"\n);\n\
            ALTER TABLE \"public\".\"profiles\" OWNER TO \"postgres\";\n\
            ALTER TABLE ONLY \"public\".\"profiles\"\n    ADD CONSTRAINT \"profiles_pkey\" PRIMARY KEY (\"id\");\n\
            CREATE POLICY \"Public profiles are viewable by everyone.\" ON \"public\".\"profiles\" FOR SELECT USING (true);\n\
            CREATE POLICY \"Users can update own profile.\" ON \"public\".\"profiles\" FOR UPDATE USING ((\"auth\".\"uid\"() = \"id\"));\n\
            ALTER TABLE \"public\".\"profiles\" ENABLE ROW LEVEL SECURITY;\n\
            GRANT ALL ON TABLE \"public\".\"profiles\" TO \"anon\";\n";
        let out = run(&[("supabase/schema.sql", dump)]);
        assert!(out.unknown.is_empty(), "{:?}", out.unknown);
        assert_eq!(
            summary(&out),
            vec![(
                "Policy \"Public profiles are viewable by everyone.\" lets anyone read every row of public.profiles"
                    .to_string(),
                Severity::Medium,
                Confidence::NeedsReview
            )]
        );
    }

    #[test]
    fn ignore_marker_and_stable_ids() {
        let out = run(&[(
            M,
            "create table public.a (id int); -- jetscan:ignore\ncreate table public.b (id int);",
        )]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.ignored_inline, 1);
        let shifted = run(&[(M, "\n\ncreate table public.b (id int);")]);
        assert_eq!(shifted.findings[0].id, out.findings[0].id);
        assert_eq!(shifted.findings[0].location.line, Some(3));
    }

    #[test]
    fn prisma_sql_needs_supabase() {
        let mut c = RlsCollector::default();
        c.sql_file(
            "prisma/migrations/1/migration.sql",
            "CREATE TABLE \"User\" (\"id\" TEXT NOT NULL);",
        );
        assert_eq!(c.finish(false).files, 0);
        let mut c = RlsCollector::default();
        c.sql_file(
            "prisma/migrations/1/migration.sql",
            "CREATE TABLE \"User\" (\"id\" TEXT NOT NULL);",
        );
        let out = c.finish(true);
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].title.contains("public.User"));
    }

    #[test]
    fn excerpt_hides_long_strings() {
        let key = crate::web_audit::testutil::stripe_secret();
        let out = run(&[(
            M,
            &format!(
                "create table public.k (id int default '{key}', note text default 'a longer sentence here');"
            ),
        )]);
        let excerpt = out.findings[0].evidence.redacted_excerpt.clone().unwrap();
        assert!(!excerpt.contains(&key));
        assert!(!excerpt.contains("longer"));
        assert!(
            excerpt.starts_with("create table public.k(id int default '…', note text default '…'"),
            "{excerpt}"
        );
    }
}
