//! Секреты, которые видно по коду, а не по формату ключа (бенчмарк `bench/VULN-APPS.md`).
//!
//! Три построчных правила — те же матчеры «строка → участки с секретом», что в `rules.rs`
//! (примеры ниже — со строковым литералом на месте `<lit>`):
//! - `hardcoded-crypto-key`: литерал передан ключом прямо в криптовызов
//!   (`createHmac(alg, <lit>)`, `jwt.sign(p, <lit>)`, `new SecretKeySpec(<lit>.getBytes(), …)`);
//! - `fallback-secret`: запасное значение секрета на случай пустой переменной окружения
//!   (`process.env.JWT_SECRET || <lit>`, `os.getenv(<SECRET_KEY>, <lit>)`);
//! - `hardcoded-password-check`: пароль сравнивается с литералом (`password == <lit>`).
//!
//! Слабое значение (`secret`, `your-secret-key`) здесь — не заглушка, а сама проблема:
//! именно с ним приложение подписывает токены, если переменную забыли задать. Поэтому
//! `is_placeholder` в первых двух правилах не применяется; отсекаются только подстановки
//! (`${X}`, `{{x}}`) и пустые строки. Потока данных нет: правило видит одну строку.

use super::Span;

/// Литерал на строке: границы содержимого (без кавычек) и байт сразу за закрывающей кавычкой.
struct Literal {
    start: usize,
    end: usize,
    after: usize,
}

/// Строковый литерал, открывающийся ровно в `at` (`'…'`, `"…"`, `` `…` ``).
/// Незакрытый на этой строке — `None`.
fn literal_at(line: &str, at: usize) -> Option<Literal> {
    let bytes = line.as_bytes();
    let quote = *bytes.get(at)?;
    if !matches!(quote, b'\'' | b'"' | b'`') {
        return None;
    }
    let mut i = at + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            byte if byte == quote => {
                return Some(Literal {
                    start: at + 1,
                    end: i,
                    after: i + 1,
                });
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
        i += 1;
    }
    i
}

/// Аргументы вызова, чья `(` стоит в `open`: границы каждого аргумента верхнего уровня.
/// Вызов, не закрытый на этой строке, отдаёт аргументы, которые успели закончиться.
fn call_args(line: &str, open: usize) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut start = open + 1;
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' => match literal_at(line, i) {
                Some(literal) => {
                    i = literal.after;
                    continue;
                }
                None => return args,
            },
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth > 0 => depth -= 1,
            b')' => {
                args.push((start, i));
                return args;
            }
            b',' if depth == 0 => {
                args.push((start, i));
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    args
}

/// Значение пригодно как находка: не пустое, не подстановка шаблона, не одни звёздочки.
fn concrete(value: &str, min_chars: usize) -> bool {
    let trimmed = value.trim();
    trimmed.chars().count() >= min_chars
        && !trimmed.contains("${")
        && !trimmed.contains("{{")
        && !trimmed.starts_with('$')
        && !trimmed.starts_with('%')
        && !(trimmed.starts_with('<') && trimmed.ends_with('>'))
        && !trimmed.bytes().all(|b| b == b'*' || b == b'x' || b == b'X')
}

fn left_boundary(line: &str, at: usize) -> bool {
    line[..at]
        .bytes()
        .next_back()
        .is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'$'))
}

/// Правило из этого файла: находка — признак в коде, а не формат ключа провайдера.
pub fn is_code_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "hardcoded-crypto-key" | "fallback-secret" | "hardcoded-password-check"
    )
}

/// Объяснение для отчётов Android/iOS: у этих правил нет «формата ключа».
pub fn explain(rule_id: &str, where_: &str) -> String {
    match rule_id {
        "hardcoded-crypto-key" => format!(
            "A signing or encryption key is written as a string in {where_}. Anyone who reads it can sign tokens or decrypt data as the app. Move the key out of the code (server,              Keystore / Keychain, or build-time secrets) and rotate it."
        ),
        "fallback-secret" => format!(
            "A secret has a hardcoded fallback in {where_}: when the environment variable is missing, this value is used instead. Fail on a missing secret instead of falling back."
        ),
        _ => format!(
            "A password is compared with a hardcoded value in {where_}. Needs review: this is often a backdoor or a test login left in the code; anyone who reads the code can log in."
        ),
    }
}

/// Правила этого файла — про код. В документации (`.md`, `.rst`, ...) та же строка — пример
/// («так делать нельзя»), а не приложение: там они не срабатывают.
pub fn applies_to(rule_id: &str, path: &str) -> bool {
    if !is_code_rule(rule_id) {
        return true;
    }
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    !matches!(
        ext.as_deref(),
        Some("md" | "mdx" | "markdown" | "rst" | "txt" | "adoc" | "asciidoc" | "ipynb")
    )
}

// --- hardcoded-crypto-key ----------------------------------------------------------------

/// (вызов с открывающей скобкой, номер аргумента-ключа).
const KEY_SINKS: &[(&str, usize)] = &[
    ("createHmac(", 1),
    ("createCipheriv(", 1),
    ("createDecipheriv(", 1),
    ("jwt.sign(", 1),
    ("jwt.verify(", 1),
    ("jsonwebtoken.sign(", 1),
    ("jsonwebtoken.verify(", 1),
    ("jwt.encode(", 1),
    ("jwt.decode(", 1),
    ("hmac.new(", 0),
    ("SecretKeySpec(", 0),
    ("SignedString(", 0),
];

pub(super) const KEY_TRIGGERS: &[&str] = &[
    "RNEncryptor",
    "RNDecryptor",
    "RNCryptor",
    "AES(key:",
    "HMAC(key:",
    "ChaCha20(key:",
    "Blowfish(key:",
    "createHmac(",
    "createCipheriv(",
    "createDecipheriv(",
    "jwt.sign(",
    "jwt.verify(",
    "jsonwebtoken.sign(",
    "jsonwebtoken.verify(",
    "jwt.encode(",
    "jwt.decode(",
    "hmac.new(",
    "SecretKeySpec(",
    "SignedString(",
];

/// Ключ-литерал в аргументе: `'k'`, `b'k'`, `"k".getBytes(…)`, `'k'.encode()`,
/// `Buffer.from('k')`, `[]byte("k")`. Аргумент целиком — этот литерал (с обёрткой).
fn key_literal(line: &str, start: usize, end: usize) -> Option<Span> {
    let bytes = line.as_bytes();
    let mut i = skip_ws(bytes, start);
    let mut wrapped = false;
    for wrapper in ["Buffer.from(", "[]byte(", "bytes("] {
        if line[i..end].starts_with(wrapper) {
            i = skip_ws(bytes, i + wrapper.len());
            wrapped = true;
            break;
        }
    }
    if bytes.get(i) == Some(&b'b') && matches!(bytes.get(i + 1), Some(b'\'' | b'"')) {
        i += 1; // Python bytes: b'…'
    }
    let literal = literal_at(line, i)?;
    if literal.after > end {
        return None;
    }
    let mut rest = line[literal.after..end].trim_start();
    if wrapped {
        // `Buffer.from('k', 'utf8')` / `[]byte("k")`: дальше — `)` или второй аргумент.
        rest = rest.trim_start_matches(|c: char| c != ')');
        rest = rest.strip_prefix(')').unwrap_or(rest).trim_start();
    }
    let tail_ok = rest.is_empty()
        || [".getBytes(", ".encode(", ".toByteArray(", ".toByteArray()"]
            .iter()
            .any(|t| rest.starts_with(t));
    if !tail_ok || !concrete(&line[literal.start..literal.end], 4) {
        return None;
    }
    // Тестовые векторы алгоритмов (`createHmac('sha256', 'key')`) — тоже ключ в коде;
    // но строка-«ключ», совпадающая с названием алгоритма, — это ошибка порядка аргументов.
    let value = line[literal.start..literal.end].to_ascii_lowercase();
    if [
        "sha1",
        "sha256",
        "sha384",
        "sha512",
        "md5",
        "hs256",
        "aes-256-cbc",
        "aes-256-gcm",
    ]
    .contains(&value.as_str())
    {
        return None;
    }
    Some(Span {
        start: literal.start,
        end: literal.end,
    })
}

pub(super) fn find_hardcoded_crypto_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for &(sink, index) in KEY_SINKS {
        for (at, _) in line.match_indices(sink) {
            // `myjwt.sign(` — не тот вызов; `crypto.createHmac(` и `.createHmac(` — те.
            if !left_boundary(line, at) {
                continue;
            }
            let open = at + sink.len() - 1;
            let args = call_args(line, open);
            if let Some(&(start, end)) = args.get(index)
                && let Some(span) = key_literal(line, start, end)
            {
                spans.push(span);
            }
        }
    }
    // Swift: `RNEncryptor.encryptData(d, with: s, password: "k")`, `RNDecryptor.decryptData(d,
    // withPassword: "k")`, CryptoSwift `AES(key: "k", iv: "…")`.
    let rn = ["RNEncryptor", "RNDecryptor", "RNCryptor"]
        .iter()
        .any(|w| line.contains(w));
    let labels: &[&str] = if rn {
        &["withPassword:", "password:"]
    } else {
        &["AES(key:", "HMAC(key:", "ChaCha20(key:", "Blowfish(key:"]
    };
    for label in labels {
        for (at, _) in line.match_indices(label) {
            if !label.contains('(') && !left_boundary(line, at) {
                continue;
            }
            let start = skip_ws(line.as_bytes(), at + label.len());
            if let Some(literal) = literal_at(line, start)
                && concrete(&line[literal.start..literal.end], 4)
            {
                spans.push(Span {
                    start: literal.start,
                    end: literal.end,
                });
            }
        }
    }
    spans.sort_by_key(|s| (s.start, s.end));
    spans.dedup();
    spans
}

// --- fallback-secret ---------------------------------------------------------------------

pub(super) const FALLBACK_TRIGGERS: &[&str] = &[
    "env.",
    "env[",
    "environ.get(",
    "getenv(",
    "env(",
    "ENV.fetch(",
    "Deno.env.get(",
];

/// Имя переменной окружения — сам секрет, а не его настройка: последняя часть имени —
/// секретное слово (`JWT_SECRET`, `DB_PASSWORD`, `GITHUB_TOKEN`, `SESSION_KEY`), а не
/// `AUTH_PASSWORD_BROKER` / `PASSWORD_RESET_TABLE` / `TOKEN_EXPIRY`.
fn secret_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let public = [
        "NEXT_PUBLIC_",
        "VITE_",
        "REACT_APP_",
        "EXPO_PUBLIC_",
        "PUBLIC_",
        "GATSBY_",
        "NUXT_PUBLIC_",
    ]
    .iter()
    .any(|p| upper.starts_with(p))
        || ["PUBLIC", "PUBLISHABLE", "ANON", "SITE_KEY"]
            .iter()
            .any(|w| upper.contains(w));
    if public {
        return false;
    }
    if upper == "SECRET_KEY_BASE" {
        return true; // Rails
    }
    let last = upper.rsplit('_').next().unwrap_or(&upper);
    match last {
        "SECRET" | "PASSWORD" | "PASSWD" | "PWD" | "PASS" | "PASSPHRASE" | "TOKEN" | "APIKEY"
        | "SALT" | "PEPPER" => true,
        // `_KEY` — секрет, только если рядом сказано, какой: `API_KEY`, `SESSION_KEY`, `APP_KEY`;
        // `CACHE_KEY`, `PARTITION_KEY`, `SORT_KEY` — имена, а не секреты.
        "KEY" => [
            "SECRET",
            "API",
            "PRIVATE",
            "SESSION",
            "ENCRYPT",
            "SIGN",
            "JWT",
            "APP",
            "MASTER",
            "AUTH",
            "ACCESS",
            "CRYPT",
            "HMAC",
            "AES",
            "CIPHER",
            "LICENSE",
            "TOKEN",
            "SERVICE_ROLE",
            "WEBHOOK",
        ]
        .iter()
        .any(|w| upper.contains(w)),
        _ => false,
    }
}

fn env_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && name.bytes().next().is_some_and(|b| !b.is_ascii_digit())
}

/// Запасное значение — литерал, весь операнд: `|| "x"`, `?? 'x'`, `?: 'x'`.
fn fallback_literal(line: &str, mut i: usize) -> Option<Span> {
    let bytes = line.as_bytes();
    i = skip_ws(bytes, i);
    let op_len = ["||", "??", "?:", "or "]
        .iter()
        .find(|op| line[i..].starts_with(**op))?
        .len();
    i = skip_ws(bytes, i + op_len);
    let literal = literal_at(line, i)?;
    let after = skip_ws(bytes, literal.after);
    // `|| "a" + b` — значение составное; `|| "x".repeat(…)` — тоже не литерал.
    if bytes
        .get(after)
        .is_some_and(|b| matches!(b, b'+' | b'.' | b'['))
    {
        return None;
    }
    concrete(&line[literal.start..literal.end], 3).then_some(Span {
        start: literal.start,
        end: literal.end,
    })
}

/// Литерал — второй аргумент вызова: `os.getenv("NAME", "x")`, `env('NAME', 'x')`.
fn default_argument(line: &str, open: usize) -> Option<(String, Span)> {
    let args = call_args(line, open);
    let (&(name_start, name_end), &(value_start, value_end)) = (args.first()?, args.get(1)?);
    let bytes = line.as_bytes();
    let name_at = skip_ws(bytes, name_start);
    let name = literal_at(line, name_at)?;
    if line[name.after..name_end].trim() != "" {
        return None;
    }
    let value_at = skip_ws(bytes, value_start);
    let value = literal_at(line, value_at)?;
    if line[value.after..value_end].trim() != "" || !concrete(&line[value.start..value.end], 3) {
        return None;
    }
    Some((
        line[name.start..name.end].to_string(),
        Span {
            start: value.start,
            end: value.end,
        },
    ))
}

pub(super) fn find_fallback_secret(line: &str) -> Vec<Span> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();

    // JS/TS: `process.env.NAME || "x"`, `process.env["NAME"] ?? 'x'`, `import.meta.env.NAME`,
    // `Bun.env.NAME`; Ruby: `ENV["NAME"] || "x"`; PHP: `getenv('NAME') ?: 'x'`.
    for prefix in ["process.env", "import.meta.env", "Bun.env", "ENV"] {
        for (at, _) in line.match_indices(prefix) {
            if !left_boundary(line, at) {
                continue;
            }
            let mut i = at + prefix.len();
            let name = match bytes.get(i) {
                Some(b'.') if prefix != "ENV" => {
                    let start = i + 1;
                    i = start;
                    while bytes
                        .get(i)
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    {
                        i += 1;
                    }
                    &line[start..i]
                }
                Some(b'[') => {
                    let Some(literal) = literal_at(line, skip_ws(bytes, i + 1)) else {
                        continue;
                    };
                    let close = skip_ws(bytes, literal.after);
                    if bytes.get(close) != Some(&b']') {
                        continue;
                    }
                    i = close + 1;
                    &line[literal.start..literal.end]
                }
                _ => continue,
            };
            if env_name(name)
                && secret_env_name(name)
                && let Some(span) = fallback_literal(line, i)
            {
                spans.push(span);
            }
        }
    }

    // `os.environ.get("NAME", "x")`, `os.getenv("NAME", "x")`, `env('NAME', 'x')` (Laravel),
    // `ENV.fetch("NAME", "x")`, `Deno.env.get("NAME") ?? "x"`, `getenv('NAME') ?: 'x'`.
    for call in [
        "environ.get(",
        "getenv(",
        "env(",
        "ENV.fetch(",
        "Deno.env.get(",
    ] {
        for (at, _) in line.match_indices(call) {
            let boundary_ok = if call == "env(" {
                left_boundary(line, at) && !line[..at].ends_with('.')
            } else {
                at == 0 || !bytes[at - 1].is_ascii_alphanumeric() || call.contains('.')
            };
            if !boundary_ok {
                continue;
            }
            let open = at + call.len() - 1;
            if let Some((name, span)) = default_argument(line, open) {
                if env_name(&name) && secret_env_name(&name) {
                    spans.push(span);
                }
                continue;
            }
            // Один аргумент и запасное значение после вызова.
            let args = call_args(line, open);
            let Some(&(name_start, name_end)) = args.first() else {
                continue;
            };
            if args.len() != 1 || bytes.get(name_end) != Some(&b')') {
                continue;
            }
            let Some(name) = literal_at(line, skip_ws(bytes, name_start)) else {
                continue;
            };
            let name = &line[name.start..name.end];
            if env_name(name)
                && secret_env_name(name)
                && let Some(span) = fallback_literal(line, name_end + 1)
            {
                spans.push(span);
            }
        }
    }
    spans.sort_by_key(|s| (s.start, s.end));
    spans.dedup();
    spans
}

// --- hardcoded-password-check ------------------------------------------------------------

pub(super) const CHECK_TRIGGERS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "passcode",
    "passphrase",
    "secret",
];

/// Часть имени, по которой видно, что сравнивают сам пароль, а не его настройку.
fn names_a_secret(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "passcode",
        "passphrase",
        "secret",
    ]
    .iter()
    .any(|w| lower.contains(w))
        && ![
            "type",
            "mode",
            "name",
            "label",
            "visib",
            "show",
            "hidden",
            "strength",
            "policy",
            "length",
            "state",
            "status",
            "error",
            "placeholder",
            "hint",
            "format",
            "rule",
            "reset",
            "confirm",
            "changed",
            "required",
            "valid",
            "match",
            "kind",
            "manager",
            "provider",
            "path",
            "file",
            "url",
        ]
        .iter()
        .any(|w| lower.contains(w))
}

/// Выражение слева от `at` (`req.body.password`, `hckey.getText().toString()`):
/// отрезки имён через `.`, пустые `()` пропускаются.
fn left_operand(line: &str, at: usize) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut i = at;
    while i > 0 && bytes[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let mut segments = Vec::new();
    loop {
        // `text!` (Swift), `?.`, `()`
        while i > 0 && matches!(bytes[i - 1], b'!' | b'?') {
            i -= 1;
        }
        if i >= 2 && &bytes[i - 2..i] == b"()" {
            i -= 2;
        }
        let end = i;
        while i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'$'))
        {
            i -= 1;
        }
        if i == end {
            break;
        }
        segments.push(&line[i..end]);
        if i > 0 && bytes[i - 1] == b'.' {
            i -= 1;
            if i > 0 && bytes[i - 1] == b'?' {
                i -= 1;
            }
            continue;
        }
        break;
    }
    segments
}

fn compared_value_ok(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    concrete(value, 4)
        && !super::rules::is_placeholder(value)
        && ![
            "true",
            "false",
            "null",
            "none",
            "undefined",
            "empty",
            "string",
            "text",
            "hidden",
            "number",
            "object",
        ]
        .contains(&lower.as_str())
}

pub(super) fn find_password_check(line: &str) -> Vec<Span> {
    // `assert x == "y"`, `expect(x).toBe…`, `XCTAssertEqual` — проверка теста, а не входа.
    let lower = line.to_ascii_lowercase();
    if lower.contains("assert") || lower.contains("expect(") {
        return Vec::new();
    }
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut push = |segments: Vec<&str>, literal: &Literal| {
        if segments.iter().any(|s| names_a_secret(s))
            && compared_value_ok(&line[literal.start..literal.end])
        {
            spans.push(Span {
                start: literal.start,
                end: literal.end,
            });
        }
    };

    // `x == "lit"`, `x === 'lit'`, `x != "lit"`
    let mut i = 0;
    while i + 1 < bytes.len() {
        let is_eq = (bytes[i] == b'=' || bytes[i] == b'!') && bytes[i + 1] == b'=';
        if !is_eq || (i > 0 && matches!(bytes[i - 1], b'=' | b'!' | b'<' | b'>')) {
            i += 1;
            continue;
        }
        let mut after = i + 2;
        if bytes.get(after) == Some(&b'=') {
            after += 1;
        }
        let value_at = skip_ws(bytes, after);
        if let Some(literal) = literal_at(line, value_at) {
            let next = skip_ws(bytes, literal.after);
            if !bytes.get(next).is_some_and(|b| matches!(b, b'+' | b'.')) {
                push(left_operand(line, i), &literal);
            }
        }
        i = after;
    }

    // `x.equals("lit")`, `x.equalsIgnoreCase("lit")`, `"lit".equals(x)`
    for method in [".equals(", ".equalsIgnoreCase("] {
        for (at, _) in line.match_indices(method) {
            let open = at + method.len() - 1;
            let args = call_args(line, open);
            let Some(&(start, end)) = args.first() else {
                continue;
            };
            if args.len() != 1 {
                continue;
            }
            let arg_at = skip_ws(bytes, start);
            if let Some(literal) = literal_at(line, arg_at)
                && line[literal.after..end].trim().is_empty()
            {
                push(left_operand(line, at), &literal);
            } else if at > 0
                && matches!(bytes[at - 1], b'"' | b'\'')
                && let Some(quote) = line[..at - 1].rfind(char::from(bytes[at - 1]))
                && let Some(literal) = literal_at(line, quote)
                && literal.after == at
            {
                let segments = left_operand(line, end);
                push(segments, &literal);
            }
        }
    }
    spans.sort_by_key(|s| (s.start, s.end));
    spans.dedup();
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Примеры пишутся с `~` вместо `'` и `^` вместо `"`, чтобы `jetscan secrets .` в CI
    /// не находил их в этом файле.
    fn found(find: fn(&str) -> Vec<Span>, line: &str) -> Vec<String> {
        let line = &line.replace('~', "'").replace('^', "\"");
        find(line)
            .iter()
            .map(|s| line[s.start..s.end].to_string())
            .collect()
    }

    #[test]
    fn code_rules_do_not_run_on_documentation() {
        assert!(!applies_to("fallback-secret", "docs/en/security.md"));
        assert!(!applies_to("hardcoded-password-check", "README.rst"));
        assert!(applies_to("hardcoded-password-check", "src/auth.ts"));
        assert!(applies_to("aws-access-key", "docs/en/security.md"));
    }

    #[test]
    fn crypto_keys_passed_as_literals_are_found() {
        let f = find_hardcoded_crypto_key;
        for (line, key) in [
            (
                "crypto.createHmac(~sha256~, ~pa4qacea4VK9t9nGv7yZtwmj~).update(d)",
                "pa4qacea4VK9t9nGv7yZtwmj",
            ),
            (
                "const token = jwt.sign({ id: user.id }, ~super-secret~, { expiresIn: ~1h~ })",
                "super-secret",
            ),
            ("jwt.verify(token, ^your-secret-key^)", "your-secret-key"),
            (
                "SecretKeySpec key = new SecretKeySpec(^49u5gh249gh2^.getBytes(), ^AES^);",
                "49u5gh249gh2",
            ),
            (
                "token = jwt.encode(payload, ^dev-secret^, algorithm=^HS256^)",
                "dev-secret",
            ),
            (
                "h = hmac.new(b~shared-key~, msg, hashlib.sha256)",
                "shared-key",
            ),
            (
                "s, err := token.SignedString([]byte(^my_secret_key^))",
                "my_secret_key",
            ),
            (
                "const c = crypto.createCipheriv(~aes-256-cbc~, Buffer.from(~0123456789abcdef0123456789abcdef~), iv)",
                "0123456789abcdef0123456789abcdef",
            ),
        ] {
            assert_eq!(found(f, line), vec![key.to_string()], "{line}");
        }
    }

    #[test]
    fn swift_crypto_library_keys_are_found() {
        let f = find_hardcoded_crypto_key;
        for (line, key) in [
            (
                "let e = try? RNEncryptor.encryptData(data, with: kRNCryptorAES256Settings, password: ^@daloq3as$qwe^)",
                "@daloq3as$qwe",
            ),
            (
                "let d = try? RNDecryptor.decryptData(enc, withPassword: ^k3y-in-app^)",
                "k3y-in-app",
            ),
            (
                "let aes = try AES(key: ^0123456789abcdef^, iv: ^fedcba9876543210^)",
                "0123456789abcdef",
            ),
        ] {
            assert_eq!(found(f, line), vec![key.to_string()], "{line}");
        }
        assert!(
            found(
                f,
                "let d = try RNDecryptor.decryptData(enc, withPassword: password)"
            )
            .is_empty()
        );
        assert!(found(f, "login(user: u, password: ^hunter22^)").is_empty());
    }

    #[test]
    fn crypto_keys_from_variables_or_env_are_not_findings() {
        let f = find_hardcoded_crypto_key;
        for line in [
            "jwt.sign(payload, process.env.JWT_SECRET)",
            "jwt.sign(payload, SECRET, { algorithm: ~HS256~ })",
            "crypto.createHmac(~sha256~, secret).update(body)",
            "createHmac(~sha256~, `${prefix}-key`)",
            "jwt.sign(payload, ~a~ + suffix)",
            "new SecretKeySpec(keyBytes, ^AES^)",
            "jwt.decode(token, options={~verify_signature~: False})",
            "myjwt.sign(x, ~not-this-library~)",
            "jwt.sign(x, ~~)",
        ] {
            assert!(found(f, line).is_empty(), "{line}");
        }
    }

    #[test]
    fn fallback_secrets_are_found() {
        let f = find_fallback_secret;
        for (line, value) in [
            (
                "const JWT_SECRET = process.env.JWT_SECRET || ^secret^;",
                "secret",
            ),
            (
                "const key = process.env.SESSION_KEY ?? ~dev-session-key~",
                "dev-session-key",
            ),
            (
                "secret: process.env[~NEXTAUTH_SECRET~] || ~changeme-now~,",
                "changeme-now",
            ),
            (
                "SECRET_KEY = os.getenv(^SECRET_KEY^, ^django-insecure-123^)",
                "django-insecure-123",
            ),
            ("SECRET_KEY = os.environ.get(~SECRET_KEY~, ~dev~)", "dev"),
            ("~password~ => env(~DB_PASSWORD~, ~root123~),", "root123"),
            (
                "$key = getenv(~API_TOKEN~) ?: ~fallback-token~;",
                "fallback-token",
            ),
            ("token = ENV.fetch(^GITHUB_TOKEN^, ^ghtoken1^)", "ghtoken1"),
            ("const s = import.meta.env.AUTH_SECRET || ~local~", "local"),
            (
                "app.use(session({ secret: process.env.PASSPORT_SECRET || ~keyboard cat~ }))",
                "keyboard cat",
            ),
            (
                "const k = process.env.STRIPE_SECRET_KEY || ~sk_test_123~",
                "sk_test_123",
            ),
        ] {
            assert_eq!(found(f, line), vec![value.to_string()], "{line}");
        }
    }

    #[test]
    fn fallbacks_that_are_not_secrets_are_not_findings() {
        let f = find_fallback_secret;
        for line in [
            "const port = process.env.PORT || ~3000~",
            "const url = process.env.API_URL || ~http://localhost:3000~",
            "const ttl = process.env.TOKEN_EXPIRY || ~1h~",
            "const pk = process.env.NEXT_PUBLIC_STRIPE_KEY || ~pk_test_x~",
            "const anon = process.env.SUPABASE_ANON_KEY || ~eyJhbGciOi~",
            "const s = process.env.JWT_SECRET || ~~",
            "const s = process.env.JWT_SECRET || fallbackSecret",
            "const s = process.env.JWT_SECRET || `${base}-x`",
            "~password~ => env(~DB_PASSWORD~, ~~),",
            "~username~ => env(~DB_USERNAME~, ~forge~),",
            "SECRET = os.getenv(~SECRET_KEY~)",
            "name = os.getenv(~SECRET_NAME~, ~jwt~)",
            "~passwords~ => env(~AUTH_PASSWORD_BROKER~, ~users~),",
            "~table~ => env(~AUTH_PASSWORD_RESET_TOKEN_TABLE~, ~password_reset_tokens~),",
            "const k = process.env.CACHE_KEY || ~app-cache~",
            "const alg = process.env.JWT_ALGORITHM || ~HS256~",
        ] {
            assert!(found(f, line).is_empty(), "{line}");
        }
    }

    #[test]
    fn password_checks_against_literals_are_found() {
        let f = find_password_check;
        for (line, value) in [
            (
                "if username == ^Admin^ && password == ^This!sA5Ecret^ {",
                "This!sA5Ecret",
            ),
            ("if (req.body.password === ~hunter22~) {", "hunter22"),
            ("if (passwordTextField.text! == ^letmein^) {", "letmein"),
            (
                "if (pwd.getText().toString().equals(^s3cr3t!^)) {",
                "s3cr3t!",
            ),
            ("if (^admin1234^.equals(password)) {", "admin1234"),
            ("if secret != ~topsecret~: abort(403)", "topsecret"),
        ] {
            assert_eq!(found(f, line), vec![value.to_string()], "{line}");
        }
    }

    #[test]
    fn password_comparisons_that_are_not_secrets_are_not_findings() {
        let f = find_password_check;
        for line in [
            "if (input.type === ~password~) {",
            "if (passwordType === ~text~) {",
            "if (passwordStrength === ~weak~) {",
            "if (event.key === ~Enter~) {",
            "if (password === confirmPassword) {",
            "if (password == ~~) {",
            "if (field.name == ^password^) {",
            "if (password === ~a~ + b) {",
            "if (secretName === ~jwt-signing~) {",
            "assert(password != null)",
            "if (password === ~true~) {",
            "    assert app.secret_key == ^config^",
            "expect(user.password).toBe(~hashed-value~)",
        ] {
            assert!(found(f, line).is_empty(), "{line}");
        }
    }
}
