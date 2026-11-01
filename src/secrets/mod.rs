//! Поиск секретов в файлах и git-истории.
//!
//! Контракт (T0.3). Публичные типы и сигнатуры здесь и в стабах подмодулей
//! меняются только по согласованию — от них зависят параллельные задачи.
//!
//! Поток данных:
//!   walk (файлы) / history (строки коммитов)
//!     → rules (матчеры по строке) + special (спецфайлы целиком)
//!     → Hit (с сырым секретом, живёт только в памяти)
//!     → Finding (только маска + отпечаток — это и уходит в отчёт).

pub mod gitstatus;
pub mod history;
pub mod machine;
pub mod report;
pub mod rules;
pub mod scan;
pub mod special;
pub mod verify;
pub mod walk;

use crate::hash;
use std::path::PathBuf;

/// Насколько мы уверены, что это настоящий секрет, а не похожая строка.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// Описание правила — то, что попадает в отчёт.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    /// Стабильный id (`aws-access-key`). Используется в JSON и игнор-листах — не переименовывать.
    pub id: &'static str,
    /// Человекочитаемое имя (`AWS Access Key ID`).
    pub name: &'static str,
    pub confidence: Confidence,
}

/// Участок строки с секретом: байтовые смещения, `end` не включительно.
/// Оба края обязаны лежать на границах UTF-8 символов.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Правило поиска по одной строке. Матчер возвращает участки с самим секретом
/// (без контекста вокруг: для `aws_secret_access_key = X` — только `X`).
/// Заглушки (`AKIAIOSFODNN7EXAMPLE`, `changeme`, ...) матчер не возвращает.
pub struct Rule {
    pub info: RuleInfo,
    pub find: fn(line: &str) -> Vec<Span>,
}

/// Сырое срабатывание. Содержит секрет целиком — наружу (в отчёт, JSON, логи)
/// не выходит никогда; превращается в `Finding` через `Finding::new`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub rule: RuleInfo,
    /// Номер строки, с 1.
    pub line: usize,
    /// Колонка в символах (не байтах), с 1.
    pub col: usize,
    pub secret: String,
}

/// Где найдено.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Location {
    File { path: PathBuf },
    Git { commit: String, path: String },
}

/// Отношение файла с находкой к git (T1.10). От этого зависит, утечка это или нет:
/// закоммиченный секрет уже у всех, кто клонировал; секрет в `.gitignore` — локальный.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tracking {
    /// Файл в git — секрет уже в репозитории.
    Tracked,
    /// Файл не в git и НЕ игнорируется — один `git add .` до утечки.
    Untracked,
    /// Файл в `.gitignore` — локальный секрет, в репозиторий не попадёт.
    Ignored,
    /// Не git-репозиторий, git недоступен, или находка из истории.
    Unknown,
}

impl Tracking {
    pub fn label(self) -> &'static str {
        match self {
            Tracking::Tracked => "tracked",
            Tracking::Untracked => "untracked",
            Tracking::Ignored => "ignored",
            Tracking::Unknown => "unknown",
        }
    }
}

/// Итог `--verify`: рабочий ли ключ (T4.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Liveness {
    /// Провайдер принял ключ — он рабочий прямо сейчас.
    Live,
    /// Провайдер отверг ключ (отозван/неверный).
    Revoked,
    /// Не удалось понять (сеть, лимит, неожиданный ответ) — причина для отчёта.
    Unknown(String),
}

impl Liveness {
    pub fn label(&self) -> &'static str {
        match self {
            Liveness::Live => "live",
            Liveness::Revoked => "revoked",
            Liveness::Unknown(_) => "unknown",
        }
    }
}

/// Находка для отчёта. Самого секрета тут нет — только маска и отпечаток.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: RuleInfo,
    pub location: Location,
    pub line: usize,
    pub col: usize,
    pub masked: String,
    pub fingerprint: String,
    /// Заполняет движок после скана; `Finding::new` ставит `Unknown`.
    pub tracking: Tracking,
    /// `--verify`: `None` — не проверялся (не просили или провайдер не поддержан).
    pub verified: Option<Liveness>,
}

impl Finding {
    pub fn new(hit: &Hit, location: Location) -> Finding {
        Finding {
            rule: hit.rule,
            location,
            line: hit.line,
            col: hit.col,
            masked: mask(&hit.secret),
            fingerprint: fingerprint(&hit.secret),
            tracking: Tracking::Unknown,
            verified: None,
        }
    }

    /// Ведёт ли к утечке: всё, кроме файлов в `.gitignore`.
    /// Это и считает `--exit-code`: в CI-чекауте игнорируемых файлов нет,
    /// а в pre-commit их не закоммитить.
    pub fn is_actionable(&self) -> bool {
        self.tracking != Tracking::Ignored
    }
}

/// Прогоняет правила по одной строке.
pub fn scan_line(rules: &[Rule], line_no: usize, line: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for rule in rules {
        for span in (rule.find)(line) {
            let Some(secret) = line.get(span.start..span.end) else {
                debug_assert!(false, "rule {} returned a bad span", rule.info.id);
                continue;
            };
            if secret.is_empty() {
                continue;
            }
            hits.push(Hit {
                rule: rule.info,
                line: line_no,
                col: line[..span.start].chars().count() + 1,
                secret: secret.to_string(),
            });
        }
    }
    hits
}

/// Прогоняет правила по тексту построчно (`\n` и `\r\n`).
pub fn scan_text(rules: &[Rule], text: &str) -> Vec<Hit> {
    text.lines()
        .enumerate()
        .flat_map(|(i, line)| scan_line(rules, i + 1, line))
        .collect()
}

const MASK_MAX_STARS: usize = 16;

/// Маска секрета для отчёта: по краям не больше 4 символов (и не больше 1/5 длины
/// с каждой стороны), середина — звёздочки. Короче 8 символов — только `****`,
/// чтобы не светить ни символы, ни длину. Управляющие символы в видимых краях → `?`.
pub fn mask(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    let n = chars.len();
    if n < 8 {
        return "****".to_string();
    }
    let k = (n / 5).min(4);
    let show = |c: &char| if c.is_control() { '?' } else { *c };
    let head: String = chars[..k].iter().map(show).collect();
    let tail: String = chars[n - k..].iter().map(show).collect();
    let stars = "*".repeat((n - 2 * k).min(MASK_MAX_STARS));
    format!("{head}{stars}{tail}")
}

/// Отпечаток секрета: первые 16 hex SHA-256 от `jetscan:v1:<секрет>`.
/// Одинаков на всех машинах и запусках — для дедупа и `.jetscanignore`.
///
/// Риск: для коротких/словарных секретов (пароль `hunter2`) отпечаток можно подобрать
/// перебором словаря. Для ключей провайдеров (16+ случайных символов) — нет.
pub fn fingerprint(secret: &str) -> String {
    let digest = hash::sha256(format!("jetscan:v1:{secret}").as_bytes());
    hash::hex(&digest[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_hides_middle_of_long_secrets() {
        // 20 символов, как AWS key id: 4 + 12 звёзд + 4.
        let s = format!("{}{}", "AKIA", "ABCDEFGHIJKLWXYZ");
        assert_eq!(mask(&s), "AKIA************WXYZ");
        // Длинный — звёзд не больше MASK_MAX_STARS.
        let long = "a".repeat(100);
        assert_eq!(mask(&long), format!("aaaa{}aaaa", "*".repeat(16)));
    }

    #[test]
    fn mask_short_secrets_reveal_nothing() {
        assert_eq!(mask(""), "****");
        assert_eq!(mask("x"), "****");
        assert_eq!(mask("hunter2"), "****");
        // 8 символов — по 1 с краю.
        assert_eq!(mask("abcdefgh"), "a******h");
        // 10 — по 2.
        assert_eq!(mask("0123456789"), "01******89");
    }

    #[test]
    fn mask_counts_chars_not_bytes() {
        // Кириллица по 2 байта — не должно паниковать на границе.
        let s = "пароль-секретный";
        let m = mask(s);
        assert!(m.starts_with("пар"));
        assert!(m.ends_with("ный"));
        assert!(!m.contains("секрет"));
    }

    #[test]
    fn mask_neutralizes_control_chars() {
        let s = "\x1b[31mABCDEFGHIJKL\x07";
        let m = mask(s);
        assert!(!m.chars().any(|c| c.is_control()));
    }

    #[test]
    fn fingerprint_is_stable_and_does_not_contain_secret() {
        let s = format!("{}{}", "ghp_", "a".repeat(36));
        let f = fingerprint(&s);
        assert_eq!(f, fingerprint(&s));
        assert_eq!(f.len(), 16);
        assert!(f.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(f, fingerprint("other"));
    }

    fn find_token(line: &str) -> Vec<Span> {
        line.match_indices("TOKEN")
            .map(|(i, m)| Span {
                start: i,
                end: i + m.len(),
            })
            .collect()
    }

    const TEST_RULE: Rule = Rule {
        info: RuleInfo {
            id: "test",
            name: "Test",
            confidence: Confidence::High,
        },
        find: find_token,
    };

    #[test]
    fn scan_text_reports_line_and_char_column() {
        let text = "first\r\nпривет TOKEN\nTOKEN x TOKEN";
        let hits = scan_text(&[TEST_RULE], text);
        let pos: Vec<(usize, usize)> = hits.iter().map(|h| (h.line, h.col)).collect();
        assert_eq!(pos, vec![(2, 8), (3, 1), (3, 9)]);
        assert!(hits.iter().all(|h| h.secret == "TOKEN"));
    }

    #[test]
    fn finding_never_carries_raw_secret() {
        let secret = format!("{}{}", "sk_live_", "Z".repeat(24));
        let hit = Hit {
            rule: TEST_RULE.info,
            line: 1,
            col: 1,
            secret: secret.clone(),
        };
        let f = Finding::new(
            &hit,
            Location::File {
                path: PathBuf::from("a"),
            },
        );
        assert!(!format!("{f:?}").contains(&secret));
    }
}
