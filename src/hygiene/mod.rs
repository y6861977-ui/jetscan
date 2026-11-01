//! Гигиена машины (T5.2): факты о том, как на диске лежат ключи и токены —
//! то, что не видно правилам секретов по одной строке.
//!
//! Контракт — не ослаблять:
//! - Только чтение, только локально, без сети и без запуска внешних программ.
//! - В `Issue` никогда нет значения секрета: ни целиком, ни частью, ни base64 —
//!   только путь, номер строки, что за проблема и как исправить.
//! - Только факты, которые можно проверить по файлу (ключ без пароля, токен
//!   открытым текстом), без догадок. Нет уверенности — нет находки.
//! - Детерминированно: сортировка по (path, line, id).
//! - Пути — относительно домашней папки, в виде `~/.ssh/id_ed25519` (с `/`).

pub mod checks;

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Ключ/токен лежит открытым текстом и даёт доступ (публикация пакетов, облако, ssh).
    High,
    /// Плохая практика, но доступ не прямой (права файла, токен без срока...).
    Medium,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::High => "high",
            Level::Medium => "medium",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    /// Стабильный id проверки: `ssh-key-no-passphrase`, `npmrc-plaintext-token`...
    pub id: &'static str,
    pub level: Level,
    /// Гигиена: `~/.ssh/id_ed25519`; workflows: `.github/workflows/ci.yml` (от корня проекта).
    pub path: String,
    /// 0 — проблема всего файла (права, ключ без пароля).
    pub line: usize,
    /// Что не так — одной фразой, без значения секрета.
    pub message: String,
    /// Как исправить — конкретная команда или шаг.
    pub fix: String,
}

/// Все проверки над домашней папкой `home`. Ошибки чтения отдельных файлов —
/// не ошибка проверки (файла нет — нечего проверять).
pub fn check(home: &Path) -> Vec<Issue> {
    let mut issues = checks::run(home);
    issues.sort_by(|a, b| (&a.path, a.line, a.id).cmp(&(&b.path, b.line, b.id)));
    issues
}
