//! Парсеры lockfile'ов. Каждый — чистая функция `fn(&str) -> Result<Vec<Dep>, String>`:
//! текст файла → зафиксированные версии. Без сети и файловой системы.
//!
//! Правила для парсеров (контракт T2.1):
//! - Только точные установленные версии; диапазоны (`^1.2`, `>=2`) — пропускать.
//! - Локальные пакеты (workspace, `file:`, `link:`, `path =`) — пропускать: их нет в OSV.
//! - Битый файл → `Err` с понятной причиной, не паника и не пустой список
//!   (пустой список выглядит как «чисто»).
//! - Дубликаты можно не убирать — дедуп делает движок.

pub mod cargo;
pub mod gomod;
pub mod npm;
pub mod pnpm;
pub mod python;
pub mod yarn;

use super::{Dep, Ecosystem};

pub type Parser = fn(&str) -> Result<Vec<Dep>, String>;

/// Вид lockfile'а: как узнать по имени файла и чем разбирать.
pub struct Kind {
    /// Для отчёта: `package-lock.json`, `requirements.txt`.
    pub label: &'static str,
    pub ecosystem: Ecosystem,
    /// По имени файла (без пути).
    pub matches: fn(&str) -> bool,
    pub parse: Parser,
}

pub static KINDS: &[Kind] = &[
    Kind {
        label: "package-lock.json",
        ecosystem: Ecosystem::Npm,
        matches: |n| n == "package-lock.json" || n == "npm-shrinkwrap.json",
        parse: npm::parse_package_lock,
    },
    Kind {
        label: "yarn.lock",
        ecosystem: Ecosystem::Npm,
        matches: |n| n == "yarn.lock",
        parse: yarn::parse,
    },
    Kind {
        label: "pnpm-lock.yaml",
        ecosystem: Ecosystem::Npm,
        matches: |n| n == "pnpm-lock.yaml",
        parse: pnpm::parse,
    },
    Kind {
        label: "Cargo.lock",
        ecosystem: Ecosystem::CratesIo,
        matches: |n| n == "Cargo.lock",
        parse: cargo::parse,
    },
    Kind {
        label: "go.mod",
        ecosystem: Ecosystem::Go,
        matches: |n| n == "go.mod",
        parse: gomod::parse,
    },
    Kind {
        label: "requirements.txt",
        ecosystem: Ecosystem::PyPI,
        matches: |n| {
            let l = n.to_ascii_lowercase();
            l.starts_with("requirements") && l.ends_with(".txt")
        },
        parse: python::parse_requirements,
    },
    Kind {
        label: "poetry.lock",
        ecosystem: Ecosystem::PyPI,
        matches: |n| n == "poetry.lock",
        parse: python::parse_poetry_lock,
    },
    Kind {
        label: "Pipfile.lock",
        ecosystem: Ecosystem::PyPI,
        matches: |n| n == "Pipfile.lock",
        parse: python::parse_pipfile_lock,
    },
    Kind {
        label: "uv.lock",
        ecosystem: Ecosystem::PyPI,
        matches: |n| n == "uv.lock",
        parse: python::parse_uv_lock,
    },
];

/// Вид lockfile'а по имени файла.
pub fn kind_for(file_name: &str) -> Option<&'static Kind> {
    KINDS.iter().find(|k| (k.matches)(file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_match_by_file_name() {
        let label = |n: &str| kind_for(n).map(|k| k.label);
        assert_eq!(label("package-lock.json"), Some("package-lock.json"));
        assert_eq!(label("npm-shrinkwrap.json"), Some("package-lock.json"));
        assert_eq!(label("requirements-dev.txt"), Some("requirements.txt"));
        assert_eq!(label("Requirements.txt"), Some("requirements.txt"));
        assert_eq!(label("Cargo.lock"), Some("Cargo.lock"));
        assert_eq!(label("package.json"), None);
        assert_eq!(label("requirements.in"), None);
    }
}
