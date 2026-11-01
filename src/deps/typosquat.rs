//! Тайпсквоттинг: имя пакета подозрительно похоже на
//! популярное (`lodahs` ↔ `lodash`, `reqeusts` ↔ `requests`), а само популярным не является.
//!
//! Контракт (T4.1, Claude):
//! - `check` — чистая функция, без сети. Списки популярных имён — `src/deps/popular/*.txt`
//!   (`include_str!`; строки с `#` — комментарии).
//! - Популярный пакет сам себе не подозрителен. Ложная тревога на настоящем пакете хуже
//!   пропуска: правила консервативные (например, Дамерау–Левенштейн = 1 для имён от 5
//!   символов, перестановка соседних букв, подмена `-`/`_`/`.`, лишний/пропущенный
//!   разделитель, scope-подмена `@types/x` ↔ `x`), с исключениями для известных пар
//!   настоящих пакетов (`react-dom`/`react-dnd` и т.п. — оба популярны → не помечаем).
//! - Имена PyPI сравнивать после `deps::pep503`.

use super::Ecosystem;
use std::collections::HashSet;
use std::sync::OnceLock;

/// На какое популярное имя похоже и почему.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspect {
    pub looks_like: String,
    /// Короткая причина для отчёта: `one letter swapped`, `extra hyphen`...
    pub reason: &'static str,
}

/// `None` — не похоже ни на одно популярное (или само популярное).
pub fn check(eco: Ecosystem, name: &str) -> Option<Suspect> {
    static NPM: OnceLock<PopularList> = OnceLock::new();
    static PYPI: OnceLock<PopularList> = OnceLock::new();
    static CRATES: OnceLock<PopularList> = OnceLock::new();

    let popular = match eco {
        Ecosystem::Npm => {
            NPM.get_or_init(|| PopularList::parse(eco, include_str!("popular/npm.txt")))
        }
        Ecosystem::PyPI => {
            PYPI.get_or_init(|| PopularList::parse(eco, include_str!("popular/pypi.txt")))
        }
        Ecosystem::CratesIo => {
            CRATES.get_or_init(|| PopularList::parse(eco, include_str!("popular/crates.txt")))
        }
        Ecosystem::Go | Ecosystem::Maven => return None,
    };
    popular.check(eco, name)
}

struct PopularName {
    original: String,
    normalized: String,
    chars: Vec<char>,
    without_separators: String,
}

struct PopularList {
    // Keep the source order for matching; never iterate the set to choose a result.
    names: Vec<PopularName>,
    known: HashSet<String>,
}

impl PopularList {
    fn parse(eco: Ecosystem, source: &str) -> Self {
        let names: Vec<_> = source
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|name| {
                let normalized = normalize(eco, name);
                PopularName {
                    original: name.to_string(),
                    chars: normalized.chars().collect(),
                    without_separators: without_separators(&normalized),
                    normalized,
                }
            })
            .collect();
        let known = names.iter().map(|n| n.normalized.clone()).collect();
        Self { names, known }
    }

    fn check(&self, eco: Ecosystem, name: &str) -> Option<Suspect> {
        let name = normalize(eco, name);
        // Check the entire list before considering any similar, more popular name.
        if name.is_empty() || self.known.contains(&name) {
            return None;
        }
        if eco == Ecosystem::Npm
            && name
                .strip_prefix("@types/")
                .is_some_and(|base| self.known.contains(base))
        {
            return None;
        }

        let chars: Vec<_> = name.chars().collect();
        let compact = without_separators(&name);
        for (rank, popular) in self.names.iter().enumerate() {
            let reason = if eco == Ecosystem::Npm && scope_differs(&name, &popular.normalized) {
                "popular name under another scope"
            } else if !compact.is_empty() && compact == popular.without_separators {
                "separator differs"
            } else {
                match one_edit(&chars, &popular.chars) {
                    Some(Edit::Swap) => "two letters swapped",
                    // Both names must be long enough. Comments/blanks are not ranks;
                    // duplicate entries keep their rank so the cutoff cannot drift.
                    Some(Edit::Character)
                        if rank < 1000 && chars.len() >= 5 && popular.chars.len() >= 5 =>
                    {
                        "one character different"
                    }
                    _ => continue,
                }
            };
            return Some(Suspect {
                looks_like: popular.original.clone(),
                reason,
            });
        }
        None
    }
}

fn normalize(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::PyPI => super::pep503(name),
        Ecosystem::Npm => name.to_ascii_lowercase(),
        _ => name.to_string(),
    }
}

fn without_separators(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .collect()
}

fn scope_differs(name: &str, popular: &str) -> bool {
    // Only @types/x <-> types-x is flattened; merely dropping an arbitrary scope
    // does not establish that an unscoped package is impersonating its owner.
    if name
        .strip_prefix("types-")
        .zip(popular.strip_prefix("@types/"))
        .or_else(|| {
            name.strip_prefix("@types/")
                .zip(popular.strip_prefix("types-"))
        })
        .is_some_and(|(a, b)| !a.is_empty() && a == b)
    {
        return true;
    }
    // Ревью Claude: «популярное имя под чужим scope» убрано. На 14 746 реальных пакетах
    // (react, yarn, pnpm, vite, vue, jest, проекты владельца) оно дало ~150 срабатываний —
    // все настоящие пакеты (@vueuse/core, @pnpm/which, @svgr/webpack...). Scope в npm
    // принадлежит владельцу, публиковать "свои" core/types/utils — нормальная практика.
    false
}

#[derive(Debug, PartialEq, Eq)]
enum Edit {
    Swap,
    Character,
}

// Exact Damerau-Levenshtein distance 1 needs no DP table: after the common
// prefix, one edit must leave equal suffixes. Reject a length gap > 1 first,
// and stop comparing at the next mismatch. O(length), no per-pair allocation.
// Work on characters so a UTF-8 byte is never mistaken for a whole character.
fn one_edit(a: &[char], b: &[char]) -> Option<Edit> {
    if a.len().abs_diff(b.len()) > 1 {
        return None;
    }
    let first = a
        .iter()
        .zip(b)
        .position(|(a, b)| a != b)
        .unwrap_or(a.len().min(b.len()));
    match a.len().cmp(&b.len()) {
        std::cmp::Ordering::Equal => {
            if first == a.len() {
                return None;
            }
            if a[first + 1..] == b[first + 1..] {
                return Some(Edit::Character);
            }
            if first + 1 < a.len()
                && a[first] == b[first + 1]
                && a[first + 1] == b[first]
                && a[first + 2..] == b[first + 2..]
            {
                return Some(Edit::Swap);
            }
            None
        }
        std::cmp::Ordering::Greater => (a[first + 1..] == b[first..]).then_some(Edit::Character),
        std::cmp::Ordering::Less => (a[first..] == b[first + 1..]).then_some(Edit::Character),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTS: [(Ecosystem, &str); 3] = [
        (Ecosystem::Npm, include_str!("popular/npm.txt")),
        (Ecosystem::PyPI, include_str!("popular/pypi.txt")),
        (Ecosystem::CratesIo, include_str!("popular/crates.txt")),
    ];

    fn assert_popular_names_are_not_flagged(limit: usize) {
        for (eco, source) in LISTS {
            // Read the corpus independently of PopularList, so a parser omission
            // cannot silently remove a name from this false-positive regression.
            let names: Vec<_> = source
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .take(limit)
                .collect();
            assert!(names.len() >= limit.min(500));
            let suspects: Vec<_> = names
                .iter()
                .filter_map(|name| check(eco, name).map(|suspect| (*name, suspect)))
                .collect();
            assert!(suspects.is_empty(), "{eco:?}: {suspects:?}");
            eprintln!("{eco:?}: 0/{} popular packages flagged", names.len());
        }
    }

    #[test]
    fn first_200_popular_names_have_no_false_positives() {
        assert_popular_names_are_not_flagged(200);
    }

    #[test]
    fn first_1000_popular_names_have_no_false_positives() {
        assert_popular_names_are_not_flagged(1000);
    }

    #[test]
    fn entire_popular_lists_have_no_false_positives() {
        assert_popular_names_are_not_flagged(usize::MAX);
    }

    #[test]
    fn known_typos_and_reasons() {
        for (eco, name, target, reason) in [
            (Ecosystem::Npm, "lodahs", "lodash", "two letters swapped"),
            (Ecosystem::Npm, "crossenv", "cross-env", "separator differs"),
            (
                Ecosystem::PyPI,
                "reqeusts",
                "requests",
                "two letters swapped",
            ),
            // One inserted '3', both names >= 5, python-dateutil is in the top 1000.
            (
                Ecosystem::PyPI,
                "python3-dateutil",
                "python-dateutil",
                "one character different",
            ),
            (
                Ecosystem::PyPI,
                "colourama",
                "colorama",
                "one character different",
            ),
            (
                Ecosystem::CratesIo,
                "srede_json",
                "serde_json",
                "two letters swapped",
            ),
            (
                Ecosystem::CratesIo,
                "serde-json",
                "serde_json",
                "separator differs",
            ),
        ] {
            assert_eq!(
                check(eco, name),
                Some(Suspect {
                    looks_like: target.into(),
                    reason,
                }),
                "{eco:?}: {name}"
            );
        }
        assert_eq!(check(Ecosystem::CratesIo, "serde_json"), None);
        assert_eq!(check(Ecosystem::Npm, "@types/lodash"), None);
    }

    #[test]
    fn npm_case_and_pep503_equivalence_are_not_typos() {
        for (eco, names) in [
            (Ecosystem::Npm, &["Lodash", "LODASH", "@TYPES/LODASH"][..]),
            (
                Ecosystem::PyPI,
                &[
                    "Requests",
                    "REQUESTS",
                    "zope.interface",
                    "zope-interface",
                    "ZOPE__..INTERFACE",
                    "python_dateutil",
                ][..],
            ),
        ] {
            for name in names {
                assert_eq!(check(eco, name), None, "{eco:?}: {name}");
            }
        }
        assert_eq!(
            check(Ecosystem::Npm, "LODAHS"),
            check(Ecosystem::Npm, "lodahs")
        );
        assert_eq!(
            check(Ecosystem::PyPI, "Reqeusts"),
            check(Ecosystem::PyPI, "reqeusts")
        );
    }

    #[test]
    fn popular_exemption_precedes_every_similarity_rule() {
        for (eco, source) in [
            (
                Ecosystem::Npm,
                "lodash\nlodahs\n@evil/lodash\n@types/lodash\ntypes-lodash\n",
            ),
            (Ecosystem::Npm, "react-dom\nreact-dnd\nreactdom\n"),
            (Ecosystem::PyPI, "colorama\ncolourama\n"),
            (Ecosystem::CratesIo, "serde_json\nserde-json\n"),
        ] {
            let list = PopularList::parse(eco, source);
            for name in source.lines() {
                assert_eq!(list.check(eco, name), None, "{eco:?}: {name}");
            }
        }
    }

    #[test]
    fn separator_changes_are_not_limited_by_edit_distance() {
        for eco in [Ecosystem::Npm, Ecosystem::CratesIo] {
            let list = PopularList::parse(eco, "python-dateutil\nreact-dom\nabc\n");
            for name in [
                "python_dateutil",
                "python.dateutil",
                "py-thondateutil",
                "pythondateutil",
            ] {
                assert_eq!(
                    list.check(eco, name),
                    Some(Suspect {
                        looks_like: "python-dateutil".into(),
                        reason: "separator differs"
                    }),
                    "{eco:?}: {name}"
                );
            }
            assert_eq!(
                list.check(eco, "reactdom").unwrap().reason,
                "separator differs"
            );
            assert_eq!(
                list.check(eco, "a_b.c-").unwrap().reason,
                "separator differs"
            );
            assert_eq!(list.check(eco, "python/datetime"), None);
        }
        assert_eq!(
            check(Ecosystem::PyPI, "pythondateutil").unwrap().reason,
            "separator differs"
        );
    }

    #[test]
    fn npm_scope_rules_and_types_exception() {
        // Ревью Claude: популярное имя под чужим scope — не тревога (на реальных проектах
        // это ~150 настоящих пакетов: @vueuse/core, @pnpm/which...).
        for name in [
            "@evil/lodash",
            "@EVIL/LODASH",
            "@vueuse/core",
            "@pnpm/which",
        ] {
            assert_eq!(check(Ecosystem::Npm, name), None, "{name}");
        }
        assert_eq!(
            check(Ecosystem::Npm, "types-lodash").unwrap().looks_like,
            "@types/lodash"
        );
        let eco = Ecosystem::Npm;
        let list = PopularList::parse(
            eco,
            "@types/widget\n@owner/widget\nstring-width\ntypes-gizmo\n",
        );
        for (name, target) in [
            ("types-widget", "@types/widget"),
            ("@types/gizmo", "types-gizmo"),
        ] {
            assert_eq!(
                list.check(eco, name),
                Some(Suspect {
                    looks_like: target.into(),
                    reason: "popular name under another scope"
                })
            );
        }
        for name in ["widget", "owner-widget", "@types/string-width"] {
            assert_eq!(list.check(eco, name), None, "{name}");
        }
        // @types is an exception only for an exact popular name, not its typos.
        assert_eq!(
            check(eco, "@types/lodahs").unwrap().reason,
            "two letters swapped"
        );
        for eco in [Ecosystem::PyPI, Ecosystem::CratesIo] {
            assert_eq!(
                PopularList::parse(eco, "lodash\n").check(eco, "@evil/lodash"),
                None
            );
        }
    }

    #[test]
    fn most_popular_match_wins_across_rules() {
        let eco = Ecosystem::Npm;
        for (source, target, reason) in [
            ("abcdef\nabcdff\n", "abcdef", "two letters swapped"),
            ("abcdff\nabcdef\n", "abcdff", "one character different"),
        ] {
            let list = PopularList::parse(eco, source);
            for _ in 0..3 {
                assert_eq!(
                    list.check(eco, "abcdfe"),
                    Some(Suspect {
                        looks_like: target.into(),
                        reason
                    })
                );
            }
        }
        let list = PopularList::parse(eco, "reactdomm\nreact-dom\n");
        assert_eq!(list.check(eco, "reactdom").unwrap().looks_like, "reactdomm");
    }

    #[test]
    fn character_edit_requires_both_names_to_have_five_characters() {
        let eco = Ecosystem::Npm;
        let list = PopularList::parse(eco, "abcd\nklmno\n");
        for name in ["abce", "xabcd", "klmn", "klm", "kxmnp"] {
            assert_eq!(list.check(eco, name), None, "{name}");
        }
        for name in ["klmnp", "xklmno", "klmnox"] {
            assert_eq!(
                list.check(eco, name).unwrap().reason,
                "one character different",
                "{name}"
            );
        }
        assert_eq!(
            list.check(eco, "abdc").unwrap().reason,
            "two letters swapped"
        );
    }

    #[test]
    fn top_1000_cutoff_counts_package_lines_only() {
        let eco = Ecosystem::Npm;
        for (preceding, character_edit_allowed) in [(999, true), (1000, false)] {
            let source = format!(
                "# heading\n\n{}  package  \r\n",
                " filler\r\n # comment\r\n\r\n".repeat(preceding)
            );
            let list = PopularList::parse(eco, &source);
            for name in ["packagf", "packagex", "packag"] {
                assert_eq!(
                    list.check(eco, name).is_some(),
                    character_edit_allowed,
                    "{preceding}: {name}"
                );
            }
            assert_eq!(
                list.check(eco, "pacakge").unwrap().reason,
                "two letters swapped"
            );
            assert_eq!(
                list.check(eco, "pack-age").unwrap().reason,
                "separator differs"
            );
            assert_eq!(list.check(eco, "@other/package"), None);
            assert_eq!(list.check(eco, "package"), None);
        }
    }

    #[test]
    fn unknown_empty_and_unsupported_names_are_not_flagged() {
        for (eco, _) in LISTS {
            for name in ["", "---", "unrelated-package-name-for-a-private-project"] {
                assert_eq!(check(eco, name), None, "{eco:?}: {name}");
            }
        }
        for eco in [Ecosystem::Go, Ecosystem::Maven] {
            for name in ["lodahs", "reqeusts", "crossenv", "@evil/lodash"] {
                assert_eq!(check(eco, name), None);
            }
        }
    }

    #[test]
    fn bounded_edit_matches_reference_distance_exhaustively() {
        // Independent full DP oracle, including empty strings, repeated characters
        // and Unicode. OSA and unrestricted Damerau-Levenshtein agree at distance 1.
        fn distance(a: &[char], b: &[char]) -> usize {
            let mut dp = vec![vec![0; b.len() + 1]; a.len() + 1];
            for (i, row) in dp.iter_mut().enumerate() {
                row[0] = i;
            }
            for (j, cell) in dp[0].iter_mut().enumerate() {
                *cell = j;
            }
            for i in 1..=a.len() {
                for j in 1..=b.len() {
                    dp[i][j] = (dp[i - 1][j] + 1)
                        .min(dp[i][j - 1] + 1)
                        .min(dp[i - 1][j - 1] + usize::from(a[i - 1] != b[j - 1]));
                    if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                        dp[i][j] = dp[i][j].min(dp[i - 2][j - 2] + 1);
                    }
                }
            }
            dp[a.len()][b.len()]
        }
        let mut words = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &level {
                for c in ['a', 'b', '\u{e9}'] {
                    let mut word = prefix.clone();
                    word.push(c);
                    next.push(word);
                }
            }
            words.extend(next.iter().cloned());
            level = next;
        }
        for a in &words {
            for b in &words {
                assert_eq!(
                    one_edit(a, b).is_some(),
                    distance(a, b) == 1,
                    "{a:?} -> {b:?}"
                );
            }
        }
    }
}
