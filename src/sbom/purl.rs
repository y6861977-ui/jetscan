//! Package URL (https://github.com/package-url/purl-spec), из незакодированных
//! имени/версии пакета. Пути lockfile'ов не участвуют в идентичности пакета.

use crate::deps::{Ecosystem, Package, pep503};

pub fn purl(p: &Package) -> String {
    let (kind, path) = match p.ecosystem {
        Ecosystem::Npm => {
            let path = match p.name.split_once('/') {
                Some((scope, name)) if scope.starts_with('@') => {
                    format!("{}/{}", encode(scope), encode(name))
                }
                _ => encode(&p.name),
            };
            ("npm", path)
        }
        Ecosystem::PyPI => ("pypi", encode(&pep503(&p.name))),
        Ecosystem::CratesIo => ("cargo", encode(&p.name)),
        Ecosystem::Go => (
            "golang",
            p.name.split('/').map(encode).collect::<Vec<_>>().join("/"),
        ),
        Ecosystem::Maven => {
            let path = match p.name.split_once(':') {
                Some((group, artifact)) => format!("{}/{}", encode(group), encode(artifact)),
                None => encode(&p.name),
            };
            ("maven", path)
        }
    };
    format!("pkg:{kind}/{path}@{}", encode(&p.version))
}

/// PURL leaves ASCII alphanumerics, `-._~` and `:` unescaped. Encode all other
/// UTF-8 bytes with uppercase hex, including literal `%`, `+`, `@`, `?`, `#`.
/// `/` is only emitted by the caller as a namespace/name separator, never by
/// encoding a single segment (or a version). Input is not already URL-encoded.
fn encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b':') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(ecosystem: Ecosystem, name: &str, version: &str) -> String {
        purl(&Package {
            ecosystem,
            name: name.into(),
            version: version.into(),
            lockfiles: vec!["unused/lockfile".into()],
        })
    }

    #[test]
    fn every_ecosystem_and_namespace() {
        for (ecosystem, name, version, expected) in [
            (Ecosystem::Npm, "react", "18.2.0", "pkg:npm/react@18.2.0"),
            (
                Ecosystem::Npm,
                "@scope/name",
                "1.2.3",
                "pkg:npm/%40scope/name@1.2.3",
            ),
            (Ecosystem::PyPI, "Django", "4.2.1", "pkg:pypi/django@4.2.1"),
            (
                Ecosystem::PyPI,
                "Foo__Bar-.baz",
                "1.0",
                "pkg:pypi/foo-bar-baz@1.0",
            ),
            (
                Ecosystem::CratesIo,
                "serde",
                "1.0.0",
                "pkg:cargo/serde@1.0.0",
            ),
            (
                Ecosystem::Go,
                "github.com/x/y",
                "v1.2.3",
                "pkg:golang/github.com/x/y@v1.2.3",
            ),
            (
                Ecosystem::Go,
                "stdlib",
                "1.22.0",
                "pkg:golang/stdlib@1.22.0",
            ),
            (
                Ecosystem::Maven,
                "org.example:artifact",
                "1.0",
                "pkg:maven/org.example/artifact@1.0",
            ),
        ] {
            assert_eq!(url(ecosystem, name, version), expected);
        }
    }

    #[test]
    fn encodes_utf8_reserved_characters_and_literal_percent() {
        assert_eq!(
            url(Ecosystem::Npm, "@a b/n%40é", "1.0+meta/@?#"),
            "pkg:npm/%40a%20b/n%2540%C3%A9@1.0%2Bmeta%2F%40%3F%23"
        );
        assert_eq!(
            url(
                Ecosystem::Go,
                "example.com/a b/é%/m@d",
                "v1.2.3+incompatible"
            ),
            "pkg:golang/example.com/a%20b/%C3%A9%25/m%40d@v1.2.3%2Bincompatible"
        );
        assert_eq!(
            url(Ecosystem::Maven, "org.example:a/b", "1:2+3"),
            "pkg:maven/org.example/a%2Fb@1:2%2B3"
        );
        assert_eq!(encode("AZaz09-._~:"), "AZaz09-._~:");
        assert_eq!(
            encode(" !\"$&'()*,;=[]\\\n"),
            "%20%21%22%24%26%27%28%29%2A%2C%3B%3D%5B%5D%5C%0A"
        );
    }
}
