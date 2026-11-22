//! Which jetscan this is: the free build (the public source) or jetscan Pro
//! (`--features pro`, built only from the private repository).
//!
//! The free build knows the Pro command names only to say where they come from, so
//! `jetscan apk app.apk` explains itself instead of looking like a typo.

/// `true` in the jetscan Pro build.
pub const PRO: bool = cfg!(feature = "pro");

/// Where jetscan Pro and jetscan Teams keys are sold.
pub const SITE: &str = "https://jetscan.jet.kim";

/// `0.4.0` in the free build, `0.4.0 (Pro)` in jetscan Pro.
pub fn version() -> String {
    let v = env!("CARGO_PKG_VERSION");
    if PRO {
        format!("{v} (Pro)")
    } else {
        v.to_string()
    }
}

/// The commands only jetscan Pro has, with one line on what each does.
pub const PRO_COMMANDS: &[(&str, &str)] = &[
    (
        "web",
        "a static audit of Next.js / Vite React source code (keys in client code, routes \
         without an access check, XSS sinks, CORS, source maps)",
    ),
    (
        "apk",
        "a static audit of Android APK files (manifest flags, exported components, \
         cleartext traffic, embedded keys; nothing is installed or run)",
    ),
    (
        "android",
        "a static audit of Android source projects (Gradle, Kotlin/Java, manifests; \
         nothing is built or run)",
    ),
    (
        "ios",
        "a static audit of iOS source projects (Xcode, Swift/Objective-C, plists, \
         entitlements; nothing is built or run)",
    ),
    (
        "url",
        "a passive check of a published website (security headers, cookies, exposed .git/.env \
         files, source maps, server-side keys in its JavaScript; browser-like requests only)",
    ),
];

/// The notice for a Pro command typed into the free build; `None` for any other word.
pub fn pro_only(command: &str) -> Option<String> {
    let (name, what) = PRO_COMMANDS.iter().find(|(name, _)| *name == command)?;
    Some(format!(
        "`{name}` is part of jetscan Pro: {what}. Get it at {SITE}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names_the_build() {
        let v = version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")));
        assert_eq!(v.ends_with(" (Pro)"), PRO);
    }

    #[test]
    fn only_pro_commands_get_the_notice() {
        for (name, _) in PRO_COMMANDS {
            let text = pro_only(name).unwrap();
            assert!(text.starts_with(&format!("`{name}` is part of jetscan Pro: ")));
            assert!(
                text.ends_with("Get it at https://jetscan.jet.kim"),
                "{text}"
            );
        }
        for other in ["scan", "secrets", "resolve", "mcp", "Apk", ""] {
            assert_eq!(pro_only(other), None, "{other}");
        }
    }
}
