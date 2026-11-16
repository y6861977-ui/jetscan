//! Правила по property lists:
//! - IOS-ATS-001 — App Transport Security в Info.plist: `NSAllowsArbitraryLoads` (с учётом того, что на
//!   iOS 10+ он игнорируется при наличии `NSAllowsArbitraryLoadsForMedia` / `…InWebContent` /
//!   `NSAllowsLocalNetworking`), исключения доменов с HTTP, слабым минимальным TLS, без forward secrecy;
//! - IOS-URLSCHEME-002 — свои URL-схемы (`CFBundleURLTypes`): точки входа, которые может открыть
//!   любое приложение (info / needs_review);
//! - IOS-ENTITLEMENTS-003 — `get-task-allow` в entitlements release-конфигурации, домены с `*` в
//!   `com.apple.developer.associated-domains`, `*` в `keychain-access-groups`.
//!
//! Значение вида `$(VAR)` раскрывается по настройкам конфигураций, которые используют файл; не
//! раскрылось — правило `partial`, а не «чисто». Info.plist и entitlements тестовых целей не проверяются
//! (это решает вызывающий).

use super::{ATS_ID, ENTITLEMENTS_ID, New, REF_MASVS, RuleOutput, URLSCHEME_ID};
use crate::ios_audit::plist::{Key, Node};
use crate::ios_audit::project::{Usage, expand};
use crate::ios_audit::types::{Confidence, Severity};
use crate::ui;
use std::collections::BTreeMap;

const REF_ATS: &str = "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity";
const REF_ATS_ARBITRARY: &str = "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads";
const REF_ATS_DOMAINS: &str = "https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsexceptiondomains";
const REF_URL_SCHEME: &str =
    "https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app";
const REF_UNIVERSAL: &str =
    "https://developer.apple.com/documentation/xcode/supporting-associated-domains";
const REF_GET_TASK_ALLOW: &str = "https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.get-task-allow";
const REF_KEYCHAIN_GROUPS: &str =
    "https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups";

/// С чем проверяется файл: какие конфигурации его используют и их настройки.
pub struct Context<'a> {
    pub path: &'a str,
    pub usages: &'a [Usage],
    pub settings: Vec<&'a BTreeMap<String, String>>,
}

impl Context<'_> {
    /// `target App` / `targets App, Share` — для `component`.
    pub fn component(&self) -> Option<String> {
        let mut names: Vec<&str> = self.usages.iter().map(|u| u.target.as_str()).collect();
        names.sort();
        names.dedup();
        match names.len() {
            0 => None,
            1 => Some(format!("target {}", names[0])),
            _ => Some(format!("targets {}", names.join(", "))),
        }
    }

    /// Наименьшая мажорная версия deployment target среди конфигураций, если все известны.
    fn min_deployment(&self) -> Option<u32> {
        let mut min = None;
        for u in self.usages {
            let major: u32 = u
                .deployment_target
                .as_deref()?
                .split('.')
                .next()?
                .trim()
                .parse()
                .ok()?;
            min = Some(min.map_or(major, |m: u32| m.min(major)));
        }
        min
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Flag {
    True,
    False,
    /// Строка-переменная, которую не удалось раскрыть.
    Unknown(String),
    Absent,
}

/// Булево значение ключа; `$(VAR)` раскрывается по настройкам (все конфигурации должны совпасть).
fn flag(node: Option<&Node>, ctx: &Context) -> Flag {
    let Some(node) = node else {
        return Flag::Absent;
    };
    if let Some(b) = node.as_bool() {
        return if b { Flag::True } else { Flag::False };
    }
    let Some(raw) = node.as_str() else {
        return Flag::False;
    };
    if !raw.contains('$') {
        return Flag::False;
    }
    let mut values = Vec::new();
    for s in &ctx.settings {
        match expand(raw, s, 0) {
            Some(v) => values.push(v.trim().to_ascii_lowercase()),
            None => return Flag::Unknown(raw.to_string()),
        }
    }
    if values.is_empty() {
        return Flag::Unknown(raw.to_string());
    }
    if values
        .iter()
        .any(|v| matches!(v.as_str(), "yes" | "true" | "1"))
    {
        Flag::True
    } else {
        Flag::False
    }
}

struct Finding<'a> {
    rule: &'static str,
    category: &'static str,
    key: &'a Key,
    title: String,
    severity: Severity,
    confidence: Confidence,
    excerpt: String,
    id_key: String,
    explanation: String,
    remediation: &'static str,
    references: Vec<&'static str>,
    cwe: &'static str,
    masvs: &'static str,
}

fn push(ctx: &Context, out: &mut RuleOutput, f: Finding) {
    let mut references = f.references;
    references.push(REF_MASVS);
    let mut tags = vec![format!("masvs:{}", f.masvs), "source:plist".to_string()];
    // Файл используют только debug-конфигурации (`LocalDebug`, `Debug`): в релиз не попадает
    // (полевой тест, Wikipedia `Local-Info.plist`).
    let debug_only = !ctx.usages.is_empty() && ctx.usages.iter().all(|u| u.debug);
    let (severity, explanation) = if debug_only && f.severity < Severity::Low {
        tags.push("build:debug-only".to_string());
        (
            Severity::Low,
            format!(
                "{} This file is used only by debug configuration(s) ({}), so it does not reach release builds.",
                f.explanation,
                ui::sanitize_line(
                    &ctx.usages
                        .iter()
                        .map(|u| u.config.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            ),
        )
    } else {
        (f.severity, f.explanation)
    };
    out.findings.push(
        New {
            rule: f.rule,
            category: f.category,
            title: f.title,
            severity,
            confidence: f.confidence,
            path: ctx.path,
            line: Some(f.key.line),
            column: Some(f.key.column),
            component: ctx.component(),
            excerpt: Some(f.excerpt),
            fingerprint: None,
            key: f.id_key,
            explanation,
            remediation: f.remediation,
            references,
            cwe_ids: vec![f.cwe],
            tags,
        }
        .build(),
    );
}

fn unknown(rule: &'static str, ctx: &Context, key: &str, raw: &str, out: &mut RuleOutput) {
    out.partial.push((
        rule,
        format!(
            "{}: {key} = {} is a build setting that could not be resolved",
            ui::sanitize_line(ctx.path),
            ui::sanitize_line(raw)
        ),
    ));
}

/// Локальные имена: ATS к ним на практике не применяется, исключение — для разработки.
fn local_domain(domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    d == "localhost"
        || d.ends_with(".local")
        || d.ends_with(".localhost")
        || d.starts_with("127.")
        || d == "::1"
        || d.starts_with("10.")
        || d.starts_with("192.168.")
        || !d.contains('.')
}

/// IOS-ATS-001 и IOS-URLSCHEME-002 по одному Info.plist.
pub fn info_plist(root: &Node, ctx: &Context, out: &mut RuleOutput) {
    ats(root, ctx, out);
    url_schemes(root, ctx, out);
}

fn ats(root: &Node, ctx: &Context, out: &mut RuleOutput) {
    let Some(ats) = root.get("NSAppTransportSecurity") else {
        return;
    };
    let overriding: Vec<&str> = [
        "NSAllowsArbitraryLoadsForMedia",
        "NSAllowsArbitraryLoadsInWebContent",
        "NSAllowsLocalNetworking",
    ]
    .into_iter()
    .filter(|k| ats.get(k).is_some())
    .collect();
    if let Some((key, node)) = ats.entry("NSAllowsArbitraryLoads") {
        match flag(Some(node), ctx) {
            Flag::True => {
                let min = ctx.min_deployment();
                let (severity, confidence, detail) = if overriding.is_empty() {
                    (
                        Severity::High,
                        Confidence::Potential,
                        "ATS is turned off for every connection: plain HTTP and weak TLS are allowed to any \
                         host, so traffic can be read or changed by anyone on the network (public Wi-Fi, a \
                         hostile router)."
                            .to_string(),
                    )
                } else if min.is_some_and(|m| m < 10) {
                    (
                        Severity::High,
                        Confidence::Potential,
                        format!(
                            "{} is also set, so iOS 10 and later ignore NSAllowsArbitraryLoads; but the \
                             deployment target is iOS {}, where ATS is off for every connection.",
                            overriding.join(", "),
                            min.unwrap_or(0)
                        ),
                    )
                } else {
                    (
                        Severity::Low,
                        Confidence::NeedsReview,
                        format!(
                            "{} is also set, and on iOS 10 / macOS 10.12 and later that makes the system ignore \
                             NSAllowsArbitraryLoads (Apple documents this). It matters only for older OS \
                             versions; remove it to make the intent clear.",
                            overriding.join(", ")
                        ),
                    )
                };
                push(
                    ctx,
                    out,
                    Finding {
                        rule: ATS_ID,
                        category: "network",
                        key,
                        title: "App Transport Security disabled (NSAllowsArbitraryLoads)"
                            .to_string(),
                        severity,
                        confidence,
                        excerpt: "NSAppTransportSecurity.NSAllowsArbitraryLoads = true".to_string(),
                        id_key: "NSAllowsArbitraryLoads".to_string(),
                        explanation: format!(
                            "{detail} Potential: whether the app actually talks to anything over HTTP is not \
                             analysed. Remove the key and add narrow NSExceptionDomains entries only for the \
                             hosts that still need them. App Review asks for a justification for this key."
                        ),
                        remediation: "enable-ats",
                        references: vec![
                            REF_ATS_ARBITRARY,
                            "https://cwe.mitre.org/data/definitions/319.html",
                        ],
                        cwe: "CWE-319",
                        masvs: "MASVS-NETWORK",
                    },
                );
            }
            Flag::Unknown(raw) => unknown(ATS_ID, ctx, "NSAllowsArbitraryLoads", &raw, out),
            _ => {}
        }
    }
    for (name, what) in [
        (
            "NSAllowsArbitraryLoadsInWebContent",
            "web content loaded in WKWebView may use plain HTTP and weak TLS",
        ),
        (
            "NSAllowsArbitraryLoadsForMedia",
            "media loaded with AVFoundation may use plain HTTP",
        ),
    ] {
        let Some((key, node)) = ats.entry(name) else {
            continue;
        };
        match flag(Some(node), ctx) {
            Flag::True => push(
                ctx,
                out,
                Finding {
                    rule: ATS_ID,
                    category: "network",
                    key,
                    title: format!(
                        "ATS relaxed for {} ({name})",
                        if name.ends_with("WebContent") {
                            "web content"
                        } else {
                            "media"
                        }
                    ),
                    severity: Severity::Low,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!("NSAppTransportSecurity.{name} = true"),
                    id_key: name.to_string(),
                    explanation: format!(
                        "With {name} = true, {what}; the rest of the app keeps ATS. Needs review: fine for a \
                         browser-like feature, but anything sensitive shown or entered in that content can be \
                         read or changed on the network."
                    ),
                    remediation: "enable-ats",
                    references: vec![REF_ATS, "https://cwe.mitre.org/data/definitions/319.html"],
                    cwe: "CWE-319",
                    masvs: "MASVS-NETWORK",
                },
            ),
            Flag::Unknown(raw) => unknown(ATS_ID, ctx, name, &raw, out),
            _ => {}
        }
    }
    let Some(domains) = ats.get("NSExceptionDomains") else {
        return;
    };
    for (domain_key, d) in domains.entries() {
        let domain = ui::sanitize_line(&domain_key.name);
        let subdomains = flag(d.get("NSIncludesSubdomains"), ctx) == Flag::True;
        let scope = if subdomains {
            format!("{domain} and its subdomains")
        } else {
            domain.clone()
        };
        let local = local_domain(&domain_key.name);
        for name in [
            "NSExceptionAllowsInsecureHTTPLoads",
            "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
        ] {
            let Some((key, node)) = d.entry(name) else {
                continue;
            };
            match flag(Some(node), ctx) {
                Flag::True => push(
                    ctx,
                    out,
                    Finding {
                        rule: ATS_ID,
                        category: "network",
                        key,
                        title: format!("Plain HTTP allowed for {domain}"),
                        severity: if local {
                            Severity::Info
                        } else {
                            Severity::Medium
                        },
                        confidence: Confidence::NeedsReview,
                        excerpt: format!("NSExceptionDomains.{domain}.{name} = true"),
                        id_key: format!("{}\0{name}", domain_key.name),
                        explanation: if local {
                            format!(
                                "ATS allows plain HTTP to {scope}. This is a local or development host name; \
                                 make sure the exception does not ship in builds that talk to real servers."
                            )
                        } else {
                            format!(
                                "ATS allows plain HTTP to {scope}: requests and responses (cookies, tokens, \
                                 personal data) can be read and changed by anyone on the network path. Needs \
                                 review: some hosts (local devices, legacy media servers) have no HTTPS; for an \
                                 API you control, switch it to HTTPS and remove the exception."
                            )
                        },
                        remediation: "remove-insecure-exception",
                        references: vec![
                            REF_ATS_DOMAINS,
                            "https://cwe.mitre.org/data/definitions/319.html",
                        ],
                        cwe: "CWE-319",
                        masvs: "MASVS-NETWORK",
                    },
                ),
                Flag::Unknown(raw) => unknown(ATS_ID, ctx, name, &raw, out),
                _ => {}
            }
        }
        for name in [
            "NSExceptionMinimumTLSVersion",
            "NSThirdPartyExceptionMinimumTLSVersion",
        ] {
            let Some((key, node)) = d.entry(name) else {
                continue;
            };
            let Some(v) = node.as_str() else { continue };
            let norm = v.trim().to_ascii_lowercase().replace(' ', "");
            if !matches!(
                norm.as_str(),
                "tlsv1.0" | "tlsv1.1" | "tlsv1" | "tlsv10" | "tlsv11"
            ) {
                continue;
            }
            push(
                ctx,
                out,
                Finding {
                    rule: ATS_ID,
                    category: "network",
                    key,
                    title: format!(
                        "Weak minimum TLS version for {domain} ({})",
                        ui::sanitize_line(v)
                    ),
                    severity: Severity::Medium,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!(
                        "NSExceptionDomains.{domain}.{name} = {}",
                        ui::sanitize_line(v)
                    ),
                    id_key: format!("{}\0{name}", domain_key.name),
                    explanation: format!(
                        "ATS accepts {} for {scope}. TLS 1.0 and 1.1 are deprecated (RFC 8996) and weaker \
                         against downgrade and cipher attacks; ATS requires TLS 1.2 by default. Needs review: \
                         the server may not support more; upgrade it and remove the exception.",
                        ui::sanitize_line(v)
                    ),
                    remediation: "raise-min-tls",
                    references: vec![
                        REF_ATS_DOMAINS,
                        "https://www.rfc-editor.org/rfc/rfc8996",
                        "https://cwe.mitre.org/data/definitions/326.html",
                    ],
                    cwe: "CWE-326",
                    masvs: "MASVS-NETWORK",
                },
            );
        }
        for name in [
            "NSExceptionRequiresForwardSecrecy",
            "NSThirdPartyExceptionRequiresForwardSecrecy",
        ] {
            let Some((key, node)) = d.entry(name) else {
                continue;
            };
            if flag(Some(node), ctx) != Flag::False
                || node.as_str().is_some_and(|s| s.contains('$'))
            {
                continue;
            }
            push(
                ctx,
                out,
                Finding {
                    rule: ATS_ID,
                    category: "network",
                    key,
                    title: format!("Forward secrecy not required for {domain}"),
                    severity: Severity::Low,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!("NSExceptionDomains.{domain}.{name} = false"),
                    id_key: format!("{}\0{name}", domain_key.name),
                    explanation: format!(
                        "ATS accepts cipher suites without forward secrecy for {scope}: if the server's private \
                         key ever leaks, recorded traffic can be decrypted. Needs review: usually a sign of an \
                         old server configuration."
                    ),
                    remediation: "require-forward-secrecy",
                    references: vec![REF_ATS_DOMAINS],
                    cwe: "CWE-326",
                    masvs: "MASVS-NETWORK",
                },
            );
        }
    }
}

/// Схема похожа на колбэк OAuth/SDK (Google Sign-In, Facebook, `…oauth…`, `…callback…`).
fn auth_callback(scheme: &str) -> bool {
    let l = scheme.to_ascii_lowercase();
    l.starts_with("com.googleusercontent.apps.")
        || (l.starts_with("fb") && l[2..].chars().all(|c| c.is_ascii_digit()) && l.len() > 4)
        || ["oauth", "auth", "callback", "login", "redirect", "msauth"]
            .iter()
            .any(|w| l.contains(w))
}

fn url_schemes(root: &Node, ctx: &Context, out: &mut RuleOutput) {
    let Some(types) = root.get("CFBundleURLTypes") else {
        return;
    };
    for t in types.items() {
        let Some((_, schemes)) = t.entry("CFBundleURLSchemes") else {
            continue;
        };
        for s in schemes.items() {
            let Some(raw) = s.as_str() else { continue };
            let resolved = ctx
                .settings
                .first()
                .and_then(|set| expand(raw, set, 0))
                .unwrap_or_else(|| raw.to_string());
            let scheme = ui::sanitize_line(resolved.trim());
            if scheme.is_empty() {
                continue;
            }
            let key = Key {
                name: raw.to_string(),
                line: s.line,
                column: s.column,
            };
            let callback = auth_callback(&scheme);
            let explanation = if callback {
                format!(
                    "The app registers the custom URL scheme \"{scheme}:\", which looks like an OAuth/SDK sign-in \
                     callback. Any other app can register the same scheme, and iOS does not say which app gets \
                     the URL, so a redirect with an authorization code can be intercepted. Use \
                     ASWebAuthenticationSession (or universal links) with PKCE, and validate state."
                )
            } else {
                format!(
                    "The app registers the custom URL scheme \"{scheme}:\". Any app or web page can open such URLs \
                     with arbitrary parameters, and another app can claim the same scheme. Needs review: treat \
                     every URL arriving in application(_:open:options:) / scene(_:openURLContexts:) as untrusted \
                     input (no actions without user confirmation, no tokens in URLs); prefer universal links for \
                     anything sensitive."
                )
            };
            push(
                ctx,
                out,
                Finding {
                    rule: URLSCHEME_ID,
                    category: "platform",
                    key: &key,
                    title: format!("Custom URL scheme \"{scheme}\" is an entry point"),
                    severity: Severity::Info,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!("CFBundleURLTypes.CFBundleURLSchemes = {scheme}"),
                    id_key: raw.to_string(),
                    explanation,
                    remediation: if callback {
                        "use-universal-links-or-aswebauth"
                    } else {
                        "validate-deep-links"
                    },
                    references: vec![
                        REF_URL_SCHEME,
                        REF_UNIVERSAL,
                        "https://cwe.mitre.org/data/definitions/939.html",
                    ],
                    cwe: "CWE-939",
                    masvs: "MASVS-PLATFORM",
                },
            );
        }
    }
}

/// IOS-ENTITLEMENTS-003 по одному файлу `.entitlements`.
pub fn entitlements(root: &Node, ctx: &Context, out: &mut RuleOutput) {
    for name in ["get-task-allow", "com.apple.security.get-task-allow"] {
        let Some((key, node)) = root.entry(name) else {
            continue;
        };
        // По конфигурациям: какая release-конфигурация получает true.
        let raw = node.as_str().unwrap_or("");
        let mut release_true: Vec<String> = Vec::new();
        let mut unknown_value = false;
        if ctx.usages.is_empty() {
            match flag(Some(node), ctx) {
                Flag::True => release_true.push(String::new()),
                Flag::Unknown(_) => unknown_value = true,
                _ => {}
            }
        } else {
            for (u, settings) in ctx.usages.iter().zip(ctx.settings.iter()) {
                if u.debug || u.test {
                    continue;
                }
                let one = Context {
                    path: ctx.path,
                    usages: std::slice::from_ref(u),
                    settings: vec![*settings],
                };
                match flag(Some(node), &one) {
                    Flag::True => release_true.push(format!("{} ({})", u.target, u.config)),
                    Flag::Unknown(_) => unknown_value = true,
                    _ => {}
                }
            }
        }
        if unknown_value {
            unknown(ENTITLEMENTS_ID, ctx, name, raw, out);
        }
        if release_true.is_empty() {
            continue;
        }
        let known = !ctx.usages.is_empty();
        push(
            ctx,
            out,
            Finding {
                rule: ENTITLEMENTS_ID,
                category: "platform",
                key,
                title: if known {
                    "get-task-allow enabled in a release configuration".to_string()
                } else {
                    "get-task-allow enabled in an entitlements file".to_string()
                },
                severity: if known {
                    Severity::High
                } else {
                    Severity::Medium
                },
                confidence: if known {
                    Confidence::Potential
                } else {
                    Confidence::NeedsReview
                },
                excerpt: format!("{name} = true"),
                id_key: name.to_string(),
                explanation: format!(
                    "get-task-allow = true lets other processes (a debugger) attach to the app and read or change \
                     its memory, including keys and tokens.{} Xcode adds this entitlement for development \
                     signing by itself; a distribution build must not have it (App Store and ad hoc \
                     distribution reject it, but enterprise/in-house builds may ship with it). Remove the key \
                     from the entitlements file.",
                    if known {
                        format!(
                            " It is used by non-debug configuration(s): {}.",
                            ui::sanitize_line(&release_true.join(", "))
                        )
                    } else {
                        " Which build configuration uses this file is not known (no Xcode project refers to it), \
                         so needs review."
                            .to_string()
                    }
                ),
                remediation: "remove-get-task-allow",
                references: vec![
                    REF_GET_TASK_ALLOW,
                    "https://cwe.mitre.org/data/definitions/489.html",
                ],
                cwe: "CWE-489",
                masvs: "MASVS-RESILIENCE",
            },
        );
    }
    if let Some(domains) = root.get("com.apple.developer.associated-domains") {
        for d in domains.items() {
            let Some(v) = d.as_str() else { continue };
            let Some((service, host)) = v.split_once(':') else {
                continue;
            };
            if !host.starts_with("*.") {
                continue;
            }
            let host = host.split('?').next().unwrap_or(host);
            let key = Key {
                name: v.to_string(),
                line: d.line,
                column: d.column,
            };
            let value = ui::sanitize_line(v);
            push(
                ctx,
                out,
                Finding {
                    rule: ENTITLEMENTS_ID,
                    category: "platform",
                    key: &key,
                    title: format!("Wildcard associated domain ({value})"),
                    severity: Severity::Low,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!("com.apple.developer.associated-domains = {value}"),
                    id_key: v.to_string(),
                    explanation: format!(
                        "The app trusts every subdomain of {} for {} (the apple-app-site-association file is \
                         fetched from each). If anyone else can publish content on a subdomain (user pages, a \
                         dangling DNS record, a third-party service), they can serve that file and {}. Needs \
                         review: list the exact hosts if you can.",
                        ui::sanitize_line(host.trim_start_matches("*.")),
                        ui::sanitize_line(service),
                        if service == "webcredentials" {
                            "be offered the user's saved passwords"
                        } else {
                            "receive universal links meant for the app"
                        }
                    ),
                    remediation: "list-exact-domains",
                    references: vec![
                        REF_UNIVERSAL,
                        "https://cwe.mitre.org/data/definitions/183.html",
                    ],
                    cwe: "CWE-183",
                    masvs: "MASVS-PLATFORM",
                },
            );
        }
    }
    if let Some(groups) = root.get("keychain-access-groups") {
        for g in groups.items() {
            let Some(v) = g.as_str() else { continue };
            if !v.contains('*') {
                continue;
            }
            let key = Key {
                name: v.to_string(),
                line: g.line,
                column: g.column,
            };
            let value = ui::sanitize_line(v);
            push(
                ctx,
                out,
                Finding {
                    rule: ENTITLEMENTS_ID,
                    category: "data_storage",
                    key: &key,
                    title: format!("Wildcard keychain access group ({value})"),
                    severity: Severity::Medium,
                    confidence: Confidence::NeedsReview,
                    excerpt: format!("keychain-access-groups = {value}"),
                    id_key: v.to_string(),
                    explanation: format!(
                        "The keychain access group \"{value}\" contains a wildcard, so keychain items may be shared \
                         with every app of the team that matches it. Needs review: name the exact shared group \
                         (`$(AppIdentifierPrefix)com.example.shared`) so only the apps that need the items get them."
                    ),
                    remediation: "name-exact-keychain-group",
                    references: vec![
                        REF_KEYCHAIN_GROUPS,
                        "https://cwe.mitre.org/data/definitions/732.html",
                    ],
                    cwe: "CWE-732",
                    masvs: "MASVS-STORAGE",
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ios_audit::plist;

    fn usage(target: &str, config: &str, debug: bool, dt: Option<&str>) -> Usage {
        Usage {
            project: "App".into(),
            target: target.into(),
            config: config.into(),
            debug,
            test: false,
            deployment_target: dt.map(str::to_string),
        }
    }

    fn run_info(
        xml: &str,
        usages: &[Usage],
        settings: Vec<&BTreeMap<String, String>>,
    ) -> RuleOutput {
        let p = plist::parse(&format!("<plist><dict>{xml}</dict></plist>")).unwrap();
        let ctx = Context {
            path: "App/Info.plist",
            usages,
            settings,
        };
        let mut out = RuleOutput::default();
        info_plist(&p.root, &ctx, &mut out);
        out
    }

    fn sev(out: &RuleOutput) -> Vec<(String, Severity)> {
        out.findings
            .iter()
            .map(|f| (f.title.clone(), f.severity))
            .collect()
    }

    #[test]
    fn arbitrary_loads_global_and_overridden() {
        let out = run_info(
            "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>",
            &[],
            vec![],
        );
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].severity, Severity::High);
        assert_eq!(out.findings[0].confidence, Confidence::Potential);
        // С InWebContent: на iOS 10+ игнорируется → low; плюс находка про web content.
        let xml = "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/><key>NSAllowsArbitraryLoadsInWebContent</key><true/></dict>";
        let u = [usage("App", "Release", false, Some("15.0"))];
        let empty = BTreeMap::new();
        let out = run_info(xml, &u, vec![&empty]);
        assert_eq!(
            sev(&out),
            vec![
                (
                    "App Transport Security disabled (NSAllowsArbitraryLoads)".to_string(),
                    Severity::Low
                ),
                (
                    "ATS relaxed for web content (NSAllowsArbitraryLoadsInWebContent)".to_string(),
                    Severity::Low
                ),
            ]
        );
        assert_eq!(
            out.findings[0].location.component.as_deref(),
            Some("target App")
        );
        // Старый deployment target — снова high.
        let u = [usage("App", "Release", false, Some("9.0"))];
        let out = run_info(xml, &u, vec![&empty]);
        assert_eq!(out.findings[0].severity, Severity::High);
        // false и отсутствие — не находка.
        let out = run_info(
            "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><false/><key>NSAllowsLocalNetworking</key><true/></dict>",
            &[],
            vec![],
        );
        assert!(out.findings.is_empty());
    }

    #[test]
    fn exception_domains() {
        let xml = "<key>NSAppTransportSecurity</key><dict><key>NSExceptionDomains</key><dict>\
            <key>legacy.example.com</key><dict><key>NSIncludesSubdomains</key><true/><key>NSExceptionAllowsInsecureHTTPLoads</key><true/><key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string><key>NSExceptionRequiresForwardSecrecy</key><false/></dict>\
            <key>localhost</key><dict><key>NSExceptionAllowsInsecureHTTPLoads</key><true/></dict>\
            <key>good.example.com</key><dict><key>NSExceptionMinimumTLSVersion</key><string>TLSv1.2</string></dict>\
            </dict></dict>";
        let out = run_info(xml, &[], vec![]);
        assert_eq!(
            sev(&out),
            vec![
                (
                    "Plain HTTP allowed for legacy.example.com".to_string(),
                    Severity::Medium
                ),
                (
                    "Weak minimum TLS version for legacy.example.com (TLSv1.0)".to_string(),
                    Severity::Medium
                ),
                (
                    "Forward secrecy not required for legacy.example.com".to_string(),
                    Severity::Low
                ),
                (
                    "Plain HTTP allowed for localhost".to_string(),
                    Severity::Info
                ),
            ]
        );
        assert!(out.findings[0].explanation.contains("and its subdomains"));
        assert!(
            out.findings
                .iter()
                .all(|f| f.confidence == Confidence::NeedsReview)
        );
    }

    #[test]
    fn build_setting_values_are_resolved_or_partial() {
        let xml = "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><string>$(ALLOW_HTTP)</string></dict>";
        let mut on = BTreeMap::new();
        on.insert("ALLOW_HTTP".to_string(), "YES".to_string());
        let u = [usage("App", "Release", false, None)];
        assert_eq!(run_info(xml, &u, vec![&on]).findings.len(), 1);
        let none = BTreeMap::new();
        let out = run_info(xml, &u, vec![&none]);
        assert!(out.findings.is_empty());
        assert!(out.partial[0].1.contains("$(ALLOW_HTTP)"));
    }

    #[test]
    fn debug_only_plists_are_capped_at_low() {
        // Wikipedia: `Local-Info.plist` используется только конфигурацией `LocalDebug`.
        let xml = "<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>";
        let s = BTreeMap::new();
        let u = [usage("Wikipedia", "LocalDebug", true, Some("17.6"))];
        let out = run_info(xml, &u, vec![&s]);
        assert_eq!(out.findings[0].severity, Severity::Low);
        assert!(out.findings[0].explanation.contains("LocalDebug"));
        assert!(
            out.findings[0]
                .tags
                .contains(&"build:debug-only".to_string())
        );
    }

    #[test]
    fn url_schemes_are_info() {
        let xml = "<key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>myapp</string><string>com.googleusercontent.apps.123-abc</string></array></dict></array>";
        let out = run_info(xml, &[], vec![]);
        assert_eq!(out.findings.len(), 2);
        assert!(
            out.findings
                .iter()
                .all(|f| f.severity == Severity::Info && f.rule_id == URLSCHEME_ID)
        );
        assert_eq!(
            out.findings[1].remediation_id.as_deref(),
            Some("IOS-URLSCHEME-002:use-universal-links-or-aswebauth")
        );
        assert_eq!(out.findings[0].location.line, Some(1));
    }

    fn run_ent(
        xml: &str,
        usages: &[Usage],
        settings: Vec<&BTreeMap<String, String>>,
    ) -> RuleOutput {
        let p = plist::parse(&format!("<plist><dict>{xml}</dict></plist>")).unwrap();
        let ctx = Context {
            path: "App/App.entitlements",
            usages,
            settings,
        };
        let mut out = RuleOutput::default();
        entitlements(&p.root, &ctx, &mut out);
        out
    }

    #[test]
    fn get_task_allow_by_configuration() {
        let xml = "<key>get-task-allow</key><true/>";
        let s = BTreeMap::new();
        let release = [usage("App", "Release", false, None)];
        let out = run_ent(xml, &release, vec![&s]);
        assert_eq!(out.findings[0].severity, Severity::High);
        assert!(out.findings[0].explanation.contains("App (Release)"));
        let debug = [usage("App", "Debug", true, None)];
        assert!(run_ent(xml, &debug, vec![&s]).findings.is_empty());
        let out = run_ent(xml, &[], vec![]);
        assert_eq!(out.findings[0].severity, Severity::Medium);
        assert_eq!(out.findings[0].confidence, Confidence::NeedsReview);
        assert!(
            run_ent("<key>get-task-allow</key><false/>", &release, vec![&s])
                .findings
                .is_empty()
        );
    }

    #[test]
    fn wildcard_domains_and_keychain_groups() {
        let xml = "<key>com.apple.developer.associated-domains</key><array><string>applinks:*.example.com</string><string>applinks:example.com</string><string>webcredentials:*.example.org</string></array>\
            <key>keychain-access-groups</key><array><string>$(AppIdentifierPrefix)com.example.shared</string><string>$(AppIdentifierPrefix)*</string></array>";
        let out = run_ent(xml, &[], vec![]);
        assert_eq!(
            sev(&out),
            vec![
                (
                    "Wildcard associated domain (applinks:*.example.com)".to_string(),
                    Severity::Low
                ),
                (
                    "Wildcard associated domain (webcredentials:*.example.org)".to_string(),
                    Severity::Low
                ),
                (
                    "Wildcard keychain access group ($(AppIdentifierPrefix)*)".to_string(),
                    Severity::Medium
                ),
            ]
        );
        assert!(out.findings[1].explanation.contains("saved passwords"));
    }
}
