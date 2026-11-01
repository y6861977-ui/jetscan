//! Read-only checks for `--verify`: identity, account metadata, or resource lists.
//! No inference endpoints, message sends, or webhook probes belong here.
//! Unknown errors stay unknown; response text must never reach a report.

use super::{Provider, Request, Response};
use crate::json::{self, Json};
use crate::secrets::Liveness;

pub static PROVIDERS: &[Provider] = &[
    Provider {
        rule_ids: &["github-token"],
        hosts: &["api.github.com"],
        build: |secret| {
            let mut req = bearer("https://api.github.com/user", secret)?;
            req.headers.extend([
                ("Accept".into(), "application/vnd.github+json".into()),
                ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
            ]);
            Some(req)
        },
        classify: classify_http,
    },
    Provider {
        // The detector cannot identify a self-hosted GitLab instance.
        rule_ids: &["gitlab-token"],
        hosts: &["gitlab.com"],
        build: |secret| {
            authenticated(
                "GET",
                "https://gitlab.com/api/v4/user",
                "PRIVATE-TOKEN",
                "",
                secret,
            )
        },
        classify: classify_gitlab,
    },
    Provider {
        rule_ids: &["slack-token"],
        hosts: &["slack.com"],
        build: |secret| {
            authenticated(
                "POST",
                "https://slack.com/api/auth.test",
                "Authorization",
                "Bearer ",
                secret,
            )
        },
        classify: classify_slack,
    },
    Provider {
        rule_ids: &["stripe-live"],
        hosts: &["api.stripe.com"],
        build: |secret| bearer("https://api.stripe.com/v1/account", secret),
        classify: classify_stripe,
    },
    Provider {
        rule_ids: &["openai"],
        hosts: &["api.openai.com"],
        build: |secret| bearer("https://api.openai.com/v1/models", secret),
        classify: classify_http,
    },
    Provider {
        rule_ids: &["anthropic"],
        hosts: &["api.anthropic.com"],
        build: |secret| {
            let mut req = authenticated(
                "GET",
                "https://api.anthropic.com/v1/models",
                "x-api-key",
                "",
                secret,
            )?;
            req.headers
                .push(("anthropic-version".into(), "2023-06-01".into()));
            Some(req)
        },
        classify: classify_http,
    },
    Provider {
        rule_ids: &["npm-token"],
        hosts: &["registry.npmjs.org"],
        build: |secret| bearer("https://registry.npmjs.org/-/whoami", secret),
        classify: classify_http,
    },
    Provider {
        rule_ids: &["telegram-bot"],
        hosts: &["api.telegram.org"],
        build: telegram,
        classify: classify_telegram,
    },
    Provider {
        rule_ids: &["sendgrid-api-key"],
        hosts: &["api.sendgrid.com"],
        build: |secret| bearer("https://api.sendgrid.com/v3/scopes", secret),
        classify: classify_http,
    },
    Provider {
        rule_ids: &["mailgun-api-key"],
        hosts: &["api.mailgun.net"],
        build: mailgun,
        classify: classify_mailgun,
    },
    Provider {
        rule_ids: &["discord-bot-token"],
        hosts: &["discord.com"],
        build: |secret| {
            authenticated(
                "GET",
                "https://discord.com/api/v10/users/@me",
                "Authorization",
                "Bot ",
                secret,
            )
        },
        classify: classify_http,
    },
    Provider {
        rule_ids: &["resend-api-key"],
        hosts: &["api.resend.com"],
        build: |secret| bearer("https://api.resend.com/domains", secret),
        classify: classify_resend,
    },
    Provider {
        rule_ids: &["huggingface-token"],
        hosts: &["huggingface.co"],
        build: |secret| bearer("https://huggingface.co/api/whoami-v2", secret),
        classify: classify_http,
    },
    Provider {
        rule_ids: &["groq-api-key"],
        hosts: &["api.groq.com"],
        build: |secret| bearer("https://api.groq.com/openai/v1/models", secret),
        classify: classify_http,
    },
    Provider {
        rule_ids: &["xai-api-key"],
        hosts: &["api.x.ai"],
        build: |secret| bearer("https://api.x.ai/v1/api-key", secret),
        classify: classify_xai,
    },
    Provider {
        rule_ids: &["replicate-token"],
        hosts: &["api.replicate.com"],
        build: |secret| bearer("https://api.replicate.com/v1/account", secret),
        classify: classify_http,
    },
];

fn valid_secret(secret: &str) -> bool {
    !secret.is_empty() && secret.bytes().all(|b| b.is_ascii_graphic())
}

fn authenticated(
    method: &'static str,
    url: &str,
    header: &str,
    prefix: &str,
    secret: &str,
) -> Option<Request> {
    if !valid_secret(secret) {
        return None;
    }
    Some(Request {
        method,
        url: url.into(),
        headers: vec![(header.into(), format!("{prefix}{secret}"))],
        body: None,
    })
}

fn bearer(url: &str, secret: &str) -> Option<Request> {
    authenticated("GET", url, "Authorization", "Bearer ", secret)
}

fn telegram(secret: &str) -> Option<Request> {
    // The key is a path component. Reject URL delimiters, dot segments and curl
    // globbing syntax so a malformed finding cannot change the getMe endpoint.
    let (id, token) = secret.split_once(':')?;
    if id.is_empty()
        || !id.bytes().all(|b| b.is_ascii_digit())
        || token.is_empty()
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return None;
    }
    Some(Request {
        method: "GET",
        url: format!("https://api.telegram.org/bot{secret}/getMe"),
        headers: Vec::new(),
        body: None,
    })
}

fn mailgun(secret: &str) -> Option<Request> {
    if !valid_secret(secret) {
        return None;
    }
    let credentials = base64(format!("api:{secret}").as_bytes());
    authenticated(
        "GET",
        "https://api.mailgun.net/v3/domains",
        "Authorization",
        "Basic ",
        &credentials,
    )
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(a >> 2) as usize] as char);
        out.push(ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn classify_http(resp: &Response) -> Liveness {
    match resp.status {
        200..=299 => Liveness::Live,
        401 => Liveness::Revoked,
        429 => Liveness::Unknown("rate limited".into()),
        500..=599 => Liveness::Unknown("provider error".into()),
        // A generic 403 does not prove either validity or revocation.
        code => Liveness::Unknown(format!("HTTP {code}")),
    }
}

/// Ревью Claude: `glpat-` бывает и от self-hosted GitLab. 401 на gitlab.com НЕ значит,
/// что ключ мёртв — на сервере компании он может работать. Ложное «revoked» опаснее
/// честного «не знаю»: человек перестанет беспокоиться.
fn classify_gitlab(resp: &Response) -> Liveness {
    if resp.status == 401 {
        Liveness::Unknown("not valid on gitlab.com (may belong to a self-hosted GitLab)".into())
    } else {
        classify_http(resp)
    }
}

/// Ревью Claude: ключи EU-региона живут на api.eu.mailgun.net — на US-хосте 401.
fn classify_mailgun(resp: &Response) -> Liveness {
    if resp.status == 401 {
        Liveness::Unknown("not valid in the US region (may be an EU-region key)".into())
    } else {
        classify_http(resp)
    }
}

/// Ревью Claude (проверено живым запросом с выдуманным ключом): на неверный ключ xAI
/// отвечает 400 `{"code":"invalid-argument","error":"Incorrect API key provided..."}`.
fn classify_xai(resp: &Response) -> Liveness {
    if resp.status == 400
        && json::parse(&resp.body)
            .ok()
            .and_then(|b| b.get("error").and_then(Json::as_str).map(str::to_string))
            .is_some_and(|e| e.starts_with("Incorrect API key"))
    {
        Liveness::Revoked
    } else {
        classify_http(resp)
    }
}

fn classify_stripe(resp: &Response) -> Liveness {
    if resp.status == 403 {
        // Stripe also returns 403 for valid restricted keys lacking permissions.
        Liveness::Live
    } else {
        classify_http(resp)
    }
}

fn classify_resend(resp: &Response) -> Liveness {
    if resp.status == 401 {
        // Sending-only keys can receive 401 on /domains. Until the error schema
        // is confirmed, no 401 here is sufficient evidence of revocation.
        Liveness::Unknown("HTTP 401".into())
    } else {
        classify_http(resp)
    }
}

fn classify_slack(resp: &Response) -> Liveness {
    if !(200..=299).contains(&resp.status) {
        return classify_http(resp);
    }
    if let Ok(body) = json::parse(&resp.body) {
        match body.get("ok").and_then(Json::as_bool) {
            Some(true) => return Liveness::Live,
            Some(false) => match body.get("error").and_then(Json::as_str) {
                Some("invalid_auth" | "token_revoked" | "account_inactive" | "not_authed") => {
                    return Liveness::Revoked;
                }
                Some("ratelimited" | "rate_limited") => {
                    return Liveness::Unknown("rate limited".into());
                }
                _ => {}
            },
            None => {}
        }
    }
    // Do not return the provider's error string or a JSON parse error: either
    // could contain the submitted secret or private account information.
    Liveness::Unknown("unexpected Slack response".into())
}

fn classify_telegram(resp: &Response) -> Liveness {
    if matches!(resp.status, 401 | 404) {
        return Liveness::Revoked;
    }
    if !(200..=299).contains(&resp.status) {
        return classify_http(resp);
    }
    if let Ok(body) = json::parse(&resp.body) {
        match body.get("ok").and_then(Json::as_bool) {
            Some(true) => return Liveness::Live,
            Some(false) => match body.get("error_code").and_then(Json::as_f64) {
                Some(401.0 | 404.0) => return Liveness::Revoked,
                Some(429.0) => return Liveness::Unknown("rate limited".into()),
                _ => {}
            },
            None => {}
        }
    }
    Liveness::Unknown("unexpected Telegram response".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::verify::{curl_config, https_host, provider_for};
    use std::collections::HashSet;

    fn secret_for(rule: &str) -> String {
        let prefix = match rule {
            "github-token" => "ghp_",
            "gitlab-token" => "glpat-",
            "slack-token" => "xoxb-",
            "stripe-live" => "sk_live_",
            "openai" => "sk-",
            "anthropic" => "sk-ant-",
            "npm-token" => "npm_",
            "telegram-bot" => return format!("{}:{}", "123456789", "fake_token-ABC"),
            "sendgrid-api-key" => "SG.",
            "mailgun-api-key" => return format!("{}{}", "test", "-key"),
            "discord-bot-token" => "dummy.",
            "resend-api-key" => "re_",
            "huggingface-token" => "hf_",
            "groq-api-key" => "gsk_",
            "xai-api-key" => "xai-",
            "replicate-token" => "r8_",
            _ => panic!("missing test fixture for {rule}"),
        };
        format!("{prefix}{}", "not-a-real-key")
    }

    fn response(status: u16, body: &str) -> Response {
        Response {
            status,
            body: body.into(),
        }
    }

    fn classify(rule: &str, status: u16, body: &str) -> Liveness {
        (provider_for(rule).unwrap().classify)(&response(status, body))
    }

    #[test]
    fn builds_read_only_requests_with_expected_authentication() {
        // Independent expectations: do not derive endpoints/auth from PROVIDERS.
        let cases = [
            (
                "github-token",
                "GET",
                "https://api.github.com/user",
                "Authorization",
                "Bearer ",
            ),
            (
                "gitlab-token",
                "GET",
                "https://gitlab.com/api/v4/user",
                "PRIVATE-TOKEN",
                "",
            ),
            (
                "slack-token",
                "POST",
                "https://slack.com/api/auth.test",
                "Authorization",
                "Bearer ",
            ),
            (
                "stripe-live",
                "GET",
                "https://api.stripe.com/v1/account",
                "Authorization",
                "Bearer ",
            ),
            (
                "openai",
                "GET",
                "https://api.openai.com/v1/models",
                "Authorization",
                "Bearer ",
            ),
            (
                "anthropic",
                "GET",
                "https://api.anthropic.com/v1/models",
                "x-api-key",
                "",
            ),
            (
                "npm-token",
                "GET",
                "https://registry.npmjs.org/-/whoami",
                "Authorization",
                "Bearer ",
            ),
            (
                "telegram-bot",
                "GET",
                "https://api.telegram.org/bot{secret}/getMe",
                "",
                "",
            ),
            (
                "sendgrid-api-key",
                "GET",
                "https://api.sendgrid.com/v3/scopes",
                "Authorization",
                "Bearer ",
            ),
            (
                "mailgun-api-key",
                "GET",
                "https://api.mailgun.net/v3/domains",
                "Authorization",
                "Basic ",
            ),
            (
                "discord-bot-token",
                "GET",
                "https://discord.com/api/v10/users/@me",
                "Authorization",
                "Bot ",
            ),
            (
                "resend-api-key",
                "GET",
                "https://api.resend.com/domains",
                "Authorization",
                "Bearer ",
            ),
            (
                "huggingface-token",
                "GET",
                "https://huggingface.co/api/whoami-v2",
                "Authorization",
                "Bearer ",
            ),
            (
                "groq-api-key",
                "GET",
                "https://api.groq.com/openai/v1/models",
                "Authorization",
                "Bearer ",
            ),
            (
                "xai-api-key",
                "GET",
                "https://api.x.ai/v1/api-key",
                "Authorization",
                "Bearer ",
            ),
            (
                "replicate-token",
                "GET",
                "https://api.replicate.com/v1/account",
                "Authorization",
                "Bearer ",
            ),
        ];
        assert_eq!(PROVIDERS.len(), cases.len());
        for (rule, method, url, header, prefix) in cases {
            let provider = provider_for(rule).unwrap();
            let secret = secret_for(rule);
            let req = (provider.build)(&secret).unwrap();
            assert_eq!(req.method, method, "{rule}");
            assert_eq!(req.url, url.replace("{secret}", &secret), "{rule}");
            assert_eq!(req.body, None, "{rule}");
            let mut expected = match rule {
                "telegram-bot" => Vec::new(),
                "mailgun-api-key" => vec![(header.into(), "Basic YXBpOnRlc3Qta2V5".into())],
                _ => vec![(header.into(), format!("{prefix}{secret}"))],
            };
            match rule {
                "github-token" => expected.extend([
                    ("Accept".into(), "application/vnd.github+json".into()),
                    ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
                ]),
                "anthropic" => expected.push(("anthropic-version".into(), "2023-06-01".into())),
                _ => {}
            }
            assert_eq!(req.headers, expected, "{rule}");
            assert!(curl_config(&req).is_some(), "{rule}");
        }
    }

    #[test]
    fn every_provider_builds_https_only_for_its_exact_allowed_hosts() {
        let mut rules = HashSet::new();
        for provider in PROVIDERS {
            assert!(!provider.rule_ids.is_empty());
            let mut built_hosts = HashSet::new();
            for &rule in provider.rule_ids {
                assert!(rules.insert(rule), "duplicate adapter for {rule}");
                let req = (provider.build)(&secret_for(rule)).unwrap();
                let host = https_host(&req.url).expect("must be an HTTPS URL");
                assert!(provider.hosts.contains(&host), "{rule}");
                built_hosts.insert(host.to_string());
            }
            let allowed: HashSet<String> = provider.hosts.iter().map(|h| (*h).into()).collect();
            assert_eq!(allowed.len(), provider.hosts.len(), "duplicate hosts");
            assert_eq!(built_hosts, allowed, "allowlist must have no unused hosts");
        }
    }

    #[test]
    fn xai_incorrect_key_400_is_revoked_other_400_unknown() {
        let wrong = Response {
            status: 400,
            body: r#"{"code":"invalid-argument","error":"Incorrect API key provided. You can obtain an API key from https://console.x.ai."}"#.into(),
        };
        assert_eq!(classify_xai(&wrong), Liveness::Revoked);
        let other = Response {
            status: 400,
            body: r#"{"error":"Bad request"}"#.into(),
        };
        assert_eq!(classify_xai(&other), Liveness::Unknown("HTTP 400".into()));
    }

    #[test]
    fn every_adapter_classifies_http_statuses_conservatively() {
        for provider in PROVIDERS {
            for &rule in provider.rule_ids {
                for status in [
                    200, 201, 204, 299, 401, 403, 429, 500, 502, 599, 302, 400, 404, 418,
                ] {
                    let expected = match status {
                        200..=299 => Liveness::Live,
                        401 if rule == "resend-api-key" => Liveness::Unknown("HTTP 401".into()),
                        // Ревью Claude: self-hosted GitLab / EU Mailgun — 401 не доказывает отзыв.
                        401 if rule == "gitlab-token" => Liveness::Unknown(
                            "not valid on gitlab.com (may belong to a self-hosted GitLab)".into(),
                        ),
                        401 if rule == "mailgun-api-key" => Liveness::Unknown(
                            "not valid in the US region (may be an EU-region key)".into(),
                        ),
                        401 => Liveness::Revoked,
                        403 if rule == "stripe-live" => Liveness::Live,
                        404 if rule == "telegram-bot" => Liveness::Revoked,
                        429 => Liveness::Unknown("rate limited".into()),
                        500..=599 => Liveness::Unknown("provider error".into()),
                        code => Liveness::Unknown(format!("HTTP {code}")),
                    };
                    // A success-looking body must never override an error status.
                    assert_eq!(
                        classify(rule, status, r#"{"ok":true}"#),
                        expected,
                        "{rule}: HTTP {status}"
                    );
                }
                for status in [200, 204, 299] {
                    let expected = match rule {
                        "slack-token" => Liveness::Unknown("unexpected Slack response".into()),
                        "telegram-bot" => Liveness::Unknown("unexpected Telegram response".into()),
                        _ => Liveness::Live,
                    };
                    assert_eq!(
                        classify(rule, status, ""),
                        expected,
                        "{rule}: HTTP {status}, empty body"
                    );
                }
            }
        }
    }

    #[test]
    fn slack_requires_a_boolean_ok_and_recognizes_authentication_errors() {
        assert_eq!(
            classify(
                "slack-token",
                200,
                " { \"ok\" : true, \"user_id\": \"test-user\" } "
            ),
            Liveness::Live
        );
        for error in [
            "invalid_auth",
            "token_revoked",
            "account_inactive",
            "not_authed",
        ] {
            let body = format!(r#"{{"ok":false,"error":"{error}"}}"#);
            assert_eq!(
                classify("slack-token", 200, &body),
                Liveness::Revoked,
                "{error}"
            );
        }
        for error in ["ratelimited", "rate_limited"] {
            let body = format!(r#"{{"ok":false,"error":"{error}"}}"#);
            assert_eq!(
                classify("slack-token", 200, &body),
                Liveness::Unknown("rate limited".into())
            );
        }
        for body in [
            r#"{"ok":false,"error":"missing_scope"}"#,
            r#"{"ok":false,"error":"no_permission"}"#,
            r#"{"ok":false,"error":"new_error"}"#,
            r#"{"ok":false}"#,
            r#"{"error":"invalid_auth"}"#,
        ] {
            assert_eq!(
                classify("slack-token", 200, body),
                Liveness::Unknown("unexpected Slack response".into())
            );
        }
    }

    #[test]
    fn telegram_checks_ok_and_explicit_authentication_error_codes() {
        assert_eq!(
            classify("telegram-bot", 200, r#"{"result":{"id":123},"ok":true}"#),
            Liveness::Live
        );
        for code in [401, 404] {
            assert_eq!(classify("telegram-bot", code, ""), Liveness::Revoked);
            let body = format!(r#"{{"ok":false,"error_code":{code},"description":"test error"}}"#);
            assert_eq!(classify("telegram-bot", 200, &body), Liveness::Revoked);
        }
        assert_eq!(
            classify("telegram-bot", 200, r#"{"ok":false,"error_code":429}"#),
            Liveness::Unknown("rate limited".into())
        );
        for body in [
            r#"{"ok":false}"#,
            r#"{"ok":false,"error_code":400}"#,
            r#"{"ok":false,"error_code":403}"#,
            r#"{"ok":false,"error_code":"401"}"#,
            r#"{"error_code":401}"#,
        ] {
            assert_eq!(
                classify("telegram-bot", 200, body),
                Liveness::Unknown("unexpected Telegram response".into())
            );
        }
    }

    #[test]
    fn json_services_do_not_accept_malformed_or_nested_success() {
        for (rule, reason) in [
            ("slack-token", "unexpected Slack response"),
            ("telegram-bot", "unexpected Telegram response"),
        ] {
            for body in [
                "",
                "not json",
                "null",
                "true",
                "{}",
                "[]",
                r#"{"ok":true"#,
                r#"{"ok":true} trailing"#,
                r#"{"ok":"true"}"#,
                r#"{"ok":1}"#,
                r#"{"ok":null}"#,
                r#"[{"ok":true}]"#,
                r#"{"result":{"ok":true}}"#,
                r#"{"message":"\"ok\":true"}"#,
            ] {
                assert_eq!(
                    classify(rule, 200, body),
                    Liveness::Unknown(reason.into()),
                    "{rule}: {body}"
                );
            }
        }
    }

    #[test]
    fn resend_unauthorized_never_mislabels_a_sending_only_key() {
        // Candidate shapes, not a claim about Resend's current error schema.
        for body in [
            "",
            "not json",
            r#"{"name":"restricted_api_key","message":"Sending access only"}"#,
            r#"{"error":{"name":"restricted_api_key"}}"#,
            r#"{"name":"validation_error","message":"Insufficient permissions"}"#,
            r#"{"name":"invalid_api_key"}"#,
        ] {
            assert_eq!(
                classify("resend-api-key", 401, body),
                Liveness::Unknown("HTTP 401".into())
            );
        }
    }

    #[test]
    fn stripe_restricted_keys_use_the_same_read_only_request() {
        let provider = provider_for("stripe-live").unwrap();
        let secret = format!("{}{}", "rk_live_", "not-a-real-key");
        let req = (provider.build)(&secret).unwrap();
        assert_eq!(req.url, "https://api.stripe.com/v1/account");
        assert_eq!(
            req.headers,
            vec![("Authorization".into(), format!("Bearer {secret}"))]
        );
        assert_eq!(
            classify(
                "stripe-live",
                403,
                r#"{"error":{"type":"permission_error"}}"#
            ),
            Liveness::Live
        );
    }

    #[test]
    fn no_classifier_copies_response_content_into_the_result() {
        for provider in PROVIDERS {
            for &rule in provider.rule_ids {
                let secret = secret_for(rule);
                let bodies = [
                    secret.clone(),
                    format!(
                        r#"{{"ok":false,"error":"{secret}","message":"{secret}","description":"{secret}"}}"#
                    ),
                    format!(r#"{{"ok": "{secret}"}}"#),
                ];
                for status in [200, 401, 403, 404, 429, 500] {
                    for body in &bodies {
                        if let Liveness::Unknown(reason) = classify(rule, status, body) {
                            assert!(!reason.contains(&secret), "{rule}");
                            assert!(!reason.contains(body), "{rule}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn builders_reject_empty_secrets_and_whitespace_or_control_characters() {
        for provider in PROVIDERS {
            for &rule in provider.rule_ids {
                assert!((provider.build)("").is_none(), "{rule}");
                for bad in [' ', '\t', '\r', '\n', '\0', '\u{1b}', '\u{7f}', '\u{a0}'] {
                    let secret = format!("{}{bad}", secret_for(rule));
                    assert!((provider.build)(&secret).is_none(), "{rule}: {bad:?}");
                }
            }
        }
    }

    #[test]
    fn telegram_rejects_tokens_that_could_change_the_request_path() {
        let provider = provider_for("telegram-bot").unwrap();
        let good = secret_for("telegram-bot");
        for suffix in [
            "/sendMessage",
            "/../sendMessage",
            "?method=sendMessage",
            "#fragment",
            "%2f",
            "\\",
            "[1-2]",
            "{one,two}",
            ":extra",
            "@other.host",
        ] {
            assert!(
                (provider.build)(&format!("{good}{suffix}")).is_none(),
                "{suffix}"
            );
        }
        for invalid in [
            format!("{}:{}", "id", "fake"),
            format!("{}:", "123"),
            format!(":{}", "fake"),
            format!("{}{}", "123", "fake"),
        ] {
            assert!((provider.build)(&invalid).is_none());
        }
    }

    #[test]
    fn base64_handles_padding_and_high_bytes() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected);
        }
        assert_eq!(base64(&[0xfb, 0xff, 0xff]), "+///");
        assert_eq!(base64(&[0]), "AA==");
    }

    #[test]
    fn unsupported_or_side_effecting_checks_are_not_registered() {
        for rule in [
            "aws-access-key",
            "aws-secret-key",
            "aws-session-token",
            "twilio",
            "shopify",
            "google-api",
            "pypi-token",
            "private-key",
            "url-credentials",
            "env-secret",
            "docker-auth",
            "git-credentials",
            "npm-auth-token",
            "pypi-password",
            "slack-webhook",
        ] {
            assert!(provider_for(rule).is_none(), "{rule}");
        }
        for provider in PROVIDERS {
            assert!(!provider.rule_ids.iter().any(|r| r.starts_with("aws-")));
        }
    }
}
