//! Правила для ключей провайдеров.
//! Без regex: ручные матчеры «префикс + алфавит + длина + границы слова».

use super::{Confidence, Rule, RuleInfo, Span};

static RULES: [Rule; 26] = [
    Rule {
        info: RuleInfo {
            id: "aws-access-key",
            name: "AWS Access Key ID",
            confidence: Confidence::High,
        },
        find: find_aws_access_key,
    },
    Rule {
        info: RuleInfo {
            id: "aws-secret-key",
            name: "AWS Secret Access Key",
            confidence: Confidence::High,
        },
        find: find_aws_secret_key,
    },
    Rule {
        info: RuleInfo {
            id: "github-token",
            name: "GitHub Token",
            confidence: Confidence::High,
        },
        find: find_github_token,
    },
    Rule {
        info: RuleInfo {
            id: "gitlab-token",
            name: "GitLab Token",
            confidence: Confidence::High,
        },
        find: find_gitlab_token,
    },
    Rule {
        info: RuleInfo {
            id: "slack-token",
            name: "Slack Token",
            confidence: Confidence::High,
        },
        find: find_slack_token,
    },
    Rule {
        info: RuleInfo {
            id: "slack-webhook",
            name: "Slack Incoming Webhook",
            confidence: Confidence::High,
        },
        find: find_slack_webhook,
    },
    Rule {
        info: RuleInfo {
            id: "stripe-live",
            name: "Stripe Live Key",
            confidence: Confidence::High,
        },
        find: find_stripe_live,
    },
    Rule {
        info: RuleInfo {
            id: "google-api",
            name: "Google API Key",
            confidence: Confidence::High,
        },
        find: find_google_api,
    },
    Rule {
        info: RuleInfo {
            id: "openai",
            name: "OpenAI API Key",
            confidence: Confidence::High,
        },
        find: find_openai,
    },
    Rule {
        info: RuleInfo {
            id: "anthropic",
            name: "Anthropic API Key",
            confidence: Confidence::High,
        },
        find: find_anthropic,
    },
    Rule {
        info: RuleInfo {
            id: "huggingface-token",
            name: "Hugging Face Access Token",
            confidence: Confidence::High,
        },
        find: find_huggingface_token,
    },
    Rule {
        info: RuleInfo {
            id: "groq-api-key",
            name: "Groq API Key",
            confidence: Confidence::High,
        },
        find: find_groq_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "replicate-token",
            name: "Replicate API Token",
            confidence: Confidence::Medium,
        },
        find: find_replicate_token,
    },
    Rule {
        info: RuleInfo {
            id: "perplexity-api-key",
            name: "Perplexity API Key",
            confidence: Confidence::High,
        },
        find: find_perplexity_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "xai-api-key",
            name: "xAI API Key",
            confidence: Confidence::High,
        },
        find: find_xai_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "resend-api-key",
            name: "Resend API Key",
            confidence: Confidence::High,
        },
        find: find_resend_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "sendgrid-api-key",
            name: "SendGrid API Key",
            confidence: Confidence::High,
        },
        find: find_sendgrid_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "twilio-api-key",
            name: "Twilio API Key SID",
            confidence: Confidence::Medium,
        },
        find: find_twilio_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "mailgun-api-key",
            name: "Mailgun API Key",
            confidence: Confidence::High,
        },
        find: find_mailgun_api_key,
    },
    Rule {
        info: RuleInfo {
            id: "discord-bot-token",
            name: "Discord Bot Token",
            confidence: Confidence::High,
        },
        find: find_discord_bot_token,
    },
    Rule {
        info: RuleInfo {
            id: "shopify-access-token",
            name: "Shopify Access Token",
            confidence: Confidence::High,
        },
        find: find_shopify_access_token,
    },
    Rule {
        info: RuleInfo {
            id: "npm-token",
            name: "npm Token",
            confidence: Confidence::High,
        },
        find: find_npm_token,
    },
    Rule {
        info: RuleInfo {
            id: "pypi-token",
            name: "PyPI Token",
            confidence: Confidence::High,
        },
        find: find_pypi_token,
    },
    Rule {
        info: RuleInfo {
            id: "telegram-bot",
            name: "Telegram Bot Token",
            confidence: Confidence::High,
        },
        find: find_telegram_bot,
    },
    Rule {
        info: RuleInfo {
            id: "private-key",
            name: "Private Key",
            confidence: Confidence::High,
        },
        find: find_private_key,
    },
    Rule {
        info: RuleInfo {
            id: "url-credentials",
            name: "Password in URL",
            confidence: Confidence::Medium,
        },
        find: find_url_credentials,
    },
];

/// Все правила. Порядок стабилен (влияет на порядок находок в отчёте).
pub fn all() -> &'static [Rule] {
    &RULES
}

/// Известная заглушка/пример, а не настоящий секрет
/// (`AKIAIOSFODNN7EXAMPLE`, `xxxx...`, `<your-key>`, `changeme`, ...).
pub fn is_placeholder(candidate: &str) -> bool {
    let candidate = candidate.trim_matches(|c: char| c.is_ascii_whitespace() || "'\"`".contains(c));
    let lower = candidate.to_ascii_lowercase();
    if lower.is_empty()
        || lower == "changeme"
        || lower.contains("<your-key>")
        || lower.contains("<your_key>")
        || lower.contains("placeholder")
        || lower.contains("changeme")
    {
        return true;
    }

    if candidate.strip_prefix("AKIA") == Some("IOSFODNN7EXAMPLE") {
        return true;
    }

    // Шаблоны подстановки (`${DB_PASS}`, `$DB_PASS`, `{{ .pass }}`, `%PASS%`, `<pass>`)
    // и слова-заглушки из документации (`user:password@host`).
    if candidate.chars().count() < 3
        || candidate.starts_with('$')
        || (candidate.starts_with('{') && candidate.ends_with('}'))
        || candidate.contains("${")
        || candidate.contains("{{")
        || (candidate.len() > 2 && candidate.starts_with('%') && candidate.ends_with('%'))
        || (candidate.starts_with('<') && candidate.ends_with('>'))
        || matches!(
            lower.as_str(),
            "password" | "passwd" | "pass" | "pwd" | "secret" | "token" | "pa55word"
        )
        || candidate.bytes().all(|byte| byte == b'*')
    {
        return true;
    }

    let payload = [
        "github_pat_",
        "sk_live_",
        "rk_live_",
        "sk-proj-",
        "sk-ant-",
        "re_",
        "SG.",
        "SK",
        "key-",
        "shpat_",
        "shpss_",
        "shpca_",
        "shppa_",
        "pplx-",
        "gsk_",
        "xai-",
        "hf_",
        "r8_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "xoxs-",
        "xapp-",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "npm_",
        "AIza",
        "AKIA",
        "ASIA",
        "pypi-AgEIcHlwaS5vcmc",
    ]
    .iter()
    .find_map(|prefix| candidate.strip_prefix(prefix))
    .or_else(|| candidate.rsplit_once(':').map(|(_, payload)| payload))
    .unwrap_or(candidate);
    // После префикса — слово-заглушка (`ghp_secret`, `sk_live_token`, `glpat-yourtoken`).
    let payload_lower = payload.to_ascii_lowercase();
    if matches!(
        payload_lower.trim_matches(|c: char| !c.is_ascii_alphanumeric()),
        "secret"
            | "token"
            | "password"
            | "key"
            | "yourtoken"
            | "your_token"
            | "yourkey"
            | "your_key"
            | "example"
            | "dummy"
            | "fake"
            | "test"
            | "redacted"
    ) {
        return true;
    }
    let significant: Vec<char> = payload
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // `xxx` и длиннее: в документации пишут и `ghp_xxx`, и `xxxxxxxx`.
    significant.len() >= 3 && significant.iter().all(|c| matches!(c, 'x' | 'X'))
}

fn find_aws_access_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "AKIA", 16, is_upper_or_digit, &mut spans);
    add_fixed_prefixed(line, "ASIA", 16, is_upper_or_digit, &mut spans);
    sorted(spans)
}

fn find_aws_secret_key(line: &str) -> Vec<Span> {
    find_labeled_value(line, "aws_secret_access_key", 40, is_base64_character)
}

fn find_github_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for prefix in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
        add_fixed_prefixed(line, prefix, 36, is_ascii_alphanumeric, &mut spans);
    }
    add_fixed_prefixed(line, "github_pat_", 82, is_urlsafe, &mut spans);
    sorted(spans)
}

fn find_gitlab_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_variable_prefixed(line, "glpat-", 20, 255, is_urlsafe, &mut spans);
    spans
}

fn find_slack_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for prefix in ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xapp-"] {
        add_variable_prefixed(line, prefix, 20, 255, is_slack_character, &mut spans);
    }
    sorted(spans)
}

fn find_slack_webhook(line: &str) -> Vec<Span> {
    const PREFIX: &str = "https://hooks.slack.com/services/";
    let bytes = line.as_bytes();
    let mut spans = Vec::new();

    for (start, _) in line.match_indices(PREFIX) {
        if !left_boundary(line, start) {
            continue;
        }

        let team_start = start + PREFIX.len();
        let team_end = ascii_run_end(bytes, team_start, is_ascii_alphanumeric);
        if !(9..=32).contains(&(team_end - team_start))
            || bytes.get(team_start) != Some(&b'T')
            || bytes.get(team_end) != Some(&b'/')
        {
            continue;
        }

        let service_start = team_end + 1;
        let service_end = ascii_run_end(bytes, service_start, is_ascii_alphanumeric);
        if !(9..=32).contains(&(service_end - service_start))
            || bytes.get(service_start) != Some(&b'B')
            || bytes.get(service_end) != Some(&b'/')
        {
            continue;
        }

        let secret_start = service_end + 1;
        let end = ascii_run_end(bytes, secret_start, is_urlsafe);
        if !(20..=128).contains(&(end - secret_start))
            || bytes.get(end) == Some(&b'/')
            || !right_boundary_for(line, end, is_urlsafe)
            || is_placeholder(&line[secret_start..end])
        {
            continue;
        }

        spans.push(Span { start, end });
    }

    sorted(spans)
}

fn find_stripe_live(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_variable_prefixed(line, "sk_live_", 24, 255, is_ascii_alphanumeric, &mut spans);
    add_variable_prefixed(line, "rk_live_", 24, 255, is_ascii_alphanumeric, &mut spans);
    sorted(spans)
}

fn find_google_api(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "AIza", 35, is_urlsafe, &mut spans);
    spans
}

fn find_openai(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for prefix in ["sk-proj-", "sk-svcacct-", "sk-admin-"] {
        add_variable_prefixed(line, prefix, 20, 512, is_urlsafe, &mut spans);
    }
    add_fixed_prefixed(line, "sk-", 48, is_ascii_alphanumeric, &mut spans);
    sorted(spans)
}

fn find_anthropic(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_variable_prefixed(line, "sk-ant-", 20, 512, is_urlsafe, &mut spans);
    spans
}

// Форматы ИИ-провайдеров (B1). Источники — открытые правила gitleaks/trufflehog
// и документация провайдеров; ссылки — в комментарии у каждого правила.

/// Hugging Face: `hf_` + 34 буквы/цифры. trufflehog `huggingface.go`:
/// `hf_[a-zA-Z0-9]{34}`; gitleaks `huggingface-access-token`: `hf_` + 34 буквы.
/// Тело случайное — в нём есть и строчные, и заглавные (вероятность обратного ~2^-34);
/// без этой проверки `hf_` + слитный идентификатор ровно в 34 символа был бы находкой.
fn find_huggingface_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "hf_", 34, is_ascii_alphanumeric, &mut spans);
    spans.retain(|span| has_lower_and_upper(&line[span.start + 3..span.end]));
    spans
}

/// Groq: `gsk_` + 52 буквы/цифры (trufflehog `groq.go`: `gsk_[a-zA-Z0-9]{52}`).
fn find_groq_api_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "gsk_", 52, is_ascii_alphanumeric, &mut spans);
    spans
}

/// Replicate: 40 символов, начинается с `r8_` (документация Replicate),
/// алфавит тела — `[0-9A-Za-z_-]` (trufflehog `replicate.go`). Префикс короткий,
/// а `_` входит в алфавит — без смешанного регистра это ловило бы snake_case
/// (`r8_` + имя переменной ровно в 37 символов). Поэтому Medium.
fn find_replicate_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "r8_", 37, is_urlsafe, &mut spans);
    spans.retain(|span| has_lower_and_upper(&line[span.start + 3..span.end]));
    spans
}

/// Perplexity: `pplx-` + 48 букв/цифр (gitleaks `perplexity-api-key`).
fn find_perplexity_api_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "pplx-", 48, is_ascii_alphanumeric, &mut spans);
    spans
}

/// xAI: `xai-` + 80 символов `[0-9a-zA-Z_]` (trufflehog `xai.go`).
fn find_xai_api_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "xai-", 80, is_alphanumeric_or_underscore, &mut spans);
    spans
}

fn find_resend_api_key(line: &str) -> Vec<Span> {
    const PREFIX: &str = "re_";
    let bytes = line.as_bytes();
    let mut spans = Vec::new();

    for (start, _) in line.match_indices(PREFIX) {
        if !left_boundary(line, start) {
            continue;
        }
        let body_start = start + PREFIX.len();

        // Current format: `re_` + 8 base58 + `_` + 24 base58.
        let first_end = body_start + 8;
        let end = first_end + 1 + 24;
        if bytes
            .get(body_start..first_end)
            .is_some_and(|part| part.iter().copied().all(is_base58))
            && bytes.get(first_end) == Some(&b'_')
            && bytes
                .get(first_end + 1..end)
                .is_some_and(|part| part.iter().copied().all(is_base58))
            && right_boundary_for(line, end, is_base58)
            && !is_placeholder(&line[start..end])
        {
            spans.push(Span { start, end });
            continue;
        }

        // Legacy keys had only the prefix and an opaque mixed-case body.
        // Ревью: без слова `resend` в строке это ловит идентификаторы
        // (`re_IPv4Address6Pattern`) — формат не документирован, нужен контекст.
        let end = ascii_run_end(bytes, body_start, is_ascii_alphanumeric);
        let body = &line[body_start..end];
        if mentions(line, "resend")
            && (16..=64).contains(&body.len())
            && has_lower_upper_digit(body)
            && right_boundary_for(line, end, is_ascii_alphanumeric)
            && !is_placeholder(&line[start..end])
        {
            spans.push(Span { start, end });
        }
    }

    sorted(spans)
}

fn find_sendgrid_api_key(line: &str) -> Vec<Span> {
    const PREFIX: &str = "SG.";
    let bytes = line.as_bytes();
    let mut spans = Vec::new();

    for (start, _) in line.match_indices(PREFIX) {
        if !left_boundary(line, start) {
            continue;
        }
        let first_start = start + PREFIX.len();
        let first_end = first_start + 22;
        let second_start = first_end + 1;
        let end = second_start + 43;
        if bytes
            .get(first_start..first_end)
            .is_some_and(|part| part.iter().copied().all(is_urlsafe))
            && bytes.get(first_end) == Some(&b'.')
            && bytes
                .get(second_start..end)
                .is_some_and(|part| part.iter().copied().all(is_urlsafe))
            && right_boundary_for(line, end, is_urlsafe)
            && !is_placeholder(&line[start..end])
        {
            spans.push(Span { start, end });
        }
    }

    sorted(spans)
}

fn find_twilio_api_key(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    // SID у Twilio — строчный hex; `SK` + верхний регистр — не он.
    add_fixed_prefixed(line, "SK", 32, is_lower_hex, &mut spans);
    spans
}

fn find_mailgun_api_key(line: &str) -> Vec<Span> {
    // `key-` + 32 hex — это и любой md5 в ключе кэша (`key-d41d8cd9...`).
    // Без контекста Mailgun (`mailgun`, basic auth `api:key-...`, `("api", "key-...")`)
    // не репортим: ложная тревога с high хуже пропуска легаси-формата.
    // Сначала дешёвая проверка: без `key-` нечего искать (профайлер B2: правило было самым
    // дорогим — три перевода всей строки в нижний регистр на КАЖДОЙ строке истории).
    if !line.contains("key-") {
        return Vec::new();
    }
    let lower = line.to_ascii_lowercase();
    if !(lower.contains("mailgun")
        || line.contains("api:key-")
        || lower.contains("\"api\"")
        || lower.contains("'api'"))
    {
        return Vec::new();
    }
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "key-", 32, is_ascii_hex, &mut spans);
    spans
}

fn find_discord_bot_token(line: &str) -> Vec<Span> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();

    for start in 0..bytes.len() {
        if !matches!(bytes[start], b'M' | b'N' | b'O') || !left_boundary(line, start) {
            continue;
        }
        let first_end = ascii_run_end(bytes, start, is_urlsafe);
        // Первая часть — base64 от числового id (17+ цифр → 23+ символа). Проверка
        // декодированием отсекает идентификаторы вида `LongName.method.otherName`.
        if !(23..=30).contains(&(first_end - start))
            || bytes.get(first_end) != Some(&b'.')
            || !is_base64_of_digits(&bytes[start..first_end])
        {
            continue;
        }
        let second_start = first_end + 1;
        let second_end = ascii_run_end(bytes, second_start, is_urlsafe);
        if second_end - second_start != 6 || bytes.get(second_end) != Some(&b'.') {
            continue;
        }
        let signature_start = second_end + 1;
        let end = ascii_run_end(bytes, signature_start, is_urlsafe);
        if !(27..=64).contains(&(end - signature_start))
            || !right_boundary_for(line, end, is_urlsafe)
            || is_placeholder(&line[signature_start..end])
        {
            continue;
        }
        spans.push(Span { start, end });
    }

    sorted(spans)
}

/// Shopify: `shpat_` (Admin API access token), `shpca_` (custom app),
/// `shppa_` (private app), `shpss_` (shared secret) — каждый + 32 hex
/// (gitleaks `shopify-access-token`, `shopify-custom-access-token`,
/// `shopify-private-app-access-token`, `shopify-shared-secret`).
fn find_shopify_access_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for prefix in ["shpat_", "shpca_", "shppa_", "shpss_"] {
        add_fixed_prefixed(line, prefix, 32, is_ascii_hex, &mut spans);
    }
    sorted(spans)
}

fn find_npm_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_fixed_prefixed(line, "npm_", 36, is_ascii_alphanumeric, &mut spans);
    spans
}

fn find_pypi_token(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    add_variable_prefixed(
        line,
        "pypi-AgEIcHlwaS5vcmc",
        16,
        1024,
        is_urlsafe,
        &mut spans,
    );
    spans
}

fn find_telegram_bot(line: &str) -> Vec<Span> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    for (colon, byte) in bytes.iter().enumerate() {
        if *byte != b':' {
            continue;
        }
        let mut start = colon;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        let digits = colon - start;
        if !(8..=10).contains(&digits) || !left_boundary(line, start) {
            continue;
        }
        let end = colon + 1 + 35;
        let Some(body) = bytes.get(colon + 1..end) else {
            continue;
        };
        if !body.iter().copied().all(is_urlsafe) || !right_boundary_for(line, end, is_urlsafe) {
            continue;
        }
        let candidate = &line[start..end];
        if !is_placeholder(candidate) {
            spans.push(Span { start, end });
        }
    }
    sorted(spans)
}

fn find_private_key(line: &str) -> Vec<Span> {
    let begin = "-----BEGIN ";
    let marker = "PRIVATE KEY";
    let mut spans = Vec::new();
    let mut search_from = 0;
    while let Some(relative) = line[search_from..].find(begin) {
        let start = search_from + relative;
        let body_start = start + begin.len();
        let Some(marker_relative) = line[body_start..].find(marker) else {
            break;
        };
        let marker_start = body_start + marker_relative;
        // PEM: `PRIVATE KEY-----`; OpenPGP armor: `PRIVATE KEY BLOCK-----`.
        let after = &line[marker_start + marker.len()..];
        let ending_len = if after.starts_with("-----") {
            marker.len() + 5
        } else if after.starts_with(" BLOCK-----") {
            marker.len() + 11
        } else {
            search_from = body_start;
            continue;
        };
        let label = &line[body_start..marker_start];
        let valid_label = label.is_empty()
            || (label.ends_with(' ')
                && label.bytes().all(|byte| {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b' '
                }));
        let end = marker_start + ending_len;
        if valid_label && left_boundary(line, start) && right_boundary(line, end) {
            spans.push(Span { start, end });
        }
        search_from = body_start;
    }
    sorted(spans)
}

fn find_url_credentials(line: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    for (separator, _) in line.match_indices("://") {
        let bytes = line.as_bytes();
        let mut scheme_start = separator;
        while scheme_start > 0 && is_scheme_character(bytes[scheme_start - 1]) {
            scheme_start -= 1;
        }
        let scheme = &line[scheme_start..separator];
        if scheme.is_empty()
            || !scheme.as_bytes()[0].is_ascii_alphabetic()
            || !left_boundary(line, scheme_start)
        {
            continue;
        }

        let authority_start = separator + 3;
        let authority_end = line[authority_start..]
            .char_indices()
            .find(|(_, c)| {
                c.is_whitespace() || matches!(c, '/' | '?' | '#' | '\'' | '"' | '<' | '>')
            })
            .map(|(offset, _)| authority_start + offset)
            .unwrap_or(line.len());
        let authority = &line[authority_start..authority_end];
        let Some(at) = authority.rfind('@') else {
            continue;
        };
        if at + 1 == authority.len() {
            continue;
        }
        let userinfo = &authority[..at];
        let Some(colon) = userinfo.find(':') else {
            continue;
        };
        if colon == 0 || colon + 1 == userinfo.len() {
            continue;
        }
        let start = authority_start + colon + 1;
        let end = authority_start + at;
        if !is_placeholder(&line[start..end]) && !is_documentation_host(&authority[at + 1..]) {
            spans.push(Span { start, end });
        }
    }
    sorted(spans)
}

/// Хост, пароль к которому не может быть утечкой: зарезервированные под документацию
/// и тесты имена (RFC 2606, RFC 6761) и loopback. Это факт, а не эвристика:
/// `example.com` никому не принадлежит, `localhost` недоступен снаружи.
/// Имена сервисов docker-compose (`db`, `redis`) сюда НЕ входят — там пароли настоящие.
fn is_documentation_host(host_port: &str) -> bool {
    // Хвост из markdown/кода (`` host` ``, `host)`, `host,`) к имени хоста не относится.
    let cut = host_port
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')))
        .unwrap_or(host_port.len());
    let host_port = &host_port[..cut];
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest) // [::1]:8080
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    // Шаблон вместо хоста (`${host}`) обрабатываем как обычный хост — пароль мог быть настоящим.
    matches!(
        host.as_str(),
        "localhost" | "127.0.0.1" | "0.0.0.0" | "::1" | "host" | "hostname"
    ) || host.starts_with("127.")
        || ["example.com", "example.org", "example.net"]
            .iter()
            .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        || [".example", ".test", ".invalid", ".localhost"]
            .iter()
            .any(|tld| host.ends_with(tld))
}

fn add_fixed_prefixed(
    line: &str,
    prefix: &str,
    body_len: usize,
    allowed: fn(u8) -> bool,
    spans: &mut Vec<Span>,
) {
    let bytes = line.as_bytes();
    for (start, _) in line.match_indices(prefix) {
        if !left_boundary(line, start) {
            continue;
        }
        let end = start + prefix.len() + body_len;
        let Some(body) = bytes.get(start + prefix.len()..end) else {
            continue;
        };
        if body.iter().copied().all(allowed) && right_boundary_for(line, end, allowed) {
            let candidate = &line[start..end];
            if !is_placeholder(candidate) {
                spans.push(Span { start, end });
            }
        }
    }
}

fn add_variable_prefixed(
    line: &str,
    prefix: &str,
    min_body_len: usize,
    max_body_len: usize,
    allowed: fn(u8) -> bool,
    spans: &mut Vec<Span>,
) {
    let bytes = line.as_bytes();
    for (start, _) in line.match_indices(prefix) {
        if !left_boundary(line, start) {
            continue;
        }
        let body_start = start + prefix.len();
        let mut end = body_start;
        while end < bytes.len() && allowed(bytes[end]) {
            end += 1;
        }
        let body_len = end - body_start;
        if (min_body_len..=max_body_len).contains(&body_len) && right_boundary(line, end) {
            let candidate = &line[start..end];
            if !is_placeholder(candidate) {
                spans.push(Span { start, end });
            }
        }
    }
}

fn find_labeled_value(
    line: &str,
    label: &str,
    value_len: usize,
    allowed: fn(u8) -> bool,
) -> Vec<Span> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    for label_start in ascii_case_insensitive_positions(line, label) {
        if !left_boundary(line, label_start) {
            continue;
        }
        let mut cursor = label_start + label.len();
        if bytes
            .get(cursor)
            .is_some_and(|byte| is_token_character(*byte as char))
        {
            continue;
        }
        if matches!(bytes.get(cursor), Some(b'\'' | b'"')) {
            cursor += 1;
        }
        skip_ascii_whitespace(bytes, &mut cursor);
        if !matches!(bytes.get(cursor), Some(b'=' | b':')) {
            continue;
        }
        cursor += 1;
        skip_ascii_whitespace(bytes, &mut cursor);
        let quote = match bytes.get(cursor) {
            Some(b'\'' | b'"') => {
                let quote = bytes[cursor];
                cursor += 1;
                Some(quote)
            }
            _ => None,
        };
        let start = cursor;
        let end = start + value_len;
        let Some(value) = bytes.get(start..end) else {
            continue;
        };
        if !value.iter().copied().all(allowed) {
            continue;
        }
        let terminated = match quote {
            Some(quote) => bytes.get(end) == Some(&quote),
            None => right_boundary_for(line, end, allowed),
        };
        if terminated && !is_placeholder(&line[start..end]) {
            spans.push(Span { start, end });
        }
    }
    sorted(spans)
}

fn ascii_case_insensitive_positions(line: &str, needle: &str) -> Vec<usize> {
    let bytes = line.as_bytes();
    let needle = needle.as_bytes();
    if needle.len() > bytes.len() {
        return Vec::new();
    }
    (0..=bytes.len() - needle.len())
        .filter(|&start| bytes[start..start + needle.len()].eq_ignore_ascii_case(needle))
        .collect()
}

fn skip_ascii_whitespace(bytes: &[u8], cursor: &mut usize) {
    while bytes
        .get(*cursor)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *cursor += 1;
    }
}

fn ascii_run_end(bytes: &[u8], start: usize, allowed: fn(u8) -> bool) -> usize {
    let mut end = start;
    while end < bytes.len() && allowed(bytes[end]) {
        end += 1;
    }
    end
}

fn left_boundary(line: &str, start: usize) -> bool {
    line[..start]
        .chars()
        .next_back()
        .is_none_or(|c| !is_token_character(c))
}

fn right_boundary(line: &str, end: usize) -> bool {
    line.get(end..)
        .and_then(|rest| rest.chars().next())
        .is_none_or(|c| !is_token_character(c))
}

fn right_boundary_for(line: &str, end: usize, allowed: fn(u8) -> bool) -> bool {
    let Some(rest) = line.get(end..) else {
        return false;
    };
    match rest.as_bytes().first().copied() {
        None => true,
        Some(byte) if byte.is_ascii() => !allowed(byte) && !is_token_character(char::from(byte)),
        Some(_) => true,
    }
}

fn is_token_character(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-')
}

fn is_scheme_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn is_ascii_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_ascii_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

/// Слово в строке без учёта регистра (`word` — в нижнем регистре).
fn mentions(line: &str, word: &str) -> bool {
    line.to_ascii_lowercase().contains(word)
}

/// base64/base64url без паддинга, который декодируется в 17+ ASCII-цифр.
fn is_base64_of_digits(segment: &[u8]) -> bool {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut digits = 0;
    for &b in segment {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return false,
        };
        bits = (bits << 6) | u32::from(v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            if !((bits >> nbits) as u8).is_ascii_digit() {
                return false;
            }
            bits &= (1 << nbits) - 1;
            digits += 1;
        }
    }
    digits >= 17
}

fn is_base58(byte: u8) -> bool {
    matches!(byte, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
}

fn has_lower_upper_digit(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_lowercase())
        && value.bytes().any(|byte| byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte.is_ascii_digit())
}

fn has_lower_and_upper(value: &str) -> bool {
    value.bytes().any(|byte| byte.is_ascii_lowercase())
        && value.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn is_alphanumeric_or_underscore(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

fn is_urlsafe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_slack_character(byte: u8) -> bool {
    is_urlsafe(byte)
}

fn is_base64_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn sorted(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by_key(|span| (span.start, span.end));
    spans.dedup();
    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(rule_id: &str, line: &str) -> Vec<String> {
        let rule = all()
            .iter()
            .find(|rule| rule.info.id == rule_id)
            .expect("rule exists");
        (rule.find)(line)
            .into_iter()
            .map(|span| line[span.start..span.end].to_string())
            .collect()
    }

    fn assert_detected(rule_id: &str, line: &str, expected: &str) {
        assert_eq!(matches(rule_id, line), vec![expected.to_string()]);
    }

    fn assert_not_detected(rule_id: &str, line: &str) {
        assert!(
            matches(rule_id, line).is_empty(),
            "{rule_id} unexpectedly matched"
        );
    }

    #[test]
    fn rule_set_is_complete_and_stable() {
        let ids: Vec<&str> = all().iter().map(|rule| rule.info.id).collect();
        assert_eq!(
            ids,
            vec![
                "aws-access-key",
                "aws-secret-key",
                "github-token",
                "gitlab-token",
                "slack-token",
                "slack-webhook",
                "stripe-live",
                "google-api",
                "openai",
                "anthropic",
                "huggingface-token",
                "groq-api-key",
                "replicate-token",
                "perplexity-api-key",
                "xai-api-key",
                "resend-api-key",
                "sendgrid-api-key",
                "twilio-api-key",
                "mailgun-api-key",
                "discord-bot-token",
                "shopify-access-token",
                "npm-token",
                "pypi-token",
                "telegram-bot",
                "private-key",
                "url-credentials",
            ]
        );
    }

    #[test]
    fn aws_access_key_examples() {
        let first = format!("{}{}", "AKIA", "A1".repeat(8));
        let second = format!("{}{}", "ASIA", "Z9".repeat(8));
        assert_detected("aws-access-key", &format!("key={first}"), &first);
        assert_detected("aws-access-key", &format!("'{second}'"), &second);

        let example = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        assert_not_detected("aws-access-key", &example);
        assert_not_detected("aws-access-key", &format!("{}{}", "AKIA", "A".repeat(15)));
        assert_not_detected("aws-access-key", &format!("{}{}", "AKIA", "A".repeat(17)));
    }

    #[test]
    fn aws_secret_key_examples() {
        let first = "Ab1/".repeat(10);
        let second = "Z+9=".repeat(10);
        assert_detected(
            "aws-secret-key",
            &format!("aws_secret_access_key = '{first}'"),
            &first,
        );
        assert_detected(
            "aws-secret-key",
            &format!("\"AWS_SECRET_ACCESS_KEY\": \"{second}\""),
            &second,
        );

        assert_not_detected(
            "aws-secret-key",
            &format!("aws_secret_access_key={}", "A".repeat(39)),
        );
        assert_not_detected("aws-secret-key", &format!("unrelated={}", "A".repeat(40)));
        assert_not_detected(
            "aws-secret-key",
            &format!("aws_secret_access_key={}", "x".repeat(40)),
        );
    }

    #[test]
    fn github_token_examples() {
        let classic = format!("{}{}", "ghp_", "A1".repeat(18));
        let fine_grained = format!("{}{}", "github_pat_", "Ab_".repeat(27) + "Z");
        assert_detected("github-token", &classic, &classic);
        assert_detected(
            "github-token",
            &format!("token={fine_grained}"),
            &fine_grained,
        );

        assert_not_detected("github-token", &format!("{}{}", "gho_", "A".repeat(35)));
        assert_not_detected("github-token", &format!("{}{}", "ghu_", "A".repeat(37)));
        assert_not_detected("github-token", &format!("{}{}", "ghp_", "x".repeat(36)));
    }

    #[test]
    fn gitlab_token_examples() {
        let first = format!("{}{}", "glpat-", "A1".repeat(10));
        let second = format!("{}{}", "glpat-", "z9".repeat(10));
        assert_detected("gitlab-token", &first, &first);
        assert_detected("gitlab-token", &format!("token: {second}"), &second);

        assert_not_detected("gitlab-token", &format!("{}{}", "glpat-", "A".repeat(19)));
        assert_not_detected("gitlab-token", &format!("{}{}", "glpat-", "A".repeat(256)));
        // Новый формат GitLab длиннее 20 — не должен теряться.
        let long = format!("{}{}", "glpat-", "Q7_k".repeat(10));
        assert_detected("gitlab-token", &long, &long);
        assert_not_detected("gitlab-token", &format!("{}{}", "glpat-", "x".repeat(20)));
    }

    #[test]
    fn slack_token_examples() {
        let first = format!("{}{}", "xoxb-", "1".repeat(20));
        let second = format!("{}{}-{}", "xoxp-", "2".repeat(10), "Ab".repeat(10));
        let app = format!("{}1-{}-{}", "xapp-", "A7".repeat(8), "b9".repeat(8));
        assert_detected("slack-token", &first, &first);
        assert_detected("slack-token", &format!("slack={second}"), &second);
        assert_detected("slack-token", &format!("app={app}"), &app);

        assert_not_detected("slack-token", &format!("{}{}", "xoxa-", "A".repeat(19)));
        assert_not_detected("slack-token", &format!("{}{}", "xoxr-", "A".repeat(256)));
        assert_not_detected("slack-token", &format!("{}{}", "xoxs-", "x".repeat(20)));
        assert_not_detected("slack-token", &format!("{}{}", "xapp-", "x".repeat(20)));
    }

    #[test]
    fn slack_webhook_examples() {
        let team = format!("{}{}", "T", "19AZ".repeat(2));
        let service = format!("{}{}", "B", "28BY".repeat(2));
        let secret = "Ab9_".repeat(6);
        let webhook = format!(
            "{}{}{}{}{}{}",
            "https://hooks.slack.com/services/", team, "/", service, "/", secret
        );
        assert_detected("slack-webhook", &format!("hook=\"{webhook}\""), &webhook);

        let placeholder_secret = "X".repeat(24);
        let documented_placeholder = format!(
            "{}{}{}{}{}{}",
            "https://hooks.slack.com/services/",
            "T00000000",
            "/",
            "B00000000",
            "/",
            placeholder_secret
        );
        assert_not_detected("slack-webhook", &documented_placeholder);
        assert_not_detected("slack-webhook", &format!("{}/extra", webhook));
        assert_not_detected(
            "slack-webhook",
            &format!(
                "{}{}{}{}{}{}",
                "https://example.test/services/", team, "/", service, "/", secret
            ),
        );
    }

    #[test]
    fn stripe_live_examples() {
        let secret = format!("{}{}", "sk_live_", "A1".repeat(12));
        let restricted = format!("{}{}", "rk_live_", "z9".repeat(16));
        assert_detected("stripe-live", &secret, &secret);
        assert_detected("stripe-live", &format!("stripe={restricted}"), &restricted);

        assert_not_detected("stripe-live", &format!("{}{}", "sk_live_", "A".repeat(23)));
        assert_not_detected("stripe-live", &format!("{}{}", "rk_live_", "A".repeat(256)));
        assert_not_detected("stripe-live", &format!("{}{}", "sk_live_", "x".repeat(24)));
    }

    #[test]
    fn google_api_examples() {
        let first = format!("{}{}", "AIza", "A1_2-".repeat(7));
        let second = format!("{}{}", "AIza", "z9".repeat(17) + "Q");
        assert_detected("google-api", &first, &first);
        assert_detected("google-api", &format!("google={second}"), &second);

        assert_not_detected("google-api", &format!("{}{}", "AIza", "A".repeat(34)));
        assert_not_detected("google-api", &format!("{}{}", "AIza", "A".repeat(36)));
        assert_not_detected("google-api", &format!("{}{}", "AIza", "x".repeat(35)));
    }

    #[test]
    fn openai_examples() {
        let classic = format!("{}{}", "sk-", "A1".repeat(24));
        let project = format!("{}{}", "sk-proj-", "Ab_9-".repeat(4));
        assert_detected("openai", &classic, &classic);
        assert_detected("openai", &format!("openai={project}"), &project);

        assert_not_detected("openai", &format!("{}{}", "sk-", "A".repeat(47)));
        assert_not_detected("openai", &format!("{}{}", "sk-proj-", "A".repeat(19)));
        assert_not_detected("openai", &format!("{}{}", "sk-proj-", "x".repeat(20)));
    }

    #[test]
    fn anthropic_examples() {
        let first = format!("{}{}", "sk-ant-", "A1".repeat(10));
        let second = format!("{}{}", "sk-ant-", "api03_".repeat(5));
        assert_detected("anthropic", &first, &first);
        assert_detected("anthropic", &format!("anthropic={second}"), &second);

        assert_not_detected("anthropic", &format!("{}{}", "sk-ant-", "A".repeat(19)));
        assert_not_detected("anthropic", &format!("{}{}", "sk-ant-", "A".repeat(513)));
        assert_not_detected("anthropic", &format!("{}{}", "sk-ant-", "x".repeat(20)));
    }

    #[test]
    fn resend_api_key_examples() {
        let current = format!("{}{}_{}", "re_", "4Gk7mP2Q", "aB3dE5fG7hJ9kM2nP4qR6sT8");
        let legacy = format!("{}{}", "re_", "Tq7Lm2Xw9Zk4Bn8Pc5");
        assert_detected("resend-api-key", &current, &current);
        assert_detected("resend-api-key", &format!("RESEND_KEY={legacy}"), &legacy);
        // Без контекста legacy-форма — это идентификаторы.
        assert_not_detected("resend-api-key", &format!("key={legacy}"));
        // Склеиваем в рантайме: в строке исходника есть id правила — это контекст.
        for ident in [
            "IPv4Address6Pattern = re.compile(x)",
            "HTTPServer2ConfigLoader = 1",
        ] {
            assert_not_detected("resend-api-key", &format!("{}{ident}", "re_"));
        }

        assert_not_detected(
            "resend-api-key",
            &format!("{}{}_{}", "re_", "4Gk7mP2", "aB3dE5fG7hJ9kM2nP4qR6sT8"),
        );
        assert_not_detected(
            "resend-api-key",
            &format!("{}{}", "re_", "lowercaseonlyvalue123"),
        );
        assert_not_detected("resend-api-key", &format!("{}{}", "re_", "x".repeat(32)));
    }

    #[test]
    fn sendgrid_api_key_examples() {
        let first_tail = format!("{}Z", "b9_".repeat(14));
        let first = format!("{}{}.{}", "SG.", "A1".repeat(11), first_tail);
        let second_tail = format!("{}Y", "M2-".repeat(14));
        let second = format!("{}{}.{}", "SG.", "q7".repeat(11), second_tail);
        assert_detected("sendgrid-api-key", &first, &first);
        assert_detected("sendgrid-api-key", &format!("token='{second}'"), &second);

        assert_not_detected(
            "sendgrid-api-key",
            &format!("{}{}.{}", "SG.", "A".repeat(21), "B".repeat(43)),
        );
        assert_not_detected(
            "sendgrid-api-key",
            &format!("{}{}.{}", "SG.", "A".repeat(22), "B".repeat(42)),
        );
        assert_not_detected(
            "sendgrid-api-key",
            &format!("{}{}.{}", "SG.", "X".repeat(22), "X".repeat(43)),
        );
    }

    #[test]
    fn twilio_api_key_examples() {
        let first = format!("{}{}", "SK", "a1".repeat(16));
        let second = format!("{}{}", "SK", "b9".repeat(16));
        assert_detected("twilio-api-key", &first, &first);
        assert_detected("twilio-api-key", &format!("sid={second}"), &second);
        assert_not_detected("twilio-api-key", &format!("{}{}", "SK", "B9".repeat(16)));

        assert_not_detected("twilio-api-key", &format!("{}{}", "SK", "a".repeat(31)));
        assert_not_detected("twilio-api-key", &format!("{}{}", "SK", "a".repeat(33)));
        assert_not_detected("twilio-api-key", &format!("{}{}G", "SK", "a".repeat(31)));
    }

    #[test]
    fn mailgun_api_key_examples() {
        let first = format!("{}{}", "key-", "a1".repeat(16));
        let second = format!("{}{}", "key-", "B9".repeat(16));
        assert_detected("mailgun-api-key", &format!("MAILGUN_KEY={first}"), &first);
        assert_detected("mailgun-api-key", &format!("mailgun={second}"), &second);
        assert_detected(
            "mailgun-api-key",
            &format!("curl -s --user api:{first}"),
            &first,
        );
        assert_detected(
            "mailgun-api-key",
            &format!("auth=(\"api\", \"{first}\")"),
            &first,
        );
        // md5 в ключе кэша — не Mailgun.
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        assert_not_detected("mailgun-api-key", &format!("cache = 'key-{md5}'"));
        assert_not_detected("mailgun-api-key", &format!("redis.set(\"key-{md5}\", v)"));

        assert_not_detected("mailgun-api-key", &format!("{}{}", "key-", "a".repeat(31)));
        assert_not_detected("mailgun-api-key", &format!("{}{}", "key-", "a".repeat(33)));
        assert_not_detected("mailgun-api-key", &format!("{}{}z", "key-", "a".repeat(31)));
    }

    #[test]
    fn discord_bot_token_examples() {
        // id — base64 от вымышленных чисел: 123456789012345678, 987654321098765432,
        // 17-значного 12345678901234567 (23 символа).
        let first_id = "MTIzNDU2Nzg5MDEyMzQ1Njc4";
        let first = format!("{}.{}.{}", first_id, "A1_b-2", "z9_".repeat(9));
        let second_id = "OTg3NjU0MzIxMDk4NzY1NDMy";
        let second = format!("{}.{}.{}", second_id, "q8-W_3", "K2m-".repeat(8));
        let short = format!(
            "{}.{}.{}",
            "MTIzNDU2Nzg5MDEyMzQ1Njc",
            "A1_b-2",
            "z9_".repeat(9)
        );
        assert_detected("discord-bot-token", &first, &first);
        assert_detected("discord-bot-token", &format!("Bot {second}"), &second);
        assert_detected("discord-bot-token", &short, &short);
        // Длинные идентификаторы через точку: первая часть не base64 от цифр.
        assert_not_detected(
            "discord-bot-token",
            "MyVeryLongComponentNameXY.method.someVeryLongIdentifierNameHereOk",
        );

        assert_not_detected(
            "discord-bot-token",
            &format!("{}.{}.{}", "M".repeat(23), "A".repeat(6), "B".repeat(27)),
        );
        assert_not_detected(
            "discord-bot-token",
            &format!("{}.{}.{}", "M".repeat(24), "A".repeat(5), "B".repeat(27)),
        );
        assert_not_detected(
            "discord-bot-token",
            &format!("{}.{}.{}", "M".repeat(24), "A".repeat(6), "X".repeat(27)),
        );
    }

    #[test]
    fn shopify_access_token_examples() {
        let first = format!("{}{}", "shpat_", "a1".repeat(16));
        let second = format!("{}{}", "shpat_", "B9".repeat(16));
        assert_detected("shopify-access-token", &first, &first);
        assert_detected("shopify-access-token", &format!("token={second}"), &second);

        assert_not_detected(
            "shopify-access-token",
            &format!("{}{}", "shpat_", "a".repeat(31)),
        );
        assert_not_detected(
            "shopify-access-token",
            &format!("{}{}", "shpat_", "a".repeat(33)),
        );
        assert_not_detected(
            "shopify-access-token",
            &format!("{}{}z", "shpat_", "a".repeat(31)),
        );
    }

    #[test]
    fn shopify_other_token_types_examples() {
        for prefix in ["shpss_", "shpca_", "shppa_"] {
            let token = format!("{prefix}{}", "c3".repeat(16));
            assert_detected("shopify-access-token", &token, &token);
            assert_detected(
                "shopify-access-token",
                &format!("SHOPIFY_SECRET=\"{token}\""),
                &token,
            );
            assert_not_detected(
                "shopify-access-token",
                &format!("{prefix}{}", "c".repeat(31)),
            );
            assert_not_detected(
                "shopify-access-token",
                &format!("{prefix}{}", "c".repeat(33)),
            );
            assert_not_detected(
                "shopify-access-token",
                &format!("{prefix}{}g", "c".repeat(31)),
            );
            assert_not_detected(
                "shopify-access-token",
                &format!("{prefix}{}", "x".repeat(32)),
            );
            assert_not_detected(
                "shopify-access-token",
                &format!("my{prefix}{}", "c3".repeat(16)),
            );
        }
        // Похожий, но не документированный префикс.
        assert_not_detected(
            "shopify-access-token",
            &format!("{}{}", "shpxx_", "c3".repeat(16)),
        );
    }

    #[test]
    fn huggingface_token_examples() {
        let first = format!("{}{}", "hf_", "AbCdEfGhQr".repeat(3) + "StUv");
        let second = format!("{}{}", "hf_", "Kz8mQ".repeat(6) + "Lw2p");
        assert_detected("huggingface-token", &first, &first);
        assert_detected("huggingface-token", &format!("token=\"{second}\""), &second);
        assert_detected(
            "huggingface-token",
            &format!("export HF_TOKEN={first}"),
            &first,
        );

        // Длина ровно 34.
        assert_not_detected(
            "huggingface-token",
            &format!("{}{}", "hf_", "Ab".repeat(16) + "C"),
        );
        assert_not_detected(
            "huggingface-token",
            &format!("{}{}", "hf_", "Ab".repeat(17) + "C"),
        );
        // Алфавит: `-`/`_` внутри — это уже не токен.
        assert_not_detected(
            "huggingface-token",
            &format!("{}{}", "hf_", "Ab-".repeat(11) + "C"),
        );
        // Заглушки.
        assert_not_detected("huggingface-token", &format!("{}{}", "hf_", "x".repeat(34)));
        assert_not_detected("huggingface-token", &format!("{}{}", "hf_", "X".repeat(34)));
        assert_not_detected(
            "huggingface-token",
            &format!("{}{}", "hf_", "your_token_here"),
        );
        // Слитный идентификатор в одном регистре.
        assert_not_detected(
            "huggingface-token",
            &format!("{}{}", "hf_", "abcdefghij".repeat(3) + "klmn"),
        );
        // Границы слова.
        assert_not_detected("huggingface-token", &format!("my{first}"));
        assert_not_detected("huggingface-token", &format!("_{first}"));
        assert_not_detected("huggingface-token", &format!("{first}_suffix"));
    }

    #[test]
    fn groq_api_key_examples() {
        let first = format!("{}{}", "gsk_", "Ab3".repeat(17) + "Z");
        let second = format!("{}{}", "gsk_", "q9W".repeat(17) + "e");
        assert_detected("groq-api-key", &first, &first);
        assert_detected("groq-api-key", &format!("GROQ_API_KEY='{second}'"), &second);

        assert_not_detected("groq-api-key", &format!("{}{}", "gsk_", "Ab3".repeat(17)));
        assert_not_detected(
            "groq-api-key",
            &format!("{}{}", "gsk_", "Ab3".repeat(17) + "ZZ"),
        );
        assert_not_detected(
            "groq-api-key",
            &format!("{}{}", "gsk_", "Ab_".repeat(17) + "Z"),
        );
        assert_not_detected("groq-api-key", &format!("{}{}", "gsk_", "x".repeat(52)));
        assert_not_detected("groq-api-key", &format!("{}{}", "gsk_", "your_key_here"));
        assert_not_detected("groq-api-key", &format!("ab{first}"));
        assert_not_detected("groq-api-key", &format!("{first}-x"));
    }

    #[test]
    fn replicate_token_examples() {
        let first = format!("{}{}", "r8_", "Ab3".repeat(12) + "Z");
        let second = format!("{}{}", "r8_", "Kq_7-".repeat(7) + "Lw");
        assert_detected("replicate-token", &first, &first);
        assert_detected(
            "replicate-token",
            &format!("REPLICATE_API_TOKEN={second}"),
            &second,
        );
        assert_detected(
            "replicate-token",
            &format!("Authorization: Bearer {first}"),
            &first,
        );

        assert_not_detected("replicate-token", &format!("{}{}", "r8_", "Ab3".repeat(12)));
        assert_not_detected(
            "replicate-token",
            &format!("{}{}", "r8_", "Ab3".repeat(12) + "ZZ"),
        );
        assert_not_detected(
            "replicate-token",
            &format!("{}{}", "r8_", "Ab.".repeat(12) + "Z"),
        );
        assert_not_detected("replicate-token", &format!("{}{}", "r8_", "x".repeat(37)));
        // snake_case-переменная ровно в 37 символов после префикса.
        assert_not_detected(
            "replicate-token",
            &format!("{}{}", "r8_", "register_value_for_cpu_context_saved1"),
        );
        assert_not_detected("replicate-token", &format!("cr{first}"));
        assert_not_detected("replicate-token", &format!("x{first}"));
    }

    #[test]
    fn perplexity_api_key_examples() {
        let first = format!("{}{}", "pplx-", "Ab3".repeat(16));
        let second = format!("{}{}", "pplx-", "9qW".repeat(16));
        assert_detected("perplexity-api-key", &first, &first);
        assert_detected(
            "perplexity-api-key",
            &format!("PERPLEXITY_API_KEY: \"{second}\""),
            &second,
        );

        assert_not_detected(
            "perplexity-api-key",
            &format!("{}{}", "pplx-", "Ab3".repeat(15) + "Ab"),
        );
        assert_not_detected(
            "perplexity-api-key",
            &format!("{}{}", "pplx-", "Ab3".repeat(16) + "Z"),
        );
        assert_not_detected(
            "perplexity-api-key",
            &format!("{}{}", "pplx-", "Ab_".repeat(16)),
        );
        assert_not_detected(
            "perplexity-api-key",
            &format!("{}{}", "pplx-", "x".repeat(48)),
        );
        assert_not_detected(
            "perplexity-api-key",
            &format!("{}{}", "pplx-", "your-api-key"),
        );
        assert_not_detected("perplexity-api-key", &format!("a{first}"));
    }

    #[test]
    fn xai_api_key_examples() {
        let first = format!("{}{}", "xai-", "Ab3_".repeat(20));
        let second = format!("{}{}", "xai-", "Zq81".repeat(20));
        assert_detected("xai-api-key", &first, &first);
        assert_detected("xai-api-key", &format!("XAI_API_KEY={second}"), &second);

        assert_not_detected("xai-api-key", &format!("{}{}", "xai-", "Ab3_".repeat(19)));
        assert_not_detected(
            "xai-api-key",
            &format!("{}{}", "xai-", "Ab3_".repeat(20) + "Q"),
        );
        assert_not_detected("xai-api-key", &format!("{}{}", "xai-", "Ab3-".repeat(20)));
        assert_not_detected("xai-api-key", &format!("{}{}", "xai-", "x".repeat(80)));
        // CSS-класс и BEM-имя — не ключ.
        assert_not_detected(
            "xai-api-key",
            "<div class=\"xai-button xai-button--primary\">",
        );
        assert_not_detected("xai-api-key", &format!("ab{first}"));
    }

    #[test]
    fn ai_key_fp_probes_are_not_findings() {
        // Строки, похожие на реальный код с этими префиксами.
        let probes = [
            "from huggingface_hub import hf_hub_download",
            "hf_token = os.environ[\"HF_TOKEN\"]",
            "hf_api = HfApi(token=hf_token)",
            "def hf_download_and_cache_model_weights_from_hub(repo):",
            "r8_value = cpu.regs.r8_",
            "mov r8_saved, r8",
            "let r8_register_value_for_cpu_context_save = 0;",
            ".xai-sidebar-collapsed { display: none; }",
            "<span class=\"xai-logo xai-logo--large\"></span>",
            "import { gsk_init } from './gsk_wrapper';",
            "pplx-online-model = \"pplx-70b-online\"",
            "shpat_token = env('SHOPIFY_ACCESS_TOKEN')",
        ];
        let ids = [
            "huggingface-token",
            "groq-api-key",
            "replicate-token",
            "perplexity-api-key",
            "xai-api-key",
            "shopify-access-token",
        ];
        for probe in probes {
            for id in ids {
                assert!(matches(id, probe).is_empty(), "{id} matched {probe}");
            }
        }
    }

    #[test]
    fn npm_token_examples() {
        let first = format!("{}{}", "npm_", "A1".repeat(18));
        let second = format!("{}{}", "npm_", "b9".repeat(18));
        assert_detected("npm-token", &first, &first);
        assert_detected("npm-token", &format!("token={second}"), &second);

        assert_not_detected("npm-token", &format!("{}{}", "npm_", "A".repeat(35)));
        assert_not_detected("npm-token", &format!("{}{}", "npm_", "A".repeat(37)));
        assert_not_detected("npm-token", &format!("{}{}", "npm_", "x".repeat(36)));
    }

    #[test]
    fn pypi_token_examples() {
        let prefix = "pypi-AgEIcHlwaS5vcmc";
        let first = format!("{prefix}{}", "A1".repeat(8));
        let second = format!("{prefix}{}", "b9_-".repeat(5));
        assert_detected("pypi-token", &first, &first);
        assert_detected("pypi-token", &format!("password={second}"), &second);

        assert_not_detected("pypi-token", &format!("{prefix}{}", "A".repeat(15)));
        assert_not_detected("pypi-token", &format!("{prefix}{}", "A".repeat(1025)));
        assert_not_detected("pypi-token", &format!("{prefix}{}", "x".repeat(16)));
    }

    #[test]
    fn telegram_bot_examples() {
        let first = format!("{}:{}", "12345678", "A1_-".repeat(8) + "AbC");
        let second = format!("{}:{}", "1234567890", "z9".repeat(17) + "Q");
        assert_detected("telegram-bot", &first, &first);
        assert_detected("telegram-bot", &format!("bot={second}"), &second);

        assert_not_detected("telegram-bot", &format!("{}:{}", "1234567", "A".repeat(35)));
        assert_not_detected(
            "telegram-bot",
            &format!("{}:{}", "12345678", "A".repeat(36)),
        );
        assert_not_detected(
            "telegram-bot",
            &format!("{}:{}", "12345678", "x".repeat(35)),
        );
    }

    #[test]
    fn private_key_examples() {
        let generic = format!("{}{}", "-----BEGIN ", "PRIVATE KEY-----");
        let rsa = format!("{}{}", "-----BEGIN RSA ", "PRIVATE KEY-----");
        assert_detected("private-key", &generic, &generic);
        assert_detected("private-key", &format!("header {rsa}"), &rsa);

        let public = format!("{}{}", "-----BEGIN ", "PUBLIC KEY-----");
        let placeholder = format!("{}{}", "-----BEGIN ", "<your-key> PRIVATE KEY-----");
        assert_not_detected("private-key", &public);
        assert_not_detected("private-key", &placeholder);
    }

    #[test]
    fn url_credential_examples() {
        let first = format!(
            "{}{}{}",
            "https://alice:", "s3cretValue", "@git.mycompany.io"
        );
        let second = format!("{}{}{}", "postgres://db_user:", "p%40ss", "@db:5432/db");
        assert_detected("url-credentials", &first, "s3cretValue");
        assert_detected("url-credentials", &second, "p%40ss");

        assert_not_detected("url-credentials", "https://alice@example.com");
        assert_not_detected("url-credentials", "https://alice:password@");
        let placeholder = format!("{}{}{}", "https://alice:", "changeme", "@example.com");
        assert_not_detected("url-credentials", &placeholder);
    }

    #[test]
    fn placeholder_examples_are_recognized() {
        assert!(is_placeholder(&format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE")));
        assert!(is_placeholder("xxxx"));
        assert!(is_placeholder("<your-key>"));
        assert!(is_placeholder("changeme"));
        assert!(!is_placeholder("real-looking-value-A1b2"));
    }
}

#[cfg(test)]
mod review_tests {
    //! Регрессии с ревью T1.2 (Claude): реальные длины токенов и шаблоны.
    use super::*;

    fn found(rule_id: &str, line: &str) -> Vec<String> {
        let rule = all().iter().find(|r| r.info.id == rule_id).unwrap();
        (rule.find)(line)
            .into_iter()
            .map(|s| line[s.start..s.end].to_string())
            .collect()
    }

    #[test]
    fn realistic_long_tokens_are_not_lost_by_length_caps() {
        // Реальные ключи OpenAI sk-proj-* ~160+ символов, Anthropic ~100, PyPI ~180-300.
        let openai = format!("{}{}", "sk-proj-", "Ab3_x-Q9".repeat(21));
        let svc = format!("{}{}", "sk-svcacct-", "Zx81Kq_w".repeat(20));
        let anthropic = format!("{}{}", "sk-ant-api03-", "Kz8_Lw-2".repeat(12));
        let pypi = format!("{}{}", "pypi-AgEIcHlwaS5vcmc", "CJGQ2YzE4_-".repeat(30));
        let stripe = format!("{}{}", "sk_live_", "51HxQk2Lm".repeat(11));
        assert_eq!(found("openai", &openai), vec![openai.clone()]);
        assert_eq!(found("openai", &svc), vec![svc.clone()]);
        assert_eq!(found("anthropic", &anthropic), vec![anthropic.clone()]);
        assert_eq!(found("pypi-token", &pypi), vec![pypi.clone()]);
        assert_eq!(found("stripe-live", &stripe), vec![stripe.clone()]);
    }

    #[test]
    fn pgp_private_key_block_is_detected() {
        let pgp = format!("{}{}", "-----BEGIN PGP ", "PRIVATE KEY BLOCK-----");
        assert_eq!(found("private-key", &pgp), vec![pgp.clone()]);
        let public = format!("{}{}", "-----BEGIN PGP ", "PUBLIC KEY BLOCK-----");
        assert!(found("private-key", &public).is_empty());
    }

    #[test]
    fn url_credential_templates_are_not_findings() {
        for line in [
            "postgres://app:${DB_PASSWORD}@db:5432/app",
            "postgres://app:$DB_PASSWORD@db:5432/app",
            "redis://default:{{ .Values.pass }}@redis",
            "mysql://root:%MYSQL_PWD%@localhost",
            "amqp://guest:<password>@rabbit",
            "https://user:password@example.com",
            "https://user:****@example.com",
        ] {
            assert!(found("url-credentials", line).is_empty(), "{line}");
        }
        let real = format!("{}{}{}", "postgres://app:", "Tq9vL2mXw", "@db/app");
        assert_eq!(
            found("url-credentials", &real),
            vec!["Tq9vL2mXw".to_string()]
        );
    }
}

#[cfg(test)]
mod review_tests_fp {
    //! Ложные срабатывания, найденные прогоном по репозиторию jet (T1.6, Claude).
    use super::*;

    #[test]
    fn doc_placeholders_after_prefix_are_not_findings() {
        assert!(is_placeholder("ghp_xxx"));
        assert!(is_placeholder("ghp_secret"));
        assert!(is_placeholder("sk_live_token"));
        let url = all()
            .iter()
            .find(|r| r.info.id == "url-credentials")
            .unwrap();
        for line in [
            "https://user:ghp_xxx@github.com/org/repo.git",
            "https://user:ghp_secret@github.com/o/r.git",
            "https://u:p@host",
            "format!(\"https://u:{}@h\", pw)",
            "f\"https://u:{password}@h\"",
        ] {
            assert!((url.find)(line).is_empty(), "{line}");
        }
        // Настоящее значение после префикса — по-прежнему находка.
        assert!(!is_placeholder(&format!("{}{}", "ghp_", "Zq8".repeat(12))));
    }
}

#[cfg(test)]
mod review_tests_hosts {
    //! Ревью T1.6 (Claude): 17 из 23 находок корпуса — пароли к учебным хостам.
    use super::*;

    fn url(line: &str) -> Vec<String> {
        let r = all()
            .iter()
            .find(|r| r.info.id == "url-credentials")
            .unwrap();
        (r.find)(line)
            .into_iter()
            .map(|s| line[s.start..s.end].to_string())
            .collect()
    }

    #[test]
    fn documentation_and_loopback_hosts_are_not_leaks() {
        let pw = format!("{}{}", "Tq9v", "L2mXw");
        for host in [
            "localhost:8080",
            "127.0.0.1",
            "127.1.2.3:9",
            "[::1]:443",
            "host",
            "api.example.com",
            "example.org",
            "svc.test",
            "x.invalid",
            "app.localhost",
            "host`",
            "localhost)",
        ] {
            assert!(url(&format!("http://u:{pw}@{host}/p")).is_empty(), "{host}");
        }
    }

    #[test]
    fn real_and_internal_hosts_are_still_findings() {
        let pw = format!("{}{}", "Tq9v", "L2mXw");
        for host in [
            "db",
            "redis:6379",
            "prod.mycompany.com",
            "examples.com",
            "10.0.0.5",
        ] {
            assert_eq!(
                url(&format!("postgres://u:{pw}@{host}/x")),
                vec![pw.clone()],
                "{host}"
            );
        }
    }
}
