//! APK-SECRET-006: ключи провайдеров внутри APK. APK скачивает кто угодно, поэтому любой
//! привилегированный ключ в нём — у всех.
//!
//! Матчеры — ядра (`secrets::rules::scan_line`, с префильтром), здесь не дублируются.
//! Что смотрим: текстовые записи (assets, `*.json`, `*.properties`, ...) построчно, строковые
//! значения атрибутов во всех AXML-записях (`AndroidManifest.xml`, `res/**/*.xml`) и пул строк
//! `classes*.dex` в корне APK (ADR-DEX: только строки, без байткода).
//! Что НЕ смотрим (ограничение, пишется в отчёт): код DEX, DEX/JAR/ZIP внутри APK (`assets/*.dex`),
//! `resources.arsc`, `lib/**` (нативный код), картинки и прочие двоичные записи, `META-INF/` (подписи).
//! Находки из DEX: «никогда не публичные» форматы — `high`/`potential` с тегом `source:dex` (строка может
//! принадлежать встроенной библиотеке); одна находка на значение на весь APK, с перечнем DEX.
//! Google API ключ (`AIza…`) — часто публичный ключ Firebase/Maps, предназначенный для клиента:
//! `info`/`needs_review` («проверьте ограничения ключа»), не critical.
//! Сырые значения не выводятся никогда: только маска ядра и отпечаток.

use super::RuleOutput;
use crate::apk_audit::axml::{self, Value};
use crate::apk_audit::dex;
use crate::apk_audit::types::{
    ApkFinding, ApkLocation, Confidence, Evidence, Severity, finding_id,
};
use crate::apk_audit::zip::{Archive, Budget};
use crate::secrets::{self, rules};
use crate::ui;

pub const SECRET_ID: &str = "APK-SECRET-006";

/// Сколько срабатываний на запись разбираем (как в web: защита от строк-бомб).
const MAX_HITS_PER_ENTRY: usize = 200;
/// Сколько `classesN.dex` читаем (одобрено в ADR-DEX).
pub const MAX_DEX_FILES: usize = 200;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretStats {
    pub text_entries: usize,
    pub axml_entries: usize,
    /// Двоичные записи вне рамок правила (arsc, нативные библиотеки, картинки, подписи).
    pub out_of_scope: usize,
    /// `classes*.dex`, чей пул строк прочитан.
    pub dex_entries: usize,
    /// DEX/JAR/ZIP/APK внутри APK, не в корне (`assets/payload.dex`) — не читаются.
    pub nested_code: usize,
    /// Замечания по DEX (checksum, map_list, размер) — в limitations.
    pub dex_notes: Vec<String>,
}

/// `classes.dex`, `classes2.dex`, … в корне APK.
fn is_root_dex(name: &str) -> bool {
    name.strip_prefix("classes")
        .and_then(|rest| rest.strip_suffix(".dex"))
        .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
}

fn out_of_scope(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with('/')
        || lower.starts_with("meta-inf/")
        || lower.starts_with("lib/")
        || lower == "resources.arsc"
        || [
            ".dex", ".so", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ttf", ".otf", ".mp3",
            ".ogg", ".mp4", ".wav", ".arsc", ".jar", ".zip", ".apk",
        ]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

fn is_axml(data: &[u8]) -> bool {
    data.len() >= 8 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x08 && data[3] == 0x00
}

#[derive(Default)]
struct EntryHits {
    hits: Vec<(Option<u32>, Option<String>, secrets::Hit)>,
    total: usize,
}

impl EntryHits {
    /// `text` — строка для матчеров; `rest` — всё значение начиная с этой строки (для тела PEM).
    fn add(&mut self, line: Option<u32>, component: Option<String>, text: &str, rest: &str) {
        for hit in rules::scan_line(1, text) {
            self.total += 1;
            if self.hits.len() < MAX_HITS_PER_ENTRY && is_real_key(&hit, text, rest) {
                self.hits.push((line, component.clone(), hit));
            }
        }
    }
}

/// Отсев заглушек ядра плюс: заголовок PEM без тела base64 — не ключ. Значение (строка DEX,
/// атрибут AXML, остаток текстового файла) известно целиком, поэтому тело проверяется здесь.
fn is_real_key(hit: &secrets::Hit, text: &str, rest: &str) -> bool {
    if rules::is_placeholder(&hit.secret) {
        return false;
    }
    if hit.rule.id != "private-key" {
        return true;
    }
    text.find(&hit.secret)
        .is_some_and(|at| crate::web_audit::rules::secret::has_pem_body(&rest[at..]))
}

/// Срабатывание в DEX: запись, индекс строки, смещение.
struct DexHit {
    entry: String,
    index: u32,
    offset: u32,
    hit: secrets::Hit,
}

pub fn check(archive: &Archive, budget: &mut Budget) -> (RuleOutput, SecretStats) {
    let mut out = RuleOutput::default();
    let mut stats = SecretStats::default();
    let mut unreadable = 0usize;
    let mut capped = Vec::new();
    let mut dex_hits: Vec<DexHit> = Vec::new();
    let mut dex_seen = 0usize;
    for (index, entry) in archive.entries.iter().enumerate() {
        if is_root_dex(&entry.name) {
            dex_seen += 1;
            if dex_seen <= MAX_DEX_FILES {
                let mut ctx = DexContext {
                    out: &mut out,
                    stats: &mut stats,
                    hits: &mut dex_hits,
                    capped: &mut capped,
                };
                scan_dex(archive, index, &entry.name, budget, &mut ctx);
            }
            continue;
        }
        let lower = entry.name.to_ascii_lowercase();
        if [".dex", ".jar", ".zip", ".apk"]
            .iter()
            .any(|ext| lower.ends_with(ext))
        {
            stats.nested_code += 1;
            continue;
        }
        if out_of_scope(&entry.name) {
            stats.out_of_scope += 1;
            continue;
        }
        let data = match archive.read(index, budget) {
            Ok(data) => data,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let mut found = EntryHits::default();
        if is_axml(&data) {
            let Ok(doc) = axml::decode(&data, &axml::Limits::default()) else {
                unreadable += 1;
                continue;
            };
            stats.axml_entries += 1;
            let mut work: Vec<(&axml::Element, String)> =
                doc.root.iter().map(|e| (e, e.name.clone())).collect();
            while let Some((element, path)) = work.pop() {
                for a in &element.attributes {
                    let name = if a.is_android() {
                        format!("android:{}", a.name())
                    } else {
                        a.name().to_string()
                    };
                    let component = Some(format!("{path}@{name}"));
                    if let Value::String(s) = &a.value {
                        found.add(None, component.clone(), s, s);
                    }
                    if let Some(raw) = &a.raw_value
                        && a.value != Value::String(raw.clone())
                    {
                        found.add(None, component.clone(), raw, raw);
                    }
                }
                for child in &element.children {
                    work.push((child, format!("{path}/{}", child.name)));
                }
            }
        } else if data.iter().take(8 * 1024).any(|&b| b == 0) {
            stats.out_of_scope += 1;
            continue;
        } else {
            stats.text_entries += 1;
            let text = String::from_utf8_lossy(&data);
            let mut offset = 0;
            for (i, line) in text.split('\n').enumerate() {
                found.add(u32::try_from(i + 1).ok(), None, line, &text[offset..]);
                offset += line.len() + 1;
                if found.total > MAX_HITS_PER_ENTRY {
                    break;
                }
            }
        }
        if found.total > MAX_HITS_PER_ENTRY {
            capped.push(entry.name.clone());
        }
        for (line, component, hit) in found.hits {
            out.findings
                .push(finding(&entry.name, line, component, &hit));
        }
    }
    if dex_seen > MAX_DEX_FILES {
        out.partial.push(format!(
            "{dex_seen} classes*.dex files; only the first {MAX_DEX_FILES} were read"
        ));
    }
    out.findings.extend(dex_findings(dex_hits));
    if unreadable > 0 {
        out.partial.push(format!(
            "{unreadable} archive entr(ies) could not be read or decoded"
        ));
    }
    if let Some(first) = capped.first() {
        out.partial.push(format!(
            "more than {MAX_HITS_PER_ENTRY} matches in {} entr(ies) (e.g. {}); the rest was not analysed",
            capped.len(),
            ui::sanitize_line(first)
        ));
    }
    (out, stats)
}

struct DexContext<'a> {
    out: &'a mut RuleOutput,
    stats: &'a mut SecretStats,
    hits: &'a mut Vec<DexHit>,
    capped: &'a mut Vec<String>,
}

/// Пул строк одного `classesN.dex` → срабатывания (дедуп — позже, на весь APK).
fn scan_dex(
    archive: &Archive,
    index: usize,
    name: &str,
    budget: &mut Budget,
    ctx: &mut DexContext,
) {
    let clean = ui::sanitize_line(name);
    let data = match archive.read(index, budget) {
        Ok(data) => data,
        Err(e) => {
            ctx.out.partial.push(format!("{clean}: {}", e.describe()));
            return;
        }
    };
    let strings = match dex::read_strings(&data, &dex::Limits::default()) {
        Ok(strings) => strings,
        Err(e) => {
            ctx.out.partial.push(format!("{clean}: {}", e.describe()));
            return;
        }
    };
    ctx.stats.dex_entries += 1;
    if strings.skipped > 0 {
        ctx.out.partial.push(format!(
            "{clean}: {} string(s) could not be read",
            strings.skipped
        ));
    }
    ctx.stats
        .dex_notes
        .extend(strings.issues.iter().map(|i| format!("{clean}: {i}")));
    let mut total = 0usize;
    for s in &strings.strings {
        let mut offset = 0;
        for line in s.value.split('\n') {
            let rest = &s.value[offset..];
            offset += line.len() + 1;
            for hit in rules::scan_line(1, line) {
                total += 1;
                if total > MAX_HITS_PER_ENTRY {
                    ctx.capped.push(name.to_string());
                    return;
                }
                if is_real_key(&hit, line, rest) {
                    ctx.hits.push(DexHit {
                        entry: name.to_string(),
                        index: s.index,
                        offset: s.offset,
                        hit,
                    });
                }
            }
        }
    }
}

/// Одна находка на значение (по отпечатку) на весь APK; первое место — по порядку записей.
fn dex_findings(hits: Vec<DexHit>) -> Vec<ApkFinding> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<DexHit>> =
        std::collections::HashMap::new();
    for h in hits {
        let fp = secrets::fingerprint(&h.hit.secret);
        if !groups.contains_key(&fp) {
            order.push(fp.clone());
        }
        groups.entry(fp).or_default().push(h);
    }
    let mut findings = Vec::new();
    for fp in order {
        let Some(group) = groups.remove(&fp) else {
            continue;
        };
        let first = &group[0];
        let mut others: Vec<String> = group[1..]
            .iter()
            .map(|h| h.entry.clone())
            .filter(|e| *e != first.entry)
            .collect();
        others.dedup();
        let mut f = finding(
            &first.entry,
            None,
            Some(format!("string_ids[{}]", first.index)),
            &first.hit,
        );
        // Решение ADR-DEX: из DEX — не critical, а high (строка может быть ключом библиотеки).
        if f.severity == Severity::Critical {
            f.severity = Severity::High;
        }
        f.explanation.push_str(
            " The string comes from the DEX string pool, so it may belong to a bundled library \
             rather than to the app's own code; DEX bytecode is not analysed, so the class that \
             uses it is not known.",
        );
        if !others.is_empty() {
            f.explanation.push_str(&format!(
                " The same value is also in: {}.",
                ui::sanitize_line(&others.join(", "))
            ));
        }
        f.tags.push("source:dex".to_string());
        f.tags.push(format!("byte_offset:{}", first.offset));
        f.tags.extend(
            others
                .iter()
                .map(|o| format!("also_in:{}", ui::sanitize_line(o))),
        );
        findings.push(f);
    }
    findings
}

fn finding(
    entry: &str,
    line: Option<u32>,
    component: Option<String>,
    hit: &secrets::Hit,
) -> ApkFinding {
    let masked = secrets::mask(&hit.secret);
    let fingerprint = secrets::fingerprint(&hit.secret);
    let public_by_design = hit.rule.id == "google-api";
    let (title, severity, confidence, explanation) = if public_by_design {
        (
            "Google API key in the APK".to_string(),
            Severity::Info,
            Confidence::NeedsReview,
            "A Google API key (AIza…) is embedded. Firebase and Maps keys are meant to ship in \
             apps and are not secret by themselves; make sure the key is restricted to this app \
             (package name + signing certificate) and to the APIs it needs."
                .to_string(),
        )
    } else {
        (
            format!("{} embedded in the APK", hit.rule.name),
            Severity::Critical,
            Confidence::Potential,
            format!(
                "A value in the format of a {} is stored inside the APK. Anyone who downloads the app \
                 can unpack it and read the value. Potential: the format matches, but whether the key \
                 is real and active is not checked. If it is real: revoke it, then move the call that \
                 needs it to your server.",
                hit.rule.name
            ),
        )
    };
    let excerpt = match &component {
        Some(c) => format!("{} = {masked}", ui::sanitize_line(c)),
        None => masked.clone(),
    };
    ApkFinding {
        id: finding_id(SECRET_ID, entry, &fingerprint),
        rule_id: SECRET_ID,
        title,
        category: "secret_exposure",
        severity,
        confidence,
        location: ApkLocation {
            archive_entry: Some(entry.to_string()),
            component,
            line,
        },
        evidence: Evidence {
            redacted_excerpt: Some(ui::sanitize_line(&excerpt)),
            fingerprint: Some(fingerprint),
        },
        explanation,
        remediation_id: Some(format!(
            "{SECRET_ID}:{}",
            if public_by_design {
                "restrict-key"
            } else {
                "revoke-and-move-to-server"
            }
        )),
        references: vec!["https://cwe.mitre.org/data/definitions/798.html"],
        cwe_ids: vec!["CWE-798"],
        tags: vec!["apk".into(), format!("key:{}", hit.rule.id)],
    }
}
