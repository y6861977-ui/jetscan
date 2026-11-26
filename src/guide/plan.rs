//! The guide for the plan on this machine: a "Your plan" box under the title, and the
//! chapters the plan does not unlock shortened to a few lines.
//!
//! The plan comes from the same decision the Pro gate uses (`license::entitlement_of`, with
//! the trial counter read from `JETSCAN_HOME`), so the guide never shows a chapter as
//! unlocked when the command itself would refuse. Reading the key and the counter is
//! read-only and local; nothing is sent.
//!
//! Chapters are marked in the guide Markdown with HTML comments, which the plain renderer
//! (and GitHub) skip:
//!
//! ```text
//! <!-- jetscan:plan web -->
//! ### 6.1 Website source code: `jetscan web source`
//! ...
//! <!-- jetscan:end -->
//! ```
//!
//! The words are `ProFeature::token`s (`web`, `apk`, `android`, `ios`, `url`, `ci`); a chapter
//! is shown in full if the plan unlocks any of them. Otherwise only its first heading stays,
//! followed by a short note on what it does and what unlocks it. Regions do not nest.

use super::Lang;
use crate::license::{self, Area, Checked, Entitlement, Plan, ProFeature, Status};

const SITE: &str = crate::edition::SITE;
const START: &str = "<!-- jetscan:plan ";
const END: &str = "<!-- jetscan:end -->";

/// What the key on this machine gives, as far as the guide is concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YourPlan {
    kind: Kind,
    /// What this program runs with the key now (the gate's answer, limited to this build).
    unlocked: Vec<ProFeature>,
    /// The key unlocks Pro audits, but this is the free build, which cannot run them.
    pro_elsewhere: bool,
    /// The key's expiry date (days since 1970-01-01), and whether its grace period runs.
    expires: Option<(i64, bool)>,
    /// Trial: (scans left, scans in the key).
    trial: Option<(u32, u32)>,
    note: Option<Note>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Free,
    Trial(Area),
    Audit,
    Pro,
    Teams,
}

/// Why a key on this machine does not count.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Note {
    /// The plan's name and the expiry date.
    Expired(Plan, i64),
    /// A key was found but not accepted.
    Invalid,
}

impl YourPlan {
    /// The plan for the checked key, `trial_used` trial scans done on this machine
    /// (`license::trial_used_in`), in this build (`pro_build`: jetscan Pro).
    pub fn of(checked: &Checked, trial_used: u32, pro_build: bool) -> YourPlan {
        let allowed: Vec<ProFeature> = ProFeature::ALL
            .into_iter()
            .filter(|f| license::entitlement_of(*f, checked, trial_used).allowed())
            .collect();
        let mut plan = YourPlan {
            kind: Kind::Free,
            unlocked: allowed
                .iter()
                .copied()
                .filter(|f| pro_build || *f == ProFeature::CiReports)
                .collect(),
            pro_elsewhere: !pro_build && allowed.iter().any(|f| *f != ProFeature::CiReports),
            expires: None,
            trial: None,
            note: None,
        };
        let (license, grace) = match &checked.status {
            Status::Free => return plan,
            Status::Invalid(_) => {
                plan.note = Some(Note::Invalid);
                return plan;
            }
            Status::Expired { license, .. } => {
                if let Some(c) = &checked.claims {
                    plan.note = Some(Note::Expired(c.plan, license.expires));
                }
                return plan;
            }
            Status::Active { license, .. } => (license, false),
            Status::Grace { license, .. } => (license, true),
        };
        let Some(c) = &checked.claims else {
            plan.note = Some(Note::Invalid);
            return plan;
        };
        plan.kind = match c.plan {
            Plan::Teams => Kind::Teams,
            Plan::Pro => Kind::Pro,
            Plan::Audit => Kind::Audit,
            Plan::Trial => Kind::Trial(c.area.unwrap_or(Area::Web)),
        };
        plan.expires = Some((license.expires, grace));
        if c.plan == Plan::Trial {
            let total = c.scans.unwrap_or(0);
            let left = ProFeature::ALL
                .into_iter()
                .find_map(|f| match license::entitlement_of(f, checked, trial_used) {
                    Entitlement::Trial { remaining, .. } => Some(remaining),
                    _ => None,
                })
                .unwrap_or(0);
            plan.trial = Some((left, total));
        }
        plan
    }

    /// Whether the guide shows chapters about `feature` in full.
    pub fn unlocks(&self, feature: ProFeature) -> bool {
        self.unlocked.contains(&feature)
    }

    /// The plan's name: Free, Trial (web), One-time audit, Pro, Teams.
    pub fn name(&self, lang: Lang) -> String {
        let ru = lang == Lang::Ru;
        match self.kind {
            Kind::Free if ru => "Бесплатный".to_string(),
            Kind::Free => "Free".to_string(),
            Kind::Trial(area) if ru => format!("Пробный ({})", area.as_str()),
            Kind::Trial(area) => format!("Trial ({})", area.as_str()),
            Kind::Audit if ru => "Разовый аудит".to_string(),
            Kind::Audit => "One-time audit".to_string(),
            Kind::Pro => "Pro".to_string(),
            Kind::Teams => "Teams".to_string(),
        }
    }

    /// One line for the terminal: `Trial: web, 1 scan left`, `Pro, until 2027-01-31`, `Free`.
    pub fn summary(&self) -> String {
        let mut s = match self.kind {
            Kind::Trial(area) => format!("Trial: {}", area.as_str()),
            _ => self.name(Lang::En),
        };
        if let Some((left, _)) = self.trial {
            s.push_str(&format!(
                ", {} left",
                crate::ui::plural(left as usize, "scan", "scans")
            ));
        } else if let Some((date, grace)) = self.expires {
            let word = if grace { "expired on" } else { "until" };
            s.push_str(&format!(", {word} {}", license::format_date(date)));
        }
        match &self.note {
            Some(Note::Expired(..)) => s.push_str("; the key on this machine has expired"),
            Some(Note::Invalid) => s.push_str("; the key on this machine was not accepted"),
            None => {}
        }
        if self.pro_elsewhere {
            s.push_str("; Pro audits need the jetscan Pro build");
        }
        s
    }

    /// The "Your plan" box, as Markdown (a quote block).
    fn render_box(&self, lang: Lang) -> String {
        let ru = lang == Lang::Ru;
        let mut head = if ru {
            format!("**Ваш тариф: {}**", self.name(lang))
        } else {
            format!("**Your plan: {}**", self.name(lang))
        };
        if let Some((date, grace)) = self.expires {
            let date = license::format_date(date);
            head.push_str(&match (ru, grace) {
                (true, false) => format!(" · действует до {date}"),
                (false, false) => format!(" · valid until {date}"),
                (true, true) => {
                    format!(" · срок вышел {date}, платное работает ещё несколько дней")
                }
                (false, true) => {
                    format!(" · expired on {date}; paid features keep working a few more days")
                }
            });
        }
        if let Some((left, total)) = self.trial {
            head.push_str(&if ru {
                format!(" · осталось пробных сканов: {left} из {total}")
            } else {
                format!(" · {left} of {total} trial scans left")
            });
        }
        let mut paragraphs = vec![head];
        match &self.note {
            Some(Note::Expired(plan, date)) => paragraphs.push(if ru {
                format!(
                    "Ключ на этом компьютере ({}) истёк {}: платные функции выключены, \
                     бесплатные проверки работают.",
                    plan.title(),
                    license::format_date(*date)
                )
            } else {
                format!(
                    "The key on this computer ({}) expired on {}: the paid features are off, \
                     the free checks keep working.",
                    plan.title(),
                    license::format_date(*date)
                )
            }),
            Some(Note::Invalid) => paragraphs.push(if ru {
                "На этом компьютере есть ключ, но он не принят (`jetscan license` скажет почему)."
                    .to_string()
            } else {
                "There is a key on this computer, but it was not accepted (`jetscan license` \
                 says why)."
                    .to_string()
            }),
            None => {}
        }
        let mut names: Vec<&str> = vec![if ru {
            "все бесплатные проверки"
        } else {
            "every free check"
        }];
        names.extend(self.unlocked.iter().map(|f| label(*f, lang)));
        paragraphs.push(if ru {
            format!("Открыто: {}.", names.join(", "))
        } else {
            format!("Unlocks: {}.", names.join(", "))
        });
        if self.pro_elsewhere {
            paragraphs.push(if ru {
                format!(
                    "Ваш ключ открывает аудиты jetscan Pro, но это бесплатная сборка: скачайте \
                     jetscan Pro в личном кабинете на <{SITE}>."
                )
            } else {
                format!(
                    "Your key unlocks the jetscan Pro audits, but this is the free build: \
                     download jetscan Pro from your account at <{SITE}> to use them."
                )
            });
        }
        paragraphs.push(if ru {
            format!(
                "Главы, которые открывает ваш тариф, показаны полностью, остальные — коротко. \
                 Другой тариф или продление: <{SITE}>."
            )
        } else {
            format!(
                "Chapters your plan unlocks are shown in full, the others in a few lines. \
                 Upgrade or renew: <{SITE}>."
            )
        });
        let lines: Vec<String> = paragraphs.iter().map(|p| format!("> {p}")).collect();
        lines.join("\n>\n")
    }
}

/// What a feature is, for the "Unlocks" line.
fn label(feature: ProFeature, lang: Lang) -> &'static str {
    let ru = lang == Lang::Ru;
    match feature {
        ProFeature::WebSource if ru => "аудит исходников сайта (`web source`)",
        ProFeature::WebSource => "the website source audit (`web source`)",
        ProFeature::Apk if ru => "аудит APK (`apk`)",
        ProFeature::Apk => "the APK audit (`apk`)",
        ProFeature::AndroidSource if ru => "аудит исходников Android (`android`)",
        ProFeature::AndroidSource => "the Android source audit (`android`)",
        ProFeature::IosSource if ru => "аудит исходников iOS (`ios`)",
        ProFeature::IosSource => "the iOS source audit (`ios`)",
        ProFeature::UrlAudit if ru => "проверка живого сайта (`url`)",
        ProFeature::UrlAudit => "the live website check (`url`)",
        ProFeature::CiReports if ru => "CI-отчёты (`--sarif`, `--sbom`, `--baseline`)",
        ProFeature::CiReports => "the CI reports (`--sarif`, `--sbom`, `--baseline`)",
    }
}

/// What a feature does, in one sentence, for the note of a shortened chapter.
fn what(feature: ProFeature, lang: Lang) -> &'static str {
    if lang == Lang::En {
        return feature.what();
    }
    match feature {
        ProFeature::WebSource => "Статический аудит безопасности исходников веб-проекта",
        ProFeature::Apk => "Статический аудит безопасности Android APK",
        ProFeature::AndroidSource => "Статический аудит исходников Android-приложения",
        ProFeature::IosSource => "Статический аудит исходников iOS-приложения",
        ProFeature::UrlAudit => "Проверка безопасности опубликованного сайта по адресу",
        ProFeature::CiReports => "CI-отчёты (--sarif, --sbom, --baseline)",
    }
}

/// The note that replaces a chapter about `features`.
fn stub(features: &[ProFeature], lang: Lang) -> String {
    let ru = lang == Lang::Ru;
    let lead = if ru {
        "**Не входит в ваш тариф.**"
    } else {
        "**Not in your plan.**"
    };
    let body = match features {
        [ProFeature::CiReports] if ru => format!(
            "CI-отчёты (`--sarif`, `--sbom`, `--baseline`) входят в jetscan Teams. Ключ: \
             <{SITE}>; он проверяется на этом компьютере, ничего не отправляется."
        ),
        [ProFeature::CiReports] => format!(
            "The CI reports (`--sarif`, `--sbom`, `--baseline`) are part of jetscan Teams. Get a \
             key at <{SITE}>; it is checked on this computer, nothing is sent."
        ),
        [f] => match f.area() {
            Some(area) if ru => format!(
                "{}. Нужен jetscan Pro, разовый аудит или бесплатная проба для `{}`: <{SITE}>.",
                what(*f, lang),
                area.as_str()
            ),
            Some(area) => format!(
                "{}. It needs jetscan Pro, a one-time audit or a free trial for `{}`: <{SITE}>.",
                what(*f, lang),
                area.as_str()
            ),
            None if ru => format!(
                "{}. Нужен jetscan Pro или разовый аудит (в бесплатную пробу не входит): <{SITE}>.",
                what(*f, lang)
            ),
            None => format!(
                "{}. It needs jetscan Pro or a one-time audit (the free trial does not include \
                 it): <{SITE}>.",
                what(*f, lang)
            ),
        },
        _ if ru => format!(
            "Эта часть — об аудитах jetscan Pro. Нужен jetscan Pro, разовый аудит или \
             бесплатная проба: <{SITE}>."
        ),
        _ => format!(
            "This part is about the jetscan Pro audits. It needs jetscan Pro, a one-time audit \
             or a free trial: <{SITE}>."
        ),
    };
    format!("> {lead} {body}")
}

/// The features of a `<!-- jetscan:plan ... -->` line; `None` for any other line. Unknown
/// words are dropped (they never unlock anything).
fn region_start(line: &str) -> Option<Vec<ProFeature>> {
    let words = line.trim().strip_prefix(START)?.strip_suffix("-->")?;
    Some(
        words
            .split_whitespace()
            .filter_map(|w| ProFeature::ALL.into_iter().find(|f| f.token() == w))
            .collect(),
    )
}

/// Checks the markers of a guide: every region is closed, none nests, every word is known.
pub fn check_markers(md: &str) -> Result<usize, String> {
    let mut open = false;
    let mut regions = 0;
    for (i, line) in md.lines().enumerate() {
        let t = line.trim();
        if t.starts_with(START) {
            let words = t.strip_prefix(START).and_then(|w| w.strip_suffix("-->"));
            let known = words.is_some_and(|w| {
                let w: Vec<&str> = w.split_whitespace().collect();
                !w.is_empty()
                    && w.iter()
                        .all(|w| ProFeature::ALL.iter().any(|f| f.token() == *w))
            });
            if open || !known {
                return Err(format!("line {}: bad or nested marker: {t}", i + 1));
            }
            open = true;
            regions += 1;
        } else if t == END {
            if !open {
                return Err(format!("line {}: an end marker without a start", i + 1));
            }
            open = false;
        }
    }
    if open {
        return Err("a region is not closed".into());
    }
    Ok(regions)
}

/// The guide Markdown for `plan`: the box after the `# ` title, and every region the plan does
/// not unlock replaced by its first heading and a short note. The marker lines are dropped.
pub fn tailor(md: &str, lang: Lang, plan: &YourPlan) -> String {
    let md = md.replace("\r\n", "\n");
    let mut out = String::with_capacity(md.len());
    let mut boxed = false;
    // Inside a hidden region: its features, and whether its note is written.
    let mut hidden: Option<(Vec<ProFeature>, bool)> = None;
    for line in md.lines() {
        let t = line.trim();
        if let Some(features) = region_start(t) {
            if !features.iter().any(|f| plan.unlocks(*f)) {
                hidden = Some((features, false));
            }
            continue;
        }
        if t == END {
            if let Some((features, false)) = hidden.take() {
                out.push_str(&stub(&features, lang));
                out.push_str("\n\n");
            }
            continue;
        }
        if let Some((features, done)) = &mut hidden {
            if !*done && !t.is_empty() {
                if t.starts_with('#') {
                    out.push_str(line);
                    out.push_str("\n\n");
                }
                out.push_str(&stub(features, lang));
                out.push_str("\n\n");
                *done = true;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
        if !boxed && line.starts_with("# ") {
            out.push('\n');
            out.push_str(&plan.render_box(lang));
            out.push('\n');
            boxed = true;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::{Claims, License, ed25519, issue_with, today, verify};

    /// A throwaway signing secret (the license tests' fixture), never a real key.
    const SEED: [u8; 32] = [42; 32];

    fn checked(claims: Claims, expires_in: i64) -> Checked {
        let teams = claims.plan == Plan::Teams;
        let l = License {
            id: format!("JS-GUIDE-{}", claims.plan.as_str()),
            org: if teams { "Acme" } else { "personal" }.into(),
            plan: claims.plan.as_str().into(),
            seats: if teams { 20 } else { 1 },
            issued: today() - 30,
            expires: today() + expires_in,
        };
        let key = issue_with(&l, &claims, &SEED).unwrap();
        verify(&key, &[ed25519::public_key(&SEED)], today())
    }

    fn plan(claims: Claims, pro_build: bool) -> YourPlan {
        YourPlan::of(&checked(claims, 100), 0, pro_build)
    }

    const MD: &str = "# Guide\n\nintro\n\n## 1. Free\n\nfree text\n\n\
        <!-- jetscan:plan web -->\n### 6.1 Web\n\nweb text\n<!-- jetscan:end -->\n\n\
        <!-- jetscan:plan url -->\n## 7. Url\n\nurl text\n\n### 7.1 Sub\n\nsub text\n<!-- jetscan:end -->\n\n\
        <!-- jetscan:plan web apk android ios url -->\n### 6.6 Menu\n\nmenu text\n<!-- jetscan:end -->\n\n\
        <!-- jetscan:plan ci -->\n### Teams\n\nci text\n<!-- jetscan:end -->\n\n## 9. End\n\nend text\n";

    /// Which of the region texts stay in the tailored guide.
    fn shown(p: &YourPlan) -> Vec<&'static str> {
        let text = tailor(MD, Lang::En, p);
        assert!(!text.contains("jetscan:"), "markers are dropped: {text}");
        assert!(
            text.contains("free text") && text.contains("end text"),
            "{text}"
        );
        for heading in ["### 6.1 Web", "## 7. Url", "### 6.6 Menu", "### Teams"] {
            assert!(text.contains(heading), "headings stay: {text}");
        }
        ["web text", "url text", "sub text", "menu text", "ci text"]
            .into_iter()
            .filter(|t| text.contains(t))
            .collect()
    }

    #[test]
    fn each_plan_sees_its_chapters() {
        assert_eq!(
            shown(&YourPlan::of(&Checked::free(), 0, true)),
            Vec::<&str>::new()
        );
        assert_eq!(
            shown(&plan(Claims::trial(Area::Web, 2), true)),
            ["web text", "menu text"]
        );
        assert_eq!(
            shown(&plan(Claims::trial(Area::Apk, 2), true)),
            ["menu text"]
        );
        let all_pro = ["web text", "url text", "sub text", "menu text"];
        assert_eq!(shown(&plan(Claims::plan(Plan::Pro), true)), all_pro);
        assert_eq!(shown(&plan(Claims::plan(Plan::Audit), true)), all_pro);
        let mut everything = all_pro.to_vec();
        everything.push("ci text");
        assert_eq!(shown(&plan(Claims::plan(Plan::Teams), true)), everything);
        // The free build runs no Pro audit, whatever the key; a Teams key keeps the CI reports.
        assert_eq!(
            shown(&plan(Claims::plan(Plan::Pro), false)),
            Vec::<&str>::new()
        );
        assert_eq!(shown(&plan(Claims::plan(Plan::Teams), false)), ["ci text"]);
    }

    #[test]
    fn hidden_chapters_say_what_unlocks_them() {
        let text = tailor(MD, Lang::En, &plan(Claims::trial(Area::Web, 2), true));
        assert!(
            text.contains(
                "A security audit of a live web address. It needs jetscan Pro or a \
                           one-time audit (the free trial does not include it)"
            ),
            "{text}"
        );
        assert!(text.contains("are part of jetscan Teams"), "{text}");
        assert!(
            !text.contains("### 7.1 Sub"),
            "only the first heading stays: {text}"
        );
        let free = tailor(MD, Lang::En, &YourPlan::of(&Checked::free(), 0, true));
        assert!(
            free.contains("a free trial for `web`: <https://jetscan.jet.kim>"),
            "{free}"
        );
        assert!(free.contains("This part is about the jetscan Pro audits"));
        let ru = tailor(MD, Lang::Ru, &YourPlan::of(&Checked::free(), 0, true));
        assert!(ru.contains("**Не входит в ваш тариф.**"), "{ru}");
        assert!(ru.contains("**Ваш тариф: Бесплатный**"), "{ru}");
    }

    #[test]
    fn the_box_names_the_plan_dates_and_trial_scans() {
        let free = YourPlan::of(&Checked::free(), 0, true);
        assert_eq!(free.summary(), "Free");
        let text = tailor(MD, Lang::En, &free);
        let after_title = text.split("# Guide\n\n").nth(1).unwrap();
        assert!(after_title.starts_with("> **Your plan: Free**"), "{text}");
        assert!(text.contains("> Unlocks: every free check."), "{text}");
        assert!(text.contains("Upgrade or renew: <https://jetscan.jet.kim>."));

        let trial = checked(Claims::trial(Area::Web, 2), 10);
        let p = YourPlan::of(&trial, 1, true);
        assert_eq!(p.summary(), "Trial: web, 1 scan left");
        let text = tailor(MD, Lang::En, &p);
        assert!(
            text.contains("**Your plan: Trial (web)** · valid until "),
            "{text}"
        );
        assert!(text.contains(" · 1 of 2 trial scans left"), "{text}");
        assert!(
            text.contains("the website source audit (`web source`)"),
            "{text}"
        );
        // Used up: the gate refuses the scan, so the chapter is short too.
        let used_up = YourPlan::of(&trial, 2, true);
        assert_eq!(used_up.summary(), "Trial: web, 0 scans left");
        assert!(!used_up.unlocks(ProFeature::WebSource));

        let teams = plan(Claims::plan(Plan::Teams), true);
        let date = license::format_date(today() + 100);
        assert_eq!(teams.summary(), format!("Teams, until {date}"));
        assert!(tailor(MD, Lang::En, &teams).contains("the CI reports (`--sarif`"));

        let elsewhere = plan(Claims::trial(Area::Ios, 2), false);
        assert!(
            elsewhere
                .summary()
                .ends_with("; Pro audits need the jetscan Pro build")
        );
        assert!(
            tailor(MD, Lang::En, &elsewhere)
                .contains("download jetscan Pro from your account at <https://jetscan.jet.kim>")
        );
    }

    #[test]
    fn expired_and_rejected_keys_count_as_free() {
        let expired = YourPlan::of(&checked(Claims::plan(Plan::Audit), -3), 0, true);
        assert_eq!(expired.name(Lang::En), "Free");
        assert!(expired.unlocked.is_empty());
        assert!(expired.summary().contains("has expired"));
        assert!(tailor(MD, Lang::En, &expired).contains("expired on"));
        // Pro in its grace period still works, and says so.
        let grace = YourPlan::of(&checked(Claims::plan(Plan::Pro), -3), 0, true);
        assert!(grace.unlocks(ProFeature::UrlAudit));
        assert!(grace.summary().starts_with("Pro, expired on "));
        let invalid = Checked {
            status: Status::Invalid("bad".into()),
            claims: None,
        };
        let p = YourPlan::of(&invalid, 0, true);
        assert_eq!(p.name(Lang::En), "Free");
        assert!(tailor(MD, Lang::En, &p).contains("was not accepted"));
    }

    #[test]
    fn markers_are_checked() {
        assert_eq!(check_markers(MD), Ok(4));
        for bad in [
            "<!-- jetscan:plan web -->\n<!-- jetscan:plan apk -->\n",
            "<!-- jetscan:end -->\n",
            "<!-- jetscan:plan web -->\n",
            "<!-- jetscan:plan nonsense -->\n<!-- jetscan:end -->\n",
        ] {
            assert!(check_markers(bad).is_err(), "{bad}");
        }
    }

    /// The guide built into this program, for each plan.
    #[test]
    fn the_built_in_guide_follows_the_plan() {
        for lang in [Lang::En, Lang::Ru] {
            let md = super::super::markdown(lang);
            assert!(check_markers(md).unwrap() > 0, "{lang:?}");
            let free = tailor(
                md,
                lang,
                &YourPlan::of(&Checked::free(), 0, cfg!(feature = "pro")),
            );
            let teams = tailor(
                md,
                lang,
                &plan(Claims::plan(Plan::Teams), cfg!(feature = "pro")),
            );
            // The Teams CI chapter: only for Teams.
            assert!(!free.contains("upload-sarif"), "{lang:?}");
            assert!(teams.contains("upload-sarif"), "{lang:?}");
            if cfg!(feature = "pro") {
                let web = tailor(md, lang, &plan(Claims::trial(Area::Web, 2), true));
                let pro = tailor(md, lang, &plan(Claims::plan(Plan::Pro), true));
                for (text, web_rules, android_rules, url_rules, ci) in [
                    (&free, false, false, false, false),
                    (&web, true, false, false, false),
                    (&pro, true, true, true, false),
                    (&teams, true, true, true, true),
                ] {
                    assert_eq!(text.contains("WEB-FIREBASE-010"), web_rules, "{lang:?}");
                    assert_eq!(text.contains("ANDROID-KEYSTORE-009"), android_rules);
                    assert_eq!(text.contains("IOS-PASTEBOARD-012"), android_rules);
                    assert_eq!(text.contains("URL-SECURITYTXT-013"), url_rules);
                    assert_eq!(text.contains("_jetscan-verify."), url_rules);
                    assert_eq!(text.contains("upload-sarif"), ci);
                }
            }
        }
    }
}
