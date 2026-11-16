//! Resolver selection is a closed allowlist. Prefix matches never enable patches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolver {
    GuidanceOnly,
    Credential,
    WorkflowExpression,
    WorkflowReview,
    DependencyAdvice,
    WebReview,
    ApkReview,
    IosReview,
}
impl Resolver {
    pub fn guidance(self) -> &'static str {
        match self {
            Self::GuidanceOnly => {
                "No reviewed resolver exists for this rule. Review the finding and its documentation manually."
            }
            Self::Credential => {
                "Review whether the credential was exposed. Revoke and rotate it with the provider, replace references and review Git history. Removing text does not revoke a credential; JetScan never rotates keys automatically."
            }
            Self::WorkflowExpression => {
                "Pass untrusted GitHub event data through a step environment variable and quote the shell variable. Only an exact reviewed workflow recipe can be patched; other syntax needs manual review."
            }
            Self::WorkflowReview => {
                "Review workflow permissions, trusted refs and action pins manually. Required capabilities cannot be inferred; write-all is never automatically reduced."
            }
            Self::DependencyAdvice => {
                "Review the existing dependency upgrade advice and compatibility implications manually. No package manager, build, script or network command is executed."
            }
            Self::WebReview => {
                "Review the source boundary and application data flow manually. Static evidence does not prove exploitation or authorization correctness."
            }
            Self::ApkReview => {
                "Change owned Android source or build configuration and rebuild separately. JetScan does not patch or execute an APK."
            }
            Self::IosReview => {
                "Change the Info.plist, entitlements, build settings or the flagged code in the Xcode project, then rebuild and re-run jetscan ios. JetScan does not edit Xcode projects, plists or source code automatically."
            }
        }
    }
}
pub fn lookup(rule_id: &str) -> Resolver {
    match rule_id {
        "gha-script-injection" => Resolver::WorkflowExpression,
        "gha-write-all-permissions"
        | "gha-pwn-request"
        | "gha-unpinned-action"
        | "gha-insecure-commands" => Resolver::WorkflowReview,
        "core-dependency" => Resolver::DependencyAdvice,
        "WEB-SECRET-001"
        | "WEB-ENV-002"
        | "WEB-SUPABASE-005"
        | "APK-SECRET-006"
        | "ANDROID-SECRET-006"
        | "ANDROID-SIGNING-008"
        | "ANDROID-KEYSTORE-009"
        | "IOS-SECRET-004"
        | "IOS-SIGNING-005" => Resolver::Credential,
        "WEB-XSS-003" | "WEB-AUTH-004" | "WEB-CORS-006" | "WEB-DEBUG-007" | "WEB-RLS-009"
        | "WEB-FIREBASE-010" => Resolver::WebReview,
        "APK-EXPORT-001" | "APK-DEBUG-002" | "APK-NET-003" | "APK-BACKUP-004" | "APK-PERMS-005" => {
            Resolver::ApkReview
        }
        // Android source audit: the "change the source / build config and rebuild" guidance.
        "ANDROID-EXPORT-001"
        | "ANDROID-DEBUG-002"
        | "ANDROID-NET-003"
        | "ANDROID-BACKUP-004"
        | "ANDROID-PERMS-005"
        | "ANDROID-MINIFY-007"
        | "ANDROID-WEBVIEW-010"
        | "ANDROID-TLS-011"
        | "ANDROID-CRYPTO-012"
        | "ANDROID-STORAGE-013"
        | "ANDROID-LOG-014" => Resolver::ApkReview,
        // iOS source audit: change the plist / entitlements / build settings / code in Xcode.
        "IOS-ATS-001"
        | "IOS-URLSCHEME-002"
        | "IOS-ENTITLEMENTS-003"
        | "IOS-STORAGE-006"
        | "IOS-KEYCHAIN-007"
        | "IOS-TLS-008"
        | "IOS-WEBVIEW-009"
        | "IOS-CRYPTO-010"
        | "IOS-LOG-011"
        | "IOS-PASTEBOARD-012" => Resolver::IosReview,
        id if crate::secrets::rules::all().iter().any(|r| r.info.id == id) => Resolver::Credential,
        _ => Resolver::GuidanceOnly,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_and_spoofed_rules_remain_guidance_only() {
        for id in [
            "",
            "gha-script-injection;run",
            "GHA-SCRIPT-INJECTION",
            "WEB-SECRET-999",
            "new-rule",
        ] {
            assert_eq!(lookup(id), Resolver::GuidanceOnly);
        }
        assert_eq!(lookup("gha-script-injection"), Resolver::WorkflowExpression);
        assert_eq!(lookup("WEB-SECRET-001"), Resolver::Credential);
        assert_eq!(lookup("core-dependency"), Resolver::DependencyAdvice);
        for rule in crate::secrets::rules::all() {
            assert_eq!(lookup(rule.info.id), Resolver::Credential);
        }
    }

    #[test]
    fn every_android_source_rule_has_a_guidance_resolver() {
        use crate::android_audit::rules as a;
        for id in [a::SECRET_ID, a::SIGNING_ID, a::KEYSTORE_ID] {
            assert_eq!(lookup(id), Resolver::Credential, "{id}");
        }
        let review = [
            a::EXPORT_ID,
            a::DEBUG_ID,
            a::NET_ID,
            a::BACKUP_ID,
            a::PERMS_ID,
            a::MINIFY_ID,
            a::WEBVIEW_ID,
            a::TLS_ID,
            a::CRYPTO_ID,
            a::STORAGE_ID,
            a::LOG_ID,
        ];
        for id in review {
            assert_eq!(lookup(id), Resolver::ApkReview, "{id}");
        }
        // A new ANDROID-* rule must get a resolver here, never fall to GuidanceOnly.
        assert_eq!(a::ALL.len(), 3 + review.len());
        for id in a::ALL {
            assert_ne!(lookup(id), Resolver::GuidanceOnly, "{id}");
        }
        // Case and suffix spoofs stay guidance-only.
        for id in ["android-tls-011", "ANDROID-TLS-011 ", "ANDROID-TLS-999"] {
            assert_eq!(lookup(id), Resolver::GuidanceOnly, "{id:?}");
        }
    }

    #[test]
    fn every_ios_source_rule_has_a_guidance_resolver() {
        use crate::ios_audit::rules as i;
        for id in [i::SECRET_ID, i::SIGNING_ID] {
            assert_eq!(lookup(id), Resolver::Credential, "{id}");
        }
        let review = [
            i::ATS_ID,
            i::URLSCHEME_ID,
            i::ENTITLEMENTS_ID,
            i::STORAGE_ID,
            i::KEYCHAIN_ID,
            i::TLS_ID,
            i::WEBVIEW_ID,
            i::CRYPTO_ID,
            i::LOG_ID,
            i::PASTEBOARD_ID,
        ];
        for id in review {
            assert_eq!(lookup(id), Resolver::IosReview, "{id}");
        }
        // A new IOS-* rule must get a resolver here, never fall to GuidanceOnly.
        assert_eq!(i::ALL.len(), 2 + review.len());
        for id in i::ALL {
            assert_ne!(lookup(id), Resolver::GuidanceOnly, "{id}");
        }
        let text = Resolver::IosReview.guidance();
        assert!(text.contains("Xcode") && !text.contains("APK"), "{text}");
        // Case and suffix spoofs stay guidance-only.
        for id in ["ios-tls-008", "IOS-TLS-008 ", "IOS-TLS-999"] {
            assert_eq!(lookup(id), Resolver::GuidanceOnly, "{id:?}");
        }
    }
}
