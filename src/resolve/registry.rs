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
        "WEB-SECRET-001" | "WEB-ENV-002" | "WEB-SUPABASE-005" | "APK-SECRET-006" => {
            Resolver::Credential
        }
        "WEB-XSS-003" | "WEB-AUTH-004" | "WEB-CORS-006" | "WEB-DEBUG-007" | "WEB-RLS-009"
        | "WEB-FIREBASE-010" => Resolver::WebReview,
        "APK-EXPORT-001" | "APK-DEBUG-002" | "APK-NET-003" | "APK-BACKUP-004" | "APK-PERMS-005" => {
            Resolver::ApkReview
        }
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
}
