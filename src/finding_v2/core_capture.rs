//! Opt-in capture for full Core V2 export. Calls the same engines as
//! combined::scan_project, injecting only observers into existing transports.
//! Existing options (including dependency-only --offline) are preserved.
use super::{
    ModelError,
    core_network::{NetworkLog, ObservedHttp, ObservedVerification},
    core_reports::{CoreContext, TargetKind},
};
use crate::{
    baseline::Hidden,
    combined::ProjectReport,
    deps::{
        self,
        osv::{Http, OsvOptions},
    },
    secrets::{
        scan::{self, ScanOptions},
        verify,
    },
};
use std::path::Path;

pub fn scan_project_observed(
    root: &Path,
    options: &ScanOptions,
    osv: &OsvOptions,
    http: &dyn Http,
    verification: &dyn verify::Transport,
    sleep: &(dyn Fn(u64) + Sync),
) -> Result<(ProjectReport, CoreContext), ModelError> {
    let log = NetworkLog::default();
    let secrets = scan::scan_with(
        root,
        options,
        &ObservedVerification {
            inner: verification,
            log: &log,
        },
    )
    .map_err(|_| ModelError("core_secret_scan_failed"))?;
    let directory = root.is_dir();
    let deps = if directory {
        Some(
            deps::scan::scan(
                root,
                osv,
                &ObservedHttp {
                    inner: http,
                    log: &log,
                },
                sleep,
            )
            .map_err(|_| ModelError("core_dependency_scan_failed"))?,
        )
    } else {
        None
    };
    let has_workflows = root.join(".github").join("workflows").is_dir()
        || ["action.yml", "action.yaml"]
            .iter()
            .any(|name| root.join(name).is_file());
    let workflows = has_workflows.then(|| crate::workflows::check(root));
    let context = CoreContext {
        target: if directory {
            TargetKind::Directory
        } else {
            TargetKind::File
        },
        verification_requested: Some(options.verify),
        network: Some(log.snapshot()),
        baseline_hidden: Some(Hidden::default()),
    };
    Ok((
        ProjectReport {
            secrets,
            deps,
            workflows,
        },
        context,
    ))
}
