use super::*;
use crate::{
    finding_v2::{RedactionPolicy, RemediationState},
    json::{self, Json},
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

/// Closed set of deterministic transformations. No executable command or raw diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipe {
    /// Untrusted `${{ github.event... }}` in a bash/sh `run:` -> step `env:`
    /// variable used as `"${NAME}"` (see `recipes.rs` for the exact subset).
    WorkflowRunEnv,
}
impl Recipe {
    pub fn id(self) -> &'static str {
        match self {
            Self::WorkflowRunEnv => "gha-run-env-v1",
        }
    }
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "gha-run-env-v1" => Some(Self::WorkflowRunEnv),
            _ => None,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum Step {
    Explain {
        description: String,
    },
    ManualAction {
        description: String,
    },
    /// The new bytes are never stored: apply recomputes them from the file
    /// (which must hash to `expected_old_hash`) and the recipe, and refuses
    /// unless they hash to `expected_new_hash`.
    FilePatch {
        description: String,
        file_path: String,
        expected_old_hash: String,
        expected_new_hash: String,
        recipe: Recipe,
    },
}
impl fmt::Debug for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Step { <redacted> }")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePrecondition {
    pub file_path: String,
    pub expected_sha256: String,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvePlan {
    pub(crate) schema_version: u32,
    pub(crate) plan_id: String,
    pub(crate) finding_ids: Vec<String>,
    pub(crate) project_root: PathBuf,
    pub(crate) plan_status: RemediationState,
    pub(crate) preconditions: Vec<FilePrecondition>,
    pub(crate) steps: Vec<Step>,
    pub(crate) verification_rule_ids: Vec<String>,
    pub(crate) warnings: Vec<String>,
}
impl fmt::Debug for ResolvePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvePlan { <redacted> }")
    }
}
impl ResolvePlan {
    /// Read-only constructor. Binds to a real canonical directory, validates
    /// structure and sanitizes descriptions. File hashes are rechecked by preview/apply.
    pub fn new(
        root: &Path,
        mut finding_ids: Vec<String>,
        mut steps: Vec<Step>,
        mut rules: Vec<String>,
        mut warnings: Vec<String>,
        policy: &RedactionPolicy<'_>,
    ) -> Result<Self, ResolveError> {
        if finding_ids.len() > 1000
            || steps.len() > 2000
            || rules.len() > 1000
            || warnings.len() > 1000
        {
            return Err(ResolveError("plan_limit"));
        }
        let project_root =
            fs::canonicalize(root).map_err(|_| ResolveError("invalid_project_root"))?;
        if !project_root.is_dir() {
            return Err(ResolveError("invalid_project_root"));
        }
        unchanged(
            project_root.to_str().ok_or(ResolveError("non_utf8_root"))?,
            policy,
        )?;
        for value in finding_ids.iter().chain(&rules) {
            unchanged(value, policy)?;
        }
        finding_ids.sort();
        finding_ids.dedup();
        rules.sort();
        rules.dedup();
        for text in &mut warnings {
            *text = policy.text(text);
        }
        warnings.sort();
        warnings.dedup();
        let mut files = BTreeMap::new();
        for step in &mut steps {
            match step {
                Step::Explain { description } | Step::ManualAction { description } => {
                    *description = policy.text(description)
                }
                Step::FilePatch {
                    description,
                    file_path,
                    expected_old_hash,
                    expected_new_hash,
                    ..
                } => {
                    *description = policy.text(description);
                    relative(file_path)?;
                    unchanged(file_path, policy)?;
                    if !sha256(expected_old_hash)
                        || !sha256(expected_new_hash)
                        || expected_old_hash == expected_new_hash
                    {
                        return Err(ResolveError("invalid_file_hash"));
                    }
                    if files
                        .insert(file_path.clone(), expected_old_hash.clone())
                        .is_some()
                    {
                        return Err(ResolveError("duplicate_patch_target"));
                    }
                }
            }
        }
        let preconditions = files
            .into_iter()
            .map(|(file_path, expected_sha256)| FilePrecondition {
                file_path,
                expected_sha256,
            })
            .collect::<Vec<_>>();
        if !preconditions.is_empty() && (finding_ids.is_empty() || rules.is_empty()) {
            return Err(ResolveError("missing_plan_binding"));
        }
        let mut result = Self {
            schema_version: PLAN_VERSION,
            plan_id: String::new(),
            finding_ids,
            project_root,
            plan_status: if preconditions.is_empty() {
                RemediationState::GuidanceOnly
            } else {
                RemediationState::Available
            },
            preconditions,
            steps,
            verification_rule_ids: rules,
            warnings,
        };
        result.plan_id = format!(
            "resolve/{}",
            digest(json::stringify(&result.document(false)).as_bytes())
        );
        result.validate()?;
        Ok(result)
    }
    pub fn id(&self) -> &str {
        &self.plan_id
    }
    pub fn root(&self) -> &Path {
        &self.project_root
    }
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
    pub fn preconditions(&self) -> &[FilePrecondition] {
        &self.preconditions
    }
    pub fn status(&self) -> RemediationState {
        self.plan_status
    }
    pub fn finding_ids(&self) -> &[String] {
        &self.finding_ids
    }
    pub fn verification_rule_ids(&self) -> &[String] {
        &self.verification_rule_ids
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn validate(&self) -> Result<(), ResolveError> {
        if self.schema_version != PLAN_VERSION {
            return Err(ResolveError("unsupported_plan_version"));
        }
        if self.plan_id
            != format!(
                "resolve/{}",
                digest(json::stringify(&self.document(false)).as_bytes())
            )
        {
            return Err(ResolveError("plan_integrity_mismatch"));
        }
        if json::stringify(&self.document(true)).len() > 1024 * 1024 {
            return Err(ResolveError("plan_limit"));
        }
        Ok(())
    }
    pub fn render_json(&self) -> Result<String, ResolveError> {
        self.validate()?;
        Ok(json::stringify(&self.document(true)))
    }
    /// Indented form for `plan.json` files; `parse` accepts both forms.
    pub fn render_pretty(&self) -> Result<String, ResolveError> {
        self.validate()?;
        Ok(json::stringify_pretty(&self.document(true)))
    }
    /// Strict import of a plan file (untrusted input). The plan is rebuilt
    /// through `new` (path rules, real canonical root, hashes, redaction) and
    /// must re-render byte for byte as the input, so unknown or duplicate
    /// fields, reordered lists, non-canonical roots or edited descriptions
    /// are refused. The plan id is a content hash, not a signature: anyone can
    /// recompute it, so every safety check still runs on the imported plan.
    pub fn parse(input: &str, policy: &RedactionPolicy<'_>) -> Result<Self, ResolveError> {
        const BAD: ResolveError = ResolveError("invalid_plan_file");
        let text = input
            .strip_prefix('\u{feff}')
            .unwrap_or(input)
            .trim_end_matches(['\n', '\r', ' ']);
        if text.len() > 1024 * 1024 {
            return Err(ResolveError("plan_limit"));
        }
        depth_guard(text, 8)?;
        let json = json::parse(text).map_err(|_| BAD)?;
        let o = fields(
            &json,
            &[
                "schema_version",
                "plan_id",
                "finding_ids",
                "project_root",
                "plan_status",
                "preconditions",
                "steps",
                "verification_rule_ids",
                "warnings",
            ],
        )?;
        if o["schema_version"].as_f64() != Some(PLAN_VERSION as f64) {
            return Err(ResolveError("unsupported_plan_version"));
        }
        let root = o["project_root"].as_str().ok_or(BAD)?;
        let mut steps = Vec::new();
        for step in o["steps"].as_array().ok_or(BAD)? {
            let kind = step.get("kind").and_then(Json::as_str).ok_or(BAD)?;
            let text = |key: &str| {
                step.get(key)
                    .and_then(Json::as_str)
                    .map(str::to_owned)
                    .ok_or(BAD)
            };
            steps.push(match kind {
                "explanation" | "manual_action" => {
                    fields(step, &["kind", "description"])?;
                    if kind == "explanation" {
                        Step::Explain {
                            description: text("description")?,
                        }
                    } else {
                        Step::ManualAction {
                            description: text("description")?,
                        }
                    }
                }
                "file_patch" => {
                    fields(
                        step,
                        &[
                            "kind",
                            "description",
                            "file_path",
                            "expected_old_hash",
                            "expected_new_hash",
                            "recipe",
                        ],
                    )?;
                    Step::FilePatch {
                        description: text("description")?,
                        file_path: text("file_path")?,
                        expected_old_hash: text("expected_old_hash")?,
                        expected_new_hash: text("expected_new_hash")?,
                        recipe: Recipe::from_id(&text("recipe")?)
                            .ok_or(ResolveError("unknown_recipe"))?,
                    }
                }
                _ => return Err(BAD),
            });
        }
        let list = |key: &str| -> Result<Vec<String>, ResolveError> {
            o[key]
                .as_array()
                .ok_or(BAD)?
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or(BAD))
                .collect()
        };
        let plan = Self::new(
            Path::new(root),
            list("finding_ids")?,
            steps,
            list("verification_rule_ids")?,
            list("warnings")?,
            policy,
        )?;
        if o["plan_id"].as_str() != Some(plan.id()) {
            return Err(ResolveError("plan_integrity_mismatch"));
        }
        if plan.render_json()? != text && plan.render_pretty()? != text {
            return Err(ResolveError("noncanonical_plan"));
        }
        Ok(plan)
    }
    pub(crate) fn document(&self, with_id: bool) -> Json {
        let mut fields = vec![
            ("schema_version", Json::Num(self.schema_version as f64)),
            ("finding_ids", strings(&self.finding_ids)),
            ("project_root", s(self.project_root.to_str().unwrap_or(""))),
            (
                "plan_status",
                s(if self.plan_status == RemediationState::Available {
                    "available"
                } else {
                    "guidance_only"
                }),
            ),
            (
                "preconditions",
                Json::Arr(
                    self.preconditions
                        .iter()
                        .map(|p| {
                            obj(vec![
                                ("file_path", s(&p.file_path)),
                                ("expected_sha256", s(&p.expected_sha256)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "steps",
                Json::Arr(
                    self.steps
                        .iter()
                        .map(|step| match step {
                            Step::Explain { description } => obj(vec![
                                ("kind", s("explanation")),
                                ("description", s(description)),
                            ]),
                            Step::ManualAction { description } => obj(vec![
                                ("kind", s("manual_action")),
                                ("description", s(description)),
                            ]),
                            Step::FilePatch {
                                description,
                                file_path,
                                expected_old_hash,
                                expected_new_hash,
                                recipe,
                            } => obj(vec![
                                ("kind", s("file_patch")),
                                ("description", s(description)),
                                ("file_path", s(file_path)),
                                ("expected_old_hash", s(expected_old_hash)),
                                ("expected_new_hash", s(expected_new_hash)),
                                ("recipe", s(recipe.id())),
                            ]),
                        })
                        .collect(),
                ),
            ),
            (
                "verification_rule_ids",
                strings(&self.verification_rule_ids),
            ),
            ("warnings", strings(&self.warnings)),
        ];
        if with_id {
            fields.push(("plan_id", s(&self.plan_id)));
        }
        obj(fields)
    }
}
pub(crate) fn relative(path: &str) -> Result<(), ResolveError> {
    crate::finding_v2::validate_relative_path(path)
        .map_err(|_| ResolveError("invalid_patch_path"))?;
    for part in path.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_lowercase();
        if part.starts_with('~')
            || part.ends_with(['.', ' '])
            || part.eq_ignore_ascii_case(".git")
            || part.contains(['<', '>', '"', '|', '?', '*'])
            || matches!(
                stem.as_str(),
                "con" | "prn" | "aux" | "nul" | "conin$" | "conout$" | "clock$"
            )
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && stem.as_bytes()[3].is_ascii_digit())
        {
            return Err(ResolveError("protected_or_ambiguous_path"));
        }
    }
    Ok(())
}
/// An object with exactly these keys.
fn fields<'a>(
    v: &'a Json,
    keys: &[&str],
) -> Result<&'a std::collections::HashMap<String, Json>, ResolveError> {
    let o = v.as_object().ok_or(ResolveError("invalid_plan_file"))?;
    if o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(ResolveError("unexpected_or_missing_plan_field"));
    }
    Ok(o)
}
/// Bound nesting before the recursive parser sees the input.
fn depth_guard(text: &str, max: usize) -> Result<(), ResolveError> {
    let (mut depth, mut string, mut escaped) = (0usize, false, false);
    for b in text.bytes() {
        if string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > max {
                    return Err(ResolveError("plan_limit"));
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}
fn unchanged(text: &str, policy: &RedactionPolicy<'_>) -> Result<(), ResolveError> {
    if text.is_empty()
        || text.len() > 4096
        || policy.text(text) != text
        || text.contains("[redacted]")
    {
        return Err(ResolveError("unsafe_plan_binding"));
    }
    Ok(())
}
fn sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}
pub(crate) fn s(text: &str) -> Json {
    Json::Str(text.to_owned())
}
fn strings(items: &[String]) -> Json {
    Json::Arr(items.iter().map(|x| s(x)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::testutil::Project;
    pub(crate) fn plan(project: &Project) -> ResolvePlan {
        ResolvePlan::new(
            &project.0,
            vec!["fixture/id".into()],
            vec![Step::Explain {
                description: "Review the issue".into(),
            }],
            vec!["fixture-rule".into()],
            vec![],
            &RedactionPolicy::default(),
        )
        .unwrap()
    }
    #[test]
    fn version_root_hash_and_payload_are_bound() {
        let p = Project::new();
        p.write("action.yml", "fixture");
        let q = Project::new();
        let mut a = plan(&p);
        assert_eq!(a, plan(&p));
        assert_ne!(a.id(), plan(&q).id());
        a.schema_version = 2;
        assert_eq!(
            a.render_json(),
            Err(ResolveError("unsupported_plan_version"))
        );
        let mut a = plan(&p);
        a.finding_ids.push("changed".into());
        assert_eq!(a.validate(), Err(ResolveError("plan_integrity_mismatch")));
        let step = Step::FilePatch {
            description: "Safe recipe".into(),
            file_path: "action.yml".into(),
            expected_old_hash: digest(b"fixture"),
            expected_new_hash: digest(b"fixed"),
            recipe: Recipe::WorkflowRunEnv,
        };
        let a = ResolvePlan::new(
            &p.0,
            vec!["f".into()],
            vec![step],
            vec!["r".into()],
            vec![],
            &RedactionPolicy::default(),
        )
        .unwrap();
        assert_eq!(a.preconditions()[0].expected_sha256, digest(b"fixture"));
        assert_eq!(a.status(), RemediationState::Available);
    }
    #[test]
    fn plan_files_roundtrip_only_in_canonical_form() {
        let p = Project::new();
        let plan = crate::resolve::testutil::patch_plan(
            &p,
            &[("workflows/pr-title.yml", ".github/workflows/a.yml")],
        );
        let policy = RedactionPolicy::default();
        let compact = plan.render_json().unwrap();
        let pretty = plan.render_pretty().unwrap();
        assert_eq!(ResolvePlan::parse(&compact, &policy).unwrap(), plan);
        assert_eq!(
            ResolvePlan::parse(&format!("\u{feff}{pretty}\r\n"), &policy).unwrap(),
            plan
        );
        let bad = |text: String| ResolvePlan::parse(&text, &policy).unwrap_err();
        // Duplicate key (last one wins in the parser) is not canonical.
        assert_eq!(
            bad(compact.replacen("{", "{\"warnings\":[\"x\"],", 1)),
            ResolveError("noncanonical_plan")
        );
        assert_eq!(
            bad(compact.replace("\"warnings\":[]", "\"warnings\":[],\"extra\":1")),
            ResolveError("unexpected_or_missing_plan_field")
        );
        assert_eq!(
            bad(compact.replace("gha-run-env-v1", "gha-shell-v9")),
            ResolveError("unknown_recipe")
        );
        assert_eq!(
            bad(compact.replace("\"schema_version\":1", "\"schema_version\":2")),
            ResolveError("unsupported_plan_version")
        );
        // Editing a description changes the content hash.
        assert_eq!(
            bad(compact.replace("Move event data", "Moved event data")),
            ResolveError("plan_integrity_mismatch")
        );
        assert_eq!(
            bad(format!("{}{}", "[".repeat(100), "]".repeat(100))),
            ResolveError("plan_limit")
        );
        assert_eq!(bad("{".into()), ResolveError("invalid_plan_file"));
    }
    #[test]
    fn unsafe_paths_hashes_and_secret_output_are_rejected_or_hidden() {
        for path in [
            "../x",
            "/x",
            "C:/x",
            ".git/config",
            "NUL",
            "a:stream",
            "a/./b",
            "a\\b",
            "file.",
            "file ",
        ] {
            assert!(relative(path).is_err());
        }
        let p = Project::new();
        let raw = ["weak", "password"].join("-");
        let policy = RedactionPolicy::new([raw.as_str()]);
        let a = ResolvePlan::new(
            &p.0,
            vec!["f".into()],
            vec![Step::Explain {
                description: raw.clone(),
            }],
            vec!["r".into()],
            vec![raw.clone()],
            &policy,
        )
        .unwrap();
        assert!(!a.render_json().unwrap().contains(&raw));
        assert!(!format!("{a:?}").contains(&raw));
        let bad = Step::FilePatch {
            description: "Bad".into(),
            file_path: "action.yml".into(),
            expected_old_hash: "bad".into(),
            expected_new_hash: digest(b"x"),
            recipe: Recipe::WorkflowRunEnv,
        };
        assert_eq!(
            ResolvePlan::new(
                &p.0,
                vec!["f".into()],
                vec![bad],
                vec!["r".into()],
                vec![],
                &policy
            ),
            Err(ResolveError("invalid_file_hash"))
        );
    }
}
