# Haxset Security Scanner — GitHub Action

Pull-request security scanning with one-click fixes. Scans the diff for
vulnerabilities, hardcoded secrets, infrastructure misconfigurations and vulnerable
dependencies, and posts verified fixes as committable GitHub suggestions.

```yaml
name: Haxset Security Scanner
on:
  pull_request: { types: [opened, reopened] }
  issue_comment: { types: [created] }
  workflow_dispatch:
permissions: { contents: read, pull-requests: write }
jobs:
  haxset:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          ref: ${{ github.event_name == 'issue_comment' && format('refs/pull/{0}/head', github.event.issue.number) || '' }}
      - uses: haxset/security-scanner-action@v1
        with:
          token: ${{ secrets.HAXSET_SCANNER_TOKEN }}
```

Generate `HAXSET_SCANNER_TOKEN` in the Haxset dashboard under **CI/CD** and add it as
a repository or organization secret.

Both `with:` values are **required**, and neither is decoration:

- **`fetch-depth: 0`** — the scanner diffs the PR against its base commit, which
  GitHub's default shallow checkout cannot reach.
- **`ref:`** — on an `issue_comment` event `actions/checkout` defaults to the
  repository's *default branch*, not the pull request. Without this line a
  `/haxset scan` comment would scan `main` while reporting against the PR, and
  `/haxset fullscan` would package the wrong tree.

## Inputs

| Input | Default | Description |
|---|---|---|
| `token` | *(required)* | Haxset CI token from the dashboard |
| `endpoint` | `https://app.haxset.com/api/ci/scan` | Only change for a self-hosted deployment |
| `poll-minutes` | `60` | How long to wait for a scan to finish |
| `start-retries` | `4` | Retries for a transient failure when starting a scan |
| `mode` | `thorough` | Depth for a whole-repository scan (`thorough` / `fast`) |
| `notify` | `` | Extra comma-separated addresses for a whole-repo report |
| `suggestions` | `true` | Post committable fix suggestions. `false` = prose remediation only |
| `github-token` | `${{ github.token }}` | Token used to read the PR and post comments |

## Pull-request commands

| Command | Effect |
|---|---|
| `/haxset scan` | Re-scan the changed code |
| `/haxset check` | Verify the reported issues are now fixed |
| `/haxset fix F1` | Generate a one-click fix for a specific finding |
| `/haxset fullscan` | Scan the entire repository (long-running; emailed) |
| `/haxset fp F1` | Mark a finding a false positive (hidden on the next scan) |
| `/haxset accept F1` | Mark it an accepted risk (hidden on the next scan) |
| `/haxset confirm F1` | Mark it a true finding (kept and flagged) |
| `/haxset help` | Show all commands |

Only users with write access (`OWNER`, `MEMBER`, `COLLABORATOR`) can drive the
scanner; bot comments are ignored.

## Permissions

`pull-requests: write` covers both the summary comment and the fix suggestions.

**`contents` stays `read`.** A suggestion is committed by the reviewer who clicks it,
under their own identity — this action never writes to your code. That is a
deliberate design choice: delivering fixes as suggestions rather than as pull
requests means you never grant a security vendor push access.

## About the fixes

Where a finding sits on a line the pull request changed, Haxset writes the patch and
posts it as a GitHub suggestion. Before a fix is offered it must survive five guards
and a verification pass:

1. **Byte-exact context match** — the model's idea of what is on those lines must
   equal the file exactly, whitespace included. A hallucinated patch cannot be
   published.
2. **Self-contained** — a fix needing edits elsewhere is discarded.
3. **Confidence threshold.**
4. **Size cap** — a large rewrite is not a one-click change.
5. **No overlap** — two suggestions may not cover the same line, since a reviewer can
   batch-commit them.

Then the patch is applied to a copy of the code and re-scanned. **Only fixes proven
to remove the finding are offered**; the rest are dropped rather than shown with a
caveat. Every suggestion is labelled AI-generated, and nothing is committed
automatically.

Fixes are not offered for **hardcoded secrets** (the real remedy is rotating the
credential, which no code change achieves) or **vulnerable dependencies** (a version
bump without a regenerated lockfile still installs the vulnerable package).

### Fork pull requests

GitHub gives a fork's `pull_request` run a read-only token, so suggestions cannot be
posted on the automatic scan. The action detects this and puts the patches in the
summary comment as copy-pasteable `diff` blocks instead, with a warning explaining
why.

Commenting **`/haxset fix F1`** on that same PR *does* produce committable
suggestions: a comment-triggered run is an `issue_comment` event on the base
repository and carries a normal write token. Only maintainers with write access can
issue the command, so this grants a fork nothing.

**The job always succeeds** — this check is non-blocking by design and never fails a
build.

## Why this is a composite action, not a bundled one

A `node20` action ships a committed `dist/index.js` produced by a bundler, so the
code a customer's CI actually executes is a minified file nobody reads. This is a
security product running inside other people's pipelines with access to their source.
What runs must stay legible, so `src/*.js` here is exactly what executes, with no
build step that could differ from the source in git and no vendored dependencies.

`actions/github-script` supplies the authenticated Octokit client and
`@actions/core`, which is why there is nothing else to install.

## Security properties worth preserving

Each of these was added deliberately and is invisible until it regresses. They are
pinned by `backend/scripts/test_ci_providers.py::test_action_hardening` in the
platform repository.

- **`execFileSync` only, never `execSync`.** An argv array is not shell-parsed, and
  this code handles fork-PR branch names chosen by external contributors — git
  refnames permit `$`, backticks and parentheses.
- **The CI token is scrubbed from anything echoed into a comment.** A PR comment on a
  public repo is world-readable, and Node quotes the whole argv back in its errors, so
  one failed request could otherwise publish the organization's shared token.
- **The fullscan Authorization header goes in a `0600` curl config file, not argv.**
  argv is readable by every process on the runner. The file is unlinked *before* it is
  written, because `mode` applies only at creation — a stale world-readable file from
  an earlier run on a persistent self-hosted runner would otherwise keep looser
  permissions.
- **`--form-string`, never `-F`.** `-F` reads a value beginning with `@` or `<` as a
  path from disk, and a branch name can start with either.
- **`git archive`** writes only the tracked tree, so `.git/` never leaves the runner.

Note that the CI token is sent to whatever `endpoint` resolves to. The default is
Haxset's API; change it only for a self-hosted deployment, and treat write access to
the workflow file as equivalent to access to the token.

## Development

```bash
node test/test_action.js      # no dependencies, no network
```

## Publishing

1. Copy this directory to the root of a public `haxset/security-scanner-action` repo.
2. Tag an immutable release (`v1.2.3`) and move the `v1` tag to it.
3. Protect the tags and require review on the repository — `@v1` means this code runs
   in customer pipelines, so the release process is the security boundary.

Customers who cannot accept a moving tag should pin a commit SHA — that keeps every
feature and lets them choose when to upgrade.

The self-contained `haxset-security-scanner-vendored.yml` workflow in the Haxset
dashboard is also supported, but it is **not** feature-equivalent: it has no fix
suggestions and no `/haxset fix`, because those live here. Say so plainly wherever
it is offered.

## License

MIT — see [LICENSE](LICENSE). The action is the client that talks to the Haxset
platform; a Haxset account and CI token are required to use it.
