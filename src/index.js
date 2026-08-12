'use strict';

/**
 * Haxset Security Scanner — entry point.
 *
 * Dispatches the three events the action responds to:
 *   * `workflow_dispatch` — the "Run workflow" button: a whole-repository scan,
 *     which needs no pull request at all and is therefore handled first;
 *   * `pull_request`      — a PR opened or reopened: scan the diff;
 *   * `issue_comment`     — a `/haxset ...` command on a PR.
 *
 * NOTHING HERE MAY FAIL THE CUSTOMER'S BUILD
 * -------------------------------------------
 * The whole run is wrapped so that any unexpected error becomes a warning and a
 * green job. A non-blocking security check that goes red on the vendor's bad day
 * gets deleted from the pipeline, and then it protects nobody. Real problems are
 * reported in the PR comment and in the run log; they never gate a merge.
 */

const { loadConfig } = require('./config');
const { makeScrub } = require('./scrub');
const { makeCommenter } = require('./comment');
const { matchCommand } = require('./commands');
const { handleFullScan } = require('./fullscan');
const { handleTriage, postHelp, resolveIds } = require('./triage');
const { runScan } = require('./scan');

/** Comment authors permitted to drive the scanner. Write access, in effect. */
const ALLOWED_ASSOCIATIONS = ['OWNER', 'MEMBER', 'COLLABORATOR'];

async function main({ github, context, core }) {
  const cfg = loadConfig();
  const scrub = makeScrub(cfg.token);
  const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}`
    + `/actions/runs/${context.runId}`;

  // ── The "Run workflow" button ───────────────────────────────────────────────
  // A whole-repository scan needs no pull request, so it is dispatched BEFORE any
  // PR resolution below.
  if (context.eventName === 'workflow_dispatch') {
    await handleFullScan({ context, core, cfg, commenter: null, scrub }, null);
    return;
  }

  const isComment = context.eventName === 'issue_comment';
  let pr = null;
  let command = null;

  if (isComment) {
    const c = context.payload.comment;
    if (!context.payload.issue || !context.payload.issue.pull_request) return;
    if (c && c.user && c.user.type === 'Bot') return;
    if (!ALLOWED_ASSOCIATIONS.includes(c.author_association)) {
      core.info(`Ignoring /haxset command from ${c.author_association} (write access required).`);
      return;
    }
    try {
      const { data } = await github.rest.pulls.get({
        ...context.repo, pull_number: context.payload.issue.number,
      });
      pr = data;
    } catch (e) {
      core.warning('Could not resolve PR for command: ' + e.message);
      return;
    }
    command = matchCommand((c && c.body) || '');
  } else {
    pr = context.payload.pull_request;
  }

  if (!pr) { core.info('Not a pull request - skipping.'); return; }

  const commenter = makeCommenter({ github, context, core, pr, runUrl });
  const ctx = { github, context, core, cfg, pr, isComment, commenter, scrub };

  // ── Command routing ─────────────────────────────────────────────────────────
  if (isComment) {
    // An unrecognised /haxset comment gets the help text rather than silence: the
    // user clearly meant to invoke something.
    if (!command || command.kind === 'help') { await postHelp(commenter); return; }
    if (command.kind === 'triage') { await handleTriage(ctx, command); return; }
    if (command.kind === 'fullscan') { await handleFullScan(ctx, pr); return; }
  }

  if (!cfg.token) {
    const post = isComment ? commenter.postNew : commenter.postSticky;
    await post('## Haxset Security Scanner\n\n⚠️ The `HAXSET_SCANNER_TOKEN` secret is not set. '
      + 'Add it under Settings > Secrets and variables > Actions.');
    return;
  }

  // ── `/haxset fix F3` ────────────────────────────────────────────────────────
  // Resolved to fingerprints HERE, against the last scan comment's hidden marker,
  // for the same reason triage is: `F3` is a positional display label the backend
  // has never heard of. An unresolvable id is reported rather than silently
  // dropped — otherwise the command would appear to work and produce nothing.
  let autofixFocus = [];
  let fixTargets = [];
  let unknownIds = [];
  if (isComment && command && command.kind === 'fix') {
    if (!command.ids.length) {
      await commenter.postNew('## Haxset Security Scanner\n\nInclude the finding id, e.g. '
        + '`/haxset fix F1`. Ids are shown next to each item in the latest scan comment.');
      return;
    }
    const { resolved, unknown, marker } = await resolveIds(commenter, command.ids);
    if (!marker) {
      await commenter.postNew('## Haxset Security Scanner\n\nNo recent scan comment was found on '
        + 'this PR, so there is nothing to fix yet. Run `/haxset scan` first.');
      return;
    }
    if (!resolved.length) {
      await commenter.postNew(`## Haxset Security Scanner\n\nCould not match `
        + `${command.ids.join(', ')} to a finding in the latest scan. Use the labels exactly as `
        + 'shown.');
      return;
    }
    autofixFocus = resolved.map((r) => r.fingerprint);
    fixTargets = resolved;
    unknownIds = unknown;
    await commenter.postNew('## Haxset Security Scanner\n\nGenerating a fix for '
      + `${resolved.map((r) => '`' + r.id + '`').join(', ')}. No credit is used.`);
  }

  // ── Scan ────────────────────────────────────────────────────────────────────
  const kind = (isComment && command) ? command.kind : null;
  const scanType = kind === 'recheck' ? 'recheck' : (kind === 'fix' ? 'fix' : 'full');
  if (isComment && scanType !== 'fix') {
    await commenter.postNew(scanType === 'recheck'
      ? '## Haxset Security Scanner\n\nRe-checking previously found issues on the latest commit.'
      : '## Haxset Security Scanner\n\nRe-scan requested - scanning the latest commit.');
  }

  await runScan(ctx, { scanType, autofixFocus, fixTargets, unknownIds });
}

/**
 * The exported entry. Swallows everything by design — see the module docstring.
 */
module.exports = async function run({ github, context, core }) {
  try {
    await main({ github, context, core });
  } catch (e) {
    core.warning(
      'Haxset Security Scanner did not complete: ' + (e && e.message ? e.message : String(e))
      + '. This check is non-blocking, so the job is not failed.',
    );
  }
};
