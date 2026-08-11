'use strict';

/**
 * `/haxset fp|accept|confirm F1` — record a reviewer's decision about a finding.
 *
 * A decision is filed against the finding's stable FINGERPRINT, not its `F1`
 * label: the label is positional and changes as findings come and go, whereas the
 * fingerprint survives line drift and re-scans. The mapping between them lives in
 * a hidden marker inside the last scan comment (`comment.findLatestFindingsMarker`),
 * which is why triage needs a prior scan to resolve against.
 */

const { apiHint } = require('./comment');

const LABEL = {
  false_positive: 'false positive',
  accepted_risk: 'accepted risk',
  true_finding: 'true finding',
};

/**
 * Resolve display labels to fingerprints against the latest scan comment.
 * @returns {{resolved: Array<{id,fingerprint}>, unknown: string[], marker: object|null}}
 */
async function resolveIds(commenter, ids) {
  const marker = await commenter.findLatestFindingsMarker();
  if (!marker || !Object.keys(marker).length) return { resolved: [], unknown: ids, marker: null };
  const resolved = [];
  const unknown = [];
  for (const id of ids) {
    if (marker[id]) resolved.push({ id, fingerprint: marker[id] });
    else unknown.push(id);
  }
  return { resolved, unknown, marker };
}

/**
 * @param {object} ctx {context, core, cfg, pr, commenter, scrub}
 * @param {{status: string, ids: string[]}} cmd
 */
async function handleTriage(ctx, { status, ids }) {
  const { context, cfg, commenter, scrub } = ctx;

  if (!cfg.token) {
    await commenter.postNew('## Haxset Security Scanner\n\n⚠️ The `HAXSET_SCANNER_TOKEN` secret '
      + 'is not set, so triage cannot be recorded.');
    return;
  }
  if (!ids.length) {
    await commenter.postNew('## Haxset Security Scanner\n\nInclude the finding id to triage, '
      + 'e.g. `/haxset fp F1`, `/haxset fp S1`, `/haxset fp I1` or `/haxset fp D1`. '
      + 'The `F#` (code finding), `S#` (secret), `I#` (misconfiguration) and `D#` (dependency) '
      + 'labels are shown next to each item in the latest scan comment.');
    return;
  }

  const { resolved, unknown, marker } = await resolveIds(commenter, ids);
  if (!marker) {
    await commenter.postNew('## Haxset Security Scanner\n\nNo recent findings comment with `F#` '
      + 'labels was found on this PR, so there is nothing to triage. Run `/haxset scan` first.');
    return;
  }
  if (!resolved.length) {
    await commenter.postNew(`## Haxset Security Scanner\n\nCould not match ${ids.join(', ')} to a `
      + 'finding in the latest scan. Use the `F#` labels exactly as shown.');
    return;
  }

  let tres = null;
  let terr = '';
  try {
    tres = await fetch(cfg.triageEndpoint, {
      method: 'POST',
      headers: { Authorization: `Bearer ${cfg.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: 'github',
        repo: `${context.repo.owner}/${context.repo.repo}`,
        prNumber: ctx.pr.number,
        fingerprints: resolved.map((r) => r.fingerprint),
        status,
        actor: (context.payload.comment.user && context.payload.comment.user.login) || null,
      }),
    });
  } catch (e) { terr = e.message; }

  if (!tres || !tres.ok) {
    const code = tres ? tres.status : 'network error';
    const detail = scrub(tres ? (await tres.text()) : terr).slice(0, 200);
    await commenter.postNew(`## Haxset Security Scanner\n\n⚠️ Could not record the triage `
      + `(${code})${apiHint(tres ? tres.status : 0)}.\n\n\`\`\`\n${detail}\n\`\`\``);
    return;
  }

  let msg = '## Haxset Security Scanner\n\n✅ Marked '
    + `${resolved.map((r) => '`' + r.id + '`').join(', ')} as **${LABEL[status]}**`;
  msg += (status === 'true_finding')
    ? '. Recorded as a confirmed issue.'
    : ' — these will be hidden on the next `/haxset scan`.';
  if (unknown.length) {
    msg += `\n\nIgnored unknown id(s): ${unknown.map((u) => '`' + u + '`').join(', ')}.`;
  }
  await commenter.postNew(msg);
}

/** The `/haxset help` reply. */
async function postHelp(commenter) {
  await commenter.postNew(
    '## Haxset Security Scanner — commands\n\n'
    + 'Comment any of these on the pull request (you need write access):\n\n'
    + '- `/haxset scan` — run a full security scan of this PR\'s changed code.\n'
    + '- `/haxset check` — re-check whether the findings already reported on this PR are now fixed.\n'
    + '- `/haxset fix F1` — generate a one-click fix for finding `F1`. Useful when a PR had more '
    + 'findings than the per-scan fix limit, so the one you care about did not get a suggestion.\n'
    + '- `/haxset fullscan` — scan the **entire repository**, not just this PR. Takes much '
    + 'longer; you get an email when it finishes and the report stays in the dashboard.\n'
    + '- `/haxset fp F1` — mark finding `F1` a **false positive** (hidden on the next scan).\n'
    + '- `/haxset accept F1` — mark finding `F1` an **accepted risk** (hidden on the next scan).\n'
    + '- `/haxset confirm F1` — mark finding `F1` a **true finding** (kept and flagged).\n'
    + '- `/haxset help` — show this message.\n\n'
    + 'Ids are shown next to each item in the scan comment: `F1`, `F2`, … for code findings, '
    + '`S1`, `S2`, … for hardcoded secrets, `I1`, `I2`, … for infrastructure misconfigurations, '
    + 'and `D1`, `D2`, … for vulnerable dependencies. '
    + 'You can pass several at once, e.g. `/haxset fp F1 S1 I1 D1`.\n\n'
    + 'Fixes are offered as GitHub suggestions you commit with one click. They are '
    + 'AI-generated and verified against the patched code before being offered — review '
    + 'them before merging, as you would any other suggested change.',
  );
}

module.exports = { handleTriage, postHelp, resolveIds, LABEL };
