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
    + 'Comment any of these on the pull request. You need write access.\n\n'
    + '**Scan**\n\n'
    + '- `/haxset scan` — scan the code this pull request changed.\n'
    + '- `/haxset check` — have the issues already reported here been fixed?\n'
    + '- `/haxset fullscan` — a thorough SAST scan of the **entire repository**, not just '
    + 'this pull request. Uses one SAST credit and takes much longer. You get an email when '
    + 'it finishes, and the full report is available on your Haxset dashboard.\n\n'
    + '**Fix**\n\n'
    + '- `/haxset fix F1` — get a one-click fix for `F1`. Free, and does not re-scan. '
    + 'If no fix can be generated you are told why, and what to change by hand.\n\n'
    + '**Triage**\n\n'
    + '- `/haxset fp F1` — false positive. Hidden on the next scan.\n'
    + '- `/haxset accept F1` — accepted risk. Hidden on the next scan.\n'
    + '- `/haxset confirm F1` — a real issue. Kept and flagged.\n\n'
    + '**Ids**\n\n'
    + 'Each item in the scan comment has an id: `F1` code findings, `S1` secrets, '
    + '`I1` misconfigurations, `D1` dependencies. Pass several at once — '
    + '`/haxset fp F1 S1 I1`.\n\n'
    + '<sub>Fixes are AI-generated and checked against the patched code before being offered. '
    + 'Review them before merging, as you would any suggested change.</sub>',
  );
}

module.exports = { handleTriage, postHelp, resolveIds, LABEL };
