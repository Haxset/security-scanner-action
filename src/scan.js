'use strict';

/**
 * The pull-request diff scan: compute the diff, ship it, poll, render, suggest.
 *
 * The scan itself runs on Haxset's side. This module's job is to produce a correct
 * diff, survive a flaky network, and render the result — and to do all of that
 * without ever failing the customer's build, because a security check that blocks
 * merges when the vendor has an outage gets removed from the pipeline.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const { apiHint } = require('./comment');
const { buildComment, buildFixComment, splitFamilies } = require('./render');
const suggestionsModule = require('./suggestions');

// Per-file and total upload gates. A file at or above FILE_LIMIT is bypassed and
// reported rather than truncated: a partially-uploaded file would be scanned as if
// complete, and "we did not look at this" is the only honest thing to say.
const FILE_LIMIT = 100 * 1024 * 1024;
const TOTAL_LIMIT = 95 * 1024 * 1024;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 408/429/5xx are worth another attempt; a 4xx is a decision, not a blip. */
const isTransientStart = (s) => s === 408 || s === 429 || s >= 500;

/**
 * Read the changed files off disk, bounded, refusing anything that is not a
 * regular file inside the checkout.
 *
 * ⚠️ SYMLINKS ARE REJECTED, and that is a security control, not tidiness.
 * `fs.statSync` and `fs.readFileSync` both FOLLOW links. A `/haxset` command runs
 * as `issue_comment` — on the base repository, so it holds the real
 * `HAXSET_SCANNER_TOKEN` — while checking out the FORK's tree. A contributor who
 * commits `notes.txt -> /proc/self/environ` therefore gets the runner's
 * environment (the CI token, the GitHub token) read into `files`, uploaded, and
 * potentially quoted back into a world-readable PR comment through a finding's
 * description or a fix's `original_lines`, which are rendered verbatim.
 *
 * `lstat` describes the link itself, so a symlink is never followed and never
 * read. `realpath` containment then also refuses a regular file that resolves
 * outside the checkout — the same class of guard the Haxset backend applies when
 * it clones a repository to scan it.
 *
 * @returns {{files: Record<string,string>, bypassed: string[], refused: string[]}}
 */
function collectFiles(names, root) {
  const files = {};
  const bypassed = [];
  const refused = [];
  // Inside the function's own error handling: a missing/unreadable cwd would
  // otherwise throw past runScan and leave the PR with no comment at all.
  let base = '';
  try { base = fs.realpathSync(root || process.cwd()); } catch (e) { base = ''; }
  let total = 0;
  for (const f of names) {
    try {
      const st = fs.lstatSync(f);
      if (st.isSymbolicLink() || !st.isFile()) { refused.push(f); continue; }
      // A regular file can still be reached through a symlinked PARENT directory.
      if (base) {
        const resolved = fs.realpathSync(f);
        if (resolved !== base && !resolved.startsWith(base + path.sep)) {
          refused.push(f);
          continue;
        }
      }
      if (st.size >= FILE_LIMIT || total + st.size > TOTAL_LIMIT) {
        bypassed.push(f);
        continue;
      }
      files[f] = fs.readFileSync(f, 'utf8');
      total += st.size;
    } catch (e) {
      // Reported, never silent. A name git still C-quotes (an embedded `"` or
      // `\\`) fails lstat, and a file deleted between the diff and the read is
      // genuinely gone — either way the reviewer must not be told the changed
      // code was scanned when one file of it was not.
      refused.push(f);
    }
  }
  return { files, bypassed, refused };
}

/**
 * Start the scan, retrying transient failures with jittered exponential backoff.
 * @returns {{res: Response|null, lastErr: string}}
 */
async function startScan({ cfg, core, payload }) {
  let res = null;
  let lastErr = '';
  for (let attempt = 1; attempt <= cfg.startAttempts; attempt++) {
    try {
      res = await fetch(cfg.endpoint, {
        method: 'POST',
        headers: { Authorization: `Bearer ${cfg.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      res = null;
      lastErr = e.message;
      core.warning(
        `Haxset Security Scanner: start attempt ${attempt}/${cfg.startAttempts} `
        + `could not reach API: ${e.message}`,
      );
    }
    if (res && res.ok) break;
    if (res && !isTransientStart(res.status)) break;
    if (attempt < cfg.startAttempts) {
      const backoff = Math.min(15000, 2000 * 2 ** (attempt - 1)) + Math.floor(Math.random() * 1000);
      if (res) {
        core.warning(
          `Haxset Security Scanner: start attempt ${attempt}/${cfg.startAttempts} got API `
          + `${res.status}; retrying in ${Math.round(backoff / 1000)}s`,
        );
      }
      await sleep(backoff);
    }
  }
  return { res, lastErr };
}

/**
 * Poll a running scan to a terminal state.
 * @returns {{data: object|null, expired: boolean, timedOut: boolean}}
 */
async function pollScan({ cfg, core, scanId }) {
  const statusUrl = `${cfg.endpoint}/${scanId}`;
  const deadline = Date.now() + cfg.pollMinutes * 60 * 1000;
  core.info(`Haxset Security Scanner: scan ${scanId} running, polling`);
  let data = null;
  while (Date.now() < deadline) {
    await sleep(10000);
    let pres;
    try {
      pres = await fetch(statusUrl, { headers: { Authorization: `Bearer ${cfg.token}` } });
    } catch (e) { continue; }
    if (pres.status === 404) return { data: null, expired: true, timedOut: false };
    if (!pres.ok) continue;
    data = await pres.json();
    if (data.state && data.state !== 'running') return { data, expired: false, timedOut: false };
  }
  return { data, expired: false, timedOut: true };
}

/**
 * Run one PR scan end to end.
 *
 * @param {object} ctx {github, context, core, cfg, pr, isComment, commenter, scrub}
 * @param {object} opts {scanType, autofixFocus, fixTargets, unknownIds}
 */
async function runScan(
  ctx,
  { scanType = 'full', autofixFocus = [], fixTargets = [], unknownIds = [] } = {},
) {
  const { github, context, core, cfg, pr, isComment, commenter, scrub } = ctx;
  const post = (md) => (isComment ? commenter.postNew(md) : commenter.postSticky(md));

  const baseSha = pr.base.sha;
  const headSha = pr.head.sha;
  // Best-effort: a shallow clone may not hold both endpoints yet. `git diff` below
  // reports the real problem if this did not help.
  try {
    execFileSync('git', ['fetch', '--no-tags', '--depth=200', 'origin', baseSha, headSha],
      { stdio: 'ignore' });
  } catch (e) { /* fetch-depth: 0 already covers the normal case */ }

  let diff = '';
  try {
    diff = execFileSync('git', ['diff', baseSha, headSha],
      { maxBuffer: 256 * 1024 * 1024 }).toString();
  } catch (e) {
    core.warning('Could not compute diff: ' + scrub(e.message));
    await post('## Haxset Security Scanner\n\n⚠️ Could not compute the PR diff. '
      + 'Ensure the workflow checks out with `fetch-depth: 0`.');
    return;
  }
  if (!diff.trim()) {
    core.info('Empty diff.');
    if (isComment) {
      await post('## Haxset Security Scanner\n\nNo file changes detected between the base '
        + 'and head of this PR, so there is nothing to scan.');
    }
    return;
  }

  const names = execFileSync(
    // `-c core.quotePath=false`: git C-QUOTES a non-ASCII path by default
    // (`"src/na\\303\\257ve.js"`), and the quoted name matches nothing on disk — so
    // the file was silently dropped, uploaded to nothing, and the comment still
    // said "no issues found". A coverage claim this product must never make.
    'git',
    ['-c', 'core.quotePath=false', 'diff', '--name-only', '--diff-filter=ACMR',
      baseSha, headSha],
    { maxBuffer: 64 * 1024 * 1024 },
  ).toString().split('\n').filter(Boolean);
  const { files, bypassed, refused } = collectFiles(names);
  if (refused.length) {
    // Named, not silent: a refused path is either a mistake worth seeing or an
    // attempt worth recording.
    core.warning(
      `Haxset refused to upload ${refused.length} path(s) that are not regular files `
      + `inside the checkout (symlinks are not followed): ${refused.join(', ')}`,
    );
  }

  const payload = {
    provider: 'github',
    repo: `${context.repo.owner}/${context.repo.repo}`,
    prNumber: pr.number,
    prTitle: pr.title,
    commitSha: headSha,
    branch: pr.head.ref,
    prAuthorLogin: pr.user && pr.user.login,
    prAuthorId: pr.user && pr.user.id,
    triggeredByLogin: isComment
      ? (context.payload.comment.user && context.payload.comment.user.login)
      : (pr.user && pr.user.login),
    scanType,
    diff,
    files,
  };
  if (autofixFocus && autofixFocus.length) payload.autofixFocus = autofixFocus;

  const { res, lastErr } = await startScan({ cfg, core, payload });
  if (res === null) {
    await post('## Haxset Security Scanner\n\n⚠️ Could not reach the Haxset API at '
      + `\`${cfg.endpoint}\` after ${cfg.startAttempts} attempt(s).`
      + `\n\n\`\`\`\n${scrub(lastErr)}\n\`\`\``);
    return;
  }
  if (!res.ok) {
    const txt = scrub(await res.text()).slice(0, 300);
    core.warning(`Haxset Security Scanner API ${res.status}: ${txt}`);
    await post(`## Haxset Security Scanner\n\n⚠️ The scan could not start - API \`${res.status}\``
      + `${apiHint(res.status)} (after ${cfg.startAttempts} attempt(s)).`
      + `\n\n\`\`\`\n${txt}\n\`\`\``);
    return;
  }

  let data = await res.json();
  if (data && data.state === 'running' && data.scan_id) {
    const polled = await pollScan({ cfg, core, scanId: data.scan_id });
    if (polled.expired) {
      await post('## Haxset Security Scanner\n\n⚠️ The scan result expired before it could be '
        + 'read. Re-run the job to try again.');
      return;
    }
    if (polled.timedOut || !polled.data || polled.data.state === 'running') {
      await post('## Haxset Security Scanner\n\n⚠️ The scan is taking longer than expected and '
        + 'did not finish within the polling window. It may still complete on the Haxset '
        + 'dashboard.');
      return;
    }
    data = polled.data;
  }

  if (data && (data.state === 'error' || data.ok === false)) {
    const msg = (data && data.message) ? data.message : 'Haxset engine error.';
    await post(`## Haxset Security Scanner\n\n⚠️ The scan could not complete - ${msg}`);
    return;
  }

  // ── Render, then suggest ─────────────────────────────────────────────────────
  // The suggestion PLAN is computed before the summary is posted, because the
  // fork-PR fallback has to be folded into that same comment — posting twice
  // would leave a reviewer reading two half-answers.
  const families = splitFamilies(data);
  const plan = suggestionsModule.planSuggestions({
    pr,
    sections: [
      { prefix: 'F', items: families.findings },
      { prefix: 'I', items: families.iac },
    ],
    enabled: cfg.suggestions && !data.recheck,
    core,
    isComment,
  });

  const { body } = data.fix_only
    ? buildFixComment({ data, requested: fixTargets, unknownIds, core })
    : buildComment({
      data, bypassed, refused, core, suggestionFallback: plan.fallbackMarkdown,
    });
  await post(body);

  // Posted AFTER the summary so the review comments read as annotations on an
  // explanation the reviewer already has, not as context-free patches. `salvage`
  // catches the case where none of them land: the patches go into a follow-up
  // comment rather than being silently discarded.
  await suggestionsModule.deliver({
    github, context, core, pr, headSha, plan,
    salvage: (md) => commenter.postNew('## Haxset Security Scanner\n\n' + md),
  });

  core.info(
    `Haxset Security Scanner: ${families.findings.length} findings, `
    + `${families.secrets.length} secrets, ${families.iac.length} misconfigurations, `
    + `${families.sca.length} vulnerable deps, ${plan.entries.length} fix(es).`,
  );
}

module.exports = { runScan, collectFiles, startScan, pollScan, FILE_LIMIT, TOTAL_LIMIT };
