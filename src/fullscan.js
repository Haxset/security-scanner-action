'use strict';

/**
 * `/haxset fullscan` and the "Run workflow" button — scan the WHOLE repository.
 *
 * Unlike the diff scan this does not diff anything: it ships the entire tracked
 * tree to the Haxset engine, which runs the complete SAST pipeline over it. That
 * takes far longer than a workflow should stay alive, so this STARTS the scan and
 * returns — the result is emailed and lives in the platform.
 *
 * TWO HARDENING DECISIONS THAT LOOK LIKE STYLE AND ARE NOT
 * --------------------------------------------------------
 * * **The Authorization header goes in a 0600 curl config file, not in argv.**
 *   argv is readable by every process on the runner AND is reproduced verbatim in
 *   Node's error message — which this function posts to the pull request when a
 *   request fails. The config file is unlinked FIRST because `mode` applies only
 *   when a file is created, so a stale world-readable file left by an earlier run
 *   on a persistent self-hosted runner would otherwise keep its looser permissions.
 * * **`--form-string`, never `-F`.** `-F` treats a value beginning with `@` or `<`
 *   as "read this path from disk". A git branch name can start with either, and on
 *   a comment-triggered fullscan that branch name was chosen by an external
 *   contributor.
 *
 * `execFileSync` throughout — never `execSync`. An argv array is not parsed by a
 * shell, so a refname containing `$`, backticks or parentheses cannot break out of
 * its field.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');

/**
 * @param {object} ctx {context, core, cfg, commenter, scrub}
 * @param {object|null} prForComment  The PR to reply on, or null for a dispatch run.
 */
async function handleFullScan(ctx, prForComment) {
  const { context, core, cfg, commenter, scrub } = ctx;

  const say = async (md) => {
    if (prForComment && commenter) await commenter.postNew(md);
    else core.info(md.replace(/[#*`]/g, ''));
  };

  if (!cfg.token) {
    await say('## Haxset Security Scanner\n\n⚠️ The `HAXSET_SCANNER_TOKEN` secret is not set.');
    return;
  }

  const tmpDir = process.env.RUNNER_TEMP || '/tmp';
  const zip = `${tmpDir}/haxset-repo.zip`;
  const curlrc = `${tmpDir}/haxset-curl.conf`;

  try {
    // `git archive` writes the tracked tree at HEAD, so `.git/` (and anything
    // marked export-ignore) never leaves the runner.
    execFileSync('git', ['archive', '--format=zip', '-o', zip, 'HEAD'], { stdio: 'pipe' });
  } catch (e) {
    await say('## Haxset Security Scanner\n\n⚠️ Could not package the repository for a full '
      + `scan.\n\n\`\`\`\n${scrub(e.message || e).slice(0, 300)}\n\`\`\``);
    return;
  }

  // ⚠️ On a comment-triggered fullscan the PR's head takes PRECEDENCE, and the
  // order matters. `context.ref` on an `issue_comment` is the BASE repository's
  // default branch — never empty — so an `||` fallback after it is dead code, and
  // the scan would be filed against `main` @ the default branch's HEAD while
  // `git archive HEAD` packaged the checked-out pull-request head. Wrong branch,
  // wrong commit, right bytes: the worst kind of mislabelled record.
  const prHead = prForComment && prForComment.head;
  const ref = (prHead && prHead.ref)
    || (context.ref || '').replace(/^refs\/heads\//, '')
    || '';
  const commitSha = (prHead && prHead.sha) || context.sha || '';

  const args = [
    '-sS', '--fail-with-body', '-X', 'POST',
    '--config', curlrc,
    '-F', `file=@${zip};type=application/zip`,
    '--form-string', `repo=${context.repo.owner}/${context.repo.repo}`,
    '--form-string', 'provider=github',
    '--form-string', `ref=${ref}`,
    '--form-string', `commitSha=${commitSha}`,
    '--form-string', `mode=${cfg.scanMode}`,
    '--form-string', `notify=${cfg.notify}`,
    '--form-string', `triggeredByLogin=${context.actor || ''}`,
    cfg.repoScanEndpoint,
  ];

  // curl streams the archive from disk; reading it into Node first would hold a
  // whole repository in memory on the runner.
  let raw = '';
  try {
    // curl's config parser reads a double-quoted value with backslash escapes, so
    // escape both; a CR/LF would start a new directive.
    const hdr = `Authorization: Bearer ${cfg.token}`
      .replace(/[\r\n]/g, '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    try { fs.unlinkSync(curlrc); } catch (e) { /* not there: fine */ }
    fs.writeFileSync(curlrc, `header = "${hdr}"\n`, { mode: 0o600 });
    raw = execFileSync('curl', args, { maxBuffer: 8 * 1024 * 1024 }).toString();
  } catch (e) {
    const detail = scrub((e.stdout && e.stdout.toString()) || e.message || e).slice(0, 300);
    await say('## Haxset Security Scanner\n\n⚠️ The full repository scan could not start.'
      + `\n\n\`\`\`\n${detail}\n\`\`\``);
    return;
  } finally {
    try { fs.unlinkSync(zip); } catch (e) { /* best-effort */ }
    try { fs.unlinkSync(curlrc); } catch (e) { /* best-effort */ }
  }

  let out = {};
  try { out = JSON.parse(raw); } catch (e) { /* fall through to the guard below */ }
  if (!out || !out.uuid) {
    await say('## Haxset Security Scanner\n\n⚠️ The full repository scan did not return a scan '
      + `id.\n\n\`\`\`\n${scrub(raw).slice(0, 300)}\n\`\`\``);
    return;
  }

  // The scan outlives this workflow, so the comment's job is to hand the reviewer a
  // LIVE link they can open right now — that page shows queue position and
  // per-phase progress while it runs, then becomes the report.
  const sha = String(commitSha).slice(0, 8);
  const track = out.url ? `**[▶ Track this scan in Haxset](${out.url})**\n\n` : '';
  // `ref` is a git refname, and refnames permit backticks — on a comment-triggered
  // fullscan it is a fork branch name an external contributor chose. Unescaped it
  // breaks out of the code span below and injects markdown (a link, an image) into
  // a comment a maintainer triggered. Not XSS (GitHub sanitises HTML), but it is
  // someone else's content wearing our voice.
  const safeRef = String(ref || 'HEAD').replace(/`/g, "'");
  await say('## Haxset Security Scanner\n\n'
    + `🔍 **Full repository scan started** — \`${safeRef}\``
    + (sha ? ` @ \`${sha}\`` : '') + '\n\n'
    + track
    + 'That page shows live progress now and becomes the full report when the scan finishes. '
    + 'This scans the **entire repository**, not just the changes in a pull request, so it '
    + 'takes considerably longer than a pull-request scan — you do not need to keep this '
    + 'workflow open. You will also get an email when the report is ready.');
  core.notice(`Haxset full repository scan started: ${out.url || out.uuid}`);
}

module.exports = { handleFullScan };
