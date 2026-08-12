'use strict';

/**
 * Committable fix suggestions on the pull-request diff.
 *
 * WHAT THIS PRODUCES
 * ------------------
 * A single review whose comments each carry a ```suggestion block. GitHub renders
 * that as a **"Commit suggestion"** button on the exact line, and an **"Add to
 * batch"** control so a reviewer can accept several and commit them in one go —
 * without leaving the review, and without this action ever needing write access to
 * the repository's contents. `permissions: pull-requests: write`, which the
 * workflow already has, is the whole requirement.
 *
 * FOUR CONSTRAINTS THAT DICTATE THE DESIGN
 * -----------------------------------------
 * 1. **The line must be part of the PR diff.** GitHub rejects a review comment
 *    anchored anywhere else. The backend's eligibility gate already enforces
 *    this, so anything arriving here with a `fix` is
 *    in-diff by construction — but a stale comment on a fast-moving PR can still
 *    422, which is why `postIndividually` exists.
 * 2. **The suggestion replaces the range verbatim, whitespace included.** The
 *    backend guarantees a byte-exact context match against the file it scanned;
 *    this module must not reformat, re-indent or trim what it was handed.
 * 3. **A fork PR gets a read-only GITHUB_TOKEN.** Review comments 403 there, so
 *    the whole feature degrades to fenced diffs inside the summary comment. It
 *    must never fail the job.
 * 4. **The comment anchors to a commit.** Posting against `headSha` means a push
 *    that lands mid-scan renders the suggestion *outdated* — visibly stale, which
 *    a reviewer can reason about — rather than silently applying to code it was
 *    never computed from.
 *
 * NOTHING HERE MAY FAIL THE JOB
 * ------------------------------
 * Every path returns rather than throws. A suggestion is a bonus on top of a
 * finished scan; if it cannot be posted the reviewer still gets the complete
 * summary comment they get today, and the run stays green.
 */

/** The label every AI-authored suggestion carries. Never imply human review. */
const AI_LABEL = 'AI-generated fix · verify before merging';
const VERIFIED_BADGE = '✅ **Verified** — the finding is gone after this change';

/**
 * Collect the findings that carry a usable fix, in display order.
 *
 * `label` is the finding's `F#` / `I#` id so the suggestion and the summary
 * comment name the same thing.
 *
 * @returns {Array<{label: string, finding: object, fix: object}>}
 */
function collectFixes(sections) {
  const out = [];
  for (const { prefix, items } of sections) {
    (items || []).forEach((f, idx) => {
      const fix = f && f.fix;
      if (!fix || !Array.isArray(fix.replacement_lines) || !fix.replacement_lines.length) return;
      if (!f.file_path || !fix.start_line || !fix.end_line) return;
      out.push({ label: `${prefix}${idx + 1}`, finding: f, fix });
    });
  }
  return out;
}

/**
 * The fence a block of lines can be wrapped in without being cut short.
 *
 * ⚠️ A fixed three-backtick fence is WRONG here, and silently so. Per CommonMark a
 * fenced block closes at the first line containing at least as many backticks as
 * the opener — so a replacement line that is itself ```` ``` ```` (routine in a
 * `.md` file, a Helm or cookiecutter template, a Python docstring, a shell
 * heredoc) closes the suggestion early. GitHub and GitLab then commit only the
 * truncated head of the patch, deleting the closing fence and everything after
 * it — while the comment still says "✅ Verified". A security vendor's one-click
 * button would corrupt the customer's file.
 *
 * The fence must therefore be one backtick longer than the longest run inside the
 * content, and at least three.
 */
function fenceFor(lines) {
  let longest = 0;
  for (const line of lines || []) {
    const runs = String(line === undefined || line === null ? '' : line).match(/`+/g);
    if (!runs) continue;
    for (const run of runs) longest = Math.max(longest, run.length);
  }
  return '`'.repeat(Math.max(3, longest + 1));
}

/**
 * Flatten free prose to a single line that cannot open a markdown block.
 *
 * ⚠️ DEFENCE IN DEPTH, on purpose. `fix.note` is model-authored text derived from
 * an untrusted diff, and it renders UNFENCED immediately above the suggestion. A
 * note carrying its own fenced `suggestion` block became a second committable
 * suggestion under the "✅ Verified" badge, having passed none of the backend's
 * guards; an *unterminated* fence instead swallowed the real one and the button
 * vanished.
 *
 * The backend's `autofix.sanitize_note` is the primary guard. This is the second,
 * because the whole reason `fenceFor` exists is that content reaching a comment
 * cannot be trusted to be fence-safe — and a single point of failure for that is
 * not a design, it is an accident waiting on a regression.
 *
 * Both CommonMark fence characters are neutralized: `~~~` opens a fenced block
 * exactly as ``` does, and both providers detect a suggestion from the rendered
 * info string, not the raw text.
 */
function safeProse(text, max = 300) {
  let flat = String(text === undefined || text === null ? '' : text)
    .replace(/\s+/g, ' ')
    .replace(/`/g, "'")
    .replace(/~/g, '-')
    // `<` is escaped for a third reason, distinct from the two fences: GitHub
    // strips HTML comments from the RENDERED body but keeps them in the raw one,
    // so text beginning `<!--` opens an HTML block that runs to the next `-->` —
    // the hidden fingerprint marker's terminator. The reviewer sees a gutted
    // comment while every machine consumer keeps working, so nothing reports it.
    .replace(/</g, '&lt;')
    .trim();
  if (flat.length > max) flat = `${flat.slice(0, max - 1).trimEnd()}…`;
  return flat;
}

/** The markdown body of one suggestion comment. */
function suggestionBody({ label, finding, fix }) {
  const parts = [];
  const sev = String(finding.severity || '').toUpperCase();
  // The title is model-authored and renders in the suggestion body, so it needs
  // the same treatment as the note — and a cap, because ONE oversized title 422s
  // the batched review and takes every other suggestion on the PR down with it
  // (GitHub rejects a comment body over 65,536 characters).
  const title = safeProse(finding.title, 200) || 'Security finding';
  parts.push(`**${sev} · \`${label}\`** — ${title}`);
  if (fix.verified) parts.push(VERIFIED_BADGE);
  if (fix.note) parts.push(safeProse(fix.note));
  // The suggestion block itself. Content is emitted verbatim: the backend proved
  // it byte-matches the file, so any normalization here would break that promise.
  // Only the FENCE adapts — see fenceFor.
  const fence = fenceFor(fix.replacement_lines);
  parts.push(fence + 'suggestion\n' + fix.replacement_lines.join('\n') + '\n' + fence);
  parts.push(`<sub>${AI_LABEL}</sub>`);
  return parts.join('\n\n');
}

/**
 * The review-comment object GitHub expects for one fix, or null if unusable.
 *
 * Returning null for an inverted range is structural rather than defensive: with
 * `start > end` the multi-line branch below is simply not taken, so the comment
 * would silently degrade to a SINGLE-line suggestion anchored at `end_line` —
 * replacing one wrong line instead of being rejected. The backend guards the
 * range too; this makes a regression there impossible to publish.
 */
function reviewComment(entry) {
  const { finding, fix } = entry;
  const start = Number(fix.start_line);
  const end = Number(fix.end_line);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end < start) {
    return null;
  }
  const comment = {
    path: finding.file_path,
    line: end,
    side: 'RIGHT',
    body: suggestionBody(entry),
  };
  // `start_line` is omitted entirely for a single-line suggestion — sending
  // start_line === line is rejected as an invalid range.
  if (start < end) {
    comment.start_line = start;
    comment.start_side = 'RIGHT';
  }
  return comment;
}

/**
 * The copy-pasteable fallback rendered into the summary comment.
 *
 * Used when review comments are impossible (a fork PR). A fenced `diff` block is
 * the closest thing to a one-click fix that survives a read-only token: the
 * reviewer still gets the exact change, they just apply it by hand.
 */
function fencedDiff(entry) {
  const { label, finding, fix } = entry;
  // ⚠️ `file_path` is escaped here too. It is repo content — a fork contributor
  // can add `src/a<!--evil.js` — and this block renders ABOVE the hidden
  // findings marker, so a raw `<!--` opens an HTML block that swallows it.
  const loc = `${safeProse(finding.file_path, 300)}:${fix.start_line}`
    + (fix.end_line > fix.start_line ? `-${fix.end_line}` : '');
  const lines = []
    .concat((fix.original_lines || []).map((l) => '-' + l))
    .concat((fix.replacement_lines || []).map((l) => '+' + l));
  // Same fence hazard as suggestionBody: a patch touching markdown would close
  // this block early and hide half the diff from the reviewer.
  const fence = fenceFor(lines);
  let out = `<details>\n<summary>🛠️ <code>${label}</code> — suggested fix for <code>${loc}</code>`
    + `${fix.verified ? ' · ✅ verified' : ''}</summary>\n\n`;
  if (fix.note) out += `${safeProse(fix.note)}\n\n`;
  out += fence + 'diff\n' + lines.join('\n') + '\n' + fence + '\n\n';
  out += `<sub>${AI_LABEL}</sub>\n\n</details>\n\n`;
  return out;
}

/**
 * True when this pull request comes from a fork.
 *
 * Checked up front rather than discovered from a 403, because a fork PR is the
 * COMMON case for open-source repositories and burning an API call to fail is
 * both slower and noisier in the log than simply taking the other path.
 *
 * ⚠️ `head.repo` is NULL when the fork has been deleted, which is why a missing
 * head resolves to `true`. Treating it as same-repo produced the worst outcome
 * available: the review path was attempted, every comment 403'd, and the fallback
 * had already been skipped — so the reviewer got findings with no patches and no
 * explanation. Unknown provenance must degrade, not gamble.
 */
function isForkPr(pr) {
  const base = pr && pr.base && pr.base.repo;
  const head = pr && pr.head && pr.head.repo;
  if (!base) return false;          // no base at all: not enough to call it a fork
  if (!head) return true;           // deleted fork — assume no write access
  return head.full_name !== base.full_name;
}

/**
 * Whether committable suggestions can be posted on this run.
 *
 * The read-only token is a property of the `pull_request` EVENT on a fork, not of
 * the pull request itself. A `/haxset ...` comment runs as `issue_comment` on the
 * BASE repository and carries a normal write token — so a maintainer typing
 * `/haxset fix F1` on a contributor's fork PR can have the button, which is
 * exactly the case that command exists for. Gating on the fork alone made the
 * flagship command permanently useless on open-source pull requests.
 */
function canPostSuggestions(pr, isComment) {
  return Boolean(isComment) || !isForkPr(pr);
}

/**
 * Post the suggestions as one review.
 *
 * Falls back to posting each comment on its own when the batch is rejected. A
 * batched `createReview` is all-or-nothing: one comment anchored to a line that
 * moved takes the entire review down with it, so the retry salvages the rest
 * rather than losing every suggestion to one stale anchor.
 *
 * @returns {{posted: number, failed: number}}
 */
async function postReview({ github, context, core, pr, headSha, entries }) {
  // Entries whose range is structurally invalid are counted as failures, not
  // filtered into oblivion: counting `failed` over the FILTERED list made a mixed
  // batch report {posted: 1, failed: 0} while silently dropping the rest — no
  // warning, no salvage, and the run log still claiming 2 fixes.
  const usable = [];
  let failed = 0;
  for (const entry of entries) {
    const comment = reviewComment(entry);
    if (comment) usable.push(comment);
    else {
      failed += 1;
      core.warning(
        `Haxset: skipped a fix suggestion for ${entry.label} — the patch range is not `
        + 'a valid line span. The finding is still listed in the summary comment.',
      );
    }
  }
  if (!usable.length) return { posted: 0, failed };
  const comments = usable;
  try {
    await github.rest.pulls.createReview({
      ...context.repo,
      pull_number: pr.number,
      commit_id: headSha,
      event: 'COMMENT',
      comments,
    });
    return { posted: comments.length, failed };
  } catch (e) {
    core.warning(
      `Haxset: could not post ${comments.length} fix suggestion(s) as one review `
      + `(${e.message}); retrying individually.`,
    );
  }

  let posted = 0;
  for (const comment of comments) {
    try {
      await github.rest.pulls.createReviewComment({
        ...context.repo, pull_number: pr.number, commit_id: headSha, ...comment,
      });
      posted += 1;
    } catch (e) {
      failed += 1;
      core.warning(
        `Haxset: skipped a fix suggestion on ${comment.path}:${comment.line} `
        + `(${e.message}). The finding is still listed in the summary comment.`,
      );
    }
  }
  return { posted, failed };
}

/**
 * Decide how this PR's fixes should be delivered.
 *
 * Returns the entries plus a `mode`:
 *   * `"review"`    — post them as review comments (call `deliver`);
 *   * `"fallback"`  — render `fallbackMarkdown` into the summary comment instead;
 *   * `"none"`      — nothing to offer.
 *
 * Split from the posting so the caller can fold the fallback into the summary
 * BEFORE that summary is posted, rather than posting twice.
 */
function planSuggestions({ pr, sections, enabled, core, isComment }) {
  if (!enabled) return { mode: 'none', entries: [], fallbackMarkdown: '' };
  const entries = collectFixes(sections);
  if (!entries.length) return { mode: 'none', entries: [], fallbackMarkdown: '' };

  // Filtered with the SAME predicate the salvage path uses: rendering a fenced
  // diff for an entry the range guard rejected shows the reviewer a patch with a
  // wrong location and tells them to apply it by hand.
  const renderable = entries.filter((e) => reviewComment(e) !== null);

  if (!canPostSuggestions(pr, isComment)) {
    core.warning(
      `Haxset: this is a fork pull request, so GitHub grants a read-only token and `
      + `committable suggestions cannot be posted. ${entries.length} fix(es) are `
      + `included in the summary comment as copy-pasteable diffs instead. `
      + `Commenting "/haxset fix" on this PR will offer them as one-click `
      + `suggestions, because a comment-triggered run gets a write token.`,
    );
    return {
      mode: 'fallback',
      entries,
      fallbackMarkdown: renderable.length ? fallbackMarkdown(
        renderable,
        'GitHub gives fork pull requests a read-only token, so these cannot be offered as '
        + 'one-click suggestions. Apply them by hand, or comment `/haxset fix F1` to have '
        + 'them posted as suggestions:',
      ) : '',
    };
  }
  return { mode: 'review', entries, fallbackMarkdown: '' };
}

/** The copy-pasteable block used whenever suggestions cannot be delivered. */
function fallbackMarkdown(entries, reason) {
  return `<details open>\n<summary><b>🛠️ ${entries.length} suggested fix`
    + `${entries.length === 1 ? '' : 'es'}</b></summary>\n\n`
    + reason + '\n\n'
    + entries.map(fencedDiff).join('')
    + '</details>\n\n';
}

/**
 * Execute a `"review"` plan. Safe to call with any plan.
 *
 * `salvage` is called with markdown when NOTHING could be posted — a deleted fork,
 * a permissions change mid-run, or every anchor gone stale after a force-push.
 * Without it the patches were computed, verified, and then thrown away in silence:
 * the summary comment had already gone out and carries no fallback, so the
 * reviewer would see findings with no fixes and nothing explaining why.
 */
async function deliver({ github, context, core, pr, headSha, plan, salvage }) {
  if (!plan || plan.mode !== 'review' || !plan.entries.length) return { posted: 0, failed: 0 };
  let res;
  try {
    res = await postReview({ github, context, core, pr, headSha, entries: plan.entries });
  } catch (e) {
    // Belt and braces: `postReview` already swallows everything, so reaching here
    // means something unforeseen. A suggestion must never fail the job.
    core.warning('Haxset: fix suggestions could not be posted: ' + e.message);
    res = { posted: 0, failed: plan.entries.length };
  }

  if (res.posted) {
    core.notice(
      `Haxset: posted ${res.posted} committable fix suggestion(s) on this pull request.`,
    );
    return res;
  }

  // Salvage only what was actually publishable. Rendering a fenced diff for an
  // entry the range guard rejected would print a patch with a wrong location —
  // republishing exactly what the guard threw out.
  const salvageable = plan.entries.filter((e) => reviewComment(e) !== null);
  if (typeof salvage === 'function' && salvageable.length) {
    core.warning(
      `Haxset: none of the ${salvageable.length} fix suggestion(s) could be posted as `
      + 'review comments. They are being added to the pull request as copy-pasteable '
      + 'diffs instead.',
    );
    try {
      await salvage(fallbackMarkdown(
        salvageable,
        'These could not be posted as one-click suggestions on the diff. Apply them by hand:',
      ));
    } catch (e) {
      core.warning('Haxset: the fix fallback could not be posted either: ' + e.message);
    }
  }
  return res;
}

module.exports = {
  AI_LABEL, VERIFIED_BADGE,
  collectFixes, suggestionBody, reviewComment, fencedDiff, fenceFor, safeProse,
  isForkPr, canPostSuggestions, fallbackMarkdown,
  planSuggestions, deliver, postReview,
};
