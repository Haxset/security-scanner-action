'use strict';

/**
 * Posting to the pull request, and reading back what we posted before.
 *
 * Two shapes:
 *   * a STICKY comment (scan results) — one comment per PR, updated in place, so a
 *     re-scan does not bury the review under a wall of history;
 *   * a NEW comment (command replies) — a reply to `/haxset ...` has to appear
 *     where the conversation is, not silently mutate a comment further up.
 *
 * Nothing here may throw. A repository that has not granted
 * `pull-requests: write`, or a fork PR whose token is read-only, must still get a
 * completed job with a warning — never a failed build caused by a security scan
 * that could not comment.
 */

const STICKY_MARKER = '<!-- haxset-security-scanner -->';
// A SECOND marker, on the sticky comment only. Every comment carries
// STICKY_MARKER (it identifies us), so selecting the sticky comment by that alone
// could pick a `/haxset help` reply and overwrite it with scan results — losing
// the real sticky comment and burying the answer someone asked for. GitLab
// already separates the two; this brings the action into line.
const STICKY_ONLY_MARKER = '<!-- haxset-sticky -->';

// GitHub rejects a comment body over 65,536 characters with a 422, and the whole
// post is lost — so ~25 findings with long descriptions produced NO comment at
// all rather than a long one. Truncating is strictly better than silence, and the
// cut is disclosed so nobody reads a short comment as a complete one. The margin
// covers the marker, the footer and the sticky header appended afterwards.
const MAX_BODY_CHARS = 60000;
const TRUNCATION_NOTE = '\n\n> ⚠️ **This comment was truncated** because it exceeded '
  + "GitHub's comment size limit. The full result is in the Haxset dashboard.\n";

/**
 * Bound a comment body, keeping the fingerprint marker and disclosing the cut.
 *
 * Three things this has to get right, each of which was wrong in a first attempt:
 *
 * 1. **It must actually bound the result.** Appending the marker tail
 *    unconditionally meant a PR with thousands of findings produced a body LONGER
 *    than the limit — a 422, and the reviewer got nothing at all, which is the
 *    exact outcome the guard exists to prevent. The tail is therefore trimmed to
 *    whole marker lines too.
 * 2. **It must not close the `<details>` blocks it cut into.** Otherwise the
 *    truncation notice, the marker and the footer all become descendants of a
 *    COLLAPSED `<details>` belonging to some unrelated finding — the disclosure
 *    hides itself.
 * 3. **It must never make a passing body fail.** Anything already inside the
 *    budget is returned untouched.
 */
function truncateBody(md) {
  const text = String(md === undefined || md === null ? '' : md);
  if (text.length <= MAX_BODY_CHARS) return text;

  const markerAt = text.indexOf('<!-- haxset-findings');
  let tail = markerAt >= 0 ? text.slice(markerAt) : '';
  // A marker bigger than half the budget is itself the problem — keep whole lines
  // so every surviving label still resolves to a real fingerprint.
  const tailBudget = Math.floor(MAX_BODY_CHARS / 2);
  if (tail.length > tailBudget) {
    const lines = tail.split('\n');
    // ⚠️ CAP THE FIRST LINE TOO. Keeping `lines[0]` unconditionally left `tail`
    // unbounded whenever that line was long — `budgetFor()` then clamped to 0, so
    // `head` was '' and the `while` guard `head.length > 0` was false on its first
    // test, returning the over-limit body unchanged. Reachable: the "not fully
    // scanned" list joins every bypassed/refused/unscanned path onto ONE line, and
    // a fork contributor chooses filenames.
    const kept = [lines[0].slice(0, Math.max(20, tailBudget - 8))];
    let used = kept[0].length + 5;               // + the closing "\n-->\n"
    for (let i = 1; i < lines.length; i++) {
      if (!/^[FSID]\d+\s+[0-9a-f]{16}$/i.test(lines[i].trim())) continue;
      if (used + lines[i].length + 1 > tailBudget) break;
      kept.push(lines[i]);
      used += lines[i].length + 1;
    }
    tail = kept.join('\n') + '\n-->\n';
  }

  // ⚠️ Iterate to a FIXED POINT, and if the result is still over, trim the HEAD —
  // never the tail. Two things were wrong in the first attempt, and the second was
  // the dangerous one:
  //
  //  * a SHORTER prefix can have MORE unclosed `<details>` (the re-cut drops
  //    closers), so a single-pass reservation under-counts; and
  //  * the overflow was then chopped off the END of the result, which is the
  //    findings marker. That left `<!-- haxset-findings` with no `-->`: the open
  //    HTML comment swallowed the footer, the marker no longer parsed, and the
  //    triage reader fell back to an OLDER scan's map — where labels are
  //    positional and have shifted — so `/haxset fp S3` filed against a different
  //    finding while the reply said it worked. That is exactly the
  //    suppress-the-wrong-finding mode all of this hardening exists to prevent.
  //
  // The marker is the one part that must survive intact, so it is the one part
  // never cut. Reachable from repo content: a secret snippet renders raw inside a
  // fence (redaction removes the credential, not the markup) and `unclosed()` is a
  // plain regex that knows nothing about fences.
  const budgetFor = (pad) => Math.max(
    0, MAX_BODY_CHARS - tail.length - TRUNCATION_NOTE.length - pad,
  );
  const unclosed = (t) => Math.max(
    0, (t.match(/<details/g) || []).length - (t.match(/<\/details>/g) || []).length,
  );
  // The head must never reach INTO the marker: `tail` already starts there,
  // so an overlapping head emits a second, unterminated
  // `<!-- haxset-findings` whose open HTML comment swallows the real one.
  const headLimit = markerAt >= 0 ? markerAt : text.length;
  const CLOSE = '</details>\n';
  const build = (h) => {
    const d = unclosed(h);
    return h + (d ? '\n' + CLOSE.repeat(d) : '') + TRUNCATION_NOTE + tail;
  };

  let debt = 0;
  let head = '';
  for (let i = 0; i < 8; i++) {
    head = text.slice(0, Math.min(headLimit, budgetFor(debt * CLOSE.length + 1)));
    const need = unclosed(head);
    if (need <= debt) break;
    debt = need;
  }

  // Guarantee by construction rather than by arithmetic: shrink the HEAD until the
  // whole thing fits. `tail` is capped at half the budget, so this terminates with
  // the notice and the marker intact even in the worst case.
  let out = build(head);
  let guard = 0;
  while (out.length > MAX_BODY_CHARS && head.length > 0 && guard < 64) {
    const over = out.length - MAX_BODY_CHARS;
    head = head.slice(0, Math.max(0, head.length - over - CLOSE.length));
    out = build(head);
    guard += 1;
  }
  return out;
}
// GLOBAL, and the LAST match wins. Belt-and-braces with `render.safeText`'s
// escaping: the marker sits at the END of the body, after every rendered
// finding, so if a scan string ever did smuggle a `<!-- haxset-findings` block
// through, it would necessarily appear EARLIER — and a first-match reader would
// take the forgery. Reading the last block means the real one always wins.
const FINDINGS_MARKER_RE = /<!-- haxset-findings\n([\s\S]*?)\n-->/g;

/**
 * @param {object} deps  {github, context, core, pr}
 */
function makeCommenter({ github, context, core, pr }) {
  // ⚠️ WHOSE COMMENTS WE TRUST. Both the sticky comment and the hidden
  // fingerprint marker are read back out of the PR's comment list, and neither
  // read used to check WHO wrote the comment. Two consequences, both silent:
  //
  //  * an outside contributor could post their own `<!-- haxset-findings -->`
  //    block (the fingerprints are printed in our own world-readable comment), and
  //    a maintainer typing `/haxset fp F2` would then file false-positive against
  //    whatever finding the forgery names — permanently suppressing a critical one
  //    while the reply cheerfully says "Marked `F2` as false positive";
  //  * a contributor who pre-posts a comment containing the sticky marker owns the
  //    comment every future scan result is written into, and can edit it.
  //
  // So: identify ourselves once, and consider only our own comments. Escaping and
  // last-block-wins do not help here — a forgery in someone else's comment is
  // never escaped by us, and it lives in a NEWER comment than the real one.
  let selfLogin = null;
  let selfResolved = false;

  async function _isOurComment(comment) {
    if (!comment || !comment.user) return false;
    if (!selfResolved) {
      selfResolved = true;
      try {
        const { data } = await github.rest.users.getAuthenticated();
        selfLogin = data && data.login ? String(data.login).toLowerCase() : null;
      } catch (e) {
        // GITHUB_TOKEN is an app installation and cannot call this endpoint. Its
        // comments are authored by `github-actions[bot]`, so the Bot type is the
        // correct fallback — and a human contributor can never have it.
        selfLogin = null;
      }
    }
    if (selfLogin) return String(comment.user.login || '').toLowerCase() === selfLogin;
    // `getAuthenticated` 403s for the default GITHUB_TOKEN (an app installation),
    // so this fallback is the path that actually runs in production — and "any
    // bot" is too wide: dependabot could post a sticky marker. Our comments are
    // authored by `github-actions[bot]` specifically.
    return comment.user.type === 'Bot'
      && String(comment.user.login || '').toLowerCase() === 'github-actions[bot]';
  }

  function body(md, sticky) {
    // Trimmed BEFORE the marker is appended by the caller? No — the marker is part
    // of `md`. So cut at a point that keeps the tail: findings are ordered
    // most-severe-first, and the marker + triage hint live at the end, so the
    // middle is what a reviewer can most afford to lose.
    const md_ = truncateBody(md);
    const footer =
      '\n\n---\nCommands: `/haxset check` (re-check fixes) · `/haxset help` (all commands).';
    return STICKY_MARKER + (sticky ? '\n' + STICKY_ONLY_MARKER : '') + '\n' + md_ + footer;
  }

  function warnPostFailed(e) {
    core.warning(
      'Haxset Security Scanner could not post a PR comment. Ensure the workflow has '
      + '`permissions: pull-requests: write` and that this is not a fork PR. ' + e.message,
    );
  }

  async function postNew(md) {
    try {
      await github.rest.issues.createComment({
        ...context.repo, issue_number: pr.number, body: body(md, false),
      });
    } catch (e) { warnPostFailed(e); }
  }

  async function postSticky(md) {
    const rendered = body(md, true);
    try {
      // PAGINATED: `listComments` returns the OLDEST 100 first, so on a busy pull
      // request our marker sits on a later page and a single-page read would miss
      // it — creating a new comment on every scan and losing the one-comment-per-PR
      // property this function exists for.
      const comments = await github.paginate(github.rest.issues.listComments, {
        ...context.repo, issue_number: pr.number, per_page: 100,
      });
      let existing = null;
      for (const c of comments) {
        if (!c.body || !c.body.includes(STICKY_ONLY_MARKER)) continue;
        if (!(await _isOurComment(c))) continue;   // eslint-disable-line no-await-in-loop
        existing = c;
        break;
      }
      if (existing) {
        await github.rest.issues.updateComment({
          ...context.repo, comment_id: existing.id, body: rendered,
        });
      } else {
        await github.rest.issues.createComment({
          ...context.repo, issue_number: pr.number, body: rendered,
        });
      }
    } catch (e) { warnPostFailed(e); }
  }

  /**
   * The `{label -> fingerprint}` map from the most recent scan comment.
   *
   * Triage and `/haxset fix` both address findings by their DISPLAY label (`F1`),
   * which is positional and meaningless to the backend. The scan comment embeds
   * the real fingerprints in a hidden HTML comment; this reads the latest one
   * back. Returns null when no scan comment exists yet.
   */
  async function findLatestFindingsMarker() {
    try {
      const comments = await github.paginate(github.rest.issues.listComments, {
        ...context.repo, issue_number: pr.number, per_page: 100,
      });
      for (let i = comments.length - 1; i >= 0; i--) {
        const body = comments[i].body || '';
        if (!body.includes(STICKY_MARKER)) continue;
        if (!(await _isOurComment(comments[i]))) continue;  // eslint-disable-line no-await-in-loop
        FINDINGS_MARKER_RE.lastIndex = 0;
        let last = null;
        let m;
        while ((m = FINDINGS_MARKER_RE.exec(body)) !== null) last = m;
        if (!last) continue;
        const map = {};
        for (const line of last[1].split('\n')) {
          const mm = line.trim().match(/^([FSID]\d+)\s+([0-9a-f]{16})$/i);
          if (mm) map[mm[1].toUpperCase()] = mm[2].toLowerCase();
        }
        return map;
      }
    } catch (e) {
      core.warning('Could not read PR comments for triage: ' + e.message);
    }
    return null;
  }

  return { postNew, postSticky, findLatestFindingsMarker, STICKY_MARKER };
}

/** Human hint for a Haxset API status code. */
function apiHint(status) {
  return status === 402 ? ' - CI scan quota exhausted (ask your Haxset admin to raise the limit)'
    : status === 401 ? ' - invalid or revoked CI token'
      : status === 403 ? ' - CI scanning is disabled for this account'
        : status === 429 ? ' - rate limited, retry shortly'
          : '';
}

module.exports = {
  makeCommenter, apiHint, STICKY_MARKER, STICKY_ONLY_MARKER, MAX_BODY_CHARS, truncateBody,
};
