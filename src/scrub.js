'use strict';

/**
 * Token redaction for anything that might reach a pull-request comment.
 *
 * A PR comment on a public repository is world-readable, and Node's
 * `child_process` errors quote the entire argv back at you ("Command failed:
 * <argv>"). Without this, ONE failed request would publish the organization's
 * shared CI token to the internet.
 *
 * The token is additionally kept out of argv entirely (see `fullscan.js`, which
 * passes the Authorization header through a 0600 curl config file rather than a
 * command-line flag). This function is the second line of defence, applied to
 * every string the action echoes into a comment.
 */

/**
 * Build a redactor bound to a specific token.
 *
 * Three passes, each catching a different leak shape:
 *   1. `Bearer <anything>` — a quoted header, whatever the token format.
 *   2. The `haxset_ci_` token format itself — catches a DIFFERENT token than ours
 *      (e.g. one pasted into a repository file the scanner echoed back).
 *   3. Our exact token, split/joined so no regex escaping is required and no
 *      metacharacter in the token can change the pattern's meaning.
 *
 * @param {string} token
 * @returns {(value: unknown) => string}
 */
function makeScrub(token) {
  return function scrub(value) {
    let out = String(value === undefined || value === null ? '' : value);
    out = out.replace(/Bearer\s+\S+/gi, 'Bearer ***');
    out = out.replace(/haxset_ci_[A-Za-z0-9._~+/=-]+/gi, 'haxset_ci_***');
    if (token) out = out.split(token).join('***');
    return out;
  };
}

module.exports = { makeScrub };
