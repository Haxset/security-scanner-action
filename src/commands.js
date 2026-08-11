'use strict';

/**
 * The `/haxset ...` pull-request command vocabulary.
 *
 * Kept in one module so the regexes cannot drift apart, and so the ORDER they are
 * tested in is stated once (see `matchCommand`) rather than implied by where each
 * `if` happens to sit.
 */

// ⚠️ Every command is anchored to the START OF A LINE (with optional leading
// whitespace). Unanchored, prose that merely MENTIONS the command — "I ran
// /haxset scan yesterday, ignore this" — billed a real scan against the org's
// quota. A command is something you type, not something you talk about.
const SCAN_RE = /(?:^|\n)\s*\/haxset[\s_-]*(?:re)?scan\b/i;
const RECHECK_RE = /(?:^|\n)\s*\/haxset[\s_-]*check\b/i;
const HELP_RE = /(?:^|\n)\s*\/haxset[\s_-]*help\b/i;
// Whole-repository scan. Disjoint from SCAN_RE — that one only allows
// whitespace/`_`/`-` between "haxset" and "scan", so the "full" word breaks it —
// but it is still matched FIRST in `matchCommand`, so the two can never be
// reordered into an ambiguity by a later edit.
const FULLSCAN_RE = /(?:^|\n)\s*\/haxset[\s_-]*full[\s_-]*(?:scan|repo(?:sitory)?)\b/i;
// Ask for a one-click fix on specific findings the per-PR cap skipped.
const FIX_RE = /(?:^|\n)\s*\/haxset[\s_-]*fix\b([^\n\r]*)/i;

const TRIAGE_RE =
  /(?:^|\n)\s*\/haxset[\s_-]*(fp|false[-_ ]?positive|accept(?:ed)?[-_ ]?risk|accept(?:ed)?|risk|confirm(?:ed)?|true|valid)\b([^\n\r]*)/i;

// The four finding-label families: F# code, S# secrets, I# misconfigurations,
// D# dependencies. Baked into the hidden marker the backend's fingerprints are
// filed under — changing a letter here means changing it in the marker writer,
// the GitLab template and the backend's label-prefix table together.
// ⚠️ DELIMITED. Unbounded, this harvested ids out of ordinary prose:
// `/haxset fp F1 in src/i18n/messages.ts` parsed as ['F1', 'I18'], and on a PR
// with >=18 misconfigurations `I18` resolves to a live fingerprint — filing
// false-positive against a finding nobody named, hidden on every future scan.
const ID_RE = /(?:^|[\s,;(])([FSID])(\d+)(?=$|[\s,.;):])/gi;

/** Normalize a triage verb to the backend's status enum, or null. */
function triageStatus(verb) {
  const v = String(verb || '').toLowerCase().replace(/[-_ ]/g, '');
  if (v === 'fp' || v === 'falsepositive' || v === 'false') return 'false_positive';
  if (v.startsWith('accept') || v === 'risk' || v === 'acceptedrisk') return 'accepted_risk';
  if (v.startsWith('confirm') || v === 'true' || v === 'valid') return 'true_finding';
  return null;
}

/** Pull the `F1 S2 I3` style ids out of a command's tail. */
function parseIds(tail) {
  const ids = [];
  let m;
  ID_RE.lastIndex = 0;
  while ((m = ID_RE.exec(String(tail || ''))) !== null) {
    ids.push((m[1] + m[2]).toUpperCase());
  }
  return [...new Set(ids)];
}

function parseTriageCommand(text) {
  const m = String(text || '').match(TRIAGE_RE);
  if (!m) return null;
  const status = triageStatus(m[1]);
  if (!status) return null;
  return { status, ids: parseIds(m[2]) };
}

/**
 * Classify a comment body into exactly one command.
 *
 * Order is load-bearing and deliberately explicit:
 *   help > triage > fix > fullscan > check > scan
 *
 * `help` first so a user asking for help never accidentally spends a credit.
 * `triage` before the scan verbs because "confirm" and "true" must not be read as
 * anything else. `fullscan` before `scan` so the most specific verb wins.
 *
 * @returns {{kind: string, status?: string, ids?: string[]}|null}
 */
function matchCommand(body) {
  const text = String(body || '');
  if (HELP_RE.test(text)) return { kind: 'help' };

  const triage = parseTriageCommand(text);
  if (triage) return { kind: 'triage', ...triage };

  const fix = text.match(FIX_RE);
  if (fix) return { kind: 'fix', ids: parseIds(fix[1]) };

  if (FULLSCAN_RE.test(text)) return { kind: 'fullscan' };
  if (RECHECK_RE.test(text)) return { kind: 'recheck' };
  if (SCAN_RE.test(text)) return { kind: 'scan' };
  return null;
}

module.exports = {
  SCAN_RE, RECHECK_RE, HELP_RE, FULLSCAN_RE, FIX_RE, TRIAGE_RE,
  triageStatus, parseIds, parseTriageCommand, matchCommand,
};
