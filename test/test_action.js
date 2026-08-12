'use strict';

/**
 * Pin the action's behaviour.
 *
 *     node action/test/test_action.js
 *
 * No dependencies and no network: the GitHub client, `core` and the Haxset API are
 * all stubbed. What this guards, in rough order of "how badly it breaks":
 *
 * 1.  **The token never reaches a comment.** A PR comment on a public repo is
 *     world-readable and Node quotes argv back in its errors, so one failed
 *     request could otherwise publish the org's shared CI token.
 * 2.  **A suggestion is well-formed or absent.** A malformed review comment takes
 *     the whole review down; a wrong `start_line` is rejected by GitHub.
 * 3.  **Nothing fails the job.** Fork PRs, API errors and unexpected exceptions
 *     must all end in a warning and a green run.
 * 4.  **Command routing order.** `help` before anything billable; `fullscan`
 *     before `scan`; `confirm`/`true` read as triage, never as a scan.
 * 5.  **Every finding family renders and is triage-able.** Secrets and IaC do not
 *     live in `findings`, so a clean-PR check that only counts those would report
 *     a leaked credential as "no issues found".
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');

const SRC = path.join(__dirname, '..', 'src');
const { makeScrub } = require(path.join(SRC, 'scrub'));
const commands = require(path.join(SRC, 'commands'));
const suggestions = require(path.join(SRC, 'suggestions'));
const render = require(path.join(SRC, 'render'));

const failures = [];
let passes = 0;

function check(label, ok, detail) {
  if (ok) { passes += 1; console.log(`  PASS  ${label}`); } else {
    failures.push(label);
    console.log(`  FAIL  ${label}${detail ? `  — ${detail}` : ''}`);
  }
}

/** A `core` stub that records what was emitted. */
function fakeCore() {
  const warnings = [];
  const notices = [];
  const infos = [];
  // ⚠️ The SECOND argument is captured. An annotation's whole value is its
  // `{file, startLine, title}` payload — dropping it meant the annotation tests
  // passed even with the payload deleted from render.js.
  const annotations = [];
  return {
    warnings, notices, infos, annotations,
    warning: (m, props) => {
      warnings.push(String(m));
      if (props) annotations.push(props);
    },
    notice: (m) => notices.push(String(m)),
    info: (m) => infos.push(String(m)),
    error: (m) => warnings.push(String(m)),
  };
}

function finding(over) {
  return Object.assign({
    vuln_class: 'sqli',
    title: 'SQL injection in get()',
    severity: 'critical',
    file_path: 'app/db.py',
    line_number: 42,
    description: 'uid is concatenated into a query.',
    remediation: 'Use a parameterized query.',
    fingerprint: 'a1b2c3d4e5f60718',
  }, over || {});
}

function fix(over) {
  return Object.assign({
    start_line: 42,
    end_line: 43,
    original_lines: ['    q = "..." + uid', '    cur.execute(q)'],
    replacement_lines: ['    cur.execute("... %s", (uid,))'],
    fix_confidence: 9,
    note: 'Parameterised the query.',
    verified: true,
  }, over || {});
}

// ── 1. token redaction ────────────────────────────────────────────────────────

function testScrub() {
  console.log('\n[token redaction]');
  const token = 'haxset_ci_S3CR3T-value_xyz';
  const scrub = makeScrub(token);

  check('the literal token is redacted', !scrub(`token=${token}`).includes(token));
  check('a Bearer header is redacted',
    scrub(`Authorization: Bearer ${token}`) === 'Authorization: Bearer ***');
  check('a DIFFERENT haxset token is redacted too',
    !scrub('found haxset_ci_someoneElsesToken in config').includes('someoneElsesToken'));
  check('an argv echo cannot leak the token',
    !scrub(`Command failed: curl -H "Authorization: Bearer ${token}" https://x`).includes(token));
  check('null and undefined do not throw', scrub(null) === '' && scrub(undefined) === '');
  check('ordinary text is untouched', scrub('nothing secret here') === 'nothing secret here');

  const weird = makeScrub('a+b/c=d.e~f-g');
  check('a token full of regex metacharacters is still redacted',
    !weird('key is a+b/c=d.e~f-g ok').includes('a+b/c=d.e~f-g'));
  check('an empty token does not redact everything',
    makeScrub('')('some text') === 'some text');
}

// ── 2. command routing ────────────────────────────────────────────────────────

function testCommands() {
  console.log('\n[command routing]');
  const kind = (s) => (commands.matchCommand(s) || {}).kind || null;

  check('/haxset scan', kind('/haxset scan') === 'scan');
  check('/haxset rescan is a scan', kind('/haxset rescan') === 'scan');
  check('/haxset check is a recheck', kind('/haxset check') === 'recheck');
  check('/haxset help', kind('/haxset help') === 'help');
  check('/haxset fullscan wins over scan', kind('/haxset fullscan') === 'fullscan');
  check('/haxset full scan (spaced) is a fullscan', kind('/haxset full scan') === 'fullscan');
  check('/haxset fullrepo is a fullscan', kind('/haxset fullrepo') === 'fullscan');
  check('/haxset fix is a fix', kind('/haxset fix F1') === 'fix');
  check('unrelated text matches nothing', kind('looks good to me') === null);
  check('a bare /haxset matches nothing', kind('/haxset') === null);

  check('/haxset fp F1 is triage', kind('/haxset fp F1') === 'triage');
  check('/haxset confirm F1 is triage, NOT a scan', kind('/haxset confirm F1') === 'triage');
  check('/haxset true F1 is triage', kind('/haxset true F1') === 'triage');
  check('/haxset accept F1 is triage', kind('/haxset accept F1') === 'triage');

  const t = commands.matchCommand('/haxset fp F1 S2 I3 D4');
  check('triage parses all four label families',
    JSON.stringify(t.ids) === JSON.stringify(['F1', 'S2', 'I3', 'D4']), JSON.stringify(t.ids));
  check('triage maps fp -> false_positive', t.status === 'false_positive');
  check('accept -> accepted_risk',
    commands.matchCommand('/haxset accepted risk F1').status === 'accepted_risk');
  check('confirm -> true_finding',
    commands.matchCommand('/haxset confirmed F1').status === 'true_finding');

  check('duplicate ids are collapsed',
    JSON.stringify(commands.parseIds('F1 F1 F2')) === JSON.stringify(['F1', 'F2']));
  check('ids are upper-cased', JSON.stringify(commands.parseIds('f1 s2')) === JSON.stringify(['F1', 'S2']));
  // The global ID_RE is module-level, so a leaked lastIndex would make the SECOND
  // call of a repeated parse return fewer ids than the first.
  check('the id regex is not sticky across calls',
    JSON.stringify(commands.parseIds('F1 S2')) === '["F1","S2"]'
    && JSON.stringify(commands.parseIds('F1 S2')) === '["F1","S2"]'
    && JSON.stringify(commands.parseIds('F3')) === '["F3"]');
  check('/haxset fix with no id parses to an empty list',
    JSON.stringify(commands.matchCommand('/haxset fix').ids) === '[]');
}

// ── 3. suggestion construction ────────────────────────────────────────────────

function testSuggestionShape() {
  console.log('\n[suggestion construction]');
  const entry = { label: 'F1', finding: finding(), fix: fix() };

  const body = suggestions.suggestionBody(entry);
  check('the body carries a suggestion fence', /(`{3,})suggestion\n/.test(body));
  check('the replacement is emitted verbatim',
    body.includes('    cur.execute("... %s", (uid,))'));

  // ── Fence width ───────────────────────────────────────────────────────────
  // A fixed 3-backtick fence is closed by any replacement line that IS a fence,
  // so the provider commits only the truncated head of the patch — deleting the
  // closing fence and everything after it — while the comment still says
  // "✅ Verified". Realistic for any fix touching markdown, a Helm/cookiecutter
  // template, a docstring, or a shell heredoc.
  check('fenceFor defaults to three backticks', suggestions.fenceFor(['a', 'b']) === '```');
  check('fenceFor out-lengths an embedded fence',
    suggestions.fenceFor(['```bash', 'x', '```']) === '````');
  check('fenceFor out-lengths a longer run',
    suggestions.fenceFor(['`````x']) === '``````');
  check('fenceFor tolerates junk', suggestions.fenceFor([null, undefined, 7]) === '```');

  const mdFix = fix({
    replacement_lines: ['```bash', 'printf %s "$USER_INPUT"', '```', 'done'],
  });
  const mdBody = suggestions.suggestionBody({ label: 'F1', finding: finding(), fix: mdFix });
  const open = mdBody.match(/(`{3,})suggestion\n/);
  const fence = open[1];
  const after = mdBody.slice(mdBody.indexOf(open[0]) + open[0].length);
  const closeAt = after.indexOf('\n' + fence);
  const committed = after.slice(0, closeAt).split('\n');
  check('a fix containing a code fence is NOT truncated',
    committed.length === 4 && committed[3] === 'done',
    JSON.stringify(committed));
  check('...because the opening fence is longer than the content',
    fence.length > 3, fence);
  check('the body is labelled AI-generated', body.includes(suggestions.AI_LABEL));
  check('a verified fix carries the verified badge', body.includes('Verified'));
  check('the finding label is shown', body.includes('`F1`'));
  const unverified = suggestions.suggestionBody(
    { label: 'F1', finding: finding(), fix: fix({ verified: false }) },
  );
  check('an unverified fix carries no verified badge', !unverified.includes('Verified'));
  check('...but is still labelled AI-generated', unverified.includes(suggestions.AI_LABEL));

  const multi = suggestions.reviewComment(entry);
  check('a multi-line suggestion sets start_line', multi.start_line === 42);
  check('...and start_side', multi.start_side === 'RIGHT');
  check('...and anchors `line` to the END of the range', multi.line === 43);
  check('...on the RIGHT side of the diff', multi.side === 'RIGHT');
  check('...at the finding path', multi.path === 'app/db.py');

  // start_line === line is rejected by GitHub as an invalid range, so a
  // single-line suggestion must omit it entirely.
  const single = suggestions.reviewComment(
    { label: 'F1', finding: finding(), fix: fix({ start_line: 42, end_line: 42 }) },
  );
  check('a SINGLE-line suggestion omits start_line', !('start_line' in single));
  check('...and omits start_side', !('start_side' in single));
  check('...and still anchors to the line', single.line === 42);

  // An inverted range must be REJECTED, not silently degraded. Without the guard
  // the multi-line branch is simply not taken, so it becomes a single-line
  // suggestion anchored at end_line — replacing one wrong line.
  for (const [label, bad] of [
    ['start > end', fix({ start_line: 50, end_line: 40 })],
    ['start = 0', fix({ start_line: 0, end_line: 2 })],
    ['a non-numeric line', fix({ start_line: 'x', end_line: 2 })],
    ['a null line', fix({ start_line: null, end_line: null })],
  ]) {
    check(`an invalid range (${label}) yields no comment`,
      suggestions.reviewComment({ label: 'F1', finding: finding(), fix: bad }) === null);
  }
}

function testCollectFixes() {
  console.log('\n[fix collection]');
  const withFix = finding({ fix: fix() });
  const without = finding({ title: 'no fix here' });
  const emptyFix = finding({ fix: fix({ replacement_lines: [] }) });
  const noPath = finding({ file_path: null, fix: fix() });

  const got = suggestions.collectFixes([
    { prefix: 'F', items: [without, withFix, emptyFix, noPath] },
    { prefix: 'I', items: [finding({ fix: fix() })] },
  ]);
  check('only findings with a usable fix are collected', got.length === 3, String(got.length));
  check('the label matches the finding POSITION in its family',
    got[0].label === 'F2', got[0].label);
  check('the IaC family uses the I prefix', got[2].label === 'I1', got[2].label);
  check('a fix with no replacement lines is a deletion, not a skip',
    got.some((g) => g.finding === emptyFix));
  check('a fix with no file path is skipped', !got.some((g) => g.finding.file_path === null));
  check('an empty input yields nothing', suggestions.collectFixes([]).length === 0);
  check('a null items list does not throw',
    suggestions.collectFixes([{ prefix: 'F', items: null }]).length === 0);
}

// ── 4. degradation ladder ─────────────────────────────────────────────────────

function testDegradation() {
  console.log('\n[degradation ladder]');
  const samePr = { head: { repo: { full_name: 'acme/app' } }, base: { repo: { full_name: 'acme/app' } } };
  const forkPr = { head: { repo: { full_name: 'contrib/app' } }, base: { repo: { full_name: 'acme/app' } } };

  const deletedFork = { head: { repo: null }, base: { repo: { full_name: 'acme/app' } } };

  check('a same-repo PR is not a fork', suggestions.isForkPr(samePr) === false);
  check('a fork PR is detected', suggestions.isForkPr(forkPr) === true);
  // GitHub nulls head.repo when the fork is deleted. Treating that as same-repo was
  // the worst option available: the review path ran, every comment 403'd, and the
  // fallback had already been skipped — findings with no patches and no reason.
  check('a DELETED fork is treated as a fork (degrade, never gamble)',
    suggestions.isForkPr(deletedFork) === true);
  check('a PR with no base repo is not treated as a fork', suggestions.isForkPr({}) === false);

  // The read-only token is a property of the fork's `pull_request` EVENT, not of
  // the PR. A /haxset command runs as issue_comment on the BASE repo with a write
  // token — which is the whole point of `/haxset fix` on an OSS contribution.
  check('a fork PR cannot post suggestions on the automatic scan',
    suggestions.canPostSuggestions(forkPr, false) === false);
  check('...but CAN when a maintainer triggers it by comment',
    suggestions.canPostSuggestions(forkPr, true) === true);
  check('a same-repo PR can post either way',
    suggestions.canPostSuggestions(samePr, false) === true
    && suggestions.canPostSuggestions(samePr, true) === true);

  const sections = [{ prefix: 'F', items: [finding({ fix: fix() }), finding({ fix: fix() })] }];

  let core = fakeCore();
  let plan = suggestions.planSuggestions({ pr: samePr, sections, enabled: true, core });
  check('a same-repo PR plans a review', plan.mode === 'review');
  check('...with no fallback markdown', plan.fallbackMarkdown === '');

  core = fakeCore();
  plan = suggestions.planSuggestions({
    pr: forkPr, sections, enabled: true, core, isComment: true,
  });
  check('a comment-triggered run on a fork plans a REVIEW', plan.mode === 'review');

  // The fork FALLBACK must filter the same entries the salvage path does — a
  // fenced diff for a rejected range shows a wrong location and tells the
  // reviewer to apply it by hand.
  core = fakeCore();
  const mixedFork = suggestions.planSuggestions({
    pr: forkPr,
    sections: [{
      prefix: 'F',
      items: [finding({ fix: fix() }), finding({ fix: fix({ start_line: 9, end_line: 2 }) })],
    }],
    enabled: true,
    core,
  });
  check('the fork fallback renders only the VALID patches',
    (mixedFork.fallbackMarkdown.match(/```diff/g) || []).length === 1,
    String((mixedFork.fallbackMarkdown.match(/```diff/g) || []).length));

  core = fakeCore();
  plan = suggestions.planSuggestions({ pr: forkPr, sections, enabled: true, core });
  check('a fork PR falls back instead of failing', plan.mode === 'fallback');
  check('...rendering fenced diffs in the summary', plan.fallbackMarkdown.includes('```diff'));
  check('...one per fix', (plan.fallbackMarkdown.match(/```diff/g) || []).length === 2);
  check('...showing removed and added lines',
    plan.fallbackMarkdown.includes('-    q = "..." + uid')
    && plan.fallbackMarkdown.includes('+    cur.execute("... %s", (uid,))'));
  check('...still labelled AI-generated', plan.fallbackMarkdown.includes(suggestions.AI_LABEL));
  check('...and warns the user why', core.warnings.some((w) => w.includes('fork')));

  core = fakeCore();
  plan = suggestions.planSuggestions({ pr: samePr, sections, enabled: false, core });
  check('the suggestions input can turn the feature off', plan.mode === 'none');
  check('...with nothing rendered', plan.fallbackMarkdown === '');

  core = fakeCore();
  plan = suggestions.planSuggestions({
    pr: samePr, sections: [{ prefix: 'F', items: [finding()] }], enabled: true, core,
  });
  check('no fixes means no plan', plan.mode === 'none' && plan.entries.length === 0);
}

async function testDeliveryNeverThrows() {
  console.log('\n[delivery never fails the job]');
  const pr = {
    number: 7,
    head: { repo: { full_name: 'acme/app' } },
    base: { repo: { full_name: 'acme/app' } },
  };
  const sections = [{
    prefix: 'F',
    items: [finding({ fix: fix() }), finding({ file_path: 'app/b.py', fix: fix() })],
  }];
  const context = { repo: { owner: 'acme', repo: 'app' } };

  // Happy path.
  let core = fakeCore();
  let created = [];
  let github = {
    rest: { pulls: { createReview: async (a) => { created.push(a); }, createReviewComment: async () => {} } },
  };
  let plan = suggestions.planSuggestions({ pr, sections, enabled: true, core });
  let res = await suggestions.deliver({ github, context, core, pr, headSha: 'deadbeef', plan });
  check('both suggestions post as ONE review', res.posted === 2 && created.length === 1);
  check('the review anchors to the head commit', created[0].commit_id === 'deadbeef');
  check('the review does not approve or request changes', created[0].event === 'COMMENT');
  check('a successful post is announced', core.notices.length === 1);

  // Batch rejected (one stale anchor) -> per-comment retry salvages the rest.
  core = fakeCore();
  const individual = [];
  github = {
    rest: {
      pulls: {
        createReview: async () => { throw new Error('422 Unprocessable Entity'); },
        createReviewComment: async (a) => {
          if (a.path === 'app/b.py') throw new Error('422 line not part of the diff');
          individual.push(a);
        },
      },
    },
  };
  res = await suggestions.deliver({ github, context, core, pr, headSha: 'deadbeef', plan });
  check('a rejected batch retries each comment individually', individual.length === 1);
  check('...posting the ones that are still valid', res.posted === 1);
  check('...counting the one that is not', res.failed === 1);
  check('...and warning rather than throwing', core.warnings.length >= 2);

  // Total failure -> still no throw.
  core = fakeCore();
  github = {
    rest: {
      pulls: {
        createReview: async () => { throw new Error('403 Resource not accessible by integration'); },
        createReviewComment: async () => { throw new Error('403'); },
      },
    },
  };
  const salvaged = [];
  res = await suggestions.deliver({
    github, context, core, pr, headSha: 'deadbeef', plan,
    salvage: async (md) => { salvaged.push(md); },
  });
  check('a total 403 posts nothing and throws nothing', res.posted === 0 && res.failed === 2);
  // Without salvage the patches were computed, verified and then discarded in
  // silence: the summary comment had already gone out and carries no fallback.
  check('...and the patches are SALVAGED into a follow-up comment', salvaged.length === 1);
  check('...as copy-pasteable diffs', salvaged[0].includes('```diff'));
  check('...one per fix', (salvaged[0].match(/```diff/g) || []).length === 2);
  check('...still labelled AI-generated', salvaged[0].includes(suggestions.AI_LABEL));

  core = fakeCore();
  res = await suggestions.deliver({
    github, context, core, pr, headSha: 'deadbeef', plan,
    salvage: async () => { throw new Error('comment failed too'); },
  });
  check('a salvage that itself fails does not throw', res.posted === 0);

  core = fakeCore();
  const noSalvage = await suggestions.deliver({
    github, context, core, pr, headSha: 'deadbeef', plan,
  });
  check('salvage is optional', noSalvage.posted === 0);

  // ── A MIXED batch must not silently drop the invalid entries ──────────────
  // Counting `failed` over the FILTERED list reported {posted:1, failed:0} while
  // discarding the rest — no warning, no salvage, and the run log still claiming
  // two fixes.
  core = fakeCore();
  const sentCounts = [];
  github = {
    rest: {
      pulls: {
        createReview: async (a) => { sentCounts.push(a.comments.length); },
        createReviewComment: async () => {},
      },
    },
  };
  const mixedPlan = {
    mode: 'review',
    entries: [
      { label: 'F1', finding: finding(), fix: fix() },
      { label: 'F2', finding: finding(), fix: fix({ start_line: 50, end_line: 40 }) },
    ],
  };
  const mixedSalvage = [];
  res = await suggestions.deliver({
    github, context, core, pr, headSha: 'deadbeef', plan: mixedPlan,
    salvage: async (md) => mixedSalvage.push(md),
  });
  check('a mixed batch posts only the valid comment', sentCounts[0] === 1);
  check('...and REPORTS the invalid one as failed', res.failed === 1, JSON.stringify(res));
  check('...and warns about it', core.warnings.some((w) => w.includes('F2')));
  check('...and does not salvage (something was posted)', mixedSalvage.length === 0);

  // When EVERY entry is structurally invalid, nothing hits the API and the
  // salvage must not republish the patches the guard just rejected.
  core = fakeCore();
  const rejectedSalvage = [];
  let apiTouched = false;
  github = {
    rest: {
      pulls: {
        createReview: async () => { apiTouched = true; },
        createReviewComment: async () => { apiTouched = true; },
      },
    },
  };
  res = await suggestions.deliver({
    github,
    context,
    core,
    pr,
    headSha: 'deadbeef',
    plan: {
      mode: 'review',
      entries: [{ label: 'F1', finding: finding(), fix: fix({ start_line: 50, end_line: 40 }) }],
    },
    salvage: async (md) => rejectedSalvage.push(md),
  });
  check('an all-invalid plan never touches the API', apiTouched === false);
  check('...and does not salvage a patch the guard rejected', rejectedSalvage.length === 0);
  check('...but still reports it as failed', res.failed === 1);

  // A successful post must NOT also salvage — that would double-report.
  core = fakeCore();
  const shouldNotSalvage = [];
  github = { rest: { pulls: { createReview: async () => {}, createReviewComment: async () => {} } } };
  await suggestions.deliver({
    github, context, core, pr, headSha: 'deadbeef', plan,
    salvage: async (md) => { shouldNotSalvage.push(md); },
  });
  check('a successful review does not also post a fallback', shouldNotSalvage.length === 0);

  // A "none" plan is a no-op even with a hostile client.
  core = fakeCore();
  github = { rest: { pulls: { createReview: async () => { throw new Error('should not be called'); } } } };
  res = await suggestions.deliver({
    github, context, core, pr, headSha: 'x', plan: { mode: 'none', entries: [] },
  });
  check('delivering a "none" plan calls no API at all', res.posted === 0);
  check('delivering a null plan does not throw',
    (await suggestions.deliver({ github, context, core, pr, headSha: 'x', plan: null })).posted === 0);
}

// ── 5. comment rendering ──────────────────────────────────────────────────────

function testRender() {
  console.log('\n[comment rendering]');
  const core = fakeCore();

  const data = {
    relevant: true,
    findings: [finding({ fix: fix() })],
    secrets: { findings: [finding({ vuln_class: 'hardcoded_secrets', title: 'AWS key', fingerprint: 'bbbbbbbbbbbbbbbb', code_snippet: 'KEY = AKIA****' })] },
    iac: { findings: [finding({ title: 'Public S3 bucket', rule_id: 'AVD-AWS-0088', is_custom: true, fingerprint: 'cccccccccccccccc' })] },
    sca: { vulnerabilities: [{ package: 'lodash', current_version: '4.17.19', severity: 'high', vuln_count: 2, fixed_version: '4.17.21', cves: ['CVE-1', 'CVE-2'], fingerprint: 'dddddddddddddddd' }] },
  };
  const out = render.buildComment({ data, bypassed: [], core });

  check('the code section renders', out.body.includes('1 code finding(s)'));
  check('the secrets section renders', out.body.includes('hardcoded secret'));
  check('the misconfiguration section renders', out.body.includes('infrastructure misconfiguration'));
  check('the dependency section renders', out.body.includes('vulnerable dependenc'));
  check('a Haxset-exclusive check is badged', out.body.includes('🛡️ Haxset'));
  check('secrets carry a ROTATE warning (a fix is never offered for them)',
    out.body.includes('Rotate this credential'));

  const marker = out.body.match(/<!-- haxset-findings\n([\s\S]*?)\n-->/);
  check('a hidden fingerprint marker is emitted', !!marker);
  const ids = marker[1].split('\n').map((l) => l.trim().split(/\s+/)[0]);
  check('all four families are addressable',
    JSON.stringify(ids.sort()) === JSON.stringify(['D1', 'F1', 'I1', 'S1']), JSON.stringify(ids));
  check('every marker line is LABEL + 16-hex',
    marker[1].split('\n').every((l) => /^[FSID]\d+\s+[0-9a-f]{16}$/.test(l.trim())));

  check('a finding with a fix is badged in the summary', out.body.includes('verified fix'));
  check('the triage hint mentions /haxset fix', out.body.includes('/haxset fix F1'));
  check('annotations were emitted for the reviewer', core.warnings.length >= 3);
  check('...carrying the file and line a reviewer needs',
    core.annotations.length >= 3
    && core.annotations.every((a) => a.file && a.startLine && a.title),
    JSON.stringify(core.annotations.slice(0, 2)));

  // A PR whose ONLY problem is a leaked credential must not read as clean.
  const secretOnly = render.buildComment({
    data: { relevant: true, findings: [], secrets: { findings: [finding({ fingerprint: 'e'.repeat(16) })] }, iac: { findings: [] }, sca: { vulnerabilities: [] } },
    bypassed: [], core: fakeCore(),
  });
  check('a secrets-only PR is never reported as "no issues found"',
    !secretOnly.body.includes('no issues found'));

  const clean = render.buildComment({
    data: { relevant: true, findings: [], secrets: { findings: [] }, iac: { findings: [] }, sca: { vulnerabilities: [] } },
    bypassed: [], core: fakeCore(),
  });
  check('a genuinely clean PR says so', clean.body.includes('no issues found'));
  check('a clean PR emits no marker', !clean.body.includes('haxset-findings'));

  const irrelevant = render.buildComment({
    data: { relevant: false, findings: [] }, bypassed: [], core: fakeCore(),
  });
  check('an irrelevant diff is reported as such',
    irrelevant.body.includes('No security-relevant code changes'));

  // Fork fallback folds into the SAME comment, not a second one.
  const withFallback = render.buildComment({
    data, bypassed: [], core: fakeCore(),
    suggestionFallback: '<details open>\n<summary><b>🛠️ 1 suggested fix</b></summary>\n\n```diff\n-a\n+b\n```\n\n</details>\n\n',
  });
  check('the fork fallback is folded into the summary comment',
    withFallback.body.includes('```diff'));
  check('...before the hidden marker',
    withFallback.body.indexOf('```diff') < withFallback.body.indexOf('haxset-findings'));

  const bypassedOut = render.buildComment({
    data, bypassed: ['huge.bin'], core: fakeCore(),
  });
  check('files we could not scan are disclosed', bypassedOut.body.includes('not fully scanned'));

  // A refused path was NOT scanned. Reporting "no issues found" while silently
  // omitting a file is a coverage claim this product must never make.
  const refusedOut = render.buildComment({
    data: { relevant: true, findings: [], secrets: { findings: [] }, iac: { findings: [] }, sca: { vulnerabilities: [] } },
    bypassed: [], refused: ['docs/link.md'], core: fakeCore(),
  });
  check('a REFUSED path is disclosed to the reviewer',
    refusedOut.body.includes('not fully scanned') && refusedOut.body.includes('docs/link.md'));
  check('...and names why it was not uploaded',
    refusedOut.body.includes('symlinks are never followed'));

  // The secret snippet is redacted at source, but redaction does not strip
  // backticks — an unfenced-by-width block would inject markdown.
  const fencedSecret = render.buildComment({
    data: {
      relevant: true,
      findings: [],
      secrets: { findings: [finding({ title: 'key', fingerprint: 'f'.repeat(16), code_snippet: 'a = "x"\n```\n# INJECTED' })] },
      iac: { findings: [] },
      sca: { vulnerabilities: [] },
    },
    bypassed: [], core: fakeCore(),
  });
  check('a secret snippet containing a fence cannot escape its block',
    fencedSecret.body.includes('````'), 'no widened fence found');
}

function testRecheckRender() {
  console.log('\n[re-check rendering]');
  const core = fakeCore();
  const data = {
    recheck: true, relevant: true,
    recheck_summary: { total: 3, fixed: 1, not_fixed: 1, triaged: 1 },
    findings: [
      finding({ status: 'fixed', recheck_note: 'Now parameterised.' }),
      finding({ status: 'not_fixed', recheck_note: 'Unchanged.' }),
      finding({ status: 'triaged', triage: 'accepted_risk' }),
    ],
  };
  const out = render.buildComment({ data, bypassed: [], core });
  check('the re-check tally renders', out.body.includes('Re-check: 1/3 fixed'));
  check('the triaged count renders', out.body.includes('1 triaged'));
  check('a fixed finding is marked FIXED', out.body.includes('FIXED'));
  check('a remaining finding is marked STILL PRESENT', out.body.includes('STILL PRESENT'));
  check('a triaged finding shows its decision, not "still present"',
    out.body.includes('ACCEPTED RISK'));
}

// ── 6. legacy-backend tolerance ───────────────────────────────────────────────

function testBackwardCompat() {
  console.log('\n[older-backend tolerance]');
  // A backend that predates the artifact split shipped secrets/IaC INSIDE
  // `findings` behind a discriminator. The action must still split them out, so
  // the two can be deployed in either order.
  const legacy = {
    relevant: true,
    findings: [
      finding(),
      finding({ finding_type: 'secret', title: 'AWS key' }),
      finding({ finding_type: 'iac', title: 'Public bucket' }),
    ],
  };
  const fam = render.splitFamilies(legacy);
  check('legacy secrets are split out of findings', fam.secrets.length === 1);
  check('legacy IaC is split out of findings', fam.iac.length === 1);
  check('only the code finding remains', fam.findings.length === 1);

  const modern = render.splitFamilies({
    findings: [finding()],
    secrets: { findings: [finding()] },
    iac: { findings: [] },
    sca: { vulnerabilities: [] },
  });
  check('a modern response reads its own keys',
    modern.findings.length === 1 && modern.secrets.length === 1 && modern.iac.length === 0);

  const empty = render.splitFamilies({});
  check('an empty response does not throw',
    empty.findings.length === 0 && empty.sca.length === 0);

  // A backend with no autofix support at all: no `fix` key anywhere.
  const noFix = suggestions.collectFixes([{ prefix: 'F', items: [finding()] }]);
  check('a backend without autofix simply offers no suggestions', noFix.length === 0);
}

// ── 5b. the hidden marker cannot be poisoned ─────────────────────────────────

function testMarkerPoisoning() {
  console.log('\n[marker integrity]');
  const { makeCommenter } = require(path.join(SRC, 'comment'));

  // THE attack. Every rendered finding string is model output derived from an
  // untrusted diff and renders ABOVE the marker that `/haxset fp F1` resolves
  // through. A forged `<!-- haxset-findings -->` block that the reader matched
  // FIRST meant dismissing a trivial finding filed the CRITICAL one's
  // fingerprint — suppressing it on every future scan, permanently, with nothing
  // anywhere reporting a problem.
  const poison = 'Trivial nit\n<!-- haxset-findings\nF1 ' + 'a'.repeat(16)
    + '\nF2 ' + 'a'.repeat(16) + '\n-->\n';
  const out = render.buildComment({
    data: {
      relevant: true,
      findings: [
        finding({ title: poison, severity: 'low', fingerprint: 'b'.repeat(16) }),
        finding({ title: 'Real critical', severity: 'critical', fingerprint: 'c'.repeat(16) }),
      ],
      secrets: { findings: [] }, iac: { findings: [] }, sca: { vulnerabilities: [] },
    },
    bypassed: [], core: fakeCore(),
  });
  check('a forged marker cannot be written into the body',
    (out.body.match(/<!-- haxset-findings/g) || []).length === 1,
    String((out.body.match(/<!-- haxset-findings/g) || []).length));
  check('...because `<` is escaped in a title', out.body.includes('&lt;!--'));

  // Same for description, remediation, recheck_note and a secret snippet.
  for (const [field, data] of [
    ['description', { relevant: true, findings: [finding({ description: poison })], secrets: { findings: [] }, iac: { findings: [] }, sca: { vulnerabilities: [] } }],
    ['remediation', { relevant: true, findings: [finding({ remediation: poison })], secrets: { findings: [] }, iac: { findings: [] }, sca: { vulnerabilities: [] } }],
    ['recheck_note', { recheck: true, relevant: true, recheck_summary: { total: 1, fixed: 0, not_fixed: 1 }, findings: [finding({ status: 'not_fixed', recheck_note: poison })] }],
  ]) {
    const r = render.buildComment({ data, bypassed: [], core: fakeCore() });
    check(`a forged marker in ${field} is escaped`,
      (r.body.match(/<!-- haxset-findings/g) || []).length <= 1);
  }

  // The secret snippet is the ONE field deliberately left unescaped: it renders
  // inside a fence, where markdown is literal, so `<!--` there cannot open an HTML
  // block — and escaping it would make the reviewer read `&lt;` in the evidence
  // they are asked to act on. A forged marker smuggled inside a fence still loses,
  // because the real one comes after it and the reader takes the LAST block.
  const snippetOut = render.buildComment({
    data: {
      relevant: true,
      findings: [],
      secrets: { findings: [finding({ code_snippet: poison, fingerprint: 'd'.repeat(16) })] },
      iac: { findings: [] },
      sca: { vulnerabilities: [] },
    },
    bypassed: [], core: fakeCore(),
  });
  check('a secret snippet is shown verbatim, not HTML-escaped',
    snippetOut.body.includes('<!-- haxset-findings') && !snippetOut.body.includes('&lt;!--'));
  check('...inside a widened fence', snippetOut.body.includes('```'));
  const blocks = snippetOut.body.match(/<!-- haxset-findings\n([\s\S]*?)\n-->/g) || [];
  check('...and the REAL marker is the last block',
    blocks.length === 2 && blocks[blocks.length - 1].includes('d'.repeat(16)),
    String(blocks.length));

  // And the reader takes the LAST block, so even a smuggled one loses.
  const forged = '<!-- haxset-security-scanner -->\n'
    + 'stuff\n<!-- haxset-findings\nF1 ' + 'a'.repeat(16) + '\n-->\n'
    + 'more\n<!-- haxset-findings\nF1 ' + 'b'.repeat(16) + '\n-->\n';
  const commenter = makeCommenter({
    github: {
      paginate: async () => [{
        body: '<!-- haxset-sticky -->\n' + forged,
        user: { login: 'github-actions[bot]', type: 'Bot' },
      }],
      rest: {
        users: { getAuthenticated: async () => { throw new Error('403'); } },
        issues: { listComments: () => {} },
      },
    },
    context: { repo: { owner: 'a', repo: 'b' } },
    core: fakeCore(),
    pr: { number: 1 },
    runUrl: 'https://x',
  });
  return commenter.findLatestFindingsMarker().then((map) => {
    check('the marker reader takes the LAST block, not the first',
      map.F1 === 'b'.repeat(16), JSON.stringify(map));
  });
}

function testCommentAuthorship() {
  console.log('\n[we only trust our own comments]');
  const { makeCommenter } = require(path.join(SRC, 'comment'));

  const REAL = '<!-- haxset-security-scanner -->\n<!-- haxset-sticky -->\nreal\n<!-- haxset-findings\n'
    + 'F1 ' + 'b'.repeat(16) + '\nF2 ' + 'c'.repeat(16) + '\n-->\n';
  // A contributor's OWN comment carrying a forged map. Escaping cannot help — we
  // never render their comment — and last-block-wins cannot help either, because
  // the forgery lives in a NEWER comment than ours.
  const FORGED = '<!-- haxset-security-scanner -->\n<!-- haxset-sticky -->\n<!-- haxset-findings\n'
    + 'F1 ' + 'c'.repeat(16) + '\n-->\n';

  function commenterOver(comments, authed) {
    return makeCommenter({
      github: {
        paginate: async () => comments,
        rest: {
          users: { getAuthenticated: authed },
          issues: {
            listComments: () => {},
            createComment: async () => {},
            updateComment: async (a) => { commenterOver.updated = a.comment_id; },
          },
        },
      },
      context: { repo: { owner: 'a', repo: 'b' } },
      core: fakeCore(),
      pr: { number: 1 },
      runUrl: 'https://x',
    });
  }

  const bot = { id: 1, body: REAL, user: { login: 'github-actions[bot]', type: 'Bot' } };
  const human = { id: 99, body: FORGED, user: { login: 'contributor', type: 'User' } };
  const failAuth = async () => { throw new Error('403'); };

  // The forgery is NEWER, so a reader that ignores authorship takes it.
  return commenterOver([bot, human], failAuth).findLatestFindingsMarker().then((map) => {
    check('a contributor cannot forge the triage map',
      map && map.F1 === 'b'.repeat(16), JSON.stringify(map));
    check('...so /haxset fp F1 still files against the REAL finding',
      map.F2 === 'c'.repeat(16));

    // And the sticky comment must be OURS, not one a contributor pre-posted.
    commenterOver.updated = null;
    const c2 = commenterOver([human, bot], failAuth);
    return c2.postSticky('new results').then(() => {
      check("the sticky comment is never written into a contributor's comment",
        commenterOver.updated === 1, String(commenterOver.updated));

      // Every comment we post carries STICKY_MARKER (it identifies us), so
      // selecting on that alone could overwrite a `/haxset help` reply with scan
      // results — losing the sticky comment AND the answer someone asked for.
      commenterOver.updated = null;
      const helpReply = {
        id: 5,
        body: '<!-- haxset-security-scanner -->\nhelp text',
        user: { login: 'github-actions[bot]', type: 'Bot' },
      };
      const realSticky = { id: 7, body: REAL, user: { login: 'github-actions[bot]', type: 'Bot' } };
      return commenterOver([helpReply, realSticky], failAuth)
        .postSticky('results').then(() => {
          check('a command reply is never mistaken for the sticky comment',
            commenterOver.updated === 7, String(commenterOver.updated));

          // With a PAT the identity comes from getAuthenticated, not the Bot type.
          const patAuthed = async () => ({ data: { login: 'haxset-ci' } });
          const patBot = { id: 7, body: REAL, user: { login: 'haxset-ci', type: 'User' } };
          const otherBot = { id: 8, body: FORGED, user: { login: 'other[bot]', type: 'Bot' } };
          return commenterOver([patBot, otherBot], patAuthed)
        .findLatestFindingsMarker().then((m2) => {
          check('a DIFFERENT bot cannot forge the map either',
            m2 && m2.F1 === 'b'.repeat(16), JSON.stringify(m2));
          // `getAuthenticated` 403s for the default GITHUB_TOKEN, so the Bot
          // fallback is the path that actually runs — it must name OUR bot, not
          // trust any bot (dependabot could post a marker).
          const rogue = { id: 9, body: FORGED, user: { login: 'dependabot[bot]', type: 'Bot' } };
          const ours = { id: 10, body: REAL, user: { login: 'github-actions[bot]', type: 'Bot' } };
          return commenterOver([ours, rogue], failAuth)
            .findLatestFindingsMarker().then((m3) => {
              check('the Bot fallback trusts only github-actions[bot]',
                m3 && m3.F1 === 'b'.repeat(16), JSON.stringify(m3));
            });
            });
        });
    });
  });
}

function testBodySizeGuard() {
  console.log('\n[comment size guard]');
  const { makeCommenter, MAX_BODY_CHARS } = require(path.join(SRC, 'comment'));
  let posted = null;
  const commenter = makeCommenter({
    github: {
      paginate: async () => [],
      rest: {
        issues: {
          createComment: async (a) => { posted = a.body; },
          updateComment: async (a) => { posted = a.body; },
        },
      },
    },
    context: { repo: { owner: 'a', repo: 'b' } },
    core: fakeCore(),
    pr: { number: 1 },
    runUrl: 'https://x',
  });

  // The truncation must BOUND the result at every scale — appending the marker
  // tail unconditionally produced a body LONGER than the limit, i.e. the same 422
  // and the same total silence the guard exists to prevent.
  const { truncateBody } = require(path.join(SRC, 'comment'));
  const markerOf = (n) => '<!-- haxset-findings\n'
    + Array.from({ length: n }, (_, i) => `F${i + 1} ${'a'.repeat(16)}`).join('\n')
    + '\n-->\n';
  for (const n of [1, 300, 3000, 5000]) {
    const b = '<details>\n<summary>x</summary>\n' + 'y'.repeat(200000) + '\n' + markerOf(n);
    const t = truncateBody(b);
    check(`a body with ${n} marker line(s) stays inside GitHub's limit`,
      t.length <= 65536, String(t.length));
    check(`...and keeps a usable marker (${n})`, /<!-- haxset-findings\nF1 a{16}/.test(t));
    // The cut lands inside a `<details>`; without closing it the notice, the
    // marker and the footer all render inside a COLLAPSED block.
    check(`...and the truncation notice is not hidden in a <details> (${n})`,
      t.indexOf('was truncated') > t.lastIndexOf('</details>'));
  }
  check('a body already inside the budget is untouched', truncateBody('hi') === 'hi');

  // ⚠️ THE MARKER MUST NEVER BE CUT. An earlier version chopped the overflow off
  // the END, leaving `<!-- haxset-findings` with no `-->`: the open HTML comment
  // swallowed the footer, the marker stopped parsing, and triage fell back to an
  // OLDER scan's map — where labels are positional and have shifted — so
  // `/haxset fp S3` filed against a different finding while the reply said it
  // worked. Reachable from repo content: a secret snippet renders raw inside a
  // fence and the `<details>` counter knows nothing about fences.
  const rnd = (seed) => { let x = seed; return () => ((x = (x * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff); };
  const rand = rnd(1337);
  let worstLen = 0;
  let overLimit = 0;
  let unterminated = 0;
  for (let i = 0; i < 1500; i++) {
    const n = Math.floor(rand() * 400);
    const kind = Math.floor(rand() * 5);
    const pad = kind === 0 ? '<details'.repeat(Math.floor(rand() * 3000))
      : kind === 1 ? '</details>'.repeat(Math.floor(rand() * 3000))
        : kind === 2 ? '<details>\n</details>\n'.repeat(Math.floor(rand() * 1500))
          : kind === 3 ? 'é😀'.repeat(Math.floor(rand() * 20000)) : '';
    const t = truncateBody(pad + 'y'.repeat(Math.floor(rand() * 150000)) + '\n' + (n ? markerOf(n) : ''));
    worstLen = Math.max(worstLen, t.length);
    if (t.length > 65536) overLimit += 1;
    const opens = (t.match(/<!-- haxset-findings/g) || []).length;
    const terms = t.split('<!-- haxset-findings').slice(1).filter((x) => x.includes('-->')).length;
    if (opens !== terms) unterminated += 1;
  }
  check('1500-case fuzz never exceeds the limit', overLimit === 0, String(worstLen));
  check('1500-case fuzz never leaves the marker unterminated', unterminated === 0);

  // The specific shape that broke it: many unclosed `<details` in the head, so the
  // re-cut removes closers and the debt GROWS.
  const nasty = '<details'.repeat(400) + 'y'.repeat(70000)
    + '</details>'.repeat(200) + '\n' + markerOf(60);
  const nt = truncateBody(nasty);
  check('a growing <details> debt still fits', nt.length <= 65536, String(nt.length));
  check('...and still terminates the marker', /<!-- haxset-findings[\s\S]*-->/.test(nt));

  const huge = 'x'.repeat(200000) + '\n<!-- haxset-findings\nF1 ' + 'a'.repeat(16) + '\n-->\n';
  return commenter.postSticky(huge).then(() => {
    check('an oversized body is truncated, not rejected',
      posted && posted.length < 65536, String(posted && posted.length));
    check('...and the truncation is disclosed', posted.includes('was truncated'));
    check('...while the fingerprint marker survives the cut',
      posted.includes('<!-- haxset-findings'));
    check('...so triage keeps working', posted.includes('F1 ' + 'a'.repeat(16)));
    return commenter.postSticky('short body').then(() => {
      check('a normal body is untouched',
        posted.includes('short body') && !posted.includes('was truncated'));
    });
  });
}

// ── 6b. symlinks are never followed ───────────────────────────────────────────

function testSymlinkGuard() {
  console.log('\n[upload guard: symlinks are refused]');
  const fs = require('fs');
  const os = require('os');
  const { collectFiles } = require(path.join(SRC, 'scan'));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'haxset-test-'));
  fs.writeFileSync(path.join(dir, 'ok.txt'), 'safe content');
  fs.mkdirSync(path.join(dir, 'nested'));
  fs.writeFileSync(path.join(dir, 'nested', 'deep.txt'), 'also safe');

  // The attack: a fork PR commits a link to a runner path. `/haxset scan` runs as
  // issue_comment — on the BASE repo, holding the real CI token — while checking
  // out the FORK's tree, so statSync/readFileSync would read the runner's own
  // environment into the upload and potentially into a world-readable comment.
  const outside = path.join(os.tmpdir(), `haxset-secret-${process.pid}.txt`);
  fs.writeFileSync(outside, 'SUPER_SECRET_TOKEN=haxset_ci_leaked');
  fs.symlinkSync(outside, path.join(dir, 'evil.txt'));
  fs.symlinkSync('/etc/passwd', path.join(dir, 'passwd.txt'));
  fs.symlinkSync(path.join(dir, 'ok.txt'), path.join(dir, 'inside-link.txt'));

  const names = ['ok.txt', 'nested/deep.txt', 'evil.txt', 'passwd.txt', 'inside-link.txt']
    .map((f) => path.join(dir, f));
  const res = collectFiles(names, dir);
  const got = Object.keys(res.files).map((f) => path.relative(dir, f)).sort();
  const refused = res.refused.map((f) => path.relative(dir, f)).sort();

  check('a regular file is uploaded', got.includes('ok.txt'));
  check('a regular file in a subdirectory is uploaded', got.includes('nested/deep.txt'));
  check('a symlink pointing OUTSIDE the checkout is refused', refused.includes('evil.txt'));
  check('a symlink to a system file is refused', refused.includes('passwd.txt'));
  // Refused even when the target is inside: a symlink is never what the diff says
  // it is, and there is no case where following one is required.
  check('even an INSIDE-pointing symlink is refused', refused.includes('inside-link.txt'));
  check('the secret never enters the payload',
    !JSON.stringify(res.files).includes('haxset_ci_leaked'));
  check('nothing is silently dropped — refusals are reported', refused.length === 3);

  // A directory named in the diff must not be read as a file.
  const withDir = collectFiles([path.join(dir, 'nested')], dir);
  check('a directory is refused, not read', withDir.refused.length === 1);

  // A file we could not read is DISCLOSED, never silently dropped. git C-quotes a
  // name containing `"` or `\` even with core.quotePath=false, so the quoted name
  // fails lstat — and telling the reviewer "no issues found" while one changed file
  // was never uploaded is a coverage claim this product must not make.
  const missing = collectFiles([path.join(dir, 'gone.txt')], dir);
  check('a file we cannot read is reported, not silently dropped',
    Object.keys(missing.files).length === 0 && missing.refused.length === 1);
  const quoted = collectFiles([path.join(dir, '"src/odd\\name.js"')], dir);
  check('a still-C-quoted name is reported too', quoted.refused.length === 1);

  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(outside, { force: true });
}

// ── 7. every module loads, and the entry point cannot fail the job ────────────

function testModulesLoad() {
  console.log('\n[module load + entry point]');
  // A syntax error or a bad require in ANY of these is a red job in every
  // customer pipeline, because `require` runs outside index.js's try/catch (see
  // the continue-on-error note in action.yml). Loading them here is the cheapest
  // possible guard against publishing a broken tree.
  for (const name of ['index', 'config', 'scrub', 'comment', 'commands',
    'triage', 'fullscan', 'render', 'scan', 'suggestions']) {
    try {
      require(path.join(SRC, name));
      check(`src/${name}.js loads`, true);
    } catch (e) {
      check(`src/${name}.js loads`, false, e.message);
    }
  }

  const run = require(path.join(SRC, 'index'));
  check('the entry point exports a function', typeof run === 'function');

  const cfg = require(path.join(SRC, 'config'));
  const saved = { ...process.env };
  try {
    delete process.env.HAXSET_ENDPOINT;
    delete process.env.HAXSET_TOKEN;
    const c = cfg.loadConfig();
    check('config defaults the endpoint', c.endpoint.startsWith('https://'));
    check('...and derives the triage endpoint', c.triageEndpoint.endsWith('/triage'));
    check('...and the repo-scan endpoint', c.repoScanEndpoint.endsWith('/repo-scan'));
    check('...and defaults suggestions ON', c.suggestions === true);
    process.env.HAXSET_SUGGESTIONS = 'false';
    check('suggestions can be turned off', cfg.loadConfig().suggestions === false);
    process.env.HAXSET_POLL_MINUTES = 'nonsense';
    check('a junk poll-minutes falls back to a sane number',
      cfg.loadConfig().pollMinutes === 60);
    process.env.HAXSET_ENDPOINT = 'https://self.hosted/api/ci/scan///';
    check('a trailing-slash endpoint is normalized',
      cfg.loadConfig().endpoint === 'https://self.hosted/api/ci/scan');
  } finally {
    process.env = saved;
  }
}

async function testEntryPointNeverThrows() {
  console.log('\n[the entry point swallows everything]');
  const run = require(path.join(SRC, 'index'));

  // A context that will explode as soon as it is touched.
  const core = fakeCore();
  const hostile = {
    github: { rest: { pulls: { get: async () => { throw new Error('boom'); } } } },
    context: {
      get eventName() { throw new Error('exploding context'); },
      repo: { owner: 'a', repo: 'b' }, runId: 1, serverUrl: 'https://github.com',
    },
    core,
  };
  let threw = false;
  try { await run(hostile); } catch (e) { threw = true; }
  check('an exploding context does not throw out of run()', !threw);
  check('...it warns instead', core.warnings.length === 1);
  check('...and says the check is non-blocking',
    core.warnings[0].includes('non-blocking'));

  // A workflow_dispatch with no token: takes the fullscan path and returns.
  const core2 = fakeCore();
  const saved = { ...process.env };
  try {
    delete process.env.HAXSET_TOKEN;
    await run({
      github: {}, core: core2,
      context: {
        eventName: 'workflow_dispatch', repo: { owner: 'a', repo: 'b' },
        runId: 1, serverUrl: 'https://github.com', payload: {},
      },
    });
    check('a token-less workflow_dispatch returns cleanly', true);
  } catch (e) {
    check('a token-less workflow_dispatch returns cleanly', false, e.message);
  } finally {
    process.env = saved;
  }

  // A non-PR issue_comment must return without touching anything.
  const core3 = fakeCore();
  try {
    await run({
      github: {}, core: core3,
      context: {
        eventName: 'issue_comment', repo: { owner: 'a', repo: 'b' },
        runId: 1, serverUrl: 'https://github.com',
        payload: { issue: {}, comment: { body: '/haxset scan' } },
      },
    });
    check('a comment on a plain issue is ignored', core3.warnings.length === 0);
  } catch (e) {
    check('a comment on a plain issue is ignored', false, e.message);
  }
}

function fixData(extra) {
  return {
    ok: true,
    status: 'scanned',
    complete: true,
    relevant: true,
    fix_only: true,
    findings: [
      {
        severity: 'high',
        title: 'SQL injection',
        file_path: 'app/db.py',
        line_number: 2,
        fingerprint: 'a'.repeat(16),
        remediation: 'Use a parameterized query.',
        fix: { start_line: 2, end_line: 2, original_lines: ['x'], replacement_lines: ['y'], verified: true },
      },
      {
        severity: 'medium',
        title: 'Path traversal',
        file_path: 'app/io.py',
        line_number: 9,
        fingerprint: 'b'.repeat(16),
        remediation: 'Resolve and contain the path before opening it.',
      },
    ],
    sca: null,
    secrets: null,
    iac: null,
    fix_report: {
      requested: 2,
      published: 1,
      results: [
        { fingerprint: 'a'.repeat(16), status: 'published' },
        {
          fingerprint: 'b'.repeat(16),
          status: 'unavailable',
          reason: 'not_in_diff',
          message: 'it sits on a line this pull request did not change.',
        },
      ],
    },
    ...(extra || {}),
  };
}

const FIX_TARGETS = [
  { id: 'F1', fingerprint: 'a'.repeat(16) },
  { id: 'F2', fingerprint: 'b'.repeat(16) },
];

function testFixRender() {
  console.log('\n[the /haxset fix reply]');
  const core = fakeCore();
  const { body } = render.buildFixComment({
    data: fixData(), requested: FIX_TARGETS, unknownIds: [], core,
  });

  check('names the finding that got a fix', body.includes('F1'));
  check('names the finding that did not', body.includes('F2'));
  check('says a suggestion was posted', /fix posted/.test(body));
  check('says why the other one has none', body.includes('no automated fix'));
  check('gives the reason verbatim from the backend',
    body.includes('it sits on a line this pull request did not change.'));
  check('falls back to the written remediation',
    body.includes('What should change:')
    && body.includes('Resolve and contain the path before opening it.'));
  check('states no credit was used', /No scan credit was used/i.test(body));

  check('does NOT re-post the full findings summary',
    !body.includes('code finding(s)') && !body.includes('vulnerable dependenc'));

  check('emits NO findings marker', !body.includes('<!-- haxset-findings'));
  check('...so label resolution still uses the scan comment',
    !/^[FSID]\d+\s+[0-9a-f]{16}$/m.test(body));

  const partial = render.buildFixComment({
    data: fixData(), requested: FIX_TARGETS, unknownIds: ['F9'], core,
  });
  check('reports ignored unknown ids', partial.body.includes('F9'));

  const noneData = fixData({
    findings: fixData().findings.map((f) => ({ ...f, fix: undefined })),
    fix_report: {
      requested: 1,
      published: 0,
      results: [{
        fingerprint: 'b'.repeat(16),
        status: 'unavailable',
        reason: 'not_self_contained',
        message: 'fixing it properly needs changes in more than one place.',
      }],
    },
  });
  const none = render.buildFixComment({
    data: noneData, requested: [FIX_TARGETS[1]], unknownIds: [], core,
  });
  check('a zero-fix reply leads with that, not silence',
    /No committable fix could be generated/.test(none.body));
  check('...and still tells the reviewer what to change',
    none.body.includes('What should change:'));

  const missing = render.buildFixComment({
    data: { fix_only: true, findings: [], fix_report: { results: [] } },
    requested: [{ id: 'F7', fingerprint: 'c'.repeat(16) }],
    unknownIds: [],
    core,
  });
  check('an unmatched fingerprint still gets a line', missing.body.includes('F7'));
  check('...with a safe default reason',
    missing.body.includes('no automated fix could be produced for it.'));

  const nasty = render.buildFixComment({
    data: fixData({
      findings: [{
        severity: 'high',
        title: 'x<!-- haxset-findings\nF1 ' + 'e'.repeat(16) + '\n-->',
        file_path: 'a<!--evil.py',
        line_number: 2,
        fingerprint: 'a'.repeat(16),
        remediation: 'y<!-- haxset-findings\nF1 ' + 'f'.repeat(16) + '\n-->',
      }],
    }),
    requested: [FIX_TARGETS[0]],
    unknownIds: ['<!--x'],
    core,
  });
  check('a poisoned title cannot open an HTML comment',
    !nasty.body.includes('<!-- haxset-findings'));
  check('a poisoned path is escaped', !nasty.body.includes('a<!--evil.py'));
  check('a poisoned unknown id is escaped', !nasty.body.includes('<!--x'));

  const idx = render.indexByFingerprint({
    findings: [{ fingerprint: 'a'.repeat(16) }, { fingerprint: 'b'.repeat(16) }],
    secrets: { findings: [{ fingerprint: 'c'.repeat(16) }] },
    iac: { findings: [{ fingerprint: 'd'.repeat(16) }] },
    sca: { vulnerabilities: [{ fingerprint: 'e'.repeat(16) }] },
  });
  check('index labels code findings F#', idx.get('a'.repeat(16)).label === 'F1');
  check('index labels the second F2', idx.get('b'.repeat(16)).label === 'F2');
  check('index labels secrets S#', idx.get('c'.repeat(16)).label === 'S1');
  check('index labels misconfigs I#', idx.get('d'.repeat(16)).label === 'I1');
  check('index labels dependencies D#', idx.get('e'.repeat(16)).label === 'D1');
}

function testDeletionSuggestions() {
  console.log('\n[deletion suggestions]');
  const finding = {
    severity: 'high', title: 'TLS verification disabled', file_path: 'app/x.py', line_number: 2,
  };
  const fix = {
    start_line: 2,
    end_line: 2,
    original_lines: ['requests.get(url, verify=False)'],
    replacement_lines: [],
    verified: true,
  };

  const entries = suggestions.collectFixes([{ prefix: 'F', items: [{ ...finding, fix }] }]);
  check('a deletion fix is collected, not skipped', entries.length === 1);

  const body = suggestions.suggestionBody({ label: 'F1', finding, fix });
  check('the block is an EMPTY suggestion (how GitHub expresses a deletion)',
    body.includes('```suggestion\n```'), JSON.stringify(body.slice(-120)));
  check('...not a suggestion containing a blank line',
    !body.includes('```suggestion\n\n```'));
  check('the reviewer is told it deletes', body.includes(suggestions.DELETION_NOTE));
  check('...and it still carries the verified badge',
    body.includes(suggestions.VERIFIED_BADGE));

  const comment = suggestions.reviewComment({ label: 'F1', finding, fix });
  check('it still produces a postable review comment', comment !== null);
  check('...anchored to the deleted line', comment && comment.line === 2);

  const fenced = suggestions.fencedDiff({ label: 'F1', finding, fix });
  check('the fork fallback shows removal only',
    fenced.includes('-requests.get(url, verify=False)') && !fenced.includes('\n+'));

  const replacement = {
    ...fix, replacement_lines: ['requests.get(url, verify=True)'], verified: true,
  };
  const rbody = suggestions.suggestionBody({ label: 'F1', finding, fix: replacement });
  check('a normal replacement is unchanged',
    rbody.includes('```suggestion\nrequests.get(url, verify=True)\n```'));
  check('...and is NOT labelled a deletion',
    !rbody.includes(suggestions.DELETION_NOTE));

  const noFix = suggestions.collectFixes([
    { prefix: 'F', items: [{ ...finding, fix: { ...fix, replacement_lines: null } }] },
  ]);
  check('a malformed replacement list is still skipped', noFix.length === 0);
}

function testFixRouting() {
  console.log('\n[the fix command routes to a fix run]');
  const src = fs.readFileSync(path.join(SRC, 'index.js'), 'utf8');
  check('a fix command sends scanType "fix"', /kind === 'fix' \? 'fix'/.test(src));
  check('a recheck is still a recheck', /kind === 'recheck' \? 'recheck'/.test(src));
  check('the resolved ids are forwarded for rendering', src.includes('fixTargets'));
  check('unknown ids are forwarded too', src.includes('unknownIds'));
  check('the ack no longer claims a re-scan', !/Generating a fix[^']*re-scanning/.test(src));
  check('the ack states it is free', /No credit is used/.test(src));

  const scanSrc = fs.readFileSync(path.join(SRC, 'scan.js'), 'utf8');
  check('a fix_only response renders the fix reply', scanSrc.includes('data.fix_only'));
  check('...and anything else renders the normal summary',
    scanSrc.includes('buildComment({'));
  check('suggestions are still delivered on a fix run',
    scanSrc.includes('suggestionsModule.deliver'));
}

// ── run ───────────────────────────────────────────────────────────────────────

async function main() {
  testScrub();
  testCommands();
  testSuggestionShape();
  testCollectFixes();
  testDegradation();
  await testDeliveryNeverThrows();
  testRender();
  testRecheckRender();
  testFixRender();
  testDeletionSuggestions();
  testFixRouting();
  testBackwardCompat();
  await testMarkerPoisoning();
  await testCommentAuthorship();
  await testBodySizeGuard();
  testSymlinkGuard();
  testModulesLoad();
  await testEntryPointNeverThrows();

  console.log('\n' + '='.repeat(72));
  if (failures.length) {
    console.log(`FAILED — ${failures.length} check(s) failed, ${passes} passed:`);
    failures.forEach((f) => console.log(`  - ${f}`));
    process.exit(1);
  }
  console.log(`All ${passes} action checks passed.`);
}

main().catch((e) => { console.error(e); process.exit(1); });
