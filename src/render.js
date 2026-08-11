'use strict';

/**
 * The pull-request summary comment.
 *
 * FOUR FAMILIES, FOUR LABEL PREFIXES
 * -----------------------------------
 *   F#  AI code findings           -> data.findings
 *   S#  hardcoded secrets          -> data.secrets.findings
 *   I#  IaC/container misconfigs   -> data.iac.findings
 *   D#  vulnerable dependencies    -> data.sca.vulnerabilities
 *
 * The last three are DETERMINISTIC SIDE ARTIFACTS: the backend returns each under
 * its own key and excludes all of them from the finding count, so a "0 findings"
 * summary can still carry a secrets section. All four are triage-able by label.
 *
 * The label is positional and means nothing to the backend, so every rendered item
 * also pushes `LABEL fingerprint` into a hidden marker block. `/haxset fp F1` and
 * `/haxset fix F1` both resolve through that marker.
 */

const { fenceFor, safeProse } = require('./suggestions');

/**
 * Neutralize a scan-derived string before it is interpolated into the comment.
 *
 * ⚠️ THIS PROTECTS THE HIDDEN MARKER, and that is a bigger deal than it looks.
 * Every rendered finding string — title, description, remediation, recheck note,
 * even a redacted secret snippet — is model output derived from an untrusted
 * diff, and all of it renders ABOVE the `<!-- haxset-findings ... -->` block that
 * `/haxset fp F1` resolves labels through. A string containing its own
 * `<!-- haxset-findings` block wrote a FAKE mapping that the reader matched
 * first, so dismissing a trivial finding filed the CRITICAL one's fingerprint —
 * suppressing it on every future scan, permanently, with nothing anywhere
 * reporting a problem. An unterminated `<!--` is the same bug inverted: it opens
 * an HTML block that swallows every row up to the marker's `-->`, hiding findings
 * from the reviewer while the machinery underneath keeps working.
 *
 * Escaping `<` closes both. Newlines are preserved — unlike `safeProse`, this text
 * is meant to be readable prose in the comment body.
 */
// The "not fully scanned" lists are joined onto ONE line, and a fork
// contributor chooses filenames — so both the COUNT and each entry are bounded.
// Unbounded, that single line pushed the comment past GitHub's limit and, worse,
// past `truncateBody`'s tail budget.
const MAX_LISTED_PATHS = 50;

function pathList(paths) {
  const all = paths || [];
  const shown = all.slice(0, MAX_LISTED_PATHS)
    .map((f) => '`' + safeText(String(f), 200) + '`').join(', ');
  return all.length > MAX_LISTED_PATHS
    ? `${shown} … and ${all.length - MAX_LISTED_PATHS} more` : shown;
}

function safeText(value, cap = 8000) {
  let out = String(value === undefined || value === null ? '' : value)
    .replace(/</g, '&lt;');
  if (out.length > cap) out = `${out.slice(0, cap - 1).trimEnd()}…`;
  return out;
}

const EMO = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

/**
 * Pull an artifact's entry list, tolerating an older backend.
 *
 * The `|| fallback` shape keeps this action working against a backend that still
 * shipped secrets/IaC inside `findings` behind a `finding_type` discriminator.
 * Harmless against a current backend (the artifact keys are always present), and
 * it means the action and the backend can be rolled out in either order.
 */
function artifactEntries(artifact, key) {
  return artifact && Array.isArray(artifact[key]) ? artifact[key] : null;
}

/** Split a scan response into its four families. */
function splitFamilies(data) {
  const all = data.findings || [];
  const secrets = artifactEntries(data.secrets, 'findings')
    || all.filter((f) => f && f.finding_type === 'secret');
  const iac = artifactEntries(data.iac, 'findings')
    || all.filter((f) => f && f.finding_type === 'iac');
  const findings = all.filter(
    (f) => !f || (f.finding_type !== 'secret' && f.finding_type !== 'iac'),
  );
  const sca = (data.sca && data.sca.vulnerabilities) || [];
  return { all, findings, secrets, iac, sca };
}

function loc(f) {
  return `${f.file_path}${f.line_number ? ':' + f.line_number : ''}`;
}

/** The one-line badge appended to a finding's summary row. */
function rowBadges(f) {
  let out = '';
  if (f.is_custom) out += ' · 🛡️ Haxset';
  if (f.triage === 'true_finding') out += ' · ✅ confirmed';
  // The reviewer needs to know a committable fix exists BEFORE expanding the row,
  // otherwise the suggestion sitting inline on the diff reads as unrelated.
  if (f.fix && Array.isArray(f.fix.replacement_lines) && f.fix.replacement_lines.length) {
    out += f.fix.verified ? ' · 🛠️ verified fix' : ' · 🛠️ fix available';
  }
  return out;
}

/**
 * Render one finding family as a collapsible section.
 *
 * `annotate` emits a GitHub check annotation so the finding also appears on the
 * Files-changed tab, which is where a reviewer actually reads code.
 */
function renderFamily({ title, open, items, prefix, core, markerLines, extra }) {
  if (!items.length) return '';
  let body = `<details open>\n<summary><b>${title}</b></summary>\n\n`;
  items.forEach((f, idx) => {
    const id = `${prefix}${idx + 1}`;
    const sev = (f.severity || '').toUpperCase();
    body += `<details>\n<summary>${EMO[f.severity] || '⚪'} <b>${sev}</b> <code>${id}</code>`
      + ` - ${safeText(f.title, 300)} (<code>${safeText(loc(f), 300)}</code>)`
      + `${rowBadges(f)}</summary>\n\n`;
    if (extra) body += extra(f);
    if (f.description) body += `${safeText(f.description)}\n\n`;
    if (f.remediation) body += `**Fix:** ${safeText(f.remediation)}\n\n`;
    if (f.fix && f.fix.verified) {
      body += '> ✅ A verified one-click fix for this is attached to the diff above.\n\n';
    }
    body += '</details>\n\n';
    if (f.fingerprint) markerLines.push(`${id} ${f.fingerprint}`);
    if (f.file_path) {
      core.warning(`${sev}: ${safeText(f.title, 300)}`, {
        title: 'Haxset Security Scanner',
        file: f.file_path,
        startLine: f.line_number || 1,
      });
    }
  });
  return body + '</details>\n\n';
}

/** The re-check ("/haxset check") block: is each prior finding fixed? */
function renderRecheck(data, all) {
  const sum = data.recheck_summary
    || { total: all.length, fixed: 0, not_fixed: all.length, triaged: 0 };
  if (all.length === 0) {
    return (data.message || 'Re-check complete - no prior findings to verify.') + '\n';
  }
  const triagedTotal = sum.triaged || 0;
  let body = `<details open>\n<summary><b>Re-check: ${sum.fixed}/${sum.total} fixed`
    + `${triagedTotal ? ` · ${triagedTotal} triaged` : ''}</b></summary>\n\n`;
  for (const f of all) {
    const sev = (f.severity || '').toUpperCase();
    // A finding the team triaged is shown with a green check and its triage label,
    // never as "still present" — the team already made that decision.
    const triaged = f.status === 'triaged'
      || f.triage === 'false_positive' || f.triage === 'accepted_risk';
    const ok = f.status === 'fixed';
    let icon;
    let label;
    if (triaged) {
      icon = '✅';
      label = f.triage === 'accepted_risk' ? 'ACCEPTED RISK' : 'FALSE POSITIVE';
    } else if (ok) { icon = '✅'; label = 'FIXED'; } else { icon = '⚠️'; label = 'STILL PRESENT'; }
    body += `<details>\n<summary>${icon} <b>${label}</b> - ${EMO[f.severity] || '⚪'} ${sev} `
      + `${safeText(f.title, 300)} (<code>${safeText(loc(f), 300)}</code>)</summary>\n\n`;
    if (f.recheck_note) body += `${safeText(f.recheck_note)}\n\n`;
    if (!ok && !triaged && f.remediation) body += `**Fix:** ${safeText(f.remediation)}\n\n`;
    body += '</details>\n\n';
  }
  return body + '</details>\n\n';
}

/** Dependencies render slightly differently — no file, no line, a version pair. */
function renderSca(sca, markerLines) {
  if (!sca.length) return '';
  const advisories = sca.reduce((n, v) => n + (v.vuln_count || 1), 0);
  let body = `<details open>\n<summary><b>📦 ${sca.length} vulnerable dependenc`
    + `${sca.length === 1 ? 'y' : 'ies'} (${advisories} advisories)</b></summary>\n\n`;
  sca.forEach((v, idx) => {
    const id = `D${idx + 1}`;
    const cnt = v.vuln_count || (v.cves ? v.cves.length : 1);
    const sev = (v.severity || '').toUpperCase();
    const upgrade = v.fixed_version && v.fixed_version !== '-'
      ? `, upgrade to \`${safeText(v.fixed_version, 100)}\`` : '';
    const cves = (v.cves && v.cves.length ? v.cves : (v.cve && v.cve !== '-' ? [v.cve] : []));
    const confirmed = v.triage === 'true_finding' ? ' · ✅ confirmed' : '';
    body += `<details>\n<summary>${EMO[v.severity] || '⚪'} <b>${sev}</b> <code>${id}</code>`
      + ` - <code>${safeText(v.package, 200)}@${safeText(v.current_version, 100)}</code>`
      + ` (${cnt} known vuln`
      + `${cnt === 1 ? '' : 's'})${confirmed}</summary>\n\n`;
    body += `${cnt} known vulnerabilit${cnt === 1 ? 'y' : 'ies'}${upgrade}.\n\n`;
    if (cves.length) body += `${safeText(cves.join(', '), 2000)}\n\n`;
    body += '</details>\n\n';
    if (v.fingerprint) markerLines.push(`${id} ${v.fingerprint}`);
  });
  return body + '</details>\n\n';
}

/**
 * Build the whole summary comment.
 *
 * @param {object} opts {data, bypassed, core, suggestionFallback}
 * @returns {{body: string, families: object, markerLines: string[]}}
 */
function buildComment({ data, bypassed, refused, core, suggestionFallback }) {
  const families = splitFamilies(data);
  const { all, findings, secrets, iac, sca } = families;
  const markerLines = [];
  let body = '## Haxset Security Scanner\n\n';

  if (data.recheck) {
    body += renderRecheck(data, all);
  } else if (!data.relevant) {
    body += '✅ No security-relevant code changes detected in this PR.\n';
  } else if (!findings.length && !secrets.length && !iac.length && !sca.length) {
    // ⚠️ Every family must be counted here. Secrets and IaC do not live in
    // `findings`, so testing only that would report a PR whose sole problem is a
    // leaked credential as "no issues found".
    body += data.suppressed_count
      ? `✅ No new issues. ${data.suppressed_count} previously-triaged finding(s) are `
        + 'hidden (false positive / accepted risk).\n'
      : '✅ Scanned the changed code - no issues found.\n';
  } else {
    body += renderFamily({
      title: `🔑 ${secrets.length} hardcoded secret${secrets.length === 1 ? '' : 's'}`,
      items: secrets, prefix: 'S', core, markerLines,
      extra: (f) => {
        // The snippet is redacted by the backend's secret scanner — the raw
        // credential never leaves it.
        // Fenced by width, like every other block: redaction removes the
        // credential, not the backticks, so a snippet containing a fence would
        // otherwise escape and inject markdown into the vendor's comment.
        const snipFence = fenceFor(String(f.code_snippet || '').split('\n'));
        let out = f.code_snippet
          ? snipFence + '\n' + String(f.code_snippet).slice(0, 2000) + '\n' + snipFence + '\n\n' : '';
        out += '> ⚠️ **Rotate this credential.** Removing it from the code does not '
          + 'revoke it, and it remains in this repository\'s git history.\n\n';
        return out;
      },
    });
    body += renderFamily({
      title: `${findings.length} code finding(s)`,
      items: findings, prefix: 'F', core, markerLines,
      extra: (f) => (f.cwe_id ? `**${safeText(f.cwe_id, 100)}**\n\n` : ''),
    });
    const custom = iac.filter((f) => f && f.is_custom).length;
    body += renderFamily({
      title: `⚙️ ${iac.length} infrastructure misconfiguration`
        + `${iac.length === 1 ? '' : 's'}${custom ? ` · ${custom} Haxset custom` : ''}`,
      items: iac, prefix: 'I', core, markerLines,
      extra: (f) => {
        const meta = [f.rule_id, f.category, f.resource].filter(Boolean);
        return meta.length
          ? meta.map((m) => `\`${safeText(m, 200)}\``).join(' · ') + '\n\n' : '';
      },
    });
    if (data.suppressed_count) {
      body += `<sub>${data.suppressed_count} other finding(s) hidden by triage `
        + '(false positive / accepted risk).</sub>\n\n';
    }
  }

  body += renderSca(sca, markerLines);

  // Fork-PR fallback: the fixes we could not offer as one-click suggestions.
  if (suggestionFallback) body += suggestionFallback;

  // The hidden marker and the triage hint come after EVERY section so they cover
  // all four label families in one block.
  if (markerLines.length) {
    body += `<!-- haxset-findings\n${markerLines.join('\n')}\n-->\n\n`;
    body += '> **Triage from the PR:** `/haxset fp F1` (false positive) · '
      + '`/haxset accept F1` (accepted risk) · `/haxset confirm F1` (true finding) · '
      + '`/haxset fix F1` (get a one-click fix). Works for `F#` code findings, '
      + '`S#` secrets, `I#` misconfigurations and `D#` dependencies alike; '
      + 'false-positive / accepted items are hidden on the next `/haxset scan`.\n\n';
  }

  // `refused` belongs here with `bypassed`: a path we declined to upload was NOT
  // scanned, and a summary that says "no issues found" while silently omitting a
  // file is a coverage claim this product must never make.
  const notScanned = []
    .concat(bypassed || [], refused || [], data.unscanned_files || [],
      data.truncated_files || []);
  if (notScanned.length) {
    body += `<details>\n<summary>⚠️ ${notScanned.length} file(s) not fully scanned</summary>\n\n`;
    if ((bypassed || []).length) {
      body += `Bypassed (>= 100 MB): ${pathList(bypassed)}\n\n`;
    }
    if ((refused || []).length) {
      body += 'Not uploaded (not a regular file inside the checkout - symlinks are never '
        + `followed): ${pathList(refused)}\n\n`;
    }
    if ((data.unscanned_files || []).length) {
      body += 'Not scanned (exceeded scan budget): '
        + `${pathList(data.unscanned_files)}\n\n`;
    }
    if ((data.truncated_files || []).length) {
      body += 'Partially scanned (truncated): '
        + `${pathList(data.truncated_files)}\n\n`;
    }
    body += 'Contact support@haxset.com for a full review of large diffs.\n\n</details>\n\n';
  }

  body += '\n<sub>Non-blocking check, powered by Haxset Security Scanner</sub>';
  return { body, families, markerLines };
}

module.exports = {
  EMO, artifactEntries, splitFamilies, buildComment, renderFamily, renderSca, safeText,
};
