'use strict';

/**
 * Action inputs, resolved once.
 *
 * Every value arrives as an environment variable set by `action.yml` from a
 * declared input, so a customer's workflow configures this action the same way it
 * configures any other one. The defaults reproduce the values the previous inline
 * template read from `vars.HAXSET_*`, so a repository migrating from that template
 * to this action changes nothing about how it behaves.
 */

/** @param {string} name @param {string} fallback */
function env(name, fallback) {
  const raw = process.env[name];
  return raw === undefined || raw === null || raw === '' ? fallback : String(raw);
}

/** A checkbox-style input. Anything but an explicit falsy word is on. */
function envBool(name, fallback) {
  const raw = env(name, fallback ? 'true' : 'false').trim().toLowerCase();
  return !['false', '0', 'no', 'off', ''].includes(raw);
}

function loadConfig() {
  const endpoint = env('HAXSET_ENDPOINT', 'https://app.haxset.com/api/ci/scan')
    .replace(/\/+$/, '');
  return {
    token: env('HAXSET_TOKEN', ''),
    endpoint,
    // Both derived from the one configured endpoint so a self-hosted deployment
    // only ever has to set a single URL.
    triageEndpoint: endpoint.replace(/\/scan$/, '/triage'),
    repoScanEndpoint: endpoint.replace(/\/scan$/, '/repo-scan'),
    pollMinutes: Math.max(1, Number(env('HAXSET_POLL_MINUTES', '60')) || 60),
    startAttempts: Math.max(1, Number(env('HAXSET_START_RETRIES', '4')) || 4),
    scanMode: env('HAXSET_SCAN_MODE', 'thorough'),
    notify: env('HAXSET_NOTIFY', ''),
    suggestions: envBool('HAXSET_SUGGESTIONS', true),
  };
}

module.exports = { loadConfig };
