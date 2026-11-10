// Refresh trust/ct-logs.json from Chrome's v3 Certificate Transparency log list.
// The verifier stays offline: this script is maintenance-only and is never
// called at verify time.
//
//   node scripts/refresh-ct-logs.mjs
//
// Collects both RFC 6962 `logs` and static-ct-api `tiled_logs`. Keeps usable,
// qualified, readonly, and retired shards (retired keys still verify older
// SCTs). Drops rejected/pending logs and the dummy "bogus placeholder" entries
// some operators publish so broken clients do not fall over.
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';
const KEEP = new Set(['usable', 'qualified', 'readonly', 'retired']);
const BOGUS = /bogus|placeholder|unbreak misbehaving/i;

function stateOf(log) {
  const st = log.state;
  if (!st || typeof st !== 'object') return '';
  return Object.keys(st)[0] || '';
}

function pickLogs(operator, list, api) {
  const out = [];
  for (const log of list || []) {
    const description = log.description || '';
    if (BOGUS.test(description)) continue;
    const state = stateOf(log);
    if (!KEEP.has(state)) continue;
    if (!log.key || !log.log_id) continue;
    out.push({
      operator,
      name: description,
      log_id: log.log_id,
      key: log.key,
      url: log.url || log.submission_url || log.monitoring_url || '',
      mmd: log.mmd,
      state,
      api,
      temporal_interval: log.temporal_interval || undefined,
    });
  }
  return out;
}

const res = await fetch(SOURCE, { headers: { 'user-agent': 'lightdrawer-refresh-ct-logs' } });
if (!res.ok) throw new Error('fetch failed: HTTP ' + res.status);
const body = await res.json();
const logs = [];
for (const op of body.operators || []) {
  const name = op.name || '';
  logs.push(...pickLogs(name, op.logs, 'rfc6962'));
  logs.push(...pickLogs(name, op.tiled_logs, 'static-ct-api'));
}
logs.sort((a, b) => (a.operator + '\0' + a.name).localeCompare(b.operator + '\0' + b.name));

const snapshot = {
  source: SOURCE,
  fetched_at: new Date().toISOString(),
  fetched_note: 'Snapshot of usable, qualified, readonly, and retired logs (RFC 6962 and static-ct-api tiled logs) for offline SCT signature checks. Refresh with: node scripts/refresh-ct-logs.mjs',
  log_list_version: body.version || null,
  log_list_timestamp: body.log_list_timestamp || null,
  logs,
};
const dest = join(dirname(fileURLToPath(import.meta.url)), '..', 'trust', 'ct-logs.json');
writeFileSync(dest, JSON.stringify(snapshot, null, 2) + '\n');
const byState = {};
for (const log of logs) byState[log.state] = (byState[log.state] || 0) + 1;
const tiled = logs.filter((l) => l.api === 'static-ct-api').length;
console.log(`wrote ${logs.length} logs (${tiled} tiled) to trust/ct-logs.json`);
console.log('by state:', byState);
console.log('list version', snapshot.log_list_version, 'timestamp', snapshot.log_list_timestamp);
