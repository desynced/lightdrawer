#!/usr/bin/env node
// Operator fallback: run the same CT tick against remote D1 + Cloudflare DNS
// using credentials from the environment (CF_DNS_TOKEN, or CLOUDFLARE_API_TOKEN
// as a last resort for a rehearsal on a trusted machine). Never prints secrets.
// The Worker cron is the normal issuer once CF_DNS_TOKEN is set as a Worker secret.
import { runCtTick } from '../src/ct-runtime.js';

function remoteD1({ accountId, databaseId, token }) {
  async function query(sql, params = []) {
    const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}/query`, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
      body: JSON.stringify({ sql, params }),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.success === false) {
      const msg = (j.errors && j.errors[0] && j.errors[0].message) || ('HTTP ' + r.status);
      throw new Error('D1 query failed: ' + msg);
    }
    return (j.result || [])[0] || { results: [] };
  }
  return {
    prepare(sql) {
      const exec = (...params) => ({
        async first() { return ((await query(sql, params)).results || [])[0] || null; },
        async all() { return { results: (await query(sql, params)).results || [] }; },
        async run() { await query(sql, params); return { success: true }; },
      });
      return Object.assign(exec(), { bind(...params) { return exec(...params); } });
    },
  };
}

const force = process.argv.includes('--force');
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const databaseId = process.env.CT_DB_ID;
const token = process.env.CF_DNS_TOKEN || process.env.CLOUDFLARE_API_TOKEN;
for (const [k, v] of Object.entries({ CLOUDFLARE_ACCOUNT_ID: accountId, CT_DB_ID: databaseId, CF_ZONE_ID: process.env.CF_ZONE_ID })) {
  if (!v) { console.error(`Set ${k}`); process.exit(2); }
}
if (!token) {
  console.error('Set CF_DNS_TOKEN (preferred) or CLOUDFLARE_API_TOKEN');
  process.exit(2);
}
const env = {
  CT_DB: remoteD1({ accountId, databaseId, token }),
  CF_DNS_TOKEN: token,
  CF_ZONE_ID: process.env.CF_ZONE_ID,
  ACME_DIRECTORY: process.env.ACME_DIRECTORY || 'https://acme-staging-v02.api.letsencrypt.org/directory',
  CT_HOSTNAME_SUFFIX: 'ct.lightdrawer.org',
};
const summary = await runCtTick(env, { force, includeOpen: force });
console.log(JSON.stringify(summary, null, 2));
if (!summary.ok) process.exit(1);
