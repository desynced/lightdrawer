import {
  lookupStampDedup,
  parseStampDedupMs,
  pruneStampDedup,
  STAMP_DEDUP_DEFAULT_MS,
  STAMP_DEDUP_ERROR,
  stampDedupRetryAfterSeconds,
  stampResultIsCacheable,
  storeStampDedup,
} from '../src/stamp-dedup.js';
import { generateStampKeyRecord } from '../src/stamp-keys.js';
import worker from '../src/worker.js';

const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const DIGEST_B = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const IP = '203.0.113.77';

function memoryD1({ keys = [] } = {}) {
  const state = {
    keys: [...keys],
    pending: [],
    dedup: new Map(),
    meta: {},
    usage: [],
  };
  return {
    state,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() {
              if (/FROM stamp_keys/.test(sql)) {
                return state.keys.find((r) => r.key_hash === params[0]) || null;
              }
              if (/FROM stamp_dedup/.test(sql)) {
                const row = state.dedup.get(params[0]);
                return row ? { ...row } : null;
              }
              if (/FROM ct_meta/.test(sql)) {
                const key = params[0];
                return Object.prototype.hasOwnProperty.call(state.meta, key)
                  ? { key, value: state.meta[key] }
                  : null;
              }
              if (/INSERT INTO mcp_lane_usage/.test(sql)) {
                let kind;
                let keyId;
                let bucket;
                if (/VALUES \('ip'/.test(sql)) {
                  kind = 'ip';
                  keyId = params[0];
                  bucket = params[1];
                } else {
                  kind = 'global';
                  keyId = 'all';
                  bucket = params[0];
                }
                let row = state.usage.find((r) => r.key_kind === kind && r.key_id === keyId && r.bucket === bucket);
                if (!row) {
                  row = { key_kind: kind, key_id: keyId, bucket, count: 1 };
                  state.usage.push(row);
                } else {
                  row.count += 1;
                }
                return { count: row.count };
              }
              return null;
            },
            async run() {
              if (/INSERT OR IGNORE INTO ct_pending/.test(sql)) {
                if (!state.pending.some((r) => r.digest === params[0])) {
                  state.pending.push({ digest: params[0], received_at: params[1] });
                }
                return { success: true };
              }
              if (/INSERT INTO stamp_dedup/.test(sql)) {
                state.dedup.set(params[0], {
                  digest: params[0],
                  last_ok_at: params[1],
                  ots_json: params[2],
                  tsr: params[3],
                });
                return { success: true };
              }
              if (/DELETE FROM stamp_dedup/.test(sql)) {
                for (const [digest, row] of [...state.dedup.entries()]) {
                  if (row.last_ok_at < params[0]) state.dedup.delete(digest);
                }
                return { success: true };
              }
              if (/DELETE FROM mcp_lane_usage/.test(sql)) {
                return { success: true };
              }
              return { success: true };
            },
          };
        },
      };
    },
  };
}

function mockLimiter() {
  return { async limit() { return { success: true }; } };
}

export async function runStampDedupTests(ok) {
  console.log('Same-digest stamp cooldown');

  ok(parseStampDedupMs({}) === STAMP_DEDUP_DEFAULT_MS, 'missing STAMP_DEDUP_MS defaults to 1 hour');
  ok(parseStampDedupMs({ STAMP_DEDUP_MS: '3600000' }) === 3600000, 'STAMP_DEDUP_MS parses milliseconds');
  ok(parseStampDedupMs({ STAMP_DEDUP_MS: '0' }) === 0, 'STAMP_DEDUP_MS=0 turns the cooldown off');
  ok(parseStampDedupMs({ STAMP_DEDUP_MS: 'nope' }) === STAMP_DEDUP_DEFAULT_MS, 'invalid STAMP_DEDUP_MS falls back to default');
  ok(stampDedupRetryAfterSeconds(1_000, 3_600_000, 1_000 + 3_600_000 - 2500) === 3, 'Retry-After is seconds until the cooldown ends');
  ok(stampResultIsCacheable({ a: 'AQIDBA==' }, null) === true, 'a calendar result is cacheable');
  ok(stampResultIsCacheable({}, 'AQID') === true, 'a FreeTSA result alone is cacheable');
  ok(stampResultIsCacheable({}, null) === false, 'an empty failure is not cacheable');

  const helperDb = memoryD1();
  const now = 1_700_000_000_000;
  const stored = await storeStampDedup(
    { CT_DB: helperDb, STAMP_DEDUP_MS: '60000' },
    DIGEST,
    { ots: { 'https://a.pool.opentimestamps.org': 'AQIDBA==' }, tsr: null },
    now,
  );
  ok(stored.stored === true, 'store writes a digest-only cooldown row');
  ok(!JSON.stringify([...helperDb.state.dedup.values()]).includes(IP), 'dedup rows never contain an IP');
  const hit = await lookupStampDedup({ CT_DB: helperDb, STAMP_DEDUP_MS: '60000' }, DIGEST, now + 1000);
  ok(hit.hit === true && hit.body && hit.body.ots['https://a.pool.opentimestamps.org'] === 'AQIDBA==', 'lookup returns the cached { ots, tsr, errors } body');
  ok(Array.isArray(hit.body.errors) && hit.body.errors.length === 0, 'cached body uses an empty errors list');
  const miss = await lookupStampDedup({ CT_DB: helperDb, STAMP_DEDUP_MS: '60000' }, DIGEST, now + 60000);
  ok(miss.hit === false, 'lookup misses after the cooldown window');
  const off = await lookupStampDedup({ CT_DB: helperDb, STAMP_DEDUP_MS: '0' }, DIGEST, now + 1000);
  ok(off.hit === false, 'lookup is a miss when STAMP_DEDUP_MS is 0');

  helperDb.state.dedup.set(DIGEST, { digest: DIGEST, last_ok_at: now, ots_json: null, tsr: null });
  const bare = await lookupStampDedup({ CT_DB: helperDb, STAMP_DEDUP_MS: '60000' }, DIGEST, now + 1000);
  ok(bare.hit === true && !bare.body && bare.retryAfter === 59, 'cooldown without a cached payload reports Retry-After');

  await pruneStampDedup({ CT_DB: helperDb, STAMP_DEDUP_MS: '60000' }, now + 60001);
  ok(!helperDb.state.dedup.has(DIGEST), 'prune deletes rows whose cooldown has ended');

  const savedFetch = globalThis.fetch;
  let calendarCalls = 0;
  let turnstileCalls = 0;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('challenges.cloudflare.com/turnstile')) {
      turnstileCalls++;
      return Response.json({ success: true });
    }
    if (u.includes('/digest') || u.includes('freetsa.org')) {
      calendarCalls++;
      return new Response(new Uint8Array([1, 2, 3, 4]), { status: 200, headers: { 'content-type': 'application/octet-stream' } });
    }
    throw new Error('unexpected fetch: ' + u);
  };

  try {
    const rec = await generateStampKeyRecord('dedup-test');
    const keys = [{ id: rec.id, label: rec.label, key_hash: rec.key_hash, revoked_at: null }];
    const db = memoryD1({ keys });
    const env = {
      STAMP_DEDUP_MS: '3600000',
      TURNSTILE_SECRET: 'test-turnstile-secret',
      CT_DB: db,
      STAMP_LIMITER: mockLimiter(),
      STAMP_AUTH_LIMITER: mockLimiter(),
      MCP_STAMP_LIMITER: mockLimiter(),
      MCP_LANE: 'on',
      MCP_IP_SALT: 'test-mcp-ip-salt',
      MCP_LIMIT_IP_HOUR: '0',
      MCP_LIMIT_GLOBAL_DAY: '0',
    };

    const keyedStamp = (digest, requestEnv = env) => worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer ' + rec.token,
      },
      body: JSON.stringify({ digest }),
    }), requestEnv, { waitUntil() {} });

    calendarCalls = 0;
    const first = await keyedStamp(DIGEST);
    const firstBody = await first.json();
    const firstCalendars = calendarCalls;
    ok(first.status === 200 && firstBody.ots && Object.keys(firstBody.ots).length > 0, 'first keyed stamp succeeds and returns ots');
    ok(firstCalendars > 0, 'first keyed stamp hits calendars');
    ok(db.state.dedup.has(DIGEST), 'successful stamp records the digest cooldown');

    calendarCalls = 0;
    const second = await keyedStamp(DIGEST);
    const secondBody = await second.json();
    ok(second.status === 200, 'second keyed stamp of the same digest succeeds from cache');
    ok(calendarCalls === 0, 'second keyed stamp of the same digest does not hit calendars');
    ok(JSON.stringify(secondBody.ots) === JSON.stringify(firstBody.ots) && secondBody.tsr === firstBody.tsr, 'cached stamp returns the same ots/tsr payload');
    ok(JSON.stringify(Object.keys(secondBody).sort()) === JSON.stringify(['errors', 'ots', 'tsr']), 'cached stamp keeps the { ots, tsr, errors } shape');

    calendarCalls = 0;
    const other = await keyedStamp(DIGEST_B);
    ok(other.status === 200 && calendarCalls > 0, 'a different digest is not blocked by the cooldown');

    calendarCalls = 0;
    const offEnv = { ...env, STAMP_DEDUP_MS: '0', CT_DB: memoryD1({ keys }) };
    const off1 = await keyedStamp(DIGEST, offEnv);
    const off1Calls = calendarCalls;
    calendarCalls = 0;
    const off2 = await keyedStamp(DIGEST, offEnv);
    ok(off1.status === 200 && off2.status === 200 && off1Calls > 0 && calendarCalls > 0, 'STAMP_DEDUP_MS=0 always goes upstream');
    ok(offEnv.CT_DB.state.dedup.size === 0, 'cooldown off stores no dedup rows');

    turnstileCalls = 0;
    calendarCalls = 0;
    const browserDb = memoryD1({ keys });
    const browserEnv = { ...env, CT_DB: browserDb };
    const browserStamp = (digest) => worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ digest, turnstile: 'ok-token' }),
    }), browserEnv, { waitUntil() {} });
    const b1 = await browserStamp(DIGEST);
    const b1Calls = calendarCalls;
    calendarCalls = 0;
    const b2 = await browserStamp(DIGEST);
    ok(b1.status === 200 && b2.status === 200 && turnstileCalls === 2, 'Turnstile /api/stamp still runs the human check before cooldown');
    ok(b1Calls > 0 && calendarCalls === 0, 'Turnstile /api/stamp honors the same-digest cooldown');

    calendarCalls = 0;
    const mcpDb = memoryD1({ keys });
    const mcpEnv = { ...env, CT_DB: mcpDb };
    const mcpStamp = (digest) => worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': IP },
      body: JSON.stringify({ digest }),
    }), mcpEnv, { waitUntil() {} });
    const m1 = await mcpStamp(DIGEST);
    const m1Body = await m1.json();
    const m1Calls = calendarCalls;
    calendarCalls = 0;
    const m2 = await mcpStamp(DIGEST);
    const m2Body = await m2.json();
    ok(m1.status === 200 && m1Calls > 0, 'MCP stamp hits calendars on the first digest');
    ok(m2.status === 200 && calendarCalls === 0, 'MCP stamp reuses the cooldown cache on a repeat digest');
    ok(JSON.stringify(m2Body.ots) === JSON.stringify(m1Body.ots), 'MCP cached stamp returns the same ots payload');
    ok(JSON.stringify(mcpDb.state).includes(IP) === false, 'MCP cooldown path still stores no raw IP');

    // Shared cooldown across lanes: keyed stamp then MCP of the same digest.
    calendarCalls = 0;
    const sharedDb = memoryD1({ keys });
    const sharedEnv = { ...env, CT_DB: sharedDb };
    const sharedKeyed = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST }),
    }), sharedEnv, { waitUntil() {} });
    ok(sharedKeyed.status === 200 && calendarCalls > 0, 'shared cooldown: keyed stamp goes upstream first');
    calendarCalls = 0;
    const sharedMcp = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': IP },
      body: JSON.stringify({ digest: DIGEST }),
    }), sharedEnv, { waitUntil() {} });
    ok(sharedMcp.status === 200 && calendarCalls === 0, 'shared cooldown: MCP reuses a keyed stamp cache');

    // Cooldown hit with no usable cached body → 429 + Retry-After.
    const bareDb = memoryD1({ keys });
    bareDb.state.dedup.set(DIGEST, {
      digest: DIGEST,
      last_ok_at: Date.now() - 1000,
      ots_json: '{not-json',
      tsr: null,
    });
    const limited = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST }),
    }), { ...env, CT_DB: bareDb }, { waitUntil() {} });
    const limitedBody = await limited.json();
    const retryAfter = Number(limited.headers.get('retry-after'));
    ok(limited.status === 429 && limitedBody.error === STAMP_DEDUP_ERROR, 'cooldown without a cached body returns 429 JSON error');
    ok(Number.isFinite(retryAfter) && retryAfter > 0 && retryAfter <= 3600, '429 includes Retry-After seconds until the cooldown ends');
    ok(JSON.stringify(Object.keys(limitedBody)) === JSON.stringify(['error']), '429 body is only { error }');
  } finally {
    globalThis.fetch = savedFetch;
  }
}
