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
// RFC 3161 TimeStampReq for DIGEST (SHA-256 of the empty file), from HOW-IT-WORKS.md.
const TSQ = 'MHsCAQEwMTANBglghkgBZQMEAgEFAAQg47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFWgCQIBAf8EBQEB/wEBhAMhAP8=';
const FREETSA_TSR = 'BQYHCA==';
const CALENDAR_URLS = new Set([
  'https://a.pool.opentimestamps.org/digest',
  'https://b.pool.opentimestamps.org/digest',
  'https://a.pool.eternitywall.com/digest',
]);

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
              if (/UPDATE stamp_dedup SET tsr = \? WHERE digest = \?/.test(sql)) {
                const row = state.dedup.get(params[1]);
                if (row) row.tsr = params[0];
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
  let freetsaCalls = 0;
  let turnstileCalls = 0;
  let freetsaStatus = 200;
  const unexpectedFetches = [];
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u === 'https://challenges.cloudflare.com/turnstile/v0/siteverify') {
      turnstileCalls++;
      return Response.json({ success: true });
    }
    if (CALENDAR_URLS.has(u)) {
      calendarCalls++;
      return new Response(new Uint8Array([1, 2, 3, 4]), { status: 200, headers: { 'content-type': 'application/octet-stream' } });
    }
    if (u === 'https://freetsa.org/tsr') {
      freetsaCalls++;
      if (freetsaStatus !== 200) return new Response('no', { status: freetsaStatus });
      return new Response(new Uint8Array([5, 6, 7, 8]), { status: 200, headers: { 'content-type': 'application/timestamp-reply' } });
    }
    unexpectedFetches.push(u);
    throw new Error('refusing unexpected fetch: ' + u);
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
    freetsaCalls = 0;
    const second = await keyedStamp(DIGEST);
    const secondBody = await second.json();
    ok(second.status === 200, 'second keyed stamp of the same digest succeeds from cache');
    ok(calendarCalls === 0 && freetsaCalls === 0, 'second keyed stamp of the same digest does not hit calendars or FreeTSA');
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
    freetsaCalls = 0;
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
    const m1Tsa = freetsaCalls;
    calendarCalls = 0;
    freetsaCalls = 0;
    const m2 = await mcpStamp(DIGEST);
    const m2Body = await m2.json();
    ok(m1.status === 200 && m1Calls > 0 && m1Tsa === 0, 'MCP stamp hits calendars on the first digest and skips FreeTSA without tsq');
    ok(m2.status === 200 && calendarCalls === 0 && freetsaCalls === 0, 'MCP stamp reuses the cooldown cache on a repeat digest');
    ok(JSON.stringify(m2Body.ots) === JSON.stringify(m1Body.ots), 'MCP cached stamp returns the same ots payload');
    ok(JSON.stringify(mcpDb.state).includes(IP) === false, 'MCP cooldown path still stores no raw IP');

    // Shared cooldown across lanes: keyed stamp then MCP of the same digest.
    calendarCalls = 0;
    freetsaCalls = 0;
    const sharedDb = memoryD1({ keys });
    const sharedEnv = { ...env, CT_DB: sharedDb };
    const sharedKeyed = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST }),
    }), sharedEnv, { waitUntil() {} });
    ok(sharedKeyed.status === 200 && calendarCalls > 0 && freetsaCalls === 0, 'shared cooldown: keyed stamp goes upstream first');
    calendarCalls = 0;
    freetsaCalls = 0;
    const sharedMcp = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': IP },
      body: JSON.stringify({ digest: DIGEST }),
    }), sharedEnv, { waitUntil() {} });
    ok(sharedMcp.status === 200 && calendarCalls === 0 && freetsaCalls === 0, 'shared cooldown: MCP reuses a keyed stamp cache');

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

    calendarCalls = 0;
    freetsaCalls = 0;
    const limitedTsq = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST, tsq: TSQ }),
    }), { ...env, CT_DB: bareDb }, { waitUntil() {} });
    ok(limitedTsq.status === 429 && calendarCalls === 0 && freetsaCalls === 0, 'unparseable cached ots stays 429 and does not call FreeTSA');

    const keyedWithTsq = (digest, tsq, requestEnv) => worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer ' + rec.token,
      },
      body: JSON.stringify(tsq ? { digest, tsq } : { digest }),
    }), requestEnv, { waitUntil() {} });

    // no-tsq cache, then the same digest with tsq: calendars stay cached, FreeTSA runs once.
    freetsaStatus = 200;
    const fillDb = memoryD1({ keys });
    const fillEnv = { ...env, CT_DB: fillDb };
    calendarCalls = 0;
    freetsaCalls = 0;
    const fillFirst = await keyedWithTsq(DIGEST, null, fillEnv);
    const fillFirstBody = await fillFirst.json();
    ok(fillFirst.status === 200 && fillFirstBody.tsr === null && calendarCalls === 3 && freetsaCalls === 0, 'no-tsq stamp calls calendars and skips FreeTSA');
    const fillRow = fillDb.state.dedup.get(DIGEST);
    const fillFrozen = Date.now() - 45_000;
    fillRow.last_ok_at = fillFrozen;
    const fillOtsJson = fillRow.ots_json;
    calendarCalls = 0;
    freetsaCalls = 0;
    const fillSecond = await keyedWithTsq(DIGEST, TSQ, fillEnv);
    const fillSecondBody = await fillSecond.json();
    const fillAfter = fillDb.state.dedup.get(DIGEST);
    ok(fillSecond.status === 200, 'tsq after a cached no-tsq stamp is HTTP 200');
    ok(calendarCalls === 0, 'tsq fill-in does not call calendars again');
    ok(freetsaCalls === 1, 'tsq fill-in calls FreeTSA');
    ok(JSON.stringify(fillSecondBody.ots) === JSON.stringify(fillFirstBody.ots), 'tsq fill-in returns the cached ots');
    ok(fillSecondBody.tsr === FREETSA_TSR, 'tsq fill-in returns the FreeTSA tsr');
    ok(Array.isArray(fillSecondBody.errors) && fillSecondBody.errors.length === 0, 'successful tsq fill-in has an empty errors list');
    ok(fillAfter.tsr === FREETSA_TSR && fillAfter.ots_json === fillOtsJson, 'tsq fill-in stores the tsr and leaves ots_json alone');
    ok(fillAfter.last_ok_at === fillFrozen, 'tsq fill-in does not change last_ok_at');
    ok(JSON.stringify(fillAfter).includes(IP) === false, 'tsr fill-in stores no raw IP');

    // Calendars succeed, FreeTSA fails, then a later tsq recovers the TSR.
    const retryDb = memoryD1({ keys });
    const retryEnv = { ...env, CT_DB: retryDb };
    freetsaStatus = 503;
    calendarCalls = 0;
    freetsaCalls = 0;
    const retryFirst = await keyedWithTsq(DIGEST, TSQ, retryEnv);
    const retryFirstBody = await retryFirst.json();
    ok(retryFirst.status === 200 && retryFirstBody.tsr === null && calendarCalls === 3 && freetsaCalls === 1, 'FreeTSA failure still returns the calendar ots');
    ok(retryFirstBody.errors.includes('FreeTSA: unavailable'), 'FreeTSA failure is listed in errors');
    ok(retryDb.state.dedup.has(DIGEST) && retryDb.state.dedup.get(DIGEST).tsr == null, 'a stamp with ots and no tsr is stored');
    const retryFrozen = Date.now() - 45_000;
    retryDb.state.dedup.get(DIGEST).last_ok_at = retryFrozen;
    calendarCalls = 0;
    freetsaCalls = 0;
    const retryFail = await keyedWithTsq(DIGEST, TSQ, retryEnv);
    const retryFailBody = await retryFail.json();
    ok(retryFail.status === 200 && calendarCalls === 0 && freetsaCalls === 1, 'failed tsr fill-in calls FreeTSA and not the calendars');
    ok(retryFailBody.tsr === null && JSON.stringify(retryFailBody.ots) === JSON.stringify(retryFirstBody.ots), 'failed tsr fill-in keeps the cached ots and tsr null');
    ok(retryFailBody.errors.includes('FreeTSA: unavailable'), 'failed tsr fill-in reports FreeTSA and stays HTTP 200');
    ok(retryDb.state.dedup.get(DIGEST).last_ok_at === retryFrozen && retryDb.state.dedup.get(DIGEST).tsr == null, 'failed tsr fill-in does not move last_ok_at or write a tsr');
    freetsaStatus = 200;
    calendarCalls = 0;
    freetsaCalls = 0;
    const retryOk = await keyedWithTsq(DIGEST, TSQ, retryEnv);
    const retryOkBody = await retryOk.json();
    ok(retryOk.status === 200 && calendarCalls === 0 && freetsaCalls === 1, 'a later tsq calls FreeTSA once and skips calendars');
    ok(retryOkBody.tsr === FREETSA_TSR && JSON.stringify(retryOkBody.ots) === JSON.stringify(retryFirstBody.ots), 'recovered stamp returns the cached ots plus the new tsr');
    ok(retryDb.state.dedup.get(DIGEST).tsr === FREETSA_TSR && retryDb.state.dedup.get(DIGEST).last_ok_at === retryFrozen, 'recovered tsr is stored without changing last_ok_at');

    // A complete { ots, tsr } cache serves both with-tsq and no-tsq callers.
    const fullDb = memoryD1({ keys });
    const fullEnv = { ...env, CT_DB: fullDb };
    freetsaStatus = 200;
    calendarCalls = 0;
    freetsaCalls = 0;
    const fullFirst = await keyedWithTsq(DIGEST, TSQ, fullEnv);
    const fullFirstBody = await fullFirst.json();
    ok(fullFirst.status === 200 && fullFirstBody.tsr === FREETSA_TSR && calendarCalls === 3 && freetsaCalls === 1, 'with-tsq stamp calls calendars and FreeTSA');
    calendarCalls = 0;
    freetsaCalls = 0;
    const fullAgain = await keyedWithTsq(DIGEST, TSQ, fullEnv);
    const fullAgainBody = await fullAgain.json();
    ok(fullAgain.status === 200 && calendarCalls === 0 && freetsaCalls === 0, 'cached tsr is not re-fetched for another tsq');
    ok(fullAgainBody.tsr === fullFirstBody.tsr && JSON.stringify(fullAgainBody.ots) === JSON.stringify(fullFirstBody.ots), 'second with-tsq request returns the cached tsr');
    const fullPlain = await keyedWithTsq(DIGEST, null, fullEnv);
    const fullPlainBody = await fullPlain.json();
    ok(fullPlain.status === 200 && calendarCalls === 0 && freetsaCalls === 0, 'no-tsq request does not call FreeTSA when a tsr is already cached');
    ok(fullPlainBody.tsr === fullFirstBody.tsr, 'no-tsq request receives the cached tsr');

    ok(unexpectedFetches.length === 0, 'stamp cooldown tests do not fetch a real URL' + (unexpectedFetches.length ? ': ' + unexpectedFetches.join(', ') : ''));
  } finally {
    globalThis.fetch = savedFetch;
  }
}
