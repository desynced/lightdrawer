import {
  consumeMcpLaneQuota,
  hashMcpIp,
  mcpLaneEnabledByEnv,
  mcpLaneLimits,
  MCP_LANE_DEFAULT_GLOBAL_DAY,
  MCP_LANE_DEFAULT_IP_HOUR,
  pruneMcpLaneUsage,
  secondsUntilNextUtcDay,
  secondsUntilNextUtcHour,
  utcDayString,
  utcHourString,
} from '../src/mcp-lane.js';
import worker from '../src/worker.js';

const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const IP = '203.0.113.50';
const OTHER_IP = '198.51.100.9';

function memoryD1({ meta = {} } = {}) {
  const state = {
    meta: { ...meta },
    usage: [],
    pending: [],
  };
  return {
    state,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() {
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
                state.pending.push({ digest: params[0], received_at: params[1] });
                return { success: true };
              }
              if (/DELETE FROM mcp_lane_usage/.test(sql)) {
                const [hour, day] = params;
                state.usage = state.usage.filter((r) => {
                  if (r.key_kind === 'ip') return r.bucket >= hour;
                  if (r.key_kind === 'global') return r.bucket >= day;
                  return true;
                });
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

function mockLimiter(seen, denyPrefix) {
  return {
    async limit({ key }) {
      seen.push(key);
      if (denyPrefix && key.startsWith(denyPrefix)) return { success: false };
      return { success: true };
    },
  };
}

export async function runMcpLaneTests(ok) {
  console.log('Open MCP stamp lane');

  ok(mcpLaneEnabledByEnv({ MCP_LANE: 'on' }) === true, 'MCP_LANE=on enables the lane');
  ok(mcpLaneEnabledByEnv({ MCP_LANE: 'OFF' }) === false, 'MCP_LANE=off disables the lane');
  ok(mcpLaneEnabledByEnv({}) === false, 'unset MCP_LANE is off (fail closed)');
  const defaults = mcpLaneLimits({});
  ok(defaults.ipHour === MCP_LANE_DEFAULT_IP_HOUR && defaults.globalDay === MCP_LANE_DEFAULT_GLOBAL_DAY, 'default caps are 20/hour per address and 500/day global');
  ok(mcpLaneLimits({ MCP_LIMIT_IP_HOUR: '7', MCP_LIMIT_GLOBAL_DAY: '40' }).ipHour === 7, 'caps are configurable via vars');
  ok(mcpLaneLimits({ MCP_LIMIT_IP_HOUR: 'nope' }).ipHour === MCP_LANE_DEFAULT_IP_HOUR, 'invalid cap vars fall back to defaults');
  ok(mcpLaneLimits({ MCP_LIMIT_IP_HOUR: '0', MCP_LIMIT_GLOBAL_DAY: '0' }).ipHour === 0 && mcpLaneLimits({ MCP_LIMIT_IP_HOUR: '0', MCP_LIMIT_GLOBAL_DAY: '0' }).globalDay === 0, '0 means a cap is off (unlimited)');
  ok(secondsUntilNextUtcHour(new Date('2026-11-11T03:59:01.000Z')) === 59, 'Retry-After for the hourly cap is seconds until the next UTC hour');
  ok(secondsUntilNextUtcDay(new Date('2026-11-11T23:59:00.000Z')) === 60, 'Retry-After for the daily cap is seconds until the next UTC day');

  const now = new Date('2026-11-11T15:04:00.000Z');
  const laterDay = new Date('2026-11-12T15:04:00.000Z');
  const saltEnv = { MCP_IP_SALT: 'test-mcp-ip-salt' };
  const a = await hashMcpIp(saltEnv, IP, now);
  const b = await hashMcpIp(saltEnv, IP, now);
  const c = await hashMcpIp(saltEnv, IP, laterDay);
  const d = await hashMcpIp(saltEnv, OTHER_IP, now);
  ok(/^[0-9a-f]{64}$/.test(a) && a === b, 'hashed IP is 64 hex chars and stable within a UTC day');
  ok(a !== c, 'hashed IP rotates with the UTC day');
  ok(a !== d, 'different addresses hash differently');
  ok(!a.includes('203') && !a.includes(IP), 'hash does not contain the raw IP');

  const derived = await hashMcpIp({ CT_TICK_SECRET: 'tick-secret-value' }, IP, now);
  const explicit = await hashMcpIp({ MCP_IP_SALT: 'tick-secret-value' }, IP, now);
  ok(derived !== explicit, 'derived salt is domain-separated from using CT_TICK_SECRET raw');
  ok(derived !== await hashMcpIp({ MCP_IP_SALT: 'other-salt' }, IP, now), 'MCP_IP_SALT overrides the derived salt');

  const db = memoryD1();
  const quotaEnv = { ...saltEnv, CT_DB: db, MCP_LIMIT_IP_HOUR: '2', MCP_LIMIT_GLOBAL_DAY: '100' };
  const q1 = await consumeMcpLaneQuota(quotaEnv, IP, now);
  const q2 = await consumeMcpLaneQuota(quotaEnv, IP, now);
  const q3 = await consumeMcpLaneQuota(quotaEnv, IP, now);
  ok(q1.limited === false && q2.limited === false && q3.limited === true && q3.scope === 'ip', 'per-address hourly cap returns limited after the cap');
  ok(JSON.stringify(db.state.usage).includes(IP) === false, 'quota rows never contain the raw IP');
  ok(db.state.usage.every((r) => r.key_kind !== 'ip' || /^[0-9a-f]{64}$/.test(r.key_id)), 'per-address key_id is a hash, not an IP');

  const unlimitedDb = memoryD1();
  const unlimitedQuota = { ...saltEnv, CT_DB: unlimitedDb, MCP_LIMIT_IP_HOUR: '0', MCP_LIMIT_GLOBAL_DAY: '0' };
  const uq1 = await consumeMcpLaneQuota(unlimitedQuota, IP, now);
  const uq2 = await consumeMcpLaneQuota(unlimitedQuota, IP, now);
  const uq3 = await consumeMcpLaneQuota(unlimitedQuota, IP, now);
  ok(uq1.limited === false && uq1.skipped === true && uq2.limited === false && uq3.limited === false, '0/0 caps never limit and report skipped');
  ok(unlimitedDb.state.usage.length === 0, 'unlimited caps write no counter rows');

  const savedFetch = globalThis.fetch;
  let turnstileCalls = 0;
  let calendarCalls = 0;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u.includes('challenges.cloudflare.com/turnstile')) {
      turnstileCalls++;
      return Response.json({ success: false });
    }
    if (u.includes('/digest') || u.includes('freetsa.org')) {
      calendarCalls++;
      return new Response(new Uint8Array([1, 2, 3, 4]), { status: 200, headers: { 'content-type': 'application/octet-stream' } });
    }
    throw new Error('unexpected fetch: ' + u);
  };

  const digestAt = (n) => n.toString(16).padStart(64, '0');
  const limitKeys = [];
  const liveDb = memoryD1();
  const env = {
    MCP_LANE: 'on',
    MCP_IP_SALT: 'test-mcp-ip-salt',
    MCP_LIMIT_IP_HOUR: '20',
    MCP_LIMIT_GLOBAL_DAY: '500',
    TURNSTILE_SECRET: 'test-turnstile-secret',
    CT_DB: liveDb,
    MCP_STAMP_LIMITER: mockLimiter(limitKeys),
    STAMP_LIMITER: mockLimiter([]),
  };

  const mcpReq = (body, headers = {}, requestEnv = env) => worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': IP, ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), requestEnv, { waitUntil() {} });

  try {
    turnstileCalls = 0;
    calendarCalls = 0;
    const good = await mcpReq({ digest: DIGEST });
    const goodBody = await good.json();
    ok(good.status === 200 && goodBody.ots && Object.keys(goodBody.ots).length > 0, 'enabled lane stamps a valid digest');
    ok(JSON.stringify(Object.keys(goodBody).sort()) === JSON.stringify(['errors', 'ots', 'tsr']), 'success JSON is exactly { ots, tsr, errors }');
    ok(goodBody.tsr === null, 'omitting tsq yields tsr: null');
    ok(turnstileCalls === 0, 'MCP lane does not call Turnstile even when the secret is configured');
    ok(calendarCalls > 0, 'MCP lane forwards the digest to calendars');
    ok(!good.headers.get('access-control-allow-origin'), 'MCP stamp responses send no CORS header');
    ok(good.headers.get('content-security-policy') === "default-src 'none'; frame-ancestors 'none'", 'MCP stamp JSON sends a tight CSP');
    ok(liveDb.state.pending.some((r) => r.digest === DIGEST), 'MCP stamp queues the hash for the certificate-log batch');
    ok(limitKeys.some((k) => k === 'mcp-stamp:' + IP), 'burst limiter uses the MCP lane key');
    ok(JSON.stringify(liveDb.state).includes(IP) === false, 'D1 state after a stamp does not contain the raw IP');

    const off = await mcpReq({ digest: DIGEST }, {}, { ...env, MCP_LANE: 'off' });
    const offBody = await off.json();
    ok(off.status === 404 && offBody.error === 'not found', 'MCP_LANE=off returns 404 {"error":"not found"}');

    const unset = await mcpReq({ digest: DIGEST }, {}, { TURNSTILE_SECRET: 'test-turnstile-secret', CT_DB: memoryD1() });
    ok(unset.status === 404 && (await unset.json()).error === 'not found', 'unset MCP_LANE returns 404 so clients fall back');

    const metaDb = memoryD1({ meta: { mcp_lane: 'off' } });
    const metaOff = await mcpReq({ digest: DIGEST }, {}, { ...env, CT_DB: metaDb });
    ok(metaOff.status === 404 && (await metaOff.json()).error === 'not found', 'ct_meta mcp_lane=off kills the lane without a redeploy');

    const badDigest = await mcpReq({ digest: 'not-a-hash' });
    ok(badDigest.status === 400 && /digest/.test((await badDigest.json()).error), 'invalid digest is 400');

    const badJson = await mcpReq('not-json');
    ok(badJson.status === 400 && (await badJson.json()).error === 'bad JSON', 'invalid JSON is 400');

    const badTsq = await mcpReq({ digest: DIGEST, tsq: '!!!' });
    ok(badTsq.status === 400 && (await badTsq.json()).error === 'bad tsq', 'invalid tsq is 400');

    const wrongTsq = await mcpReq({ digest: DIGEST, tsq: btoa('\x30\x05hello') });
    ok(wrongTsq.status === 400 && /tsq must be/.test((await wrongTsq.json()).error), 'tsq that is not for this digest is 400');

    const oversized = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"digest":"' + 'a'.repeat(64) + '","pad":"' + 'x'.repeat(5000) + '"}'));
        controller.close();
      },
    });
    const bigInit = { method: 'POST', headers: { 'cf-connecting-ip': IP }, body: oversized, duplex: 'half' };
    const big = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', bigInit), env, { waitUntil() {} });
    ok(big.status === 413 && ((await big.json()).error || '').includes('too large'), 'oversized MCP body is 413');

    const method = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', { method: 'GET' }), env, { waitUntil() {} });
    ok(method.status === 405 && (await method.json()).error === 'POST only', 'GET /api/mcp/stamp is 405');

    const preflight = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'OPTIONS',
      headers: { origin: 'https://other.example', 'access-control-request-method': 'POST' },
    }), env, { waitUntil() {} });
    ok(preflight.status === 405 && !preflight.headers.get('access-control-allow-origin'), 'OPTIONS on the MCP lane is rejected (no CORS)');

    const ipDb = memoryD1();
    const ipEnv = { ...env, CT_DB: ipDb, MCP_LIMIT_IP_HOUR: '2', MCP_LIMIT_GLOBAL_DAY: '100' };
    const first = await mcpReq({ digest: digestAt(1) }, {}, ipEnv);
    const second = await mcpReq({ digest: digestAt(2) }, {}, ipEnv);
    const third = await mcpReq({ digest: digestAt(3) }, {}, ipEnv);
    const thirdBody = await third.json();
    ok(first.status === 200 && second.status === 200, 'first two stamps under the per-address cap succeed');
    ok(third.status === 429 && thirdBody.error === 'Too many requests. Try again later.', 'third stamp over the per-address cap is 429');
    const retryAfter = Number(third.headers.get('retry-after'));
    ok(Number.isFinite(retryAfter) && retryAfter > 0 && retryAfter <= 3600, 'hourly 429 sends Retry-After until the next UTC hour');
    ok(JSON.stringify(ipDb.state).includes(IP) === false, 'per-address cap rows do not store the raw IP');

    const globalDb = memoryD1();
    const globalEnv = { ...env, CT_DB: globalDb, MCP_LIMIT_IP_HOUR: '100', MCP_LIMIT_GLOBAL_DAY: '2' };
    const g1 = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.10' },
      body: JSON.stringify({ digest: digestAt(11) }),
    }), globalEnv, { waitUntil() {} });
    const g2 = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.11' },
      body: JSON.stringify({ digest: digestAt(12) }),
    }), globalEnv, { waitUntil() {} });
    const g3 = await worker.fetch(new Request('https://lightdrawer.example/api/mcp/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cf-connecting-ip': '203.0.113.12' },
      body: JSON.stringify({ digest: digestAt(13) }),
    }), globalEnv, { waitUntil() {} });
    ok(g1.status === 200 && g2.status === 200, 'first two stamps under the global daily cap succeed');
    ok(g3.status === 429, 'third stamp over the global daily cap is 429');
    const gRetry = Number(g3.headers.get('retry-after'));
    ok(Number.isFinite(gRetry) && gRetry > 0 && gRetry <= 86400, 'daily 429 sends Retry-After until the next UTC day');

    const noCapDb = memoryD1();
    const noCapEnv = { ...env, CT_DB: noCapDb, MCP_LIMIT_IP_HOUR: '0', MCP_LIMIT_GLOBAL_DAY: '0' };
    const n1 = await mcpReq({ digest: digestAt(21) }, {}, noCapEnv);
    const n2 = await mcpReq({ digest: digestAt(22) }, {}, noCapEnv);
    const n3 = await mcpReq({ digest: digestAt(23) }, {}, noCapEnv);
    ok(n1.status === 200 && n2.status === 200 && n3.status === 200, 'stamps succeed when hourly and daily caps are 0');
    ok(noCapDb.state.usage.length === 0, 'no D1 counter rows are written when caps are off');
    ok(JSON.stringify(noCapDb.state).includes(IP) === false, 'no raw IP is stored when caps are off');

    const burstSeen = [];
    const burst = await mcpReq({ digest: DIGEST }, {}, { ...env, MCP_STAMP_LIMITER: mockLimiter(burstSeen, 'mcp-stamp:') });
    ok(burst.status === 429 && burst.headers.get('retry-after') === '10', 'burst limiter returns 429 with Retry-After 10');

    const exploded = memoryD1();
    exploded.prepare = function (sql) {
      if (/INSERT INTO mcp_lane_usage/.test(sql)) {
        return { bind() { return { async first() { throw new Error('D1 quota exploded internals'); }, async run() { throw new Error('no'); } }; } };
      }
      return memoryD1().prepare(sql);
    };
    const down = await mcpReq({ digest: DIGEST }, {}, { ...env, CT_DB: exploded });
    const downBody = await down.json();
    ok(down.status === 503 && downBody.error === 'stamp lane unavailable', 'quota store failure is 503');
    ok(!JSON.stringify(downBody).includes('exploded internals'), 'raw D1 messages are not returned');

    // Existing /api/stamp path must still require Turnstile when configured.
    turnstileCalls = 0;
    calendarCalls = 0;
    const stampAnon = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ digest: DIGEST }),
    }), env, { waitUntil() {} });
    ok(stampAnon.status === 403 && /Human check/.test((await stampAnon.json()).error), '/api/stamp without a key still requires Turnstile');
    ok(calendarCalls === 0, '/api/stamp does not forward a digest after a failed human check');

    const stampToken = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ digest: DIGEST, turnstile: 'dummy-token' }),
    }), env, { waitUntil() {} });
    ok(stampToken.status === 403 && /Human check/.test((await stampToken.json()).error), '/api/stamp still rejects a failed human check');
    ok(turnstileCalls === 1, '/api/stamp still calls siteverify when a Turnstile token is sent');

    const stampCors = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'OPTIONS',
      headers: { origin: 'https://other.example', 'access-control-request-method': 'POST' },
    }), env, { waitUntil() {} });
    ok(stampCors.status === 405 && !stampCors.headers.get('access-control-allow-origin'), '/api/stamp OPTIONS is still rejected');

    db.state.usage.push(
      { key_kind: 'ip', key_id: 'aa', bucket: '2026-11-11T14', count: 3 },
      { key_kind: 'ip', key_id: 'bb', bucket: utcHourString(now), count: 1 },
      { key_kind: 'global', key_id: 'all', bucket: '2026-11-10', count: 9 },
      { key_kind: 'global', key_id: 'all', bucket: utcDayString(now), count: 2 },
    );
    const pruned = await pruneMcpLaneUsage({ CT_DB: db }, now);
    ok(pruned.pruned === true, 'prune runs against D1');
    ok(!db.state.usage.some((r) => r.bucket === '2026-11-11T14' || r.bucket === '2026-11-10'), 'prune deletes expired hour and day buckets');
    ok(db.state.usage.some((r) => r.key_kind === 'ip' && r.bucket === utcHourString(now)), 'prune keeps the current hour bucket');
    ok(db.state.usage.some((r) => r.key_kind === 'global' && r.bucket === utcDayString(now)), 'prune keeps the current day bucket');

  } finally {
    globalThis.fetch = savedFetch;
  }
}
