import {
  generateStampKeyRecord,
  hashStampKey,
  insertStampKeySql,
  parseBearer,
  resolveStampCaller,
  revokeStampKeySql,
  stampAuthLimitKey,
  stampLimitKey,
  timingSafeEqualHex,
} from '../src/stamp-keys.js';
import worker from '../src/worker.js';

const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function mockD1(rows, onLookup) {
  return {
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() {
              if (/stamp_keys/.test(sql)) {
                if (onLookup) onLookup(params[0]);
                return rows.find((r) => r.key_hash === params[0]) || null;
              }
              return null;
            },
            async run() { return { success: true }; },
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

export async function runStampApiTests(ok) {
  console.log('Server stamp keys (trusted caller path)');

  const rec = await generateStampKeyRecord('fairview');
  ok(rec.token.startsWith('ldsk_') && rec.token.length > 20, 'minted key has ldsk_ prefix and random bytes');
  ok(rec.key_hash === await hashStampKey(rec.token), 'stored hash is SHA-256 of the plaintext key');
  ok(rec.key_hash !== rec.token && rec.key_hash.length === 64, 'plaintext is not stored; hash is 64 hex chars');
  ok(/INSERT INTO stamp_keys/.test(insertStampKeySql(rec)) && !insertStampKeySql(rec).includes(rec.token), 'insert SQL contains the hash, not the plaintext');
  const revSql = revokeStampKeySql(rec.id);
  ok(/UPDATE stamp_keys SET revoked_at = '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z'/.test(revSql) && !revSql.includes("datetime("), 'revoke SQL sets an ISO-8601 UTC revoked_at');
  let threw = false; try { insertStampKeySql({ ...rec, label: "bad'label" }); } catch { threw = true; }
  ok(threw, 'insert SQL rejects a label that could break quoting');
  threw = false; try { insertStampKeySql({ ...rec, created_at: "2026-11-09T00:00:00.000Z','x" }); } catch { threw = true; }
  ok(threw, 'insert SQL rejects a created_at that could break quoting');
  threw = false; try { revokeStampKeySql(rec.id, "2026-11-09T00:00:00.000Z','x"); } catch { threw = true; }
  ok(threw, 'revoke SQL rejects a revoked_at that could break quoting');

  ok(parseBearer(null).kind === 'none' && parseBearer('').kind === 'none', 'missing Authorization is anonymous');
  ok(parseBearer('Basic abc').kind === 'none', 'non-Bearer Authorization is anonymous (browser path unchanged)');
  ok(parseBearer('Bearer ').kind === 'invalid' && parseBearer('Bearer    ').kind === 'invalid', 'empty Bearer is invalid');
  ok(parseBearer('Bearer ' + rec.token).kind === 'token', 'Bearer <key> parses');
  ok(parseBearer('bearer ' + rec.token).kind === 'token', 'bearer scheme is case-insensitive');

  ok(await timingSafeEqualHex(rec.key_hash, rec.key_hash), 'equal hashes compare equal');
  ok(!(await timingSafeEqualHex(rec.key_hash, '0'.repeat(64))), 'different hashes compare unequal');
  ok(stampLimitKey({ id: rec.id }, '1.2.3.4') === 'stamp:key:' + rec.id, 'keyed requests use a per-key rate-limit bucket');
  ok(stampLimitKey(null, '1.2.3.4') === 'stamp:1.2.3.4', 'anonymous requests keep the per-IP bucket');
  ok(stampAuthLimitKey('1.2.3.4') === 'stamp:auth:1.2.3.4', 'Bearer attempts use a per-IP auth bucket');

  const rows = [{ id: rec.id, label: rec.label, key_hash: rec.key_hash, revoked_at: null }];
  const envLookup = { CT_DB: mockD1(rows) };
  const bearerReq = (token) => new Request('https://lightdrawer.example/api/stamp', { method: 'POST', headers: { authorization: 'Bearer ' + token } });
  ok((await resolveStampCaller(new Request('https://lightdrawer.example/api/stamp', { method: 'POST' }), envLookup)).status === 'anonymous', 'no header → anonymous');
  const okAuth = await resolveStampCaller(bearerReq(rec.token), envLookup);
  ok(okAuth.status === 'ok' && okAuth.caller.label === 'fairview' && okAuth.caller.id === rec.id, 'valid key resolves to its label');
  ok((await resolveStampCaller(bearerReq('ldsk_not-a-real-key'), envLookup)).status === 'unauthorized', 'unknown key is unauthorized');
  const revoked = { CT_DB: mockD1([{ ...rows[0], revoked_at: '2026-11-09T00:00:00.000Z' }]) };
  ok((await resolveStampCaller(bearerReq(rec.token), revoked)).status === 'unauthorized', 'revoked key is unauthorized');
  ok((await resolveStampCaller(bearerReq(rec.token), {})).status === 'unauthorized', 'Bearer without CT_DB is unauthorized (fail closed)');

  const savedFetch = globalThis.fetch;
  let turnstileCalls = 0;
  let calendarCalls = 0;
  const limitKeys = [];
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

  const env = {
    TURNSTILE_SECRET: 'test-turnstile-secret',
    CT_DB: mockD1(rows),
    STAMP_LIMITER: mockLimiter(limitKeys),
  };
  const stamp = (headers, extra = {}) => worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ digest: DIGEST, ...extra }),
  }), env, { waitUntil() {} });

  try {
    const anon = await stamp({});
    const anonBody = await anon.json();
    ok(anon.status === 403 && /Human check/.test(anonBody.error), 'without a key, Turnstile still required when configured');

    const bad = await stamp({ authorization: 'Bearer ldsk_nope' });
    const badBody = await bad.json();
    ok(bad.status === 401 && typeof badBody.error === 'string', 'bad key returns 401, not a Turnstile 403');
    ok(badBody.error === 'Invalid or revoked API key.', '401 error text is human-readable');

    turnstileCalls = 0;
    calendarCalls = 0;
    const good = await stamp({ authorization: 'Bearer ' + rec.token });
    const goodBody = await good.json();
    ok(good.status === 200 && goodBody.ots && Object.keys(goodBody.ots).length > 0, 'valid key stamps without a Turnstile token');
    ok(turnstileCalls === 0, 'valid key does not call siteverify');
    ok(calendarCalls > 0, 'valid key still forwards the digest to calendars');
    ok(!('caller' in goodBody) && !('label' in goodBody) && Array.isArray(goodBody.errors), 'receipt JSON is unchanged (ots/tsr/errors only)');
    ok(limitKeys.some((k) => k === 'stamp:key:' + rec.id), 'valid key is rate-limited by key id, not IP');
    ok(limitKeys.some((k) => k === 'stamp:auth:local'), 'valid key also counts against the per-IP auth bucket');

    const cross = await stamp({ origin: 'https://other.example' });
    ok(cross.status === 403 && /cross-origin/.test((await cross.json()).error), 'cross-origin without a key is still rejected');

    turnstileCalls = 0;
    const keyedCross = await stamp({ authorization: 'Bearer ' + rec.token, origin: 'https://other.example' });
    ok(keyedCross.status === 200 && turnstileCalls === 0, 'valid key is accepted even if Origin is another site');

    const limiterDenied = [];
    const envLimited = { ...env, STAMP_LIMITER: mockLimiter(limiterDenied, 'stamp:key:') };
    const limited = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST }),
    }), envLimited, { waitUntil() {} });
    ok(limited.status === 429, 'per-key rate limit returns 429');

    // Fairview's server caller: JSON in/out, Bearer key, no Origin, no tsq.
    const fairviewFetch = (token, requestEnv = env) => worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        authorization: 'Bearer ' + token,
      },
      body: JSON.stringify({ digest: DIGEST }),
    }), requestEnv, { waitUntil() {} });
    const isErrorShape = (body) => body && typeof body === 'object' && typeof body.error === 'string' && body.error.length > 0 && JSON.stringify(Object.keys(body)) === JSON.stringify(['error']);

    const fv = await fairviewFetch(rec.token);
    const fvBody = await fv.json();
    ok(fv.status === 200 && /application\/json/.test(fv.headers.get('content-type') || ''), 'Fairview-shaped request (JSON, no Origin, no tsq) succeeds with JSON content-type');
    ok(fvBody.tsr === null, 'omitting tsq yields tsr: null');
    ok(JSON.stringify(Object.keys(fvBody).sort()) === JSON.stringify(['errors', 'ots', 'tsr']), 'success JSON is exactly { ots, tsr, errors }');
    ok(fvBody.ots && typeof fvBody.ots === 'object' && Array.isArray(fvBody.errors), 'success ots is an object and errors is an array');
    ok(!('caller' in fvBody) && !('label' in fvBody) && !String(JSON.stringify(fvBody)).includes('fairview'), 'Fairview label does not appear in the response');
    ok(!fv.headers.get('access-control-allow-origin'), 'stamp responses send no CORS header (server-to-server)');

    const fvBad = await fairviewFetch('ldsk_nope');
    const fvBadBody = await fvBad.json();
    ok(fvBad.status === 401 && isErrorShape(fvBadBody) && /application\/json/.test(fvBad.headers.get('content-type') || ''), 'Fairview bad key: 401 {"error": "<text>"}');

    const fvEmpty = await fairviewFetch('');
    ok(fvEmpty.status === 401 && isErrorShape(await fvEmpty.json()), 'Fairview empty Bearer: 401 {"error": "<text>"}');

    const envRevoked = { ...env, CT_DB: mockD1([{ ...rows[0], revoked_at: '2026-11-09T00:00:00.000Z' }]) };
    const fvRevoked = await fairviewFetch(rec.token, envRevoked);
    ok(fvRevoked.status === 401 && isErrorShape(await fvRevoked.json()), 'Fairview revoked key: 401 {"error": "<text>"}');

    const fvLimited = await fairviewFetch(rec.token, envLimited);
    const fvLimitedBody = await fvLimited.json();
    ok(fvLimited.status === 429 && isErrorShape(fvLimitedBody) && /application\/json/.test(fvLimited.headers.get('content-type') || ''), 'Fairview rate limit: 429 {"error": "<text>"}');

    let lookups = 0;
    const envAuthLimited = {
      ...env,
      CT_DB: mockD1(rows, () => { lookups++; }),
      STAMP_AUTH_LIMITER: mockLimiter([], 'stamp:auth:'),
    };
    const authFlood = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', authorization: 'Bearer ldsk_junk' },
      body: JSON.stringify({ digest: DIGEST }),
    }), envAuthLimited, { waitUntil() {} });
    const authFloodBody = await authFlood.json();
    ok(authFlood.status === 429 && isErrorShape(authFloodBody), 'junk Bearer over the per-IP auth limit returns 429 {error}');
    ok(lookups === 0, 'per-IP auth limit runs before any D1 lookup');

    const preflight = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'OPTIONS',
      headers: {
        origin: 'https://other.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization,content-type',
      },
    }), env, { waitUntil() {} });
    ok(preflight.status === 405 && !preflight.headers.get('access-control-allow-origin'), 'OPTIONS preflight on /api/stamp is rejected (no browser CORS)');

    ok(fv.headers.get('content-security-policy') === "default-src 'none'; frame-ancestors 'none'", 'stamp JSON sends a tight CSP');
    ok(fv.headers.get('x-content-type-options') === 'nosniff', 'stamp JSON sends nosniff');
    ok(fv.headers.get('referrer-policy') === 'no-referrer', 'stamp JSON sends no-referrer');

    const oversized = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"digest":"' + 'a'.repeat(64) + '","pad":"' + 'x'.repeat(5000) + '"}'));
        controller.close();
      },
    });
    const bigReqInit = {
      method: 'POST',
      headers: { authorization: 'Bearer ' + rec.token },
      body: oversized,
    };
    // Node's fetch requires duplex when the body is a stream.
    bigReqInit.duplex = 'half';
    const big = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', bigReqInit), env, { waitUntil() {} });
    ok(big.status === 413, 'stamp body over the cap is 413 even without Content-Length');
    ok(((await big.json()).error || '').includes('too large'), 'oversized body returns a generic too-large error');

    const boomFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      const u = String(url);
      if (u.includes('challenges.cloudflare.com/turnstile')) return Response.json({ success: false });
      if (u.includes('/digest') || u.includes('freetsa.org')) throw new Error('secret internals boom SQL table ct_pending');
      throw new Error('unexpected fetch: ' + u);
    };
    const boom = await stamp({ authorization: 'Bearer ' + rec.token });
    const boomBody = await boom.json();
    globalThis.fetch = boomFetch;
    ok(boom.status === 200 && Array.isArray(boomBody.errors) && boomBody.errors.length > 0, 'stamp still returns JSON when upstreams fail');
    ok(boomBody.errors.every((e) => /unavailable$/.test(e)), 'upstream failures use a generic unavailable message');
    ok(!JSON.stringify(boomBody).includes('secret internals') && !JSON.stringify(boomBody).includes('ct_pending'), 'raw upstream messages are not returned');

    const explodingDb = {
      prepare(sql) {
        if (/ct_pending/.test(sql)) {
          return { bind() { return { async run() { throw new Error('D1 UNIQUE exploded internals'); }, async first() { return null; } }; } };
        }
        return mockD1(rows).prepare(sql);
      },
    };
    const exploded = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + rec.token },
      body: JSON.stringify({ digest: DIGEST }),
    }), { ...env, CT_DB: explodingDb }, { waitUntil() {} });
    const explodedBody = await exploded.json();
    ok(exploded.status === 200 && explodedBody.errors.includes('CT queue: unavailable'), 'CT queue failures use a generic error');
    ok(!JSON.stringify(explodedBody).includes('exploded internals'), 'raw D1 messages are not returned');

    const tickSeen = [];
    const tickEnv = {
      CT_TICK_SECRET: 'tick-secret-value',
      STAMP_AUTH_LIMITER: mockLimiter(tickSeen),
    };
    const wrongLen = await worker.fetch(new Request('https://lightdrawer.example/api/ct/tick', {
      method: 'POST',
      headers: { authorization: 'Bearer x', 'content-type': 'application/json' },
      body: '{}',
    }), tickEnv, { waitUntil() {} });
    ok(wrongLen.status === 401, 'tick rejects a wrong-length secret');
    ok(wrongLen.headers.get('content-security-policy') === "default-src 'none'; frame-ancestors 'none'", 'tick JSON sends a tight CSP');
    ok(tickSeen.some((k) => k === 'ct-tick:local'), 'tick uses a distinct rate-limit key');

    const tickLimited = await worker.fetch(new Request('https://lightdrawer.example/api/ct/tick', {
      method: 'POST',
      headers: { authorization: 'Bearer tick-secret-value', 'content-type': 'application/json' },
      body: '{}',
    }), { ...tickEnv, STAMP_AUTH_LIMITER: mockLimiter([], 'ct-tick:') }, { waitUntil() {} });
    ok(tickLimited.status === 429, 'tick is rate-limited independently of stamp buckets');
  } finally {
    globalThis.fetch = savedFetch;
  }
}
