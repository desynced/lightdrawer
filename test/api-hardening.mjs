// Unknown /api paths, non-POST stamp methods, and the OpenTimestamps upgrade proxy.
import worker from '../src/worker.js';

const IP = '203.0.113.8';
const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ALICE = 'https://alice.btc.calendar.opentimestamps.org';
const GOOD = '0123abcd';
// Sentinel commitments the fetch mock treats specially. Both are even-length hex.
const REDIRECT_COMMITMENT = 'deadbeef';
const PENDING_COMMITMENT = '00000000';

const ALLOWED_HOSTS = [
  'alice.btc.calendar.opentimestamps.org',
  'bob.btc.calendar.opentimestamps.org',
  'a.pool.opentimestamps.org',
  'b.pool.opentimestamps.org',
  'finney.calendar.eternitywall.com',
  'a.pool.eternitywall.com',
  'btc.calendar.catallaxy.com',
  'ots.btc.catallaxy.com',
];

function limiter(seen, denyPrefix) {
  return {
    async limit({ key }) {
      if (seen) seen.push(key);
      if (denyPrefix && String(key).startsWith(denyPrefix)) return { success: false };
      return { success: true };
    },
  };
}

function makeCtx() {
  const jobs = [];
  return {
    waitUntil(p) { jobs.push(Promise.resolve(p)); },
    drain() { return Promise.all(jobs); },
  };
}

function corsNames(res) {
  return [...res.headers.keys()].filter((name) => name.startsWith('access-control-'));
}

export async function runApiHardeningTests(ok) {
  console.log('Scanner paths, stamp methods, and the upgrade proxy');

  const fetches = [];
  const cachePuts = [];
  const savedFetch = globalThis.fetch;
  const hadCaches = Object.prototype.hasOwnProperty.call(globalThis, 'caches');
  const savedCaches = globalThis.caches;

  // Workers fetch follows redirects unless redirect is "manual". Passing
  // "error" throws in Workers, so the mock follows only when the worker
  // left the default in place, and only for the sentinel commitment.
  globalThis.fetch = async (input, opts = {}) => {
    const target = input instanceof Request ? input.url : String(input);
    const redirect = (opts && opts.redirect) || 'follow';
    fetches.push({ url: target, redirect });
    if (target.endsWith('/timestamp/' + REDIRECT_COMMITMENT)) {
      if (redirect === 'follow') {
        const next = 'https://evil.example/secret';
        fetches.push({ url: next, redirect, followed: true });
        return new Response('pwned', { status: 200, headers: { 'content-type': 'text/plain' } });
      }
      return new Response('go-away', { status: 302, headers: { location: 'https://evil.example/secret' } });
    }
    if (target.endsWith('/timestamp/' + PENDING_COMMITMENT)) {
      return new Response('pending-body', { status: 404, headers: { 'content-type': 'text/plain' } });
    }
    return new Response(new Uint8Array([9, 9, 9]), { status: 200 });
  };
  globalThis.caches = {
    default: {
      async match() { return undefined; },
      async put(req) { cachePuts.push(req.url); },
    },
  };

  const allowSeen = [];
  const allowEnv = { UPGRADE_LIMITER: limiter(allowSeen, null) };
  const stampEnv = {
    MCP_LANE: 'on',
    MCP_IP_SALT: 'test-mcp-ip-salt',
    MCP_LIMIT_IP_HOUR: '0',
    MCP_LIMIT_GLOBAL_DAY: '0',
    MCP_STAMP_LIMITER: limiter(null, null),
    STAMP_LIMITER: limiter(null, null),
    UPGRADE_LIMITER: limiter(null, null),
  };

  async function call(url, init, env) {
    const ctx = makeCtx();
    try {
      const res = await worker.fetch(new Request(url, init), env || {}, ctx);
      await ctx.drain();
      return res;
    } catch (e) {
      return new Response(JSON.stringify({ error: 'test harness: ' + (e && e.message ? e.message : e) }), {
        status: 599,
        headers: { 'content-type': 'application/json' },
      });
    }
  }

  function upgradeUrl(cal, commitment) {
    const url = new URL('https://lightdrawer.example/api/ots/upgrade');
    if (cal !== undefined) url.searchParams.set('cal', cal);
    if (commitment !== undefined) url.searchParams.set('commitment', commitment);
    return url;
  }

  async function upgrade(cal, commitment, env, extraHeaders) {
    return call(upgradeUrl(cal, commitment), {
      headers: { 'cf-connecting-ip': IP, origin: 'null', ...extraHeaders },
    }, env);
  }

  try {
    const probes = [
      '/api/v2/.env',
      '/api/.env',
      '/api/phpinfo.php',
      '/api/actuator/env',
      '/api/.git/config',
      '/api/v2/%2eenv',
      '/api/no-such-route',
    ];
    for (const path of probes) {
      for (const method of ['GET', 'HEAD', 'OPTIONS', 'POST']) {
        const before = fetches.length;
        const res = await call('https://lightdrawer.example' + path, {
          method,
          headers: { origin: 'https://scanner.example', 'access-control-request-method': 'GET' },
        }, {});
        const text = await res.text();
        let body = null;
        try { body = JSON.parse(text); } catch { body = null; }
        const cors = corsNames(res);
        ok(
          res.status === 404
            && /application\/json/.test(res.headers.get('content-type') || '')
            && body && body.error === 'not found' && Object.keys(body).length === 1
            && cors.length === 0
            && !text.includes('.env') && !text.includes('phpinfo') && !text.includes('git'),
          method + ' ' + path + ' is 404 JSON with no CORS headers',
        );
        ok(fetches.length === before, method + ' ' + path + ' does not fetch upstream');
      }
    }

    const leaked = await call('https://lightdrawer.example/api/v2/.env?token=should-not-echo', {
      headers: { origin: 'https://scanner.example' },
    }, {});
    const leakedText = await leaked.text();
    ok(
      leaked.status === 404 && !leakedText.includes('should-not-echo') && corsNames(leaked).length === 0,
      'probe query string is not echoed and still has no CORS',
    );

    for (const path of ['/api/stamp', '/api/mcp/stamp']) {
      for (const method of ['OPTIONS', 'GET', 'HEAD']) {
        const before = fetches.length;
        const res = await call('https://lightdrawer.example' + path + '?digest=' + DIGEST, {
          method,
          headers: {
            origin: 'https://scanner.example',
            'access-control-request-method': 'POST',
            'access-control-request-headers': 'content-type,authorization',
            'content-type': 'application/json',
            'cf-connecting-ip': IP,
          },
        }, stampEnv);
        const text = await res.text();
        let body = null;
        try { body = JSON.parse(text); } catch { body = null; }
        ok(
          res.status === 405
            && /application\/json/.test(res.headers.get('content-type') || '')
            && body && body.error === 'POST only' && Object.keys(body).length === 1
            && corsNames(res).length === 0
            && !text.includes(DIGEST),
          method + ' ' + path + ' is 405 JSON with no CORS and does not stamp',
        );
        ok(fetches.length === before, method + ' ' + path + ' does not fetch a calendar or FreeTSA');
      }
    }

    const offList = [
      'https://evil.example',
      'https://example.com',
      'https://169.254.169.254',
      'https://localhost',
      'https://alice.btc.calendar.opentimestamps.org.evil.example',
      'https://notalice.btc.calendar.opentimestamps.org',
      'https://a.pool.opentimestamps.org.evil.example',
      'https://c.pool.opentimestamps.org',
      'https://calendar.opentimestamps.org',
      'https://b.pool.eternitywall.com',
      'https://alice.btc.calendar.opentimestamps.org.',
      'https://alice.btc.calendar.opentimestamps.org@evil.example',
    ];
    for (const cal of offList) {
      const before = fetches.length;
      const res = await upgrade(cal, GOOD, allowEnv);
      const body = await res.json();
      ok(res.status === 400 && body.error === 'calendar not on allowlist', 'off-allowlist calendar is rejected: ' + cal);
      ok(fetches.length === before, 'off-allowlist calendar does not fetch upstream: ' + cal);
      ok(res.headers.get('access-control-allow-origin') === '*', 'off-allowlist error still allows verify.html to read it');
      ok(!res.headers.get('access-control-allow-credentials'), 'upgrade errors do not send allow-credentials');
    }

    const beforeUnbound = fetches.length;
    const unbound = await upgrade('https://evil.example', GOOD, {});
    const unboundBody = await unbound.json();
    ok(
      unbound.status === 400 && unboundBody.error === 'calendar not on allowlist' && fetches.length === beforeUnbound,
      'off-allowlist host is rejected when the upgrade limiter is not bound',
    );

    const badUrls = [
      'http://alice.btc.calendar.opentimestamps.org',
      'https://alice.btc.calendar.opentimestamps.org/timestamp/0123abcd',
      'https://alice.btc.calendar.opentimestamps.org?x=1',
      'https://alice.btc.calendar.opentimestamps.org/extra',
      'file:///etc/passwd',
      'not a url',
    ];
    for (const cal of badUrls) {
      const before = fetches.length;
      const res = await upgrade(cal, GOOD, allowEnv);
      const body = await res.json();
      ok(res.status === 400 && body.error === 'bad calendar URL', 'calendar URL with a scheme, path, or query is rejected: ' + cal);
      ok(fetches.length === before, 'bad calendar URL does not fetch upstream');
    }

    const missingCal = await upgrade(undefined, GOOD, allowEnv);
    ok((await missingCal.json()).error === 'bad calendar URL' && missingCal.status === 400, 'missing cal is a bad calendar URL');

    const badCommitments = [undefined, '', 'abc', 'zz', '0123abcd/extra', 'ab'.repeat(257), '0123 abcd'];
    for (const commitment of badCommitments) {
      const before = fetches.length;
      const res = await upgrade(ALICE, commitment, allowEnv);
      const body = await res.json();
      ok(res.status === 400 && body.error === 'bad commitment', 'bad commitment is rejected');
      ok(fetches.length === before, 'bad commitment does not fetch upstream');
      ok(res.headers.get('access-control-allow-origin') === '*', 'bad commitment error still allows verify.html to read it');
    }

    const denied = [];
    const denyEnv = { UPGRADE_LIMITER: limiter(denied, 'upgrade:') };
    const beforeDeny = fetches.length;
    const limited = await upgrade(ALICE, GOOD, denyEnv);
    const limitedBody = await limited.json();
    ok(limited.status === 429 && limitedBody.error === 'rate limited', 'tripped upgrade limiter returns 429');
    ok(fetches.length === beforeDeny, 'tripped upgrade limiter does not fetch upstream');
    ok(denied.includes('upgrade:' + IP), 'upgrade limiter key is upgrade:<ip>');
    ok(limited.headers.get('access-control-allow-origin') === '*', 'upgrade 429 still allows verify.html to read it');
    ok(!JSON.stringify(limitedBody).includes('alice'), 'rate-limit error does not echo the calendar');

    for (const method of ['POST', 'HEAD', 'PUT']) {
      const before = fetches.length;
      const res = await call(upgradeUrl(ALICE, GOOD), {
        method,
        headers: { 'cf-connecting-ip': IP },
      }, allowEnv);
      const body = await res.json();
      ok(res.status === 405 && body.error === 'GET only', method + ' /api/ots/upgrade is 405');
      ok(fetches.length === before, method + ' /api/ots/upgrade does not fetch upstream');
    }

    const beforeOptions = fetches.length;
    const preflight = await call(upgradeUrl(ALICE, GOOD), {
      method: 'OPTIONS',
      headers: { origin: 'null', 'access-control-request-method': 'GET' },
    }, allowEnv);
    ok(preflight.status === 204, 'OPTIONS /api/ots/upgrade is 204 so file:// verify.html can preflight');
    ok(preflight.headers.get('access-control-allow-origin') === '*', 'upgrade preflight allows any origin');
    ok((preflight.headers.get('access-control-allow-methods') || '').includes('GET'), 'upgrade preflight allows GET');
    ok(fetches.length === beforeOptions, 'upgrade preflight does not fetch upstream');

    for (const host of ALLOWED_HOSTS) {
      const before = fetches.length;
      const puts = cachePuts.length;
      const res = await upgrade('https://' + host, GOOD, allowEnv);
      const buf = new Uint8Array(await res.arrayBuffer());
      const mine = fetches.slice(before);
      ok(res.status === 200 && buf.length === 3 && buf.every((b) => b === 9), 'allowlisted calendar returns the timestamp bytes: ' + host);
      ok(res.headers.get('content-type') === 'application/vnd.opentimestamps.v1', 'allowlisted upgrade keeps the calendar content type');
      ok(res.headers.get('access-control-allow-origin') === '*', 'allowlisted upgrade stays open for verify.html');
      ok(res.headers.get('cache-control') === 'public, max-age=3600', 'successful upgrade is cacheable for an hour');
      ok(
        mine.length === 1
          && mine[0].url === 'https://' + host + '/timestamp/' + GOOD
          && mine[0].redirect === 'manual',
        'allowlisted upgrade fetches only that host and does not follow redirects',
      );
      ok(cachePuts.length === puts + 1 && cachePuts[cachePuts.length - 1] === 'https://lightdrawer-cache.invalid/ots/' + host + '/' + GOOD, 'successful upgrade is cached under that host');
    }

    const upperBefore = fetches.length;
    const upper = await upgrade(ALICE, '0123ABCD', allowEnv);
    ok(upper.status === 200, 'uppercase commitment is accepted');
    ok(
      fetches.length === upperBefore + 1 && fetches[fetches.length - 1].url.endsWith('/timestamp/0123abcd'),
      'uppercase commitment is fetched in lowercase',
    );

    const hostCaseBefore = fetches.length;
    const hostCase = await upgrade('https://ALICE.BTC.CALENDAR.OPENTIMESTAMPS.ORG', GOOD, allowEnv);
    ok(hostCase.status === 200, 'uppercase calendar host is accepted');
    ok(
      fetches.length === hostCaseBefore + 1
        && fetches[fetches.length - 1].url === 'https://alice.btc.calendar.opentimestamps.org/timestamp/' + GOOD,
      'uppercase calendar host is fetched in lowercase',
    );

    const portBefore = fetches.length;
    const portRes = await upgrade('https://alice.btc.calendar.opentimestamps.org:8443', GOOD, allowEnv);
    const portFetches = fetches.slice(portBefore);
    ok(portRes.status === 200, 'a non-default port is not dialed; the allowlisted host is used on 443');
    ok(
      portFetches.length === 1 && portFetches[0].url === 'https://alice.btc.calendar.opentimestamps.org/timestamp/' + GOOD,
      'upstream URL does not include the caller-supplied port',
    );

    const userBefore = fetches.length;
    const userRes = await upgrade('https://evil.example@alice.btc.calendar.opentimestamps.org', GOOD, allowEnv);
    const userFetches = fetches.slice(userBefore);
    ok(userRes.status === 200, 'userinfo does not change the allowlisted host');
    ok(
      userFetches.length === 1
        && userFetches[0].url === 'https://alice.btc.calendar.opentimestamps.org/timestamp/' + GOOD
        && !userFetches.some((f) => f.url.includes('evil.example')),
      'userinfo is not used as the upstream host',
    );

    const redirectBefore = fetches.length;
    const putsBefore = cachePuts.length;
    const redirected = await upgrade(ALICE, REDIRECT_COMMITMENT, allowEnv);
    const redirectText = await redirected.text();
    const redirectFetches = fetches.slice(redirectBefore);
    ok(redirected.status === 502, 'a calendar redirect is an error');
    ok(/calendar HTTP 302/.test(redirectText), 'redirect error names the redirect status and not the other host');
    ok(!redirectText.includes('evil.example') && !redirectText.includes('pwned') && !redirectText.includes('go-away'), 'redirect target body is not returned');
    ok(!redirected.headers.get('location'), 'redirect Location is not copied to the caller');
    ok(redirected.headers.get('access-control-allow-origin') === '*', 'redirect error still allows verify.html to read it');
    ok(
      redirectFetches.length === 1
        && redirectFetches[0].url === 'https://alice.btc.calendar.opentimestamps.org/timestamp/' + REDIRECT_COMMITMENT
        && redirectFetches[0].redirect === 'manual'
        && !redirectFetches.some((f) => f.followed),
      'a calendar redirect is not fetched',
    );
    ok(cachePuts.length === putsBefore, 'a redirect is not cached');

    const pendingBefore = fetches.length;
    const pendingPuts = cachePuts.length;
    const pending = await upgrade(ALICE, PENDING_COMMITMENT, allowEnv);
    const pendingBody = await pending.json();
    ok(pending.status === 404 && pendingBody.pending === true, 'calendar 404 stays a pending result for verify.html');
    ok(pending.headers.get('access-control-allow-origin') === '*', 'pending upgrade stays readable from file://');
    ok(pending.headers.get('cache-control') === 'public, max-age=300', 'pending upgrade is cached briefly');
    ok(!JSON.stringify(pendingBody).includes('pending-body'), 'pending result does not include the calendar body');
    ok(fetches.length === pendingBefore + 1 && fetches[fetches.length - 1].redirect === 'manual', 'pending upgrade does not follow a redirect');
    ok(cachePuts.length === pendingPuts, 'a pending calendar 404 is not stored in the edge cache');

    ok(allowSeen.some((key) => key === 'upgrade:' + IP), 'allowed upgrades are still counted on the upgrade limiter');
  } finally {
    globalThis.fetch = savedFetch;
    if (hadCaches) globalThis.caches = savedCaches;
    else delete globalThis.caches;
  }
}
