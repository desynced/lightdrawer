import { generateStampKeyRecord } from '../src/stamp-keys.js';
import {
  MCP_ALARM_429_DEFAULT_PER_MIN,
  mcp429AlarmSnapshot,
  mcpAlarm429PerMin,
  recordMcp429,
  resetMcp429AlarmForTests,
} from '../src/mcp-lane.js';
import { isStampUpstreamUrl, isTurnstileUrl } from './upstream-url.mjs';
import worker from '../src/worker.js';

const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const IP = '203.0.113.77';
const LABEL = 'metrics-caller';

function memoryD1({ keys = [], dedup = null } = {}) {
  const state = { meta: {}, usage: [], pending: [], keys, dedup };
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
              if (/FROM stamp_dedup/.test(sql)) {
                if (!state.dedup || state.dedup.digest !== params[0]) return null;
                return state.dedup;
              }
              if (/stamp_keys/.test(sql)) {
                return state.keys.find((r) => r.key_hash === params[0]) || null;
              }
              return null;
            },
            async run() {
              if (/INSERT OR IGNORE INTO ct_pending/.test(sql)) {
                state.pending.push({ digest: params[0] });
                return { success: true };
              }
              if (/INSERT INTO stamp_dedup/.test(sql) || /UPDATE stamp_dedup/.test(sql)) {
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

function mockLimiter(denyPrefix) {
  return {
    async limit({ key }) {
      if (denyPrefix && String(key).startsWith(denyPrefix)) return { success: false };
      return { success: true };
    },
  };
}

function parseLogged(args) {
  const first = args[0];
  if (typeof first !== 'string') return null;
  try { return JSON.parse(first); } catch { return null; }
}

function captureLogs() {
  const lines = [];
  const origLog = console.log;
  const origWarn = console.warn;
  console.log = (...args) => {
    const parsed = parseLogged(args);
    if (parsed && (parsed.msg === 'stamp' || parsed.msg === 'mcp-lane-alarm')) lines.push(parsed);
    else origLog(...args);
  };
  console.warn = (...args) => {
    const parsed = parseLogged(args);
    if (parsed && (parsed.msg === 'stamp' || parsed.msg === 'mcp-lane-alarm')) lines.push(parsed);
    else origWarn(...args);
  };
  return {
    lines,
    restore() {
      console.log = origLog;
      console.warn = origWarn;
    },
  };
}

function stampLines(lines) {
  return lines.filter((l) => l.msg === 'stamp');
}

function alarmLines(lines) {
  return lines.filter((l) => l.msg === 'mcp-lane-alarm');
}

function lineIsPrivate(line, secrets) {
  const text = JSON.stringify(line);
  return secrets.every((secret) => secret && !text.includes(secret));
}

const STAMP_KEYS = ['msg', 'path', 'status', 'via', 'limited'];
const ALARM_KEYS = ['msg', 'reason', 'count'];

export async function runStampMetricsTests(ok) {
  console.log('Stamp lane metrics');

  const rec = await generateStampKeyRecord(LABEL);
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (isTurnstileUrl(url)) {
      let token = '';
      try {
        if (init && init.body && typeof init.body.get === 'function') token = init.body.get('response') || '';
      } catch { /* ignore */ }
      const okToken = token === 'human-ok';
      return Response.json({ success: okToken });
    }
    if (isStampUpstreamUrl(url)) {
      return new Response(new Uint8Array([9, 9, 9]), { status: 200, headers: { 'content-type': 'application/octet-stream' } });
    }
    throw new Error('unexpected fetch: ' + url);
  };

  const baseEnv = {
    MCP_LANE: 'on',
    MCP_IP_SALT: 'metrics-salt',
    MCP_LIMIT_IP_HOUR: '0',
    MCP_LIMIT_GLOBAL_DAY: '0',
    MCP_ALARM_429_PER_MIN: '0',
    TURNSTILE_SECRET: 'test-turnstile-secret',
    CT_DB: memoryD1({ keys: [{ id: rec.id, label: rec.label, key_hash: rec.key_hash, revoked_at: null }] }),
    MCP_STAMP_LIMITER: mockLimiter(),
    STAMP_LIMITER: mockLimiter(),
    STAMP_AUTH_LIMITER: mockLimiter(),
  };

  const call = (pathname, { method = 'POST', headers = {}, body, env = baseEnv } = {}) => {
    const init = { method, headers: { 'cf-connecting-ip': IP, ...headers } };
    if (body !== undefined) {
      init.headers['content-type'] = init.headers['content-type'] || 'application/json';
      init.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    return worker.fetch(new Request('https://lightdrawer.example' + pathname, init), env, { waitUntil() {} });
  };

  const secrets = [IP, DIGEST, rec.id, rec.label, rec.token, 'test-turnstile-secret', 'human-ok'];

  try {
    resetMcp429AlarmForTests();
    const cap = captureLogs();
    try {
      const mcpOk = await call('/api/mcp/stamp', { body: { digest: DIGEST } });
      ok(mcpOk.status === 200, 'metrics fixture: MCP stamp succeeds');
      const mcpBad = await call('/api/mcp/stamp', { body: { digest: 'nope' } });
      ok(mcpBad.status === 400, 'metrics fixture: bad MCP digest is 400');

      const burstEnv = { ...baseEnv, CT_DB: memoryD1(), MCP_STAMP_LIMITER: mockLimiter('mcp-stamp:') };
      const burst = await call('/api/mcp/stamp', { body: { digest: DIGEST }, env: burstEnv });
      ok(burst.status === 429, 'metrics fixture: burst limit is 429');

      const ipEnv = {
        ...baseEnv,
        CT_DB: memoryD1(),
        MCP_LIMIT_IP_HOUR: '1',
        MCP_LIMIT_GLOBAL_DAY: '0',
      };
      const ipFirst = await call('/api/mcp/stamp', { body: { digest: '11'.padStart(64, '0') }, env: ipEnv });
      const ipSecond = await call('/api/mcp/stamp', { body: { digest: '22'.padStart(64, '0') }, env: ipEnv });
      ok(ipFirst.status === 200 && ipSecond.status === 429, 'metrics fixture: hourly cap 429');

      const globalEnv = {
        ...baseEnv,
        CT_DB: memoryD1(),
        MCP_LIMIT_IP_HOUR: '0',
        MCP_LIMIT_GLOBAL_DAY: '1',
      };
      const gFirst = await call('/api/mcp/stamp', { body: { digest: '33'.padStart(64, '0') }, env: globalEnv });
      const gSecond = await call('/api/mcp/stamp', { body: { digest: '44'.padStart(64, '0') }, env: globalEnv });
      ok(gFirst.status === 200 && gSecond.status === 429, 'metrics fixture: daily cap 429');

      const dedupEnv = {
        ...baseEnv,
        CT_DB: memoryD1({
          dedup: { digest: DIGEST, last_ok_at: Date.now(), ots_json: 'null', tsr: null },
        }),
      };
      const dedup = await call('/api/mcp/stamp', { body: { digest: DIGEST }, env: dedupEnv });
      ok(dedup.status === 429, 'metrics fixture: digest cooldown without a cached body is 429');

      const keyed = await call('/api/stamp', {
        headers: { authorization: 'Bearer ' + rec.token },
        body: { digest: DIGEST },
      });
      ok(keyed.status === 200, 'metrics fixture: valid key stamps');

      const keyedLimitEnv = { ...baseEnv, STAMP_LIMITER: mockLimiter('stamp:key:') };
      const keyedLimit = await call('/api/stamp', {
        headers: { authorization: 'Bearer ' + rec.token },
        body: { digest: DIGEST },
        env: keyedLimitEnv,
      });
      ok(keyedLimit.status === 429, 'metrics fixture: per-key limit is 429');

      const human = await call('/api/stamp', { body: { digest: DIGEST, turnstile: 'human-ok' } });
      ok(human.status === 200, 'metrics fixture: passed human check stamps');

      const humanFail = await call('/api/stamp', { body: { digest: DIGEST, turnstile: 'human-no' } });
      ok(humanFail.status === 403, 'metrics fixture: failed human check is 403');

      const badKey = await call('/api/stamp', {
        headers: { authorization: 'Bearer ldsk_not-a-real-key' },
        body: { digest: DIGEST },
      });
      ok(badKey.status === 401, 'metrics fixture: bad key is 401');

      const devEnv = { ...baseEnv, TURNSTILE_SECRET: undefined, CT_DB: memoryD1() };
      const dev = await call('/api/stamp', { body: { digest: DIGEST }, env: devEnv });
      ok(dev.status === 200, 'metrics fixture: stamp without Turnstile configured still succeeds');

      const method = await call('/api/stamp', { method: 'GET' });
      ok(method.status === 405, 'metrics fixture: GET /api/stamp is 405');
      const mcpMethod = await call('/api/mcp/stamp', { method: 'GET' });
      ok(mcpMethod.status === 405, 'metrics fixture: GET /api/mcp/stamp is 405');
    } finally {
      cap.restore();
    }

    const logged = stampLines(cap.lines);
    const expectLine = (pred, label) => {
      const hit = logged.find(pred);
      ok(!!hit, label);
      if (hit) {
        ok(JSON.stringify(Object.keys(hit)) === JSON.stringify(STAMP_KEYS), label + ' has only msg, path, status, via, limited');
        ok(typeof hit.status === 'number', label + ' status is a number');
        ok(lineIsPrivate(hit, secrets), label + ' omits key id, label, digest, token, and IP');
      }
      return hit;
    };

    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 200 && l.via === 'mcp' && l.limited === false, 'MCP 200 log is via mcp');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 400 && l.via === 'mcp' && l.limited === false, 'MCP 400 log is via mcp');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 429 && l.via === 'mcp' && l.limited === 'burst', 'MCP burst 429 log is limited burst');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 429 && l.via === 'mcp' && l.limited === 'ip', 'MCP hourly 429 log is limited ip');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 429 && l.via === 'mcp' && l.limited === 'global', 'MCP daily 429 log is limited global');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 429 && l.via === 'mcp' && l.limited === 'dedup', 'MCP digest-cooldown 429 log is limited dedup');
    expectLine((l) => l.path === '/api/stamp' && l.status === 200 && l.via === 'key' && l.limited === false, 'valid key 200 log is via key');
    expectLine((l) => l.path === '/api/stamp' && l.status === 429 && l.via === 'key' && l.limited === false, 'per-key 429 stays via key and is not a named lane cap');
    expectLine((l) => l.path === '/api/stamp' && l.status === 200 && l.via === 'turnstile' && l.limited === false, 'passed human check 200 log is via turnstile');
    expectLine((l) => l.path === '/api/stamp' && l.status === 403 && l.via === null && l.limited === false, 'failed human check is not via turnstile');
    expectLine((l) => l.path === '/api/stamp' && l.status === 401 && l.via === null && l.limited === false, 'invalid key is not via key');
    expectLine((l) => l.path === '/api/stamp' && l.status === 200 && l.via === null && l.limited === false, 'browser stamp with Turnstile unset is not labeled turnstile');
    expectLine((l) => l.path === '/api/stamp' && l.status === 405 && l.via === null, 'GET /api/stamp is logged');
    expectLine((l) => l.path === '/api/mcp/stamp' && l.status === 405 && l.via === 'mcp' && l.limited === false, 'GET /api/mcp/stamp is logged as the open lane');

    ok(logged.length === 16, 'each finished stamp request writes one stamp line');
    ok(alarmLines(cap.lines).length === 0, 'alarm stays quiet while MCP_ALARM_429_PER_MIN is 0');
    ok(mcp429AlarmSnapshot().count === 0, 'a disabled alarm does not count 429s');

    ok(mcpAlarm429PerMin({}) === MCP_ALARM_429_DEFAULT_PER_MIN, 'missing MCP_ALARM_429_PER_MIN defaults to 20');
    ok(mcpAlarm429PerMin({ MCP_ALARM_429_PER_MIN: 'nope' }) === 20, 'invalid MCP_ALARM_429_PER_MIN falls back to 20');
    ok(mcpAlarm429PerMin({ MCP_ALARM_429_PER_MIN: '0' }) === 0, 'MCP_ALARM_429_PER_MIN=0 disables the alarm');

    resetMcp429AlarmForTests();
    const unitCap = captureLogs();
    const minuteA = new Date('2026-11-12T18:04:10.000Z');
    const minuteB = new Date('2026-11-12T18:05:00.000Z');
    const thresholdEnv = { MCP_ALARM_429_PER_MIN: '20' };
    try {
      for (let i = 0; i < 20; i++) recordMcp429(thresholdEnv, minuteA);
      ok(alarmLines(unitCap.lines).length === 0, '20 MCP 429s in a minute do not warn when the threshold is 20');
      const tripped = recordMcp429(thresholdEnv, minuteA);
      ok(tripped.warned === true && tripped.count === 21, 'the 21st MCP 429 exceeds the threshold');
      recordMcp429(thresholdEnv, minuteA);
      recordMcp429(thresholdEnv, minuteA);
      const firstMinute = alarmLines(unitCap.lines);
      ok(firstMinute.length === 1 && firstMinute[0].count === 21 && firstMinute[0].reason === '429-spike', 'the warning fires once in that UTC minute');
      ok(JSON.stringify(Object.keys(firstMinute[0])) === JSON.stringify(ALARM_KEYS), 'alarm JSON is only msg, reason, and count');
      ok(!JSON.stringify(firstMinute[0]).includes(IP), 'alarm JSON has no IP');

      for (let i = 0; i < 21; i++) recordMcp429(thresholdEnv, minuteB);
      const bothMinutes = alarmLines(unitCap.lines);
      ok(bothMinutes.length === 2 && bothMinutes[1].count === 21, 'a new UTC minute can warn once more');
    } finally {
      unitCap.restore();
    }

    resetMcp429AlarmForTests();
    const offCap = captureLogs();
    try {
      for (let i = 0; i < 30; i++) recordMcp429({ MCP_ALARM_429_PER_MIN: '0' }, minuteA);
      ok(alarmLines(offCap.lines).length === 0 && mcp429AlarmSnapshot().count === 0, 'threshold 0 does not count or warn');
    } finally {
      offCap.restore();
    }

    resetMcp429AlarmForTests();
    const workerCap = captureLogs();
    const RealDate = Date;
    const fixedMs = Date.parse('2026-11-12T18:10:30.000Z');
    globalThis.Date = class extends RealDate {
      constructor(...args) {
        if (args.length === 0) super(fixedMs);
        else super(...args);
      }
      static now() { return fixedMs; }
    };
    const alarmEnv = { ...baseEnv, MCP_ALARM_429_PER_MIN: '1', CT_DB: memoryD1(), MCP_STAMP_LIMITER: mockLimiter('mcp-stamp:') };
    try {
      await call('/api/mcp/stamp', { body: { digest: DIGEST }, env: alarmEnv });
      await call('/api/mcp/stamp', { body: { digest: DIGEST }, env: alarmEnv });
      await call('/api/mcp/stamp', { body: { digest: DIGEST }, env: alarmEnv });
      const warns = alarmLines(workerCap.lines);
      ok(warns.length === 1 && warns[0].reason === '429-spike' && warns[0].count === 2, 'worker emits the 429 alarm once when the open lane is over the threshold');
      const burstLogs = stampLines(workerCap.lines);
      ok(burstLogs.length === 3 && burstLogs.every((l) => l.via === 'mcp' && l.status === 429 && l.limited === 'burst'), 'each of those 429s still has its own stamp line');

      const stampLimited = {
        ...baseEnv,
        MCP_ALARM_429_PER_MIN: '1',
        STAMP_LIMITER: mockLimiter('stamp:'),
        CT_DB: memoryD1({ keys: [{ id: rec.id, label: rec.label, key_hash: rec.key_hash, revoked_at: null }] }),
      };
      const before = alarmLines(workerCap.lines).length;
      await call('/api/stamp', { headers: { authorization: 'Bearer ' + rec.token }, body: { digest: DIGEST }, env: stampLimited });
      await call('/api/stamp', { headers: { authorization: 'Bearer ' + rec.token }, body: { digest: DIGEST }, env: stampLimited });
      ok(alarmLines(workerCap.lines).length === before, '/api/stamp 429s do not trip the MCP lane alarm');
    } finally {
      globalThis.Date = RealDate;
      workerCap.restore();
    }

    resetMcp429AlarmForTests();
  } finally {
    globalThis.fetch = savedFetch;
    resetMcp429AlarmForTests();
  }
}
