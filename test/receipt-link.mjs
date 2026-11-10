import worker from '../src/worker.js';
import {
  cacheControlFor,
  escapeHtml,
  formatUtc,
  normalizeDigest,
  parseReceiptPath,
  recordToJson,
} from '../src/receipt-lookup.js';

const DIGEST = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const OTHER = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const HOST = '0123456789abcdef0123456789abcdef.0123456789abcdef0123456789abcdef.ct.lightdrawer.org';

function mockCtDb({ pending = [], leaves = [], fail = false } = {}) {
  return {
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async first() {
              if (fail) throw new Error('d1 down');
              const digest = params[0];
              if (/FROM ct_leaves/.test(sql)) {
                const row = leaves.find((r) => r.digest === digest);
                if (!row) return null;
                return {
                  published: row.published,
                  hostname: row.hostname,
                  root: row.root,
                  tree_size: row.tree_size,
                  batch_id: row.batch_id,
                  opened_at: row.opened_at,
                  closed_at: row.closed_at,
                  issued_at: row.issued_at,
                };
              }
              if (/FROM ct_pending/.test(sql)) {
                return pending.find((r) => r.digest === digest) || null;
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

const pendingEnv = {
  CT_DB: mockCtDb({ pending: [{ digest: DIGEST, received_at: '2026-11-09T16:02:00.000Z' }] }),
  ASSETS: { fetch() { return new Response('HOME', { headers: { 'content-type': 'text/html' } }); } },
};

const batchedEnv = {
  CT_DB: mockCtDb({
    leaves: [{
      digest: DIGEST,
      published: 0,
      hostname: HOST,
      root: 'ab'.repeat(32),
      tree_size: 3,
      batch_id: '2026-11-09T16:00:00.000Z',
      opened_at: '2026-11-09T16:00:00.000Z',
      closed_at: '2026-11-09T16:15:00.000Z',
      issued_at: null,
    }],
  }),
  ASSETS: pendingEnv.ASSETS,
};

const anchoredEnv = {
  CT_DB: mockCtDb({
    leaves: [{
      digest: DIGEST,
      published: 1,
      hostname: HOST,
      root: 'ab'.repeat(32),
      tree_size: 3,
      batch_id: '2026-11-09T16:00:00.000Z',
      opened_at: '2026-11-09T16:00:00.000Z',
      closed_at: '2026-11-09T16:15:00.000Z',
      issued_at: '2026-11-09T22:00:00.000Z',
    }],
  }),
  ASSETS: pendingEnv.ASSETS,
};

const emptyEnv = { CT_DB: mockCtDb(), ASSETS: pendingEnv.ASSETS };

function req(path, { method = 'GET', headers = {} } = {}) {
  return new Request('https://lightdrawer.org' + path, { method, headers });
}

async function fetchPath(path, env, opts) {
  return worker.fetch(req(path, opts), env, { waitUntil() {} });
}

export async function runReceiptLinkTests(ok) {
  console.log('Shareable receipt link (/r/<digest>)');

  ok(normalizeDigest(DIGEST) === DIGEST, '64 lowercase hex is accepted');
  ok(normalizeDigest(DIGEST.toUpperCase()) === DIGEST, 'uppercase hex is normalized');
  ok(normalizeDigest('  ' + DIGEST + '  ') === DIGEST, 'surrounding whitespace is trimmed');
  ok(normalizeDigest('xyz') === null && normalizeDigest(DIGEST.slice(0, 63)) === null, 'short or non-hex is rejected');
  ok(normalizeDigest('<script>alert(1)</script>') === null, 'markup is not a digest');
  ok(parseReceiptPath('/r/' + DIGEST).kind === 'ok', '/r/<digest> parses');
  ok(parseReceiptPath('/r/' + DIGEST.toUpperCase()).needsCanonical === true, 'uppercase path needs a canonical redirect');
  ok(parseReceiptPath('/r/' + DIGEST + '/').trailingSlash === true, 'trailing slash is detected');
  ok(parseReceiptPath('/r/').kind === 'empty' && parseReceiptPath('/r/nope').kind === 'malformed', 'empty and malformed paths are flagged');
  ok(formatUtc('2026-11-09T16:02:00.000Z') === '9 November 2026 at 4:02 PM UTC', 'times are formatted in plain UTC');
  ok(escapeHtml('<script>"x"&\'</script>') === '&lt;script&gt;&quot;x&quot;&amp;&#39;&lt;/script&gt;', 'HTML output is escaped');
  ok(cacheControlFor('found', { status: 'pending' }) === 'public, max-age=60', 'pending records have a short cache');
  ok(cacheControlFor('found', { status: 'anchored' }) === 'public, max-age=3600', 'anchored records have a longer cache');

  const home = await fetchPath('/', emptyEnv);
  ok(home.status === 200 && (await home.text()) === 'HOME', 'plain / is still the static home page');

  const bounced = await fetchPath('/?digest=' + DIGEST, emptyEnv);
  ok(bounced.status === 302 && bounced.headers.get('location') === 'https://lightdrawer.org/r/' + DIGEST, '/?digest= redirects 302 to /r/<digest>');
  const bouncedCase = await fetchPath('/?digest=' + DIGEST.toUpperCase(), emptyEnv);
  ok(bouncedCase.status === 302 && bouncedCase.headers.get('location') === 'https://lightdrawer.org/r/' + DIGEST, '/?digest= uppercases are redirected to lowercase');

  const badQuery = await fetchPath('/?digest=not-a-hash', emptyEnv);
  const badQueryBody = await badQuery.text();
  ok(badQuery.status === 400 && /does not look like a fingerprint/i.test(badQueryBody), 'invalid /?digest= returns 400 HTML');

  const malformed = await fetchPath('/r/not-a-hash', emptyEnv);
  const malformedBody = await malformed.text();
  ok(malformed.status === 400 && /does not look like a fingerprint/i.test(malformedBody), 'malformed /r/ path returns 400 HTML');
  ok(/text\/html/.test(malformed.headers.get('content-type') || ''), 'malformed page is HTML');
  ok(!malformed.headers.get('access-control-allow-origin'), 'HTML lookup sends no CORS header');

  const xss = await fetchPath('/r/' + encodeURIComponent('"><script>alert(1)</script>'), emptyEnv);
  const xssBody = await xss.text();
  ok(xss.status === 400 && !xssBody.includes('<script>alert(1)</script>'), 'injected markup is escaped or rejected on a malformed path');

  const missing = await fetchPath('/r/' + OTHER, emptyEnv);
  const missingBody = await missing.text();
  ok(missing.status === 404 && /No stamp found for this fingerprint/.test(missingBody), 'unknown digest returns 404 with the friendly heading');
  ok(missingBody.includes(OTHER) && /typo/.test(missingBody) && /hashed exactly/.test(missingBody), 'not-found page shows the fingerprint and typo / exact-hash explanations');
  ok(/verify\.html/.test(missingBody) && /receipt file/.test(missingBody), 'not-found page still points at the offline checker');
  ok((missing.headers.get('cache-control') || '').includes('max-age=60'), 'not-found pages have a short cache');

  const pending = await fetchPath('/r/' + DIGEST, pendingEnv);
  const pendingBody = await pending.text();
  ok(pending.status === 200, 'queued digest returns 200');
  ok(/First received/.test(pendingBody) && /9 November 2026 at 4:02 PM UTC/.test(pendingBody), 'pending page shows the exact first-received time');
  ok(!/Stamped no later than/.test(pendingBody), 'pending page does not use the batch-window label');
  ok(/Certificate log/.test(pendingBody) && /On the way/.test(pendingBody), 'pending page says the certificate-log record is on the way');
  ok(/How to check this yourself/.test(pendingBody) && /verify\.html/.test(pendingBody), 'pending page includes the how-to-check note');
  ok(/Technical details/.test(pendingBody) && pendingBody.includes('2026-11-09T16:02:00.000Z'), 'exact ISO time is in the technical section');
  ok((pending.headers.get('cache-control') || '').includes('max-age=60'), 'pending pages have a short cache');
  ok(pendingBody.includes('paypal.me/josephball'), 'footer keeps the PayPal support link');

  const canon = await fetchPath('/r/' + DIGEST.toUpperCase() + '/', pendingEnv);
  ok(canon.status === 302 && canon.headers.get('location') === 'https://lightdrawer.org/r/' + DIGEST, 'uppercase or trailing-slash /r/ paths redirect to the canonical URL');

  const batched = await fetchPath('/r/' + DIGEST, batchedEnv);
  const batchedBody = await batched.text();
  ok(batched.status === 200 && /Stamped no later than/.test(batchedBody) && /9 November 2026 at 4:15 PM UTC/.test(batchedBody), 'batched-but-unpublished uses the no-later-than label at window close');
  ok(/16:00/.test(batchedBody) && /batch window/.test(batchedBody), 'batched page names the window start');
  ok(!/First received/.test(batchedBody), 'batched page does not claim an exact first-received time');
  ok(/already in a batch/.test(batchedBody), 'batched page says the fingerprint is in a batch waiting for a certificate');

  const evilHost = {
    CT_DB: mockCtDb({
      leaves: [{
        digest: DIGEST,
        published: 1,
        hostname: '"><script>alert(1)</script>',
        root: 'ab'.repeat(32),
        tree_size: 1,
        batch_id: 'id<"x">',
        opened_at: '2026-11-09T16:00:00.000Z',
        closed_at: '2026-11-09T16:15:00.000Z',
        issued_at: '2026-11-09T22:00:00.000Z',
      }],
    }),
    ASSETS: pendingEnv.ASSETS,
  };
  const anchored = await fetchPath('/r/' + DIGEST, anchoredEnv);
  const anchoredBody = await anchored.text();
  ok(anchored.status === 200 && /public certificate-log record/.test(anchoredBody), 'anchored page says the certificate-log record is public');
  ok(anchoredBody.includes(HOST) && anchoredBody.includes('https://crt.sh/?q=' + encodeURIComponent(HOST)), 'anchored page links to crt.sh for the hostname');
  ok(/9 November 2026 at 10:00 PM UTC/.test(anchoredBody), 'anchored page shows the certificate issue time');
  ok((anchored.headers.get('cache-control') || '').includes('max-age=3600'), 'anchored pages have a longer cache');
  ok(/statement\.json/.test(anchoredBody), 'page explains the URL uses the statement fingerprint');

  const evil = await fetchPath('/r/' + DIGEST, evilHost);
  const evilBody = await evil.text();
  ok(!evilBody.includes('<script>alert(1)</script>') && evilBody.includes('&lt;script&gt;'), 'hostname in HTML is escaped');
  ok(!evilBody.includes('id<"x">') && evilBody.includes('id&lt;&quot;x&quot;&gt;'), 'batch id in HTML is escaped');

  const asJson = await fetchPath('/r/' + DIGEST, anchoredEnv, { headers: { accept: 'application/json' } });
  const jsonBody = await asJson.json();
  ok(asJson.status === 200 && /application\/json/.test(asJson.headers.get('content-type') || ''), 'Accept: application/json on /r/ returns JSON');
  ok(jsonBody.found === true && jsonBody.status === 'anchored' && jsonBody.digest === DIGEST, 'JSON names the anchored record');
  ok(jsonBody.stamped_no_later_than === '2026-11-09T16:15:00.000Z' && jsonBody.certificate && jsonBody.certificate.crtsh_url.includes('crt.sh'), 'JSON includes the window close and crt.sh URL');
  ok(!asJson.headers.get('access-control-allow-origin'), 'JSON lookup sends no CORS header');

  const browserAccept = await fetchPath('/r/' + DIGEST, pendingEnv, { headers: { accept: 'text/html,application/xhtml+xml,application/json;q=0.9' } });
  ok(/text\/html/.test(browserAccept.headers.get('content-type') || ''), 'a browser Accept header still gets HTML');

  const api = await fetchPath('/api/lookup?digest=' + DIGEST, pendingEnv);
  const apiBody = await api.json();
  ok(api.status === 200 && apiBody.found === true && apiBody.stage === 'queued' && apiBody.received_at === '2026-11-09T16:02:00.000Z', '/api/lookup returns the queued record as JSON');
  ok(apiBody.certificate === null && apiBody.batch === null, 'queued JSON has no batch or certificate object');

  const apiMissing = await fetchPath('/api/lookup?digest=' + OTHER, emptyEnv);
  const apiMissingBody = await apiMissing.json();
  ok(apiMissing.status === 404 && apiMissingBody.found === false && /No stamp found/.test(apiMissingBody.error), '/api/lookup missing digest is 404 JSON');

  const apiBad = await fetchPath('/api/lookup?digest=nope', emptyEnv);
  ok(apiBad.status === 400 && (await apiBad.json()).error === 'digest must be 64 hex chars (SHA-256)', '/api/lookup malformed digest is 400 JSON');

  const noDb = await fetchPath('/r/' + DIGEST, { ASSETS: pendingEnv.ASSETS });
  ok(noDb.status === 404 && /No stamp found/.test(await noDb.text()), 'missing CT_DB is a friendly 404, not a crash');

  const down = await fetchPath('/r/' + DIGEST, { CT_DB: mockCtDb({ fail: true }), ASSETS: pendingEnv.ASSETS });
  ok(down.status === 502 && /could not be read/.test(await down.text()), 'D1 failure returns 502 HTML');

  const post = await fetchPath('/r/' + DIGEST, pendingEnv, { method: 'POST' });
  ok(post.status === 405, 'POST /r/<digest> is rejected');

  const shape = recordToJson({
    found: true, digest: DIGEST, status: 'anchored', stage: 'anchored',
    received_at: null, stamped_no_later_than: '2026-11-09T16:15:00.000Z',
    batch_opened_at: '2026-11-09T16:00:00.000Z', batch_closed_at: '2026-11-09T16:15:00.000Z',
    batch_id: '2026-11-09T16:00:00.000Z', tree_size: 3, root: 'ab'.repeat(32),
    hostname: HOST, issued_at: '2026-11-09T22:00:00.000Z', published: true,
    crtsh_url: 'https://crt.sh/?q=' + encodeURIComponent(HOST),
  });
  ok(shape.certificate.hostname === HOST && shape.batch.closed_at.endsWith('16:15:00.000Z'), 'JSON shape exposes batch window and certificate, not a PEM');
}
