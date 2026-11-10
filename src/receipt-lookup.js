// Public fingerprint lookup for shareable receipt links.
// LightDrawer stores only SHA-256 fingerprints (never files or full receipts).
// Exact first-seen time lives in ct_pending.received_at. Once a digest moves
// into a closed sub-batch, that timestamp is deleted; only the batch window
// (ct_batches.opened_at / closed_at) remains, so the honest label is
// "stamped no later than" the window close.
const DIGEST_RE = /^[0-9a-f]{64}$/;

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];

const LOGO_SVG = `<svg class="logo-mark" viewBox="0 0 128 128" width="36" height="36" aria-hidden="true"><defs><radialGradient id="ldGlow" cx="64" cy="64" r="22" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#FFF1B8"/><stop offset="1" stop-color="#FFF1B8" stop-opacity="0"/></radialGradient></defs><circle cx="64" cy="64" r="22" fill="url(#ldGlow)" opacity=".55"/><g fill="none" stroke-linecap="round" stroke-width="7"><path d="M56 118 H40 A30 30 0 0 1 10 88 V40 A30 30 0 0 1 40 10 H88 A30 30 0 0 1 118 40 V88 A30 30 0 0 1 88 118 H72" stroke="currentColor"/><path d="M56 102 H46 A20 20 0 0 1 26 82 V46 A20 20 0 0 1 46 26 H82 A20 20 0 0 1 102 46 V82 A20 20 0 0 1 82 102 H72" stroke="currentColor"/><path d="M56 86 H52 A10 10 0 0 1 42 76 V52 A10 10 0 0 1 52 42 H76 A10 10 0 0 1 86 52 V76 A10 10 0 0 1 76 86 H72" stroke="#C9A227"/></g><circle cx="64" cy="64" r="11" fill="none" stroke="#C9A227" stroke-width="4"/><path d="M64 57 V64 L69 68" fill="none" stroke="#C9A227" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/><path d="M64 86 V122" stroke="#C9A227" stroke-width="5" stroke-linecap="round"/></svg>`;

export function normalizeDigest(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  return DIGEST_RE.test(s) ? s : null;
}

export function receiptPath(digest) {
  return '/r/' + digest;
}

export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function formatUtc(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  const hours = d.getUTCHours();
  const h12 = hours % 12 || 12;
  const mins = String(d.getUTCMinutes()).padStart(2, '0');
  const ampm = hours >= 12 ? 'PM' : 'AM';
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} at ${h12}:${mins} ${ampm} UTC`;
}

function crtshUrl(hostname) {
  return hostname ? 'https://crt.sh/?q=' + encodeURIComponent(hostname) : null;
}

export async function lookupStamp(db, digest) {
  const row = await db.prepare(
    `SELECT b.published, b.hostname, b.root, b.tree_size, b.id AS batch_id,
            b.opened_at, b.closed_at, c.issued_at
       FROM ct_leaves l
       JOIN ct_batches b ON b.id = l.batch_id
       LEFT JOIN ct_certs c ON c.id = b.cert_id
      WHERE l.digest = ?`
  ).bind(digest).first();
  if (row) {
    // published with a certificate is "anchored". A closed batch still waiting
    // for a certificate stays "pending", but the batch window is already known.
    const anchored = !!(row.published && row.issued_at);
    return {
      found: true,
      digest,
      status: anchored ? 'anchored' : 'pending',
      stage: anchored ? 'anchored' : 'batched',
      received_at: null,
      stamped_no_later_than: row.closed_at || null,
      batch_opened_at: row.opened_at || null,
      batch_closed_at: row.closed_at || null,
      batch_id: row.batch_id || null,
      tree_size: row.tree_size == null ? null : row.tree_size,
      root: row.root || null,
      hostname: row.hostname || null,
      issued_at: row.issued_at || null,
      published: !!row.published,
      crtsh_url: crtshUrl(row.hostname),
    };
  }
  const pending = await db.prepare('SELECT digest, received_at FROM ct_pending WHERE digest = ?').bind(digest).first();
  if (pending) {
    return {
      found: true,
      digest,
      status: 'pending',
      stage: 'queued',
      received_at: pending.received_at || null,
      stamped_no_later_than: null,
      batch_opened_at: null,
      batch_closed_at: null,
      batch_id: null,
      tree_size: null,
      root: null,
      hostname: null,
      issued_at: null,
      published: false,
      crtsh_url: null,
    };
  }
  return { found: false, digest, status: 'not_found' };
}

export function recordToJson(record) {
  if (!record || !record.found) {
    return {
      found: false,
      digest: record && record.digest ? record.digest : null,
      error: 'No stamp found for this fingerprint.',
    };
  }
  return {
    found: true,
    digest: record.digest,
    status: record.status,
    stage: record.stage,
    received_at: record.received_at,
    stamped_no_later_than: record.stamped_no_later_than,
    batch: record.stage === 'queued' ? null : {
      opened_at: record.batch_opened_at,
      closed_at: record.batch_closed_at,
      id: record.batch_id,
      tree_size: record.tree_size,
      root: record.root,
      hostname: record.hostname,
      published: record.published,
    },
    certificate: record.status === 'anchored' ? {
      issued_at: record.issued_at,
      hostname: record.hostname,
      crtsh_url: record.crtsh_url,
    } : null,
  };
}

export function cacheControlFor(kind, record) {
  if (kind === 'malformed') return 'public, max-age=300';
  if (kind === 'error') return 'no-store';
  if (kind === 'not_found') return 'public, max-age=60';
  if (record && record.status === 'anchored') return 'public, max-age=3600';
  return 'public, max-age=60';
}

export function securityHeaders(contentType, cacheControl) {
  const csp = contentType.includes('html')
    ? "default-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    : "default-src 'none'; frame-ancestors 'none'";
  return {
    'content-type': contentType,
    'cache-control': cacheControl,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'x-frame-options': 'DENY',
    'content-security-policy': csp,
  };
}

function preferJson(req) {
  const accept = req.headers.get('accept') || '';
  if (!accept.includes('application/json')) return false;
  if (accept.includes('text/html')) return false;
  return true;
}

export function wantsJson(req, pathname) {
  return pathname === '/api/lookup' || preferJson(req);
}

function shell({ title, description, canonical, robots, body }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#F4F2EC" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#1A1814" media="(prefers-color-scheme: dark)">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(description)}">
${robots ? '<meta name="robots" content="noindex">\n' : ''}<link rel="canonical" href="${escapeHtml(canonical)}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/apple-touch-icon.png" sizes="180x180">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="top">
  <a class="brand" href="/" aria-label="LightDrawer home">
    ${LOGO_SVG}
    <span class="wordmark"><span class="light">Light</span><span class="drawer">Drawer</span></span>
  </a>
  <nav aria-label="Primary">
    <a href="/">Make a receipt</a>
    <a href="/verify.html">Check a receipt</a>
  </nav>
</header>
<main>
${body}
</main>
<footer>No accounts. No file storage. This page shows only what LightDrawer itself recorded. <a href="https://paypal.me/josephball" rel="noopener">Support LightDrawer</a>.</footer>
</body>
</html>
`;
}

function howToCheck() {
  return `<section class="how-check">
  <h2>How to check this yourself</h2>
  <p>This page only shows whether LightDrawer has a record of the fingerprint, and what its certificate-log status is. It is not the full proof, and you do not have to trust this website.</p>
  <p>The complete time records — Bitcoin (OpenTimestamps) and the RFC&nbsp;3161 timestamp — live in the receipt file the person kept (usually a download ending in <code>.lightdrawer-receipt.zip</code>). Anyone can open the <a href="/verify.html">receipt checker</a> and drop in that receipt plus the original file. The checker works even if you save a copy and open it offline.</p>
  <p>A match means that exact file existed by the time on the receipt. It does not show who made the file, or that what it shows is true.</p>
</section>`;
}

function technicalDetails(digest, record) {
  const rows = [];
  const add = (k, v) => { if (v != null && v !== '') rows.push(`<dt>${escapeHtml(k)}</dt><dd><code>${escapeHtml(String(v))}</code></dd>`); };
  add('Fingerprint', digest);
  if (!record || !record.found) return `<details class="tech"><summary>Technical details</summary>
    <dl>
      ${rows.join('\n      ')}
    </dl>
    <p>A LightDrawer fingerprint is a SHA-256 hash, written as 64 lowercase hexadecimal characters. For a receipt made on this site, the link uses the hash of <code>statement.json</code> (the file’s fingerprint plus any notes), which is what was sent to the witnesses — not the hash of the original file alone.</p>
  </details>`;
  add('Status', record.status);
  add('Stage', record.stage);
  add('First received (ISO-8601)', record.received_at);
  add('Batch opened (ISO-8601)', record.batch_opened_at);
  add('Batch closed (ISO-8601)', record.batch_closed_at);
  add('Batch id', record.batch_id);
  add('Tree size', record.tree_size);
  add('Merkle root', record.root);
  add('Certificate hostname', record.hostname);
  add('Certificate issued (ISO-8601)', record.issued_at);
  return `<details class="tech"><summary>Technical details</summary>
    <dl>
      ${rows.join('\n      ')}
    </dl>
    <p>A LightDrawer fingerprint is a SHA-256 hash, written as 64 lowercase hexadecimal characters. For a receipt made on this site, the link uses the hash of <code>statement.json</code> (the file’s fingerprint plus any notes), which is what was sent to the witnesses — not the hash of the original file alone. The exact first-seen time is stored only while the fingerprint is waiting in the queue. After it is placed in a batch, only the batch window remains.</p>
  </details>`;
}

function timeBlock(record) {
  if (record.received_at) {
    const pretty = formatUtc(record.received_at) || record.received_at;
    return `<dt>First received</dt><dd>${escapeHtml(pretty)}. This is when LightDrawer first saw the fingerprint.</dd>`;
  }
  if (record.stamped_no_later_than) {
    const latest = formatUtc(record.stamped_no_later_than) || record.stamped_no_later_than;
    const opened = formatUtc(record.batch_opened_at);
    const closed = formatUtc(record.batch_closed_at);
    const window = opened && closed
      ? ` LightDrawer received it during the batch window from ${opened} to ${closed}. The exact second is not kept after the fingerprint is placed in a batch.`
      : ' The exact second is not kept after the fingerprint is placed in a batch.';
    return `<dt>Stamped no later than</dt><dd>${escapeHtml(latest)}.${escapeHtml(window)}</dd>`;
  }
  return '';
}

function ctBlock(record) {
  if (record.status === 'anchored') {
    const issued = formatUtc(record.issued_at);
    const host = record.hostname ? `<code>${escapeHtml(record.hostname)}</code>` : 'the batch hostname';
    const crt = record.crtsh_url ? ` <a href="${escapeHtml(record.crtsh_url)}" rel="noopener">Look it up on crt.sh</a>` : '';
    const issuedLine = issued ? ` The certificate was issued on ${escapeHtml(issued)}.` : '';
    return `<dt>Certificate log</dt><dd>Published. A public certificate includes ${host}.${issuedLine}${crt}</dd>`;
  }
  if (record.stage === 'batched') {
    return `<dt>Certificate log</dt><dd>On the way. This fingerprint is already in a batch and is waiting for a public certificate, usually within about six hours.</dd>`;
  }
  return `<dt>Certificate log</dt><dd>On the way. LightDrawer has the fingerprint and will add it to a public certificate-log record, usually within about six hours.</dd>`;
}

export function renderReceiptHtml({ kind, digest, record, origin }) {
  const canonical = origin + (digest ? receiptPath(digest) : '/r/');
  if (kind === 'malformed') {
    const body = `<h1>That does not look like a fingerprint</h1>
  <p class="promise">A LightDrawer fingerprint is 64 hexadecimal characters — the letters a–f and the digits 0–9.</p>
  <p>Check the link and try again. If you copied it by hand, a missing or extra character is enough to make it invalid.</p>
  ${howToCheck()}
  ${technicalDetails(digest || '', null)}
  <p><a href="/">Make a receipt</a> · <a href="/verify.html">Check a receipt</a></p>`;
    return shell({
      title: 'That does not look like a fingerprint — LightDrawer',
      description: 'A LightDrawer fingerprint is 64 hexadecimal characters.',
      canonical: origin + '/',
      robots: true,
      body,
    });
  }
  if (kind === 'not_found') {
    const body = `<h1>No stamp found for this fingerprint</h1>
  <p class="promise">LightDrawer does not have a record of this fingerprint.</p>
  <p class="fingerprint-box"><strong>Fingerprint</strong><br><code>${escapeHtml(digest)}</code></p>
  <p>That can happen if the address has a typo, if the file was stamped somewhere else or never stamped here, or if the file was not hashed exactly — even a tiny change produces a different fingerprint.</p>
  <p>For a receipt made on this site, the link uses the fingerprint of the receipt’s statement, not the hash of the original file alone.</p>
  ${howToCheck()}
  ${technicalDetails(digest, null)}
  <p><a href="/">Make a receipt</a> · <a href="/verify.html">Check a receipt</a></p>`;
    return shell({
      title: 'No stamp found for this fingerprint — LightDrawer',
      description: 'LightDrawer does not have a record of this fingerprint.',
      canonical,
      robots: true,
      body,
    });
  }
  if (kind === 'error') {
    const body = `<h1>This record could not be read just now</h1>
  <p class="promise">Something went wrong while looking up that fingerprint. Please try again in a minute.</p>
  ${digest ? `<p class="fingerprint-box"><strong>Fingerprint</strong><br><code>${escapeHtml(digest)}</code></p>` : ''}
  <p><a href="/">Make a receipt</a> · <a href="/verify.html">Check a receipt</a></p>`;
    return shell({
      title: 'Lookup unavailable — LightDrawer',
      description: 'The fingerprint record could not be read just now.',
      canonical: digest ? canonical : origin + '/',
      robots: true,
      body,
    });
  }
  const lead = record.stage === 'anchored'
    ? 'LightDrawer has a public certificate-log record of this fingerprint.'
    : 'LightDrawer has a record of this fingerprint.';
  const body = `<h1>Fingerprint record</h1>
  <p class="promise">${escapeHtml(lead)}</p>
  <p class="fingerprint-box"><strong>Fingerprint</strong><br><code>${escapeHtml(digest)}</code></p>
  <dl>
    <dt>Record</dt><dd>Yes — LightDrawer has seen this fingerprint.</dd>
    ${timeBlock(record)}
    ${ctBlock(record)}
  </dl>
  ${howToCheck()}
  ${technicalDetails(digest, record)}
  <p><a href="/">Make a receipt</a> · <a href="/verify.html">Check a receipt</a></p>`;
  return shell({
    title: 'Fingerprint record — LightDrawer',
    description: lead,
    canonical,
    robots: true,
    body,
  });
}

export function htmlResponse(req, { kind, digest, record, origin, status }) {
  const cache = cacheControlFor(kind, record);
  const html = renderReceiptHtml({ kind, digest, record, origin });
  const headers = securityHeaders('text/html; charset=utf-8', cache);
  const body = req.method === 'HEAD' ? null : html;
  return new Response(body, { status, headers });
}

export function jsonResponse(req, { kind, digest, record, status }) {
  const cache = cacheControlFor(kind, record);
  let payload;
  if (kind === 'malformed') payload = { error: 'digest must be 64 hex chars (SHA-256)' };
  else if (kind === 'error') payload = { error: 'CT store error' };
  else payload = recordToJson(record || { found: false, digest });
  const headers = securityHeaders('application/json; charset=utf-8', cache);
  const body = req.method === 'HEAD' ? null : JSON.stringify(payload);
  return new Response(body, { status, headers });
}

export function parseReceiptPath(pathname) {
  if (pathname === '/r' || pathname === '/r/') return { kind: 'empty' };
  if (!pathname.startsWith('/r/')) return null;
  let rest = pathname.slice(3);
  const slash = rest.endsWith('/');
  if (slash) rest = rest.slice(0, -1);
  if (!rest || rest.includes('/')) return { kind: 'malformed', raw: rest };
  const digest = normalizeDigest(rest);
  if (!digest) return { kind: 'malformed', raw: rest };
  return { kind: 'ok', digest, raw: rest, trailingSlash: slash, needsCanonical: slash || rest !== digest };
}

export function redirectToReceipt(origin, digest, status = 302) {
  return new Response(null, {
    status,
    headers: {
      location: origin + receiptPath(digest),
      'cache-control': 'public, max-age=3600',
      'referrer-policy': 'no-referrer',
    },
  });
}
