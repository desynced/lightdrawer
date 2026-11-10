import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  compareFileHash,
  normalizeHexHash,
  parseDigestFragment,
  parseExpectQuery,
  resolveStampLink,
  stampLinkNotice,
} from '../src/stamp-link.js';
import worker from '../src/worker.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const OTHER = 'a'.repeat(64);
const SAMPLE = '078f28349dca9d925f4a9ccc012ae3d02dd03fc7ae02a875804348c941edf334';
const EVENT_ATTR = /\son[a-z]+\s*=/i;
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr', 'path', 'circle', 'rect', 'stop']);

function decodeEntities(html) {
  return String(html)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');
}

function extractSnippet(html, id) {
  const m = html.match(new RegExp(`<code id="${id}">([\\s\\S]*?)</code>`));
  return m ? decodeEntities(m[1]) : null;
}

function tagsMatch(html) {
  const re = /<(\/)?([a-zA-Z][\w:-]*)\b[^>]*?(\/)?>/g;
  const stack = [];
  let m;
  while ((m = re.exec(html))) {
    const close = m[1];
    const name = m[2].toLowerCase();
    const self = m[3];
    if (self || VOID.has(name)) continue;
    if (close) {
      if (stack.pop() !== name) return false;
    } else {
      stack.push(name);
    }
  }
  return stack.length === 0;
}

export async function runStampButtonTests(ok) {
  console.log('Stamp button link parsing and notices');

  ok(normalizeHexHash(ABC) === ABC, 'valid lowercase hash is accepted');
  ok(normalizeHexHash(ABC.toUpperCase()) === ABC, 'uppercase hash is normalized');
  ok(normalizeHexHash('  ' + ABC + '  ') === ABC, 'surrounding whitespace is trimmed');
  ok(normalizeHexHash(ABC + '0') === null, 'a 65-character value is rejected');
  ok(normalizeHexHash(ABC.slice(0, 63)) === null, 'a 63-character value is rejected');
  ok(normalizeHexHash('') === null && normalizeHexHash(null) === null, 'empty values are rejected');
  ok(normalizeHexHash('<img src=x onerror=alert(1)>') === null, 'an HTML payload is not a hash');
  ok(normalizeHexHash('javascript:alert(1)') === null, 'a javascript: URL is not a hash');
  ok(normalizeHexHash(ABC + '\n') === ABC, 'a trailing newline is trimmed before the hex check');

  ok(parseExpectQuery('').present === false && parseExpectQuery('').hash === null, 'missing expect is absent');
  ok(parseExpectQuery('?expect=' + ABC).hash === ABC, 'expect query is read');
  ok(parseExpectQuery('expect=' + ABC).hash === ABC, 'expect query works without a leading ?');
  ok(parseExpectQuery('?expect=' + encodeURIComponent('<script>alert(1)</script>')).hash === null, 'XSS expect value is rejected');
  ok(parseExpectQuery('?expect=' + encodeURIComponent('<script>alert(1)</script>')).present === true, 'invalid expect is still marked present');
  const xssSearch = resolveStampLink({ search: '?expect=<img src=x onerror=alert(1)>' });
  ok(!JSON.stringify(xssSearch).includes('<img') && !JSON.stringify(xssSearch).includes('onerror'), 'parsed expect result does not keep raw HTML');
  ok(xssSearch.invalid && !xssSearch.expected, 'invalid expect does not become the expected hash');

  ok(parseDigestFragment('').present === false, 'missing fragment digest is absent');
  ok(parseDigestFragment('#digest=' + ABC).hash === ABC, 'fragment digest is read');
  ok(parseDigestFragment('#foo=1&digest=' + ABC).hash === ABC, 'fragment digest can follow another param');
  ok(parseDigestFragment('#digest=' + ABC + '&foo=1').hash === ABC, 'fragment digest can precede another param');
  ok(parseDigestFragment('#digest=' + encodeURIComponent(ABC.toUpperCase())).hash === ABC, 'encoded fragment digest is decoded and normalized');
  const xssFrag = resolveStampLink({ hash: '#digest=<img src=x onerror=alert(1)>' });
  ok(!JSON.stringify(xssFrag).includes('<img') && xssFrag.invalid && !xssFrag.expected, 'XSS fragment is rejected and not reflected');

  const onlyExpect = resolveStampLink({ search: '?expect=' + ABC });
  ok(onlyExpect.expected === ABC && onlyExpect.source === 'query' && !onlyExpect.conflict, 'expect-only link uses the query hash');
  const onlyFrag = resolveStampLink({ hash: '#digest=' + OTHER });
  ok(onlyFrag.expected === OTHER && onlyFrag.source === 'fragment', 'digest-only link uses the fragment hash');
  const bothSame = resolveStampLink({ search: '?expect=' + ABC, hash: '#digest=' + ABC });
  ok(bothSame.expected === ABC && !bothSame.conflict && bothSame.source === 'fragment', 'matching expect and digest prefer the fragment without conflict');
  const bothDiff = resolveStampLink({ search: '?expect=' + ABC, hash: '#digest=' + OTHER });
  ok(bothDiff.conflict && bothDiff.expected === OTHER && bothDiff.source === 'fragment', 'conflicting values prefer the fragment digest and flag a conflict');
  const ignoredDigestQuery = resolveStampLink({ search: '?digest=' + ABC });
  ok(!ignoredDigestQuery.expected && !ignoredDigestQuery.expect.present, '?digest= is not treated as an expected file hash');

  ok(compareFileHash(ABC, ABC) === 'match', 'identical hashes match');
  ok(compareFileHash(ABC.toUpperCase(), ABC) === 'match', 'hash compare is case-insensitive');
  ok(compareFileHash(ABC, OTHER) === 'mismatch', 'different hashes mismatch');
  ok(compareFileHash(ABC, null) === 'none', 'no expected hash is none');
  ok(compareFileHash(null, ABC) === 'waiting', 'expected hash with no file is waiting');

  const wait = stampLinkNotice(onlyExpect, null);
  ok(wait.comparison === 'waiting' && wait.canStamp && wait.notices.some((n) => n.kind === 'waiting'), 'a known expect without a file shows a waiting notice');
  ok(wait.notices.every((n) => !String(n.title + n.body).includes('<')), 'waiting notice text has no HTML markup');
  const match = stampLinkNotice(onlyExpect, ABC);
  ok(match.comparison === 'match' && match.canStamp && match.notices.some((n) => n.kind === 'match' && n.hash === ABC), 'a matching file is allowed to stamp');
  const miss = stampLinkNotice(onlyExpect, OTHER);
  ok(miss.comparison === 'mismatch' && miss.canStamp === false, 'a mismatched file cannot stamp');
  ok(miss.notices.some((n) => n.kind === 'mismatch' && n.expected === ABC && n.actual === OTHER), 'mismatch notice names both validated hashes');
  const conflictNotice = stampLinkNotice(bothDiff, ABC);
  ok(conflictNotice.notices.some((n) => n.kind === 'conflict') && conflictNotice.notices.some((n) => n.kind === 'mismatch'), 'conflicting link plus a file matching only expect still warns');
  const invalidNotice = stampLinkNotice(xssSearch, null);
  const invalidBlob = JSON.stringify(invalidNotice);
  ok(invalidNotice.notices.some((n) => n.kind === 'invalid'), 'invalid input produces a generic invalid notice');
  ok(!invalidBlob.includes('<img') && !invalidBlob.includes('onerror') && !invalidBlob.includes('alert(1)'), 'notices do not echo a raw XSS payload');

  console.log('Stamp button snippets and docs');
  const buttonHtml = readFileSync(join(root, 'web/ui/button.html'), 'utf8');
  const exampleHtml = readFileSync(join(root, 'examples/stamp-button/example.html'), 'utf8');
  const helper = readFileSync(join(root, 'web/snippets/lightdrawer-stamp.js'), 'utf8');
  const exampleHelper = readFileSync(join(root, 'examples/stamp-button/lightdrawer-stamp.js'), 'utf8');
  const publicHelper = readFileSync(join(root, 'public/lightdrawer-stamp.js'), 'utf8');
  ok(helper === exampleHelper && helper === publicHelper, 'docs, example, and built helper script are identical');

  const linkSnippet = extractSnippet(buttonHtml, 'snippet-link');
  const expectSnippet = extractSnippet(buttonHtml, 'snippet-expect');
  const embedSnippet = extractSnippet(buttonHtml, 'snippet-embed');
  const checkSnippet = extractSnippet(buttonHtml, 'snippet-check');
  const cssSnippet = extractSnippet(buttonHtml, 'snippet-css');
  ok(!!linkSnippet && !!expectSnippet && !!embedSnippet && !!checkSnippet && !!cssSnippet, 'docs page includes every copy-paste snippet');

  for (const [name, html] of [['link', linkSnippet], ['expect', expectSnippet], ['embed', embedSnippet], ['check', checkSnippet]]) {
    ok(tagsMatch(html), name + ' snippet has matching HTML tags');
    ok(!EVENT_ATTR.test(html), name + ' snippet has no inline event handlers');
    ok(!/javascript:/i.test(html), name + ' snippet has no javascript: URLs');
    ok(!html.includes('/api/stamp'), name + ' snippet does not mention /api/stamp');
    ok(html.includes('https://lightdrawer.org'), name + ' snippet points at lightdrawer.org');
  }
  ok(linkSnippet.includes('Stamp this with LightDrawer'), 'simple link uses the public label');
  ok(/expect=YOUR_FILE_SHA256_HERE/.test(expectSnippet), 'expect snippet uses a placeholder file hash');
  ok(/data-lightdrawer-file="file-to-stamp"/.test(embedSnippet) && embedSnippet.includes('lightdrawer-stamp.js'), 'embed snippet uses a data attribute and a self-hosted script');
  ok(embedSnippet.includes('<script src="lightdrawer-stamp.js" defer></script>'), 'embed snippet loads the helper with defer and no inline handlers');
  ok(/\/r\/RECEIPT_FINGERPRINT_HERE/.test(checkSnippet), 'check snippet points at /r/<receipt fingerprint>');
  ok(cssSnippet.includes('.lightdrawer-stamp') && !EVENT_ATTR.test(cssSnippet), 'optional CSS targets the stamp class');
  ok(!EVENT_ATTR.test(buttonHtml) && !EVENT_ATTR.test(exampleHtml), 'docs and example pages have no inline event handlers');

  ok(!/fetch\s*\(/.test(helper) && !/XMLHttpRequest/.test(helper), 'helper script does not make network requests');
  ok(!/Authorization/i.test(helper) && !/ldsk_/.test(helper), 'helper script does not mention API keys');
  ok(helper.includes("url.hash = 'digest=' + digest"), 'helper puts the file hash in the URL fragment');
  ok(helper.includes('addEventListener') && !EVENT_ATTR.test(helper), 'helper is CSP-friendly');
  ok(!/return=/.test(linkSnippet + expectSnippet + embedSnippet + checkSnippet), 'snippets do not add a return= redirect');

  ok(exampleHtml.includes('https://lightdrawer.org/?expect=' + SAMPLE), 'example page’s simple link expects the sample file hash');
  ok(exampleHtml.includes('data-lightdrawer-file="file-to-stamp"'), 'example page includes the embed button');
  ok(exampleHtml.includes('https://lightdrawer.org/r/RECEIPT_FINGERPRINT_HERE'), 'example page includes the check-receipt variant');
  ok(exampleHtml.includes('example-demo.js'), 'example page can retarget a local LightDrawer origin without changing committed hrefs');

  const sample = readFileSync(join(root, 'examples/stamp-button/sample.txt'));
  const { createHash } = await import('node:crypto');
  ok(createHash('sha256').update(sample).digest('hex') === SAMPLE, 'documented sample.txt hash matches the file bytes');

  const appJs = readFileSync(join(root, 'public/app.js'), 'utf8');
  ok(appJs.includes('function resolveStampLink') && appJs.includes('function stampLinkNotice'), 'homepage bundle includes stamp-link helpers');
  ok(readFileSync(join(root, 'public/button.html'), 'utf8').includes('Stamp this with LightDrawer'), 'build copies the button guide');
  ok(readFileSync(join(root, 'public/button.js'), 'utf8').includes('data-copy-target'), 'build copies the copy-button script');

  console.log('Stamp button does not loosen /api/stamp');
  const savedFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('challenges.cloudflare.com/turnstile')) return Response.json({ success: false });
    throw new Error('unexpected fetch: ' + url);
  };
  try {
    const env = { TURNSTILE_SECRET: 'test-turnstile-secret' };
    const cross = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'https://other.example' },
      body: JSON.stringify({ digest: ABC }),
    }), env, { waitUntil() {} });
    ok(cross.status === 403 && /cross-origin/.test((await cross.json()).error), 'cross-origin /api/stamp without a key is still rejected');
    ok(!cross.headers.get('access-control-allow-origin'), 'cross-origin stamp rejection sends no CORS header');
    const keyless = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ digest: ABC }),
    }), env, { waitUntil() {} });
    ok(keyless.status === 403 && /Human check/.test((await keyless.json()).error), 'keyless /api/stamp without Turnstile is still rejected');
    const preflight = await worker.fetch(new Request('https://lightdrawer.example/api/stamp', {
      method: 'OPTIONS',
      headers: { origin: 'https://other.example', 'access-control-request-method': 'POST' },
    }), env, { waitUntil() {} });
    ok(preflight.status === 405 && !preflight.headers.get('access-control-allow-origin'), 'OPTIONS preflight on /api/stamp is still rejected');
  } finally {
    globalThis.fetch = savedFetch;
  }
}
