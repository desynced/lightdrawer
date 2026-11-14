// Static checks for the plain-language example pages under web/ui/examples/.
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SITE = 'https://lightdrawer.org';
const EVENT_ATTR = /\son[a-z]+\s*=/i;
// Every step-by-step guide. The homepage cards and the /examples index must link to each one.
export const GUIDES = ['you-made-it-first', 'repair-or-move-out', 'agreed-version', 'sealed-bids', 'journalists', 'photographers', 'small-businesses', 'artists', 'insurance-records'];
// Wording that would read as a certification, compliance, or guarantee claim. It is only allowed in a
// sentence that clearly says LightDrawer is NOT that (for example "It is not a certification").
const CLAIM = /\b(certified|certif(?:y|ies|ication)|complian(?:t|ce)|guarantee[sd]?|tamper-?proof|legally (?:binding|valid)|court-?(?:approved|proof)|admissible)\b/i;
const NEVER = /\b(SOC ?2|ISO ?27001|HIPAA|GDPR|FedRAMP)\b/i;
const NEGATION = /\b(not|never|no|nor|without)\b/i;

const read = (p) => readFileSync(join(root, p), 'utf8');
// Visible text, one line per block (paragraph, list item, heading, cell), so a heading never shares a sentence with the text after it.
const text = (html) => html.replace(/<(script|style)[\s\S]*?<\/\1>/gi, '\n').replace(/<\/?(?:p|li|h[1-6]|td|th|tr|blockquote|summary|details|div|section|ul|ol|title|header|footer|main)\b[^>]*>/gi, '\n').replace(/<[^>]+>/g, ' ').replace(/&nbsp;|&amp;|&lt;|&gt;/g, ' ').replace(/[ \t]+/g, ' ');
const hrefs = (html) => [...html.matchAll(/<a\s[^>]*href="([^"]*)"/g)].map((m) => m[1]);

// Map a same-site link to the file the static asset server would return (default html_handling).
function siteFile(href) {
  let u;
  try { u = new URL(href, SITE + '/'); } catch { return null; }
  if (u.origin !== SITE) return undefined; // external link, not checked here
  const p = u.pathname;
  if (p === '/') return 'public/index.html';
  if (p === '/examples' || p === '/examples/') return 'public/examples/index.html';
  if (p === '/button') return 'public/button.html';
  if (p.endsWith('.html')) return 'public' + p;
  return 'public' + p + '.html';
}

function claimProblems(html) {
  const bad = [];
  for (const s of text(html).split(/\n|(?<=[.!?])\s+/)) {
    if (NEVER.test(s)) bad.push(s.trim());
    else if (CLAIM.test(s) && !NEGATION.test(s)) bad.push(s.trim());
  }
  return bad;
}

export async function runExamplePagesTests(ok) {
  console.log('Example pages');
  const files = readdirSync(join(root, 'web/ui/examples')).filter((f) => f.endsWith('.html')).sort();
  const expected = [...GUIDES.map((g) => g + '.html'), 'index.html'].sort();
  ok(JSON.stringify(files) === JSON.stringify(expected), `example pages are exactly the ${GUIDES.length} guides plus the index`);

  for (const f of files) {
    const slug = f.replace(/\.html$/, '');
    const name = slug === 'index' ? 'examples index' : slug + ' page';
    const src = read('web/ui/examples/' + f);
    const built = join(root, 'public/examples', f);
    ok(existsSync(built) && readFileSync(built, 'utf8') === src, `build copies the ${name}`);
    ok(!/<script\b/i.test(src) && !EVENT_ATTR.test(src) && !/<style\b/i.test(src) && !/\sstyle\s*=/i.test(src), `${name} has no scripts, inline handlers, or inline styles`);
    ok(/<link rel="stylesheet" href="\/style\.css">/.test(src) && /<main class="docs example-page">/.test(src), `${name} uses the site stylesheet and page layout`);
    const footer = (src.match(/<footer>[\s\S]*?<\/footer>/) || [''])[0];
    const supportLink = hrefs(footer).some((h) => { try { const u = new URL(h); return u.protocol === 'https:' && u.host === 'paypal.me' && u.pathname === '/josephball'; } catch { return false; } });
    ok(src.includes('<header class="top">') && supportLink, `${name} has the site header and footer`);
    const ogUrl = (src.match(/<meta property="og:url" content="([^"]*)">/) || [])[1];
    let og = null;
    try { og = new URL(ogUrl); } catch { /* checked below */ }
    const wantPath = slug === 'index' ? '/examples/' : '/examples/' + slug;
    ok(og !== null && og.protocol === 'https:' && og.host === 'lightdrawer.org' && og.pathname === wantPath && og.search === '' && og.hash === '', `${name} declares its own page URL`);
    ok(/<h2 id="limits">What (?:this|a receipt) does and does not prove<\/h2>/.test(src), `${name} has the "does and does not prove" section`);
    if (slug !== 'index') {
      ok(/<h3>It does not show<\/h3>/.test(src), `${name} lists what a receipt does not show`);
      ok(/<section id="setup"/.test(src) && /<h2 id="mismatch">If something does not match<\/h2>/.test(src), `${name} has step-by-step setup and a mismatch guide`);
      ok(/<blockquote class="sample">/.test(src), `${name} has sample wording`);
      ok(hrefs(src).some((h) => siteFile(h) === 'public/examples/index.html'), `${name} links back to the examples index`);
    }
    const metaText = [...src.matchAll(/<meta (?:name|property)="(?:description|og:title|og:description)" content="([^"]*)">/g)].map((m) => `<p>${m[1]}</p>`).join('');
    const claims = claimProblems(src + metaText);
    ok(claims.length === 0, `${name} makes no certification, compliance, or guarantee claims` + (claims.length ? ': ' + claims.join(' | ') : ''));
    const broken = hrefs(src).filter((h) => !h.startsWith('#')).map((h) => [h, siteFile(h)]).filter(([, p]) => p === null || (p && !existsSync(join(root, p))));
    ok(broken.length === 0, `${name} has no broken site links` + (broken.length ? ': ' + broken.map(([h]) => h).join(', ') : ''));
  }

  const bids = read('web/ui/examples/sealed-bids.html');
  ok(bids.includes('Who sent the file') && bids.includes('That nobody opened the bid early') && bids.includes('mail servers'), 'sealed-bids page states its limits');
  ok(bids.includes('Bid file integrity receipt (requested)'), 'sample bid notice is included');
  ok(!/zipped or renamed/i.test(bids) && /zipped, converted, or re-saved/.test(bids) && /Renaming a file does not change its fingerprint/.test(bids), 'sealed-bids mismatch causes no longer say renaming changes a file');

  const home = read('web/ui/index.html');
  const cardSection = (id) => (home.match(new RegExp(`<section[^>]*aria-labelledby="${id}"[\\s\\S]*?</section>`)) || [''])[0];
  const cards = [cardSection('why-title'), cardSection('who-title')].flatMap((s) => [...s.matchAll(/<li>[\s\S]*?<\/li>/g)].map((m) => m[0]));
  const cardTargets = cards.map((c) => hrefs(c).map(siteFile).filter((p) => p && p.startsWith('public/examples/')));
  ok(cards.length === GUIDES.length && cardTargets.every((t) => t.length === 1 && existsSync(join(root, t[0]))), 'every homepage use-case card links to an existing example page');
  const linked = new Set(cardTargets.flat());
  ok(GUIDES.every((g) => linked.has(`public/examples/${g}.html`)), 'the homepage cards link every guide');
  ok(hrefs(home).some((h) => siteFile(h) === 'public/examples/index.html'), 'homepage links the examples index');
  ok(/<a href="\/examples\/sealed-bids">/.test(home), 'homepage links the sealed-bids example');

  const index = read('web/ui/examples/index.html');
  const indexTargets = new Set(hrefs(index).map(siteFile));
  ok(GUIDES.every((g) => indexTargets.has(`public/examples/${g}.html`)), 'examples index links every guide');

  // /examples and /examples/ are served from public/examples/index.html by the static asset server
  // (default html_handling), as long as the Worker does not run first for that path.
  const wr = read('wrangler.jsonc');
  const htmlHandling = (wr.match(/"html_handling"\s*:\s*"([^"]+)"/) || [])[1];
  const firstList = (wr.match(/"run_worker_first"\s*:\s*\[([^\]]*)\]/) || [])[1] || '';
  const first = [...firstList.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  const workerFirst = (p) => first.some((r) => r === p || (r.endsWith('/*') && p.startsWith(r.slice(0, -1))));
  ok((htmlHandling === undefined || htmlHandling === 'auto-trailing-slash') && !workerFirst('/examples') && !workerFirst('/examples/') && existsSync(join(root, 'public/examples/index.html')), '/examples is served from the static examples index');
}
