// Static checks for the plain-language example pages under web/ui/examples/.
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const EVENT_ATTR = /\son[a-z]+\s*=/i;

export async function runExamplePagesTests(ok) {
  console.log('Example pages');
  const src = readFileSync(join(root, 'web/ui/examples/sealed-bids.html'), 'utf8');
  const built = join(root, 'public/examples/sealed-bids.html');
  ok(existsSync(built) && readFileSync(built, 'utf8') === src, 'build copies the sealed-bids example page');
  ok(!/<script\b/i.test(src) && !EVENT_ATTR.test(src), 'sealed-bids page has no scripts or inline event handlers');
  const ogUrl = (src.match(/<meta property="og:url" content="([^"]*)">/) || [])[1];
  let ogParsed = null;
  try { ogParsed = new URL(ogUrl); } catch { /* checked below */ }
  ok(/<link rel="stylesheet" href="\/style\.css">/.test(src), 'sealed-bids page uses the site stylesheet');
  ok(ogParsed !== null && ogParsed.origin === 'https://lightdrawer.org' && ogParsed.pathname === '/examples/sealed-bids', 'sealed-bids page declares its own page URL');
  ok(src.includes('Who sent the file') && src.includes('That nobody opened the bid early') && src.includes('mail servers'), 'sealed-bids page states its limits');
  ok(!/\b(SOC ?2|ISO ?27001|certified|guarantee[sd]?)\b/i.test(src.replace(/It is not a certification/g, '')), 'sealed-bids page makes no certification or guarantee claims');
  ok(src.includes('Bid file integrity receipt (requested)'), 'sample bid notice is included');
  const home = readFileSync(join(root, 'web/ui/index.html'), 'utf8');
  ok(/<a href="\/examples\/sealed-bids">/.test(home), 'homepage links the sealed-bids example');
}
