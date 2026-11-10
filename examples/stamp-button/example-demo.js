/* Local-demo helper: if this page is opened with ?ld=http://127.0.0.1:8787
   (or another http(s) origin), rewrite LightDrawer links to that origin so
   a developer can try the button against a local wrangler server. Production
   copies of this page should omit ?ld= and keep the https://lightdrawer.org links. */
(function () {
  'use strict';
  const raw = new URLSearchParams(window.location.search).get('ld');
  if (!raw) return;
  let base;
  try { base = new URL(raw); } catch (err) { return; }
  if (base.protocol !== 'http:' && base.protocol !== 'https:') return;
  const links = document.querySelectorAll('a[href^="https://lightdrawer.org"]');
  for (let i = 0; i < links.length; i++) {
    const current = new URL(links[i].getAttribute('href'), 'https://lightdrawer.org');
    links[i].href = base.origin + current.pathname + current.search + current.hash;
  }
})();
