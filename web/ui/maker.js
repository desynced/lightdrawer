/* Receipt maker UI (served by the Worker's static assets). */
(function () {
  const $ = (id) => document.getElementById(id);
  let file = null, fileHash = null, c2pa = null, cfg = { turnstileSiteKey: '' }, tsToken = null, tsWidget = null;
  function friendlyTime(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return String(iso);
      return d.toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
    } catch (e) { return String(iso); }
  }
  // provenance form
  for (const [k, label, help] of PROVENANCE_FIELDS) {
    const w = document.createElement('div'); if (k === 'collector_notes' || k === 'source_url') w.className = 'wide';
    const l = document.createElement('label'); l.htmlFor = 'p_' + k; l.textContent = label; const s = document.createElement('small'); s.textContent = help; l.append(s);
    const i = document.createElement(k === 'collector_notes' ? 'textarea' : 'input'); i.id = 'p_' + k; if (k === 'collected_at') i.placeholder = new Date().toISOString();
    w.append(l, i); $('prov').append(w);
  }
  fetch('/api/config').then((r) => r.json()).then((c) => { cfg = c; if (c.turnstileSiteKey) loadTurnstile(); }).catch(() => {});
  function loadTurnstile() {
    window.onTurnstileLoad = () => { tsWidget = window.turnstile.render('#turnstile', { sitekey: cfg.turnstileSiteKey, callback: (t) => { tsToken = t; }, 'expired-callback': () => { tsToken = null; } }); };
    const s = document.createElement('script'); s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad'; s.async = true; document.head.append(s);
  }
  const drop = $('drop'), input = $('file');
  function currentStampLink() {
    return resolveStampLink({ search: location.search, hash: location.hash });
  }
  function renderStampLinkBanner(notice) {
    const box = $('expect-banner');
    if (!box) return;
    box.replaceChildren();
    if (!notice || !notice.notices.length) {
      box.hidden = true;
      box.className = 'expect-banner';
      return;
    }
    box.hidden = false;
    const kinds = notice.notices.map((n) => n.kind);
    box.className = 'expect-banner' + (
      kinds.includes('mismatch') || kinds.includes('conflict') ? ' mismatch' :
      kinds.includes('match') ? ' match' : ' info'
    );
    for (const n of notice.notices) {
      const h = document.createElement('strong');
      h.textContent = n.title;
      box.append(h);
      const p = document.createElement('p');
      p.textContent = n.body;
      box.append(p);
      if (n.hash || n.expected) {
        const row = document.createElement('p');
        row.append('Expected fingerprint: ');
        const code = document.createElement('code');
        code.textContent = n.hash || n.expected;
        row.append(code);
        box.append(row);
      }
      if (n.actual) {
        const row = document.createElement('p');
        row.append('This file’s fingerprint: ');
        const code = document.createElement('code');
        code.textContent = n.actual;
        row.append(code);
        box.append(row);
      }
    }
  }
  function applyStampLinkState(currentFileHash) {
    const notice = stampLinkNotice(currentStampLink(), currentFileHash);
    renderStampLinkBanner(notice);
    return notice;
  }
  applyStampLinkState(null);
  window.addEventListener('hashchange', () => {
    const notice = applyStampLinkState(fileHash);
    if (fileHash) $('go').disabled = !notice.canStamp;
  });
  drop.addEventListener('click', () => input.click());
  drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]); });
  input.addEventListener('change', () => input.files[0] && pick(input.files[0]));
  async function pick(f) {
    file = f; $('status').textContent = 'Preparing a fingerprint…'; $('go').disabled = true; $('result').textContent = '';
    try {
      fileHash = toHex(await sha256Source(f, {
        onProgress(done, total) {
          if (!total) return;
          const pct = Math.min(100, Math.floor((done * 100) / total));
          $('status').textContent = total > SHA256_FILE_CHUNK
            ? `Preparing a fingerprint… ${pct}% (${formatBytes(done)} of ${formatBytes(total)})`
            : 'Preparing a fingerprint…';
        },
      }));
      try { c2pa = await c2paInspectSource(f); } catch (e) { c2pa = { present: true, error: e.message }; }
      $('fileinfo').hidden = false; $('hash').textContent = fileHash; $('size').textContent = `${f.size.toLocaleString()} bytes · ${f.name}`;
      $('c2pa').textContent = !c2pa.present ? 'None found' : c2pa.error ? 'Present but could not be read: ' + c2pa.error : `Found (${c2pa.manifestCount}): ${[c2pa.active.generator, c2pa.active.signer && 'signer ' + c2pa.active.signer].filter(Boolean).join(' · ')}. Read only — not independently checked.`;
      drop.classList.add('has-file');
      drop.querySelector('strong').textContent = f.name; $('status').textContent = '';
      const notice = applyStampLinkState(fileHash);
      $('go').disabled = !notice.canStamp;
    } catch (e) {
      $('status').textContent = '';
      $('result').textContent = '';
      const d = document.createElement('div'); d.className = 'err'; d.textContent = 'Could not read that file: ' + e.message;
      $('result').append(d); $('go').disabled = true;
    }
  }
  async function stamp(digestBytes, tsq) {
    const r = await fetch('/api/stamp', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ digest: toHex(digestBytes), tsq: toB64(tsq), turnstile: tsToken }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'stamp proxy HTTP ' + r.status);
    const ots = {}; for (const [k, v] of Object.entries(j.ots || {})) ots[k] = fromB64(v);
    return { ots, tsr: j.tsr ? fromB64(j.tsr) : null, errors: j.errors || [] };
  }
  $('go').addEventListener('click', async () => {
    if (cfg.turnstileSiteKey && !tsToken) { $('status').textContent = 'Please complete the check above first.'; return; }
    $('go').disabled = true; $('status').textContent = 'Recording the fingerprint with independent witnesses…'; $('result').textContent = '';
    try {
      const prov = {}; for (const [k] of PROVENANCE_FIELDS) prov[k] = $('p_' + k).value;
      const verifierHtml = new Uint8Array(await (await fetch('/verify.html')).arrayBuffer());
      const rc = await makeReceipt({ fileMeta: { name: file.name, size: file.size, mediaType: file.type, sha256Hex: fileHash }, provenance: prov, c2pa: c2pa && !c2pa.error ? c2pa : null, stampFn: stamp, rekor: $('rekor').checked, verifierHtml, trustFiles: TRUST_FILES });
      const box = document.createElement('div'); const good = rc.otsBytes || rc.tsr; box.className = good ? 'ok' : 'err';
      const h = document.createElement('strong'); h.textContent = good ? 'Your receipt is ready.' : 'No time record could be obtained.'; box.append(h);
      const ul = document.createElement('ul');
      const add = (t) => { const li = document.createElement('li'); li.textContent = t; ul.append(li); };
      if (rc.index.proofs.rfc3161) add('An independent timestamp authority recorded it on ' + friendlyTime(rc.index.proofs.rfc3161.gen_time) + '.');
      if (rc.index.proofs.opentimestamps) add('Bitcoin confirmation usually finishes within a few hours. When you check the receipt later, you can look up the latest confirmation.');
      if (rc.index.proofs.ct) add(rc.index.proofs.ct.status === 'anchored' ? 'A public certificate-log record is ready.' : 'A public certificate-log record is on the way, usually within about four hours. You can refresh it later when you check the receipt.');
      if (rc.index.proofs.rekor) add('Published on the public transparency log (entry #' + rc.index.proofs.rekor.log_index + ').');
      for (const e of rc.errors) add('Problem: ' + e);
      box.append(ul);
      if (good) {
        const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([rc.zip], { type: 'application/zip' })); a.download = file.name + '.lightdrawer-receipt.zip'; a.textContent = 'Download ' + a.download; box.append(a);
        a.click();
        if (rc.index && rc.index.statement_sha256) {
          const share = document.createElement('p'); share.className = 'share-link';
          share.append('Share link: ');
          const link = document.createElement('a');
          const path = '/r/' + rc.index.statement_sha256;
          link.href = path;
          link.textContent = (location.origin || 'https://lightdrawer.org') + path;
          share.append(link);
          box.append(share);
        }
      }
      $('result').append(box); $('status').textContent = '';
    } catch (e) { $('status').textContent = ''; const d = document.createElement('div'); d.className = 'err'; d.textContent = 'Something went wrong: ' + e.message; $('result').append(d); }
    finally { $('go').disabled = false; if (tsWidget !== null && window.turnstile) { window.turnstile.reset(tsWidget); tsToken = null; } }
  });
})();
