/* Offline verifier UI. All rendering uses textContent to avoid injecting receipt data as HTML. */
(function () {
  const $ = (id) => document.getElementById(id);
  let receiptFiles = null, original = null;
  $('pin').textContent = TRUST.rootSha256; $('ver').textContent = LD_VERSION;
  // Default upgrade proxy when this page is opened from file://.
  // At launch on lightdrawer.org, change this to 'https://lightdrawer.org'.
  const DEFAULT_UPGRADE_PROXY = 'https://lightdrawer.org';
  $('proxy').value = DEFAULT_UPGRADE_PROXY;
  if (location.protocol.startsWith('http')) {
    $('proxy').value = location.origin;
    if ($('siteNav')) $('siteNav').hidden = false;
  }
  const readFile = (f) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(new Uint8Array(r.result)); r.onerror = () => rej(r.error); r.readAsArrayBuffer(f); });
  const KNOWN = { 'statement.json': 'statement.json', 'receipt.json': 'receipt.json', 'rekor-entry.json': 'proofs/rekor-entry.json', 'ct.json': 'proofs/ct.json' };
  async function loadReceipt(list) {
    const files = {}; const names = [];
    for (const f of list) {
      const b = await readFile(f); names.push(f.name);
      if (/\.zip$/i.test(f.name) || (b[0] === 0x50 && b[1] === 0x4b)) Object.assign(files, await zipRead(b));
      else if (/\.ots$/i.test(f.name)) files['proofs/statement.json.ots'] = b;
      else if (/\.tsr$/i.test(f.name)) files['proofs/statement.json.tsr'] = b;
      else if (KNOWN[f.name]) files[KNOWN[f.name]] = b;
    }
    receiptFiles = files; $('nameReceipt').textContent = names.join(', ') + ` (${Object.keys(files).length} receipt files)`; ready();
  }
  async function loadOriginal(f) { original = { name: f.name, file: f, size: f.size }; $('nameFile').textContent = `${f.name} (${f.size.toLocaleString()} bytes)`; ready(); }
  function ready() { $('go').disabled = !receiptFiles; }
  function wire(drop, input, fn) {
    drop.addEventListener('click', () => input.click());
    drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
    input.addEventListener('change', () => input.files.length && fn(input.files).catch(showErr));
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files.length) fn(e.dataTransfer.files).catch(showErr); });
  }
  wire($('dropReceipt'), $('inReceipt'), loadReceipt);
  wire($('dropFile'), $('inFile'), (fl) => loadOriginal(fl[0]));
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function showErr(e) { const o = $('out'); o.textContent = ''; const v = el('div', 'verdict fail'); v.append(el('h2', '', 'Could not read that'), el('div', 'det', e.message || String(e))); o.append(v); }
  function friendlyTime(d) {
    try {
      return d.toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
    } catch (e) {
      return d.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
    }
  }
  function findCheck(r, id) {
    for (const s of r.sections || []) {
      for (const c of s.checks || []) if (c.id === id) return c;
    }
    return null;
  }
  const SECTION_TITLES = {
    'File and statement': 'Your file',
    'RFC 3161 timestamp (FreeTSA)': 'Timestamp authority',
    'OpenTimestamps (Bitcoin)': 'Bitcoin record',
    'Certificate Transparency (public certificate log)': 'Public certificate logs',
    'Sigstore Rekor transparency log': 'Public transparency log',
    'Provenance (collector\'s statements)': 'Notes from the collector',
    'C2PA Content Credentials (read only)': 'Built-in credentials (read only)',
    'Receipt': 'Receipt',
  };
  $('go').addEventListener('click', async () => {
    $('go').disabled = true; $('out').textContent = 'Checking…';
    try {
      const opts = {};
      if ($('online').checked) opts.lookupBlock = (h) => otsEsploraLookup(h);
      if ($('upgrade').checked) {
        const base = $('proxy').value.replace(/\/+$/, '');
        opts.fetchUpgrade = async (cal, hex) => { const r = await fetch(`${base}/api/ots/upgrade?cal=${encodeURIComponent(cal)}&commitment=${hex}`); if (r.status === 404) return null; if (!r.ok) throw new Error('proxy HTTP ' + r.status); return new Uint8Array(await r.arrayBuffer()); };
        opts.fetchCtUpgrade = async (hex) => {
          const r = await fetch(`${base}/api/ct/upgrade?digest=${hex}`);
          if (r.status === 404) return null;
          if (!r.ok) throw new Error('CT upgrade HTTP ' + r.status);
          const j = await r.json();
          if (!j || j.pending || j.status === 'pending') return null;
          return utf8(JSON.stringify(j, null, 2) + '\n');
        };
      }
      opts.onHashProgress = (done, total) => {
        if (!total) return;
        const pct = Math.min(100, Math.floor((done * 100) / total));
        $('out').textContent = total > SHA256_FILE_CHUNK
          ? `Checking the original file… ${pct}% (${formatBytes(done)} of ${formatBytes(total)})`
          : 'Checking the original file…';
      };
      render(await verifyReceipt(receiptFiles, original, opts));
    } catch (e) { showErr(e); } finally { $('go').disabled = false; }
  });
  function render(r) {
    const o = $('out'); o.textContent = '';
    const verdict = r.verdict || 'fail';
    const fileChk = findCheck(r, 'file.hash');
    const fileFail = fileChk && fileChk.status === 'fail';
    const filePass = fileChk && fileChk.status === 'pass';
    const when = r.times && r.times.length ? friendlyTime(r.times[0].time) : null;
    let head, summary;
    if (fileFail) {
      head = 'This file does NOT match';
      summary = 'This is not the same file the receipt was made for, or the file has been changed since then.';
    } else if (verdict === 'pass' && filePass && when) {
      head = 'This file matches its receipt — it existed by ' + when;
      summary = 'The file is unchanged, and independent witnesses recorded it by this time.';
    } else if (verdict === 'pass' && filePass) {
      head = 'This file matches its receipt';
      summary = 'The file is unchanged from the one named in the receipt.';
    } else if (verdict === 'pass' && when) {
      head = 'This receipt checks out — the file existed by ' + when;
      summary = 'You did not add the original file, so this only checks the receipt itself.';
    } else if (verdict === 'incomplete') {
      head = 'Not confirmed yet';
      summary = 'Bitcoin confirmation usually finishes within a few hours. Tick “Look up the latest confirmations” and try again later.';
    } else {
      head = 'This receipt has a problem';
      summary = 'Something in the receipt did not check out. The details below explain what was found.';
    }
    const v = el('div', 'verdict ' + verdict);
    v.append(el('h2', '', head));
    if (summary) v.append(el('div', '', summary));
    if (r.statement && !fileFail) v.append(el('div', 'det', 'Receipt for “' + r.statement.subject.name + '”. The fingerprint is a unique code of that exact file.'));
    if (when && verdict !== 'pass') v.append(el('div', 'det', 'Earliest recorded time: ' + when + '.'));
    if (verdict === 'pass' && r.times && r.times[0] && r.times[0].note) v.append(el('div', 'det', 'Note: ' + r.times[0].note + '.'));
    if (verdict === 'pass' && !original && !fileFail) v.append(el('div', 'det', 'Add the original file above if you want to confirm that this is still that same file.'));
    o.append(v);
    for (const s of r.sections) {
      const sec = el('section'); sec.append(el('h3', '', SECTION_TITLES[s.title] || s.title));
      for (const c of s.checks) { const row = el('div', 'row'); const body = el('div'); body.append(el('div', '', c.title)); if (c.detail) body.append(el('div', 'det', c.detail)); row.append(el('span', 'tag ' + c.status, c.status), body); sec.append(row); }
      o.append(sec);
    }
    if (r.upgradedOts) {
      const b = el('button', '', 'Download the updated Bitcoin confirmation');
      b.onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r.upgradedOts])); a.download = 'statement.json.ots'; a.click(); };
      o.append(el('p', 'det', 'The Bitcoin record was updated. Save this file and replace proofs/statement.json.ots in the receipt so it checks offline next time.'), b);
    }
    if (r.upgradedCt) {
      const b = el('button', '', 'Download the updated certificate-log record');
      b.onclick = () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r.upgradedCt])); a.download = 'ct.json'; a.click(); };
      o.append(el('p', 'det', 'The certificate-log record was updated. Save this file and replace proofs/ct.json in the receipt so it checks offline next time.'), b);
    }
  }
})();
