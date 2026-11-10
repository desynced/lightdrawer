/*! LightDrawer stamp helper (self-host this file on your own site).
    It hashes a chosen file in the visitor's browser with Web Crypto and
    opens the link's href with #digest=<sha256>. Browsers do not send the
    fragment to any server. This script never calls /api/stamp and never
    uses an API key. Visitors still finish (and complete any human check)
    on LightDrawer. */
(function () {
  'use strict';

  function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  async function sha256File(file) {
    const data = await file.arrayBuffer();
    return toHex(await crypto.subtle.digest('SHA-256', data));
  }

  function statusFor(link, message) {
    const id = link.getAttribute('data-lightdrawer-status');
    const el = id ? document.getElementById(id) : null;
    if (el) el.textContent = message || '';
  }

  function openStamp(link, url) {
    if (link.target === '_blank') {
      const opened = window.open(url, link.target, 'noopener,noreferrer');
      if (opened) opened.opener = null;
      return;
    }
    window.location.assign(url);
  }

  function enhance(root) {
    const scope = root || document;
    const links = scope.querySelectorAll('a[data-lightdrawer-file]');
    for (let i = 0; i < links.length; i++) {
      const link = links[i];
      if (link.getAttribute('data-lightdrawer-ready') === '1') continue;
      link.setAttribute('data-lightdrawer-ready', '1');
      link.addEventListener('click', function (event) {
        const inputId = link.getAttribute('data-lightdrawer-file');
        const input = inputId ? document.getElementById(inputId) : null;
        const file = input && input.files && input.files[0];
        if (!file) {
          event.preventDefault();
          statusFor(link, 'Choose a file first, then click Stamp this with LightDrawer.');
          return;
        }
        event.preventDefault();
        statusFor(link, 'Preparing a fingerprint…');
        sha256File(file).then(function (digest) {
          const url = new URL(link.href, window.location.href);
          url.hash = 'digest=' + digest;
          statusFor(link, '');
          openStamp(link, url.toString());
        }).catch(function () {
          statusFor(link, 'Could not read that file here. Opening LightDrawer so you can drop it there instead.');
          openStamp(link, link.href);
        });
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { enhance(document); });
  } else {
    enhance(document);
  }

  window.lightdrawerStamp = { enhance: enhance };
})();
