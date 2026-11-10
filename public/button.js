/* Copy buttons for the public /button guide. No inline event handlers. */
(function () {
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.append(ta);
      ta.select();
      try {
        if (!document.execCommand('copy')) throw new Error('copy failed');
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        ta.remove();
      }
    });
  }

  document.querySelectorAll('[data-copy-target]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const id = btn.getAttribute('data-copy-target');
      const el = id ? document.getElementById(id) : null;
      if (!el) return;
      const original = btn.textContent;
      copyText(el.textContent).then(function () {
        btn.textContent = 'Copied';
        window.setTimeout(function () { btn.textContent = original; }, 2000);
      }).catch(function () {
        btn.textContent = 'Copy failed';
        window.setTimeout(function () { btn.textContent = original; }, 2000);
      });
    });
  });
})();
