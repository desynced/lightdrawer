// Classify mocked upstreams by hostname and path, not by a substring of the whole URL.

function parseUrl(url) {
  try {
    return url instanceof URL ? url : new URL(String(url));
  } catch {
    return null;
  }
}

export function isTurnstileUrl(url) {
  const u = parseUrl(url);
  if (!u) return false;
  return u.hostname === 'challenges.cloudflare.com' && (u.pathname === '/turnstile' || u.pathname.startsWith('/turnstile/'));
}

export function isFreetsaUrl(url) {
  const u = parseUrl(url);
  if (!u) return false;
  return u.hostname === 'freetsa.org' || u.hostname.endsWith('.freetsa.org');
}

export function isCalendarDigestUrl(url) {
  const u = parseUrl(url);
  if (!u) return false;
  return u.pathname === '/digest' || u.pathname.endsWith('/digest');
}

export function isStampUpstreamUrl(url) {
  return isFreetsaUrl(url) || isCalendarDigestUrl(url);
}
