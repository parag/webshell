// Who a login attempt is counted against, for the rate limiter.
//
// `tailscale serve` and nginx run on the same machine and connect from loopback,
// so the socket address is 127.0.0.1 for every proxied client. Only in that case
// do we read the proxy's headers: the Tailscale login first (Serve sets it for
// tailnet users and strips any copy sent by the client), then the first hop of
// X-Forwarded-For. A non-loopback peer could set these headers itself, so for
// those the socket address is the key.

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

function isLoopback(addr) {
  return LOOPBACK.has(String(addr || ''));
}

function clientKey(req) {
  const addr = (req.socket && req.socket.remoteAddress) || '';
  if (isLoopback(addr)) {
    const h = req.headers || {};
    const login = String(h['tailscale-user-login'] || '').trim();
    if (login) return `ts:${login.toLowerCase()}`;
    const xff = String(h['x-forwarded-for'] || '').split(',')[0].trim();
    if (xff) return `ip:${xff}`;
  }
  return `ip:${addr}`;
}

module.exports = { clientKey, isLoopback, LOOPBACK };
