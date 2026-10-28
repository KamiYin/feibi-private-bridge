import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import https from 'node:https';
import { isIP } from 'node:net';

export class BridgeError extends Error {
  constructor(code, message, reason) { super(message); this.code = code; this.reason = reason; }
}
export const fail = (reason, code = -32602) => { throw new BridgeError(code, reason, reason); };
export const digest = value => createHash('sha256').update(value).digest('hex');
export function equal(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}
export function exactObject(value, allowed, required = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid_object');
  if (Object.keys(value).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(value, k))) fail('invalid_arguments');
}
export function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_.:@-]{1,256}$/.test(value)) fail('invalid_identifier');
  return value;
}
export function textValue(value, maxBytes) {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value) > maxBytes || value.includes('\0')) fail('invalid_text');
  return value;
}
export function signingKey(secret) {
  if (typeof secret !== 'string' || !/^whsec_[A-Za-z0-9+/]+={0,2}$/.test(secret)) fail('invalid_signing_secret');
  const encoded = secret.slice(6), key = Buffer.from(encoded, 'base64');
  if (key.length < 24 || key.length > 64 || key.toString('base64') !== encoded) fail('invalid_signing_secret');
  return key;
}
// Standard Webhooks: HMAC-SHA256 over id.timestamp.exact-body-bytes.
export function signature(secret, id, seconds, body) {
  const hmac = createHmac('sha256', signingKey(secret));
  hmac.update(`${id}.${seconds}.`); hmac.update(body);
  return `v1,${hmac.digest('base64')}`;
}
export function signedRequest(subscription, payload, now) {
  const body = Buffer.from(JSON.stringify(payload));
  if (body.length > 262144) fail('event_too_large');
  const seconds = String(Math.floor(now / 1000));
  const id = payload.eventId;
  const keys = [subscription.secret];
  if (subscription.oldSecret && subscription.rotateUntil > now) keys.push(subscription.oldSecret);
  return { body, headers: {
    'Content-Type': 'application/json',
    'webhook-id': id,
    'webhook-timestamp': seconds,
    'webhook-signature': keys.map(key => signature(key, id, seconds, body)).join(' '),
    'X-MCP-Subscription-Id': subscription.id,
  }};
}
export function validateCallbackUrl(raw, allowedOrigins) {
  let url; try { url = new URL(raw); } catch { fail('invalid_callback', -32015); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.port && url.port !== '443' || isIP(url.hostname.replace(/^\[|\]$/g, ''))) fail('invalid_callback', -32015);
  if (!allowedOrigins.includes(url.origin)) fail('callback_origin_not_approved', -32015);
  return url;
}
export function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const [a,b,c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 ||
      a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 ||
      a === 192 && b === 0 || a === 192 && b === 2 || a === 192 && b === 88 && c === 99 ||
      a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113);
  }
  // Conservative: only global-unicast IPv6, excluding special/documentation/tunnel blocks.
  if (isIP(address) === 6) {
    const normalized = new URL(`http://[${address}]/`).hostname.slice(1,-1);
    const [first, second] = normalized.split(':').map(v => parseInt(v || '0', 16));
    return first >= 0x2000 && first <= 0x3fff && !(first === 0x2001 && (second <= 0x1ff || second === 0xdb8)) && first !== 0x2002 && !(first === 0x3fff && second <= 0xfff);
  }
  return false;
}
// No redirects, no proxy environment, fresh DNS validation for EVERY request, pinned address + original TLS hostname.
export function createSafePoster({ allowedOrigins, resolver = lookup, request = https.request, timeoutMs = 10000 }) {
  return async (raw, { body, headers }) => {
    const deadline = performance.now() + timeoutMs;
    const url = validateCallbackUrl(raw, allowedOrigins);
    let addresses, dnsTimer;
    try {
      addresses = await Promise.race([
        Promise.resolve().then(() => resolver(url.hostname, { all: true, verbatim: true })),
        new Promise((_resolve, reject) => { dnsTimer = setTimeout(() => reject(new BridgeError(-32015, 'timeout', 'timeout')), timeoutMs); }),
      ]);
    } catch (e) { if (e instanceof BridgeError && e.reason === 'timeout') throw e; fail('dns_failure', -32015); }
    finally { clearTimeout(dnsTimer); }
    // A timed-out resolver may settle later, but this function has already rejected and cannot connect.
    const remainingMs = deadline - performance.now();
    if (remainingMs <= 0) fail('timeout', -32015);
    if (!addresses.length || addresses.some(x => !isPublicAddress(x.address) || isIP(x.address) !== x.family)) fail('non_public_callback', -32015);
    const chosen = addresses[0];
    return new Promise((resolve, reject) => {
      const req = request(url, { method: 'POST', agent: false, servername: url.hostname,
        rejectUnauthorized: true, headers: { ...headers, 'Content-Length': body.length },
        lookup: (_hostname, opts, cb) => cb(null, opts?.all ? [chosen] : chosen.address, chosen.family),
      }, res => {
        const status = res.statusCode ?? 0;
        if (status >= 300 && status < 400) { res.resume(); reject(new BridgeError(-32015, 'redirect_blocked', 'redirect_blocked')); return; }
        const chunks = []; let size = 0;
        res.on('data', chunk => { size += chunk.length; if (size > 65536) res.destroy(new Error('response_too_large')); else chunks.push(chunk); });
        res.on('error', () => reject(new BridgeError(-32015, 'response_failed', 'response_failed')));
        res.on('end', () => { let json = null; try { json = JSON.parse(Buffer.concat(chunks)); } catch {} resolve({ status, json }); });
      });
      const timer = setTimeout(() => req.destroy(new Error('timeout')), remainingMs);
      req.on('close', () => clearTimeout(timer));
      req.on('error', err => reject(new BridgeError(-32015, err.message === 'timeout' ? 'timeout' : 'network_failure', err.message === 'timeout' ? 'timeout' : 'network_failure')));
      req.end(body);
    });
  };
}
export function makeAudit(sink = () => {}) {
  // Allowlist log shape; never pass exceptions, URLs, credentials, users or message bodies.
  return (action, status) => sink({ action: String(action).replace(/[^a-z_]/g, ''), status: String(status).replace(/[^a-z_]/g, '') });
}
export function devBearerVerifier(token, ownerPrincipal) {
  if (typeof token !== 'string' || token.length < 32 || !ownerPrincipal) fail('auth_configuration_missing');
  return async req => equal(req.headers.authorization, `Bearer ${token}`)
    ? { id: ownerPrincipal, scopes: ['wecom:read', 'wecom:reply', 'wecom:events'] } : null;
}
