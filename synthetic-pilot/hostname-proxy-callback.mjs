import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { BridgeError, validateCallbackUrl } from '../src/security.mjs';

const error = reason => new BridgeError(-32015, 'CallbackEndpointError', reason);
function parseProxy(raw) {
  let proxy; try { proxy = new URL(raw); } catch { throw error('invalid_proxy_configuration'); }
  // Configured proxy is trusted infrastructure, not a caller-supplied callback.
  // No URL auth, PAC, SOCKS, file, redirects or arbitrary alternate route support.
  if (!['http:','https:'].includes(proxy.protocol) || proxy.username || proxy.password || proxy.search || proxy.hash || proxy.pathname !== '/') throw error('invalid_proxy_configuration');
  return proxy;
}
export function existingHttpsProxy(env = {}) {
  const upper = env.HTTPS_PROXY, lower = env.https_proxy;
  if (upper && lower && upper !== lower) throw error('conflicting_proxy_configuration');
  const raw = upper || lower;
  if (!raw) throw error('existing_https_proxy_required');
  return parseProxy(raw).href;
}
function outboundHeaders(input, length) {
  const allowed = new Set(['content-type','webhook-id','webhook-timestamp','webhook-signature','x-mcp-subscription-id']);
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw error('invalid_callback_headers');
  const headers = {};
  for (const [key,value] of Object.entries(input)) {
    const name = key.toLowerCase();
    if (!allowed.has(name) || Object.hasOwn(headers,name) || typeof value !== 'string' || value.length > 2048 || !/^[\x20-\x7e]+$/.test(value)) throw error('invalid_callback_headers');
    headers[name] = value;
  }
  if (Object.keys(headers).length !== allowed.size || headers['content-type'] !== 'application/json' || !/^\d+$/.test(headers['webhook-timestamp'])) throw error('invalid_callback_headers');
  return { ...headers, 'content-length': length, connection: 'close' };
}

/** Standard hostname CONNECT for ONE independently reviewed official origin.
 * This is not DNS pinning. The configured platform proxy resolves the destination
 * and enforces its hostname/egress policy. No IP CONNECT or alternate route exists.
 */
export function validateOfficialCallbackOrigin(raw) {
  let url; try { url = new URL(raw); } catch { throw error('invalid_official_callback_origin'); }
  if (typeof raw !== 'string' || raw.length > 261 || url.origin !== raw ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*(?:openai\.com|chatgpt\.com)$/.test(url.hostname)) throw error('invalid_official_callback_origin');
  validateCallbackUrl(`${raw}/`, [raw]);
  return raw;
}
export function createHostnameProxyCallbackPoster({ proxyUrl, approvedOrigin, hostnameProxyReviewApproved = false,
  proxyHttpRequest = http.request, proxyHttpsRequest = https.request,
  tlsConnect = tls.connect, callbackRequest = https.request, timeoutMs = 10000 } = {}) {
  if (hostnameProxyReviewApproved !== true) throw error('hostname_proxy_review_required');
  validateOfficialCallbackOrigin(approvedOrigin);
  const allowedOrigins = [approvedOrigin];
  const proxy = parseProxy(proxyUrl);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10000) throw error('invalid_transport_configuration');
  const origins = [...allowedOrigins];
  for (const origin of origins) { try { if (new URL(origin).origin !== origin) throw new Error(); validateCallbackUrl(`${origin}/`, origins); } catch { throw error('invalid_callback_origin'); } }
  return (raw, { body, headers } = {}) => new Promise((resolve,reject) => {
    let url, safeHeaders;
    try {
      url = validateCallbackUrl(raw, origins);
      if (!Buffer.isBuffer(body) || body.length === 0 || body.length > 262144) throw error('invalid_callback_body');
      safeHeaders = outboundHeaders(headers, body.length);
    } catch (e) { reject(e instanceof BridgeError ? e : error('invalid_callback_request')); return; }
    // Retain immutable exact bytes across asynchronous CONNECT/TLS, preserving signatures.
    const bytes = Buffer.from(body);
    const resources = new Set(); let done = false, agent;
    const cleanup = () => { for (const item of resources) { try { item.destroy(); } catch {} } try { agent?.destroy(); } catch {} };
    const finish = (failure, result) => { if (done) return; done = true; clearTimeout(timer); cleanup(); failure ? reject(failure) : resolve(result); };
    const fail = reason => finish(error(reason));
    const track = item => { resources.add(item); if (done) { try { item.destroy(); } catch {} } return item; };
    const timer = setTimeout(() => fail('timeout'), timeoutMs);
    // This total deadline includes proxy resolution/connect, target TLS and response.
    Promise.resolve().then(() => {
      if (done) return;
      const authority = `${url.hostname}:443`;
      agent = new https.Agent({ keepAlive: false, maxSockets: 1, maxFreeSockets: 0, maxCachedSessions: 0 });
      agent.createConnection = (_options, callback) => {
        if (done) { callback(error('timeout')); return; }
        const connect = proxy.protocol === 'https:' ? proxyHttpsRequest : proxyHttpRequest;
        let proxyRequest;
        try {
          proxyRequest = track(connect({ protocol: proxy.protocol, hostname: proxy.hostname.replace(/^\[|\]$/g,''),
            port: proxy.port || (proxy.protocol === 'https:' ? 443 : 80), method: 'CONNECT', path: authority,
            headers: { host: authority }, agent: false, maxHeaderSize: 16384,
            ...(proxy.protocol === 'https:' ? { servername: isIP(proxy.hostname.replace(/^\[|\]$/g,'')) ? '' : proxy.hostname, rejectUnauthorized: true, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] } : {}),
          }));
        } catch { fail('proxy_connect_failed'); return; }
        proxyRequest.maxHeadersCount = 40;
        proxyRequest.once('error', () => fail('proxy_connect_failed'));
        proxyRequest.once('response', res => { track(res); fail('proxy_connect_rejected'); });
        proxyRequest.once('connect', (res, socket, head) => {
          track(socket);
          if (done) return;
          // Do not accept proxy redirects, authentication challenges, or tunnel pre-read bytes.
          if (res.statusCode !== 200 || head?.length) return fail('proxy_connect_rejected');
          let secure;
          try {
            secure = track(tlsConnect({ socket, servername: url.hostname, rejectUnauthorized: true,
              checkServerIdentity: tls.checkServerIdentity, minVersion: 'TLSv1.2', ALPNProtocols: ['http/1.1'] }));
          } catch { return fail('callback_tls_failed'); }
          secure.once('error', () => fail('callback_tls_failed'));
          secure.once('secureConnect', () => {
            if (done) return;
            if (secure.authorized !== true || secure.alpnProtocol && secure.alpnProtocol !== 'http/1.1') return fail('callback_tls_failed');
            callback(null, secure);
          });
        });
        proxyRequest.end();
      };
      if (done) return;
      let req;
      try {
        req = track(callbackRequest(url, { method: 'POST', agent, rejectUnauthorized: true,
          servername: url.hostname, headers: safeHeaders, maxHeaderSize: 16384 }, res => {
          track(res); if (done) return;
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) return fail('redirect_blocked');
          const chunks = []; let size = 0;
          res.on('data', chunk => { size += chunk.length; if (size > 65536) fail('response_too_large'); else chunks.push(chunk); });
          res.once('aborted', () => fail('response_failed'));
          res.once('error', () => fail('response_failed'));
          res.once('end', () => {
            if (done) return;
            if (res.complete !== true) return fail('response_failed');
            let json = null; try { json = JSON.parse(Buffer.concat(chunks)); } catch {}
            finish(null, { status, json });
          });
        }));
        req.maxHeadersCount = 40;
        req.once('error', () => fail('callback_request_failed'));
        req.end(bytes);
      } catch { fail('callback_request_failed'); }
    }).catch(() => fail('transport_failed'));
  });
}
