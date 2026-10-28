// Separate candidate transport. Construction is inert; no automatic requests.
// Existing platform proxy owns destination DNS/egress policy: NOT local IP pinning.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { isIP } from 'node:net';
import { approvedIlinkOrigin, ILINK_ORIGIN, APP_CLIENT_VERSION } from './ilink.mjs';

const error = code => Object.assign(new Error(code), { code });
const reject = code => { throw error(code); };
function parseProxy(raw) {
  let proxy; try { proxy = new URL(raw); } catch { reject('INVALID_EXISTING_PROXY'); }
  if (!['http:','https:'].includes(proxy.protocol) || proxy.username || proxy.password || proxy.search || proxy.hash || proxy.pathname !== '/') reject('INVALID_EXISTING_PROXY');
  return proxy;
}
function existingProxy(env) {
  if (env.HTTPS_PROXY && env.https_proxy && env.HTTPS_PROXY !== env.https_proxy) reject('CONFLICTING_EXISTING_PROXY');
  if (!env.HTTPS_PROXY && !env.https_proxy) reject('EXISTING_HTTPS_PROXY_REQUIRED');
  return parseProxy(env.HTTPS_PROXY || env.https_proxy);
}
function endpoint(path, method, legacyQrGet) {
  if (typeof path !== 'string' || path.length > 12500) reject('ILINK_ENDPOINT_REJECTED');
  if (method === 'POST') {
    if (path === '/ilink/bot/get_bot_qrcode?bot_type=3') return 'qr';
    if (path === '/ilink/bot/getupdates' || path === '/ilink/bot/sendmessage') return 'authenticated';
  } else if (method === 'GET') {
    if (legacyQrGet && path === '/ilink/bot/get_bot_qrcode?bot_type=3') return 'qr_legacy';
    let url; try { url = new URL(path, ILINK_ORIGIN); } catch { reject('ILINK_ENDPOINT_REJECTED'); }
    const pairs = [...url.searchParams], qr = url.searchParams.get('qrcode'), code = url.searchParams.get('verify_code');
    if (url.origin === ILINK_ORIGIN && url.pathname === '/ilink/bot/get_qrcode_status' && !url.hash &&
        typeof qr === 'string' && /^[\x21-\x7e]{1,4096}$/.test(qr) &&
        pairs.length === (code === null ? 1 : 2) && pairs[0]?.[0] === 'qrcode' &&
        (code === null || pairs[1]?.[0] === 'verify_code' && /^\d{1,16}$/.test(code)) &&
        path === '/ilink/bot/get_qrcode_status?qrcode=' + encodeURIComponent(qr) + (code === null ? '' : '&verify_code=' + encodeURIComponent(code))) return 'qr_status';
  }
  reject('ILINK_ENDPOINT_REJECTED');
}
function safeHeaders(input, mode, bodyLength) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) reject('ILINK_HEADERS_REJECTED');
  const common = ['ilink-app-id','ilink-app-clientversion'];
  const names = ['qr_status','qr_legacy'].includes(mode) ? common : [...common,'content-type','authorizationtype','x-wechat-uin',...(mode === 'authenticated' ? ['authorization'] : [])];
  const out = {};
  for (const [key,value] of Object.entries(input)) {
    const name = key.toLowerCase();
    if (!names.includes(name) || Object.hasOwn(out,name) || typeof value !== 'string' || value.length > 8200 || !/^[\x20-\x7e]+$/.test(value)) reject('ILINK_HEADERS_REJECTED');
    out[name] = value;
  }
  if (Object.keys(out).length !== names.length || out['ilink-app-id'] !== 'bot' || out['ilink-app-clientversion'] !== APP_CLIENT_VERSION) reject('ILINK_HEADERS_REJECTED');
  if (!['qr_status','qr_legacy'].includes(mode)) {
    if (out['content-type'] !== 'application/json' || out.authorizationtype !== 'ilink_bot_token') reject('ILINK_HEADERS_REJECTED');
    const encoded = out['x-wechat-uin'], decoded = Buffer.from(encoded,'base64').toString('ascii');
    if (Buffer.from(decoded,'ascii').toString('base64') !== encoded || !/^(?:0|[1-9]\d{0,9})$/.test(decoded) || Number(decoded) > 4294967295) reject('ILINK_HEADERS_REJECTED');
    if (mode === 'authenticated' && (!/^Bearer [\x21-\x7e]{1,8192}$/.test(out.authorization) || out.authorization.startsWith('Bearer sk-'))) reject('ILINK_HEADERS_REJECTED');
  }
  return { ...out, ...(['qr_status','qr_legacy'].includes(mode) ? {} : {'content-length':bodyLength}), connection:'close' };
}

export function createIlinkProxyTransport({ env = {}, approvedOrigins = [ILINK_ORIGIN], networkActionApproved = false, allowLegacyQrGet = false,
  proxyHttpRequest = http.request, proxyHttpsRequest = https.request, tlsConnect = tls.connect, targetRequest = https.request } = {}) {
  if (networkActionApproved !== true) reject('ILINK_NETWORK_APPROVAL_REQUIRED');
  if (!Array.isArray(approvedOrigins) || !approvedOrigins.length || approvedOrigins.length > 4) reject('INVALID_ILINK_ALLOWLIST');
  const origins = Object.freeze([...new Set(approvedOrigins.map(approvedIlinkOrigin))]);
  if (!origins.includes(ILINK_ORIGIN)) reject('FIXED_QR_ORIGIN_REQUIRED');
  const proxy = existingProxy(env);
  return request => new Promise((resolve,rejectPromise) => {
    let url, mode, bytes, headers, signal, timeoutMs;
    try {
      if (!request || typeof request !== 'object' || Array.isArray(request) || Object.keys(request).some(k => !['origin','path','method','headers','body','redirect','timeoutMs','signal'].includes(k))) reject('ILINK_REQUEST_REJECTED');
      const origin = approvedIlinkOrigin(request.origin);
      if (!origins.includes(origin)) reject('ILINK_ORIGIN_NOT_APPROVED');
      mode = endpoint(request.path, request.method, allowLegacyQrGet === true);
      if (['qr','qr_legacy'].includes(mode) && origin !== ILINK_ORIGIN) reject('FIXED_QR_ORIGIN_REQUIRED');
      if (request.redirect !== 'error' || !Number.isSafeInteger(request.timeoutMs) || request.timeoutMs < 1 || request.timeoutMs > 35000) reject('ILINK_REQUEST_REJECTED');
      if (['qr_status','qr_legacy'].includes(mode)) { if (request.body !== undefined) reject('ILINK_BODY_REJECTED'); bytes = undefined; }
      else { if (!Buffer.isBuffer(request.body) || !request.body.length || request.body.length > 262144) reject('ILINK_BODY_REJECTED'); bytes = Buffer.from(request.body); }
      headers = safeHeaders(request.headers, mode, bytes?.length);
      signal = request.signal; timeoutMs = request.timeoutMs;
      if (signal !== undefined && !(signal instanceof AbortSignal)) reject('ILINK_REQUEST_REJECTED');
      if (signal?.aborted) reject('ILINK_REQUEST_ABORTED');
      url = new URL(request.path, origin);
      if (url.origin !== origin || url.username || url.password || url.hash) reject('ILINK_REQUEST_REJECTED');
    } catch (e) { rejectPromise(e?.code ? e : error('ILINK_REQUEST_REJECTED')); return; }
    // Never retain caller-mutable header/body objects across async CONNECT/TLS.
    const method = request.method;
    const resources = new Set(); let done = false, agent, timer;
    const cleanup = () => { for (const r of resources) { try { r.destroy(); } catch {} } try { agent?.destroy(); } catch {} };
    const finish = (failure, result) => { if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener('abort',onAbort); cleanup(); failure ? rejectPromise(failure) : resolve(result); };
    const fail = code => finish(error(code));
    const onAbort = () => fail('ILINK_REQUEST_ABORTED');
    const track = item => { resources.add(item); if (done) { try { item.destroy(); } catch {} } return item; };
    timer = setTimeout(() => fail('ILINK_REQUEST_TIMEOUT'), timeoutMs);
    signal?.addEventListener('abort',onAbort,{once:true});
    if (signal?.aborted) { onAbort(); return; }
    Promise.resolve().then(() => {
      if (done) return;
      const authority = `${url.hostname}:443`;
      agent = new https.Agent({keepAlive:false,maxSockets:1,maxFreeSockets:0,maxCachedSessions:0});
      agent.createConnection = (_options, callback) => {
        if (done) { callback(error('ILINK_REQUEST_ABORTED')); return; }
        const connect = proxy.protocol === 'https:' ? proxyHttpsRequest : proxyHttpRequest;
        let proxyRequest;
        try {
          proxyRequest = track(connect({protocol:proxy.protocol,hostname:proxy.hostname.replace(/^\[|\]$/g,''),
            port:proxy.port || (proxy.protocol === 'https:' ? 443 : 80),method:'CONNECT',path:authority,
            headers:{host:authority},agent:false,maxHeaderSize:16384,
            ...(proxy.protocol === 'https:' ? {servername:isIP(proxy.hostname.replace(/^\[|\]$/g,'')) ? '' : proxy.hostname,
              rejectUnauthorized:true,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1']} : {})}));
        } catch { fail('ILINK_PROXY_CONNECT_FAILED'); return; }
        proxyRequest.maxHeadersCount = 40;
        proxyRequest.once('error',() => fail('ILINK_PROXY_CONNECT_FAILED'));
        proxyRequest.once('response',res => {track(res);fail('ILINK_PROXY_REJECTED');});
        proxyRequest.once('connect',(res,socket,head) => {
          track(socket); if (done) return;
          if (res.statusCode !== 200 || head?.length) return fail('ILINK_PROXY_REJECTED');
          let secure;
          try {secure=track(tlsConnect({socket,servername:url.hostname,rejectUnauthorized:true,checkServerIdentity:tls.checkServerIdentity,
            minVersion:'TLSv1.2',ALPNProtocols:['http/1.1']}));} catch {return fail('ILINK_TLS_FAILED');}
          secure.once('error',() => fail('ILINK_TLS_FAILED'));
          secure.once('secureConnect',() => {
            if (done) return;
            if (secure.authorized !== true || secure.alpnProtocol && secure.alpnProtocol !== 'http/1.1') return fail('ILINK_TLS_FAILED');
            callback(null,secure);
          });
        });
        proxyRequest.end();
      };
      let req;
      try {
        req=track(targetRequest(url,{method,agent,rejectUnauthorized:true,servername:url.hostname,headers,maxHeaderSize:16384},res => {
          track(res); if (done) return;
          const status=res.statusCode ?? 0;
          if (status>=300 && status<400) return fail('ILINK_REDIRECT_BLOCKED');
          const chunks=[];let size=0;
          res.on('data',chunk => {size+=chunk.length;if(size>1048576)fail('ILINK_RESPONSE_BOUND');else chunks.push(chunk);});
          res.once('aborted',() => fail('ILINK_RESPONSE_FAILED'));
          res.once('error',() => fail('ILINK_RESPONSE_FAILED'));
          res.once('end',() => {
            if(done)return;if(res.complete!==true)return fail('ILINK_RESPONSE_FAILED');
            let body;try{body=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));}catch{return fail('ILINK_RESPONSE_ENCODING');}
            finish(null,{status,body});
          });
        }));
        req.maxHeadersCount=40;req.once('error',() => fail('ILINK_REQUEST_FAILED'));req.end(bytes);
      } catch {fail('ILINK_REQUEST_FAILED');}
    }).catch(() => fail('ILINK_TRANSPORT_FAILED'));
  });
}
