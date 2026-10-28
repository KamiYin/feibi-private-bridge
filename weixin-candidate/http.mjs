import http from 'node:http';
import { equal, exactObject } from '../src/security.mjs';
import { VERSION_META, CAPS_META, rpcError } from '../synthetic-pilot/service.mjs';
export const MCP_AUTH_HEADER = 'x-synthetic-mcp-auth';
export const OPERATOR_AUTH_HEADER = 'x-synthetic-operator-auth';
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const single = (req, name) => {
  let count = 0; for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === name) count++;
  return count === 1 && typeof req.headers[name] === 'string' ? req.headers[name] : undefined;
};
function decodeName(value) {
  if (typeof value !== 'string') return undefined;
  if (value.startsWith('=?base64?') && value.endsWith('?=')) {
    const encoded = value.slice(9,-2), bytes = Buffer.from(encoded, 'base64');
    if (bytes.toString('base64') !== encoded) return undefined;
    try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return undefined; }
  }
  return /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/.test(value) ? value : undefined;
}
const statusFor = response => response.error?.code === -32601 ? 404 : [-32700,-32600,-32602,-32020,-32021,-32022].includes(response.error?.code) ? 400 : response.error?.code === 1001 ? 401 : 200;

// Construct only. Loopback binding is performed by the gated runtime. No anonymous health route.
export function createWeixinServer({ pilot, principal, session, mcpSecret, operatorSecret }) {
  if (typeof mcpSecret !== 'string' || typeof operatorSecret !== 'string' || mcpSecret.length < 40 || operatorSecret.length < 40 || equal(mcpSecret, operatorSecret)) throw new Error('distinct_authentication_required');
  const server = http.createServer(async (req, res) => {
    const send = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(body === undefined ? '' : JSON.stringify(body)); };
    try {
      const peer = req.socket.remoteAddress;
      if (!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(peer)) return send(403);
      let host; try { host = new URL(`http://${single(req,'host')}`).hostname; } catch { return send(400); }
      if (!['127.0.0.1','localhost'].includes(host) || req.headers.origin !== undefined) return send(403);
      if (!['/mcp','/local/qr-start','/local/qr-poll','/local/confirm-owner','/local/status','/local/approve-callback'].includes(req.url)) return send(404);
      const local = req.url !== '/mcp';
      if (!equal(single(req, local ? OPERATOR_AUTH_HEADER : MCP_AUTH_HEADER), local ? operatorSecret : mcpSecret)) return send(401);
      if (req.method !== 'POST') { res.setHeader('Allow', 'POST'); return send(405); }
      if (!/^application\/json(?:\s*;|$)/i.test(single(req, 'content-type') ?? '')) return send(415);
      if (!local) {
        const accept = single(req, 'accept') ?? '';
        const types = accept.split(',').map(x => x.trim().split(';')[0]);
        if (!types.includes('application/json') || !types.includes('text/event-stream')) return send(406);
      }
      let size = 0; const chunks = [];
      for await (const chunk of req) { size += chunk.length; if (size > 65536) return send(413); chunks.push(chunk); }
      let message; try { message = JSON.parse(Buffer.concat(chunks)); } catch { return send(400, rpcError(undefined, -32700, 'parse_error')); }
      if (local) {
        try {
          await pilot.authorize(principal);
          if (req.url === '/local/approve-callback') {
            exactObject(message, ['origin'], ['origin']);
            return send(200, await pilot.approveCallbackOrigin(message.origin));
          }
          if (req.url === '/local/qr-start') {
            exactObject(message, []); return send(200, await session.startQr());
          }
          if (req.url === '/local/qr-poll') {
            exactObject(message, ['verify_code']);
            return send(200, await session.pollQr({ verifyCode: message.verify_code }));
          }
          if (req.url === '/local/confirm-owner') {
            exactObject(message, ['nonce','user_confirmed_scan'], ['nonce','user_confirmed_scan']);
            return send(200, session.confirmOwner({ nonce: message.nonce, userConfirmedScan: message.user_confirmed_scan }));
          }
          exactObject(message, []);
          return send(200, { session: session.status(), mcp: await pilot.status() });
        } catch (e) {
          const known = new Set(['QR_ACTION_APPROVAL_REQUIRED','SESSION_STOPPED_OR_EXPIRED','QR_ALREADY_STARTED','QR_NOT_POLLABLE','QR_EXPIRED','INVALID_VERIFICATION_INPUT','CURRENT_CHAT_OWNER_CONFIRMATION_REQUIRED','OWNER_CONFIRMATION_REQUIRED','EXACT_ILINK_ORIGIN_REVIEW_REQUIRED','ILINK_AUTHORIZATION_STOP','ILINK_PAYMENT_OR_QUOTA_STOP','ILINK_SESSION_INVALIDATED','NO_REUSABLE_LOCAL_SESSION','VERIFICATION_BLOCKED','ILINK_TRANSPORT_FAILED','ILINK_REDIRECT_BLOCKED','ILINK_HTTP_REJECTED','INVALID_ILINK_JSON','INVALID_ILINK_RESPONSE','INVALID_QR_RESPONSE','ILINK_BUSINESS_REJECTED','ILINK_RESPONSE_BOUND','CONFIRMED_IDENTITY_REQUIRED','CONFIRMED_API_ORIGIN_REQUIRED']);
          return send(400, { error: 'local_operation_rejected', reason: known.has(e?.code) ? e.code : 'LOCAL_OPERATION_REJECTED' });
        }
      }
      const id = object(message) && (typeof message.id === 'string' || Number.isSafeInteger(message.id)) ? message.id : undefined;
      const meta = message?.params?._meta;
      if (!object(meta) || typeof meta[VERSION_META] !== 'string' || !object(meta[CAPS_META])) return send(400, rpcError(id, -32602, 'required_per_request_metadata_missing'));
      if (single(req,'mcp-protocol-version') !== meta[VERSION_META] || single(req,'mcp-method') !== message.method ||
        message.method === 'tools/call' && decodeName(single(req,'mcp-name')) !== message.params.name) return send(400, rpcError(id, -32020, 'HeaderMismatch'));
      const response = await pilot.rpc(principal, message);
      return send(statusFor(response), response);
    } catch { if (!res.headersSent) send(500, { error: 'internal_error' }); }
  });
  server.requestTimeout = 40000; server.headersTimeout = 10000; server.maxHeadersCount = 40;
  return server;
}
