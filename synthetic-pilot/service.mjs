import { randomBytes, randomUUID } from 'node:crypto';
import { validateOfficialCallbackOrigin } from './hostname-proxy-callback.mjs';
import { BridgeError, canonical, digest, equal, exactObject, fail, signature, signedRequest, signingKey, validateCallbackUrl } from '../src/security.mjs';

export const VERSION = '2026-07-28';
export const VERSION_META = 'io.modelcontextprotocol/protocolVersion';
export const CAPS_META = 'io.modelcontextprotocol/clientCapabilities';
const INFO = { name: 'same-dot-synthetic-events-pilot', version: '0.1.0' };
const HOUR = 3600000;
const CALLBACK_REASONS = new Set(['none','accepted','challenge_failed','transport_failed','timeout','proxy_connect_failed','proxy_connect_rejected','callback_tls_failed','callback_request_failed','redirect_blocked','response_too_large','response_failed','invalid_callback_request','http_rejected']);
const callbackReason = e => CALLBACK_REASONS.has(e?.reason) ? e.reason : 'transport_failed';
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const schema = properties => ({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const uuid = { type: 'string', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' };
export function runId(value) { if (typeof value !== 'string' || !new RegExp(uuid.pattern).test(value)) fail('invalid_run_id'); return value; }
export const EVENT = { name: 'test.message', description: 'One synthetic connectivity test for the selected run. Contains no WeChat, WeCom, memory or user file data.', delivery: ['webhook'],
  inputSchema: schema({ run_id: uuid }), payloadSchema: schema({ run_id: uuid, text: { type: 'string' }, proof: { type: 'string' } }) };
export const TOOLS = [
  { name: 'test_status', description: 'Read safe synthetic pilot counts. Does not reveal event proofs or access any personal channel.', inputSchema: schema({}), annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
  { name: 'reply_test', description: 'Record a local synthetic receipt only; never sends a message. Supply event run_id, event_id, proof, and an opaque test_phrase previously chosen in the CURRENT dot conversation, not obtained from this event. Parent separately verifies the phrase and intended chat.',
    inputSchema: schema({ run_id: uuid, event_id: { type: 'string' }, proof: { type: 'string' }, test_phrase: { type: 'string', pattern: '^test-phrase:[A-Za-z0-9_-]{8,80}$' } }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
];
export function rpcError(id, code, message, data) { return { jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), error: { code, message, ...(data ? { data } : {}) } }; }

// This class has no network, SDK, filesystem, environment, or message-channel dependencies.
// It uses only the explicitly provided store and callback transport. All inputs are synthetic.
export class SyntheticPilot {
  constructor({ store, post, allowedCallbackOrigins = [], principal, authorize = () => false,
    callbacksApproved = false, injectionApproved = false, originReviewApproved = false, postFactory, runtimeExpiresAt = Infinity, now = Date.now, audit = () => {} }) {
    if (!store || !principal || typeof post !== 'function') throw new Error('pilot_dependencies_required');
    this.store = store; this.post = post; this.origins = [...allowedCallbackOrigins]; this.principal = principal;
    this.authorizeAccess = authorize; this.callbacksApproved = callbacksApproved; this.injectionApproved = injectionApproved;
    this.now = now; this.audit = audit; this.tail = Promise.resolve(); this.stopped = false;
    if (originReviewApproved && (callbacksApproved || injectionApproved || allowedCallbackOrigins.length || typeof postFactory !== 'function')) throw new Error('origin_review_must_start_closed');
    this.originReviewApproved = originReviewApproved; this.postFactory = postFactory; this.pendingOrigin = null;
    if (runtimeExpiresAt !== Infinity && (!Number.isSafeInteger(runtimeExpiresAt) || runtimeExpiresAt <= now())) throw new Error('invalid_runtime_expiration');
    this.runtimeExpiresAt = runtimeExpiresAt;
    this.callbackDiagnostic = { phase: 'idle', status: 0, reason: 'none' };
    // A separate file is mandatory: do not adopt any previous WeCom state.
    const maps = ['requests','subscriptions','deliveries','verification','echoes'];
    if (!object(store.state) || store.state.version !== 1 ||
      Object.keys(store.state).some(k => !['version','syntheticPilot',...maps].includes(k)) ||
      maps.some(k => !object(store.state[k]))) throw new Error('non_pilot_state_rejected');
    if (store.state.syntheticPilot !== 1) {
      if (Object.hasOwn(store.state,'syntheticPilot') || maps.some(k => Object.keys(store.state[k]).length !== 0)) throw new Error('non_pilot_state_rejected');
      store.update(s => { s.syntheticPilot = 1; });
    }
  }
  async lock(fn) { const prior = this.tail; let release; this.tail = new Promise(r => { release = r; }); await prior; try { return await fn(); } finally { release(); } }
  async authorize(caller) { if (this.stopped || this.now() >= this.runtimeExpiresAt || caller !== this.principal || !await this.authorizeAccess()) fail('not_authorized', 1001); }
  stop() { this.stopped = true; this.callbacksApproved = false; this.injectionApproved = false; }
  identity(p) { return `sub_${digest(canonical([this.principal.id, p.delivery.url, p.name, p.arguments])).slice(0,40)}`; }
  validateSubscription(p, subscribe) {
    exactObject(p, subscribe ? ['name','arguments','delivery','cursor','ttlMs'] : ['name','arguments','delivery'], ['name','arguments','delivery']);
    if (p.name !== EVENT.name) fail('unknown_event');
    exactObject(p.arguments, ['run_id'], ['run_id']); runId(p.arguments.run_id);
    exactObject(p.delivery, subscribe ? ['mode','url','secret'] : ['mode','url'], subscribe ? ['mode','url','secret'] : ['mode','url']);
    if (p.delivery.mode !== 'webhook') fail('webhook_only');
    let url;
    if (subscribe && this.originReviewApproved && this.origins.length === 0) {
      let origin; try { origin = validateOfficialCallbackOrigin(new URL(p.delivery.url).origin); } catch { fail('invalid_official_callback_origin', -32015); }
      url = validateCallbackUrl(p.delivery.url, [origin]);
    } else url = validateCallbackUrl(p.delivery.url, this.origins);
    if (subscribe) {
      signingKey(p.delivery.secret);
      if (p.cursor != null) fail('replay_not_supported');
      if (p.ttlMs != null && (!Number.isSafeInteger(p.ttlMs) || p.ttlMs <= 0)) fail('invalid_ttl');
    }
    return url;
  }
  async approveCallbackOrigin(origin) {
    return this.lock(async () => {
      await this.authorize(this.principal);
      if (!this.originReviewApproved) fail('origin_review_not_approved', 1003);
      validateOfficialCallbackOrigin(origin);
      if (this.origins.length === 1 && this.origins[0] === origin) return { approved: true, origin, callbacks_enabled: this.callbacksApproved, injection_enabled: this.injectionApproved, same_dot_verified: false };
      if (this.origins.length || origin !== this.pendingOrigin) fail('observed_origin_mismatch', 1003);
      // Construct first; failure cannot partially arm the service. Exact origin is
      // immutable for the rest of this bounded runtime. No subscription is adopted.
      const nextPost = this.postFactory(origin);
      if (typeof nextPost !== 'function') fail('invalid_callback_transport', 1003);
      this.post = nextPost; this.origins = [origin]; this.pendingOrigin = null;
      this.callbacksApproved = true; this.injectionApproved = true;
      this.audit('callback_origin','approved');
      return { approved: true, origin, callbacks_enabled: true, injection_enabled: true, same_dot_verified: false };
    });
  }
  async subscribe(caller, p) {
    await this.authorize(caller);
    return this.lock(async () => {
      await this.authorize(caller); const url = this.validateSubscription(p, true);
      if (this.originReviewApproved && this.origins.length === 0) {
        if (this.pendingOrigin && this.pendingOrigin !== url.origin) fail('observed_origin_mismatch', -32015);
        this.pendingOrigin = url.origin;
        this.audit('callback_origin','pending_review');
        fail('callback_origin_pending_operator_review', -32015);
      }
      if (!this.callbacksApproved) fail('callback_delivery_not_approved', 1003);
      const id = this.identity(p), old = this.store.state.subscriptions[id];
      if (Object.values(this.store.state.subscriptions).some(s => s.id !== id && s.expiresAt > this.now())) fail('already_bound_to_another_subscription', 1003);
      const cacheKey = digest(canonical([this.principal.id, p.delivery.url]));
      if ((this.store.state.verification[cacheKey] ?? 0) <= this.now() || old?.secret !== p.delivery.secret) {
        const challenge = randomBytes(32).toString('base64url'), vid = `msg_verification_${randomUUID()}`;
        const body = Buffer.from(JSON.stringify({ type: 'verification', challenge }));
        const request = signedRequest({ id, secret: p.delivery.secret }, { eventId: vid }, this.now());
        request.body = body; request.headers['webhook-signature'] = signature(p.delivery.secret, vid, request.headers['webhook-timestamp'], body);
        let response; const started = this.now();
        try { response = await this.post(p.delivery.url, request); }
        catch (e) { this.callbackDiagnostic = { phase: 'verification', status: 0, reason: callbackReason(e) }; throw new BridgeError(-32015, 'CallbackEndpointError', this.callbackDiagnostic.reason); }
        const valid = this.now() - started <= 10000 && response.status >= 200 && response.status < 300 && equal(response.json?.challenge, challenge);
        this.callbackDiagnostic = { phase: 'verification', status: Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : 0, reason: valid ? 'accepted' : 'challenge_failed' };
        if (!valid) throw new BridgeError(-32015, 'CallbackEndpointError', 'challenge_failed');
        await this.authorize(caller); if (!this.callbacksApproved) fail('callback_delivery_not_approved', 1003);
        this.store.update(s => { s.verification[cacheKey] = this.now() + 5 * 60000; });
      }
      const expiresAt = Math.min(this.runtimeExpiresAt, this.now() + Math.min(p.ttlMs ?? HOUR, HOUR));
      this.store.update(s => { s.subscriptions[id] = { id, owner: this.principal.id, name: p.name, arguments: { ...p.arguments }, url: p.delivery.url, secret: p.delivery.secret, expiresAt,
        ...(old && old.secret !== p.delivery.secret ? { oldSecret: old.secret, rotateUntil: this.now() + 300000 } : old?.oldSecret && old.rotateUntil > this.now() ? { oldSecret: old.oldSecret, rotateUntil: old.rotateUntil } : {}) }; });
      this.audit('subscription', 'active'); return { id, refreshBefore: new Date(expiresAt).toISOString(), cursor: null, truncated: false };
    });
  }
  async unsubscribe(caller, p) {
    await this.authorize(caller); this.validateSubscription(p, false);
    return this.lock(async () => {
      await this.authorize(caller); const id = this.identity(p);
      this.store.update(s => { delete s.subscriptions[id]; for (const d of Object.values(s.deliveries)) if (d.subscriptionId === id && d.status === 'pending') d.status = 'unsubscribed'; });
      this.audit('subscription', 'removed'); return {};
    });
  }
  async inject(run) {
    runId(run);
    return this.lock(async () => {
      await this.authorize(this.principal);
      if (!this.injectionApproved || !this.callbacksApproved) fail('injection_not_approved', 1003);
      if (Object.hasOwn(this.store.state.requests, run)) return { run_id: run, duplicate: true };
      if (Object.keys(this.store.state.requests).length >= 100) fail('pilot_capacity_reached', 1003);
      const subs = Object.values(this.store.state.subscriptions).filter(s => s.owner === this.principal.id && s.expiresAt > this.now() && s.arguments.run_id === run);
      if (subs.length !== 1) fail('matching_verified_subscription_required', 1003);
      const event = { eventId: `evt_${randomUUID()}`, name: EVENT.name, timestamp: new Date(this.now()).toISOString(),
        data: { run_id: run, text: `synthetic-ping:${run}`, proof: randomBytes(32).toString('base64url') }, cursor: null };
      this.store.update(s => {
        s.requests[run] = { runId: run, eventId: event.eventId, proofHash: digest(event.data.proof), subscriptionId: subs[0].id, expiresAt: Math.min(this.runtimeExpiresAt, this.now() + HOUR), reply: null };
        s.deliveries[event.eventId] = { subscriptionId: subs[0].id, runId: run, event, attempts: 0, nextAttemptAt: this.now(), status: 'pending' };
      });
      this.audit('test_event', 'queued'); return { run_id: run, event_id: event.eventId, duplicate: false };
    });
  }
  async deliverDue() {
    return this.lock(async () => {
      if (!this.callbacksApproved || this.stopped || this.now() >= this.runtimeExpiresAt || !await this.authorizeAccess()) return { attempted: 0 };
      let attempted = 0;
      for (const [key, d] of Object.entries(this.store.state.deliveries)) {
        if (d.status !== 'pending' || d.nextAttemptAt > this.now()) continue;
        const sub = this.store.state.subscriptions[d.subscriptionId], run = this.store.state.requests[d.runId];
        if (!sub || sub.owner !== this.principal.id || sub.expiresAt <= this.now() || !run || run.expiresAt <= this.now() || d.attempts >= 5) {
          this.store.update(s => { s.deliveries[key].status = 'inactive'; }); continue;
        }
        if (!this.callbacksApproved || this.stopped || this.now() >= this.runtimeExpiresAt || !await this.authorizeAccess()) break;
        this.store.update(s => { const item = s.deliveries[key]; item.attempts++; item.nextAttemptAt = this.now() + Math.min(60000, 1000 * 2 ** (item.attempts - 1)); });
        attempted++; let status = 0, failure = null;
        try { status = (await this.post(sub.url, signedRequest(sub, d.event, this.now()))).status; } catch (e) { failure = callbackReason(e); }
        this.callbackDiagnostic = { phase: 'delivery', status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : 0, reason: failure ?? (status >= 200 && status < 300 ? 'accepted' : 'http_rejected') };
        this.store.update(s => { const item = s.deliveries[key]; item.status = status >= 200 && status < 300 ? 'accepted' : status >= 400 && status < 500 && ![408,429].includes(status) || item.attempts >= 5 ? 'failed' : 'pending'; if (status === 410) delete s.subscriptions[d.subscriptionId]; });
        this.audit('event_delivery', this.store.state.deliveries[key].status);
      }
      return { attempted };
    });
  }
  async reply(caller, p) {
    await this.authorize(caller); exactObject(p, ['run_id','event_id','proof','test_phrase'], ['run_id','event_id','proof','test_phrase']); runId(p.run_id);
    if (typeof p.test_phrase !== 'string' || !/^test-phrase:[A-Za-z0-9_-]{8,80}$/.test(p.test_phrase) || typeof p.proof !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(p.proof)) fail('synthetic_receipt_only');
    return this.lock(async () => {
      await this.authorize(caller); const r = this.store.state.requests[p.run_id];
      if (!r || r.expiresAt <= this.now() || r.eventId !== p.event_id || !equal(r.proofHash, digest(p.proof))) fail('event_proof_invalid', 1004);
      if (r.reply && r.reply.test_phrase !== p.test_phrase) fail('receipt_conflict', 1009);
      const duplicate = !!r.reply;
      if (!duplicate) this.store.update(s => { s.requests[p.run_id].reply = { test_phrase: p.test_phrase, recordedAt: new Date(this.now()).toISOString(), status: 'recorded_locally' }; });
      this.audit('reply_test', duplicate ? 'duplicate' : 'recorded');
      return { run_id: p.run_id, event_id: p.event_id, status: 'recorded_locally', duplicate, external_message_sent: false, same_dot_verified: false };
    });
  }
  status() { return { service: INFO.name, protocol_version: VERSION, synthetic_only: true, personal_channel_connected: false,
    callbacks_enabled: this.callbacksApproved && !this.stopped && this.now() < this.runtimeExpiresAt, pending_callback_origin: this.pendingOrigin, callback_diagnostic: { ...this.callbackDiagnostic }, active_subscriptions: Object.values(this.store.state.subscriptions).filter(s => s.expiresAt > this.now()).length,
    queued_tests: Object.keys(this.store.state.requests).length, recorded_receipts: Object.values(this.store.state.requests).filter(r => r.reply).length, same_dot_verified: false }; }
  receipt(run) { runId(run); const r = this.store.state.requests[run]; return r ? { run_id: run, event_id: r.eventId, callback_status: this.store.state.deliveries[r.eventId]?.status, reply: r.reply ? { ...r.reply } : null, same_dot_verified: false } : null; }
  async rpc(caller, message) {
    const id = object(message) && (typeof message.id === 'string' || Number.isSafeInteger(message.id)) ? message.id : undefined;
    try {
      await this.authorize(caller);
      exactObject(message, ['jsonrpc','id','method','params'], ['jsonrpc','id','method','params']);
      if (message.jsonrpc !== '2.0' || id === undefined || typeof message.method !== 'string') fail('invalid_request', -32600);
      exactObject(message.params, Object.keys(message.params ?? {}));
      const { _meta, ...p } = message.params;
      if (!object(_meta) || typeof _meta[VERSION_META] !== 'string' || !object(_meta[CAPS_META])) fail('required_per_request_metadata_missing', -32602);
      if (_meta[VERSION_META] !== VERSION) return rpcError(id, -32022, 'Unsupported protocol version', { supported: [VERSION], requested: _meta[VERSION_META] });
      let result;
      switch (message.method) {
        case 'server/discover': exactObject(p, []); result = { supportedVersions: [VERSION], capabilities: { tools: {}, events: {} } }; break;
        case 'ping': exactObject(p, []); result = {}; break;
        case 'tools/list': case 'events/list': exactObject(p, ['cursor']); if (p.cursor != null) fail('invalid_cursor'); result = message.method === 'tools/list' ? { tools: TOOLS } : { events: [EVENT] }; break;
        case 'events/subscribe': result = await this.subscribe(caller, p); break;
        case 'events/unsubscribe': result = await this.unsubscribe(caller, p); break;
        case 'tools/call': {
          exactObject(p, ['name','arguments'], ['name']);
          if (p.name === 'test_status') { exactObject(p.arguments ?? {}, []); result = this.status(); }
          else if (p.name === 'reply_test') result = await this.reply(caller, p.arguments);
          else fail('unknown_tool');
          result = { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result }; break;
        }
        default: fail(message.method === 'initialize' ? 'modern_only_use_2026-07-28_server_discover' : 'method_not_found', -32601);
      }
      return { jsonrpc: '2.0', id, result: { resultType: 'complete', ...result, _meta: { 'io.modelcontextprotocol/serverInfo': INFO } } };
    } catch (e) {
      this.audit('rpc', 'rejected'); const known = e instanceof BridgeError;
      return rpcError(id, known ? e.code : -32603, known ? e.message : 'internal_error', known && e.reason ? { reason: e.reason } : undefined);
    }
  }
}
