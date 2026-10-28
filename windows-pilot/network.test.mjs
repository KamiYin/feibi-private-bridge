import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import { lookup as namedLookup } from 'node:dns/promises';
import { syncBuiltinESMExports } from 'node:module';
import { WINDOWS_FIXED_ORIGINS, snapshotFromExplicitProxyEnv, validateWindowsRouting } from './network.mjs';
import { createIlinkProxyTransport } from '../weixin-candidate/transport.mjs';
import { createHostnameProxyCallbackPoster } from '../synthetic-pilot/hostname-proxy-callback.mjs';

// These tests are pure configuration checks, not Windows execution evidence.
// Guard actual TCP, TLS, HTTP, DNS and listener entry points against accidents.
let forbiddenCalls = 0;
const forbidden = () => { forbiddenCalls++; throw new Error('REAL_NETWORK_FORBIDDEN'); };
const old = { nc: net.connect, ncc: net.createConnection, sc: net.Socket.prototype.connect,
  listen: net.Server.prototype.listen, tls: tls.connect, http: http.request, https: https.request,
  dns: dns.lookup, dnsPromise: dns.promises.lookup };
net.connect = net.createConnection = net.Socket.prototype.connect = net.Server.prototype.listen = forbidden;
tls.connect = http.request = https.request = dns.lookup = dns.promises.lookup = forbidden;
syncBuiltinESMExports();
assert.equal(namedLookup, forbidden);
test.after(() => {
  net.connect = old.nc; net.createConnection = old.ncc; net.Socket.prototype.connect = old.sc;
  net.Server.prototype.listen = old.listen; tls.connect = old.tls; http.request = old.http;
  https.request = old.https; dns.lookup = old.dns; dns.promises.lookup = old.dnsPromise;
  syncBuiltinESMExports();
});

const snapshot = (proxyUrl = 'http://127.0.0.1:7890') => ({ version: 1, source: 'windows-default-web-proxy',
  routes: WINDOWS_FIXED_ORIGINS.map(origin => ({ origin, proxyUrl })) });
const validate = (value = snapshot(), extra = {}) => validateWindowsRouting({ snapshot: value,
  existingRouteApproved: true, platform: 'win32', ...extra });
const code = expected => e => e.code === expected && e.message === expected;

test('default closed: actual Windows platform and explicit existing-route approval are required', () => {
  for (const platform of ['linux', 'darwin', '', null]) assert.throws(() => validate(snapshot(), { platform }), code('WINDOWS_RUNTIME_REQUIRED'));
  for (const existingRouteApproved of [false, undefined, null, 'true', 1]) assert.throws(() => validate(snapshot(), { existingRouteApproved }), code('WINDOWS_EXISTING_ROUTE_APPROVAL_REQUIRED'));
  if (process.platform !== 'win32') assert.throws(() => validateWindowsRouting({ snapshot: snapshot(), existingRouteApproved: true }), code('WINDOWS_RUNTIME_REQUIRED'));
});

test('same existing local HTTP proxy is canonicalized into a fresh frozen HTTPS_PROXY only', () => {
  const s = snapshot(), result = validate(s);
  assert.equal(result.proxyUrl, 'http://127.0.0.1:7890/');
  assert.deepEqual(result.env, { HTTPS_PROXY: 'http://127.0.0.1:7890/' });
  assert.deepEqual(result.summary, { mode: 'existing-proxy', origins: 3 });
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.env) && Object.isFrozen(result.summary));
  s.routes[0].proxyUrl = 'http://changed.invalid:8080';
  assert.equal(result.proxyUrl, 'http://127.0.0.1:7890/');
  assert.ok(Object.isFrozen(WINDOWS_FIXED_ORIGINS));
});

test('legitimate existing HTTPS and IPv6 loopback proxy addresses are accepted without connecting', () => {
  assert.equal(validate(snapshot('https://existing-proxy.invalid:8443/')).proxyUrl, 'https://existing-proxy.invalid:8443/');
  assert.equal(validate(snapshot('http://[::1]:7890/')).proxyUrl, 'http://[::1]:7890/');
  const s = snapshot('http://localhost:80'); s.routes[1].proxyUrl = 'http://localhost/';
  assert.equal(validate(s).proxyUrl, 'http://localhost/');
});

test('DIRECT, null or destination returned by GetProxy is a precise blocker, never a fallback', () => {
  for (const value of [null, WINDOWS_FIXED_ORIGINS[1], `${WINDOWS_FIXED_ORIGINS[1]}/`]) {
    const s = snapshot(); s.routes[1].proxyUrl = value;
    assert.throws(() => validate(s), code('WINDOWS_DIRECT_ROUTE_UNSUPPORTED'));
  }
  const s = snapshot(); s.routes[2].proxyUrl = 'DIRECT';
  assert.throws(() => validate(s), code('WINDOWS_PROXY_CONFIGURATION_INVALID'));
});

test('different destination-specific PAC routes stop rather than silently using Tencent route everywhere', () => {
  for (const index of [1, 2]) {
    const s = snapshot(); s.routes[index].proxyUrl = 'http://another-existing-proxy.invalid:8080';
    assert.throws(() => validate(s), code('WINDOWS_DIFFERING_ROUTES_UNSUPPORTED'));
  }
});

test('exact 3 approved origins only: missing, duplicate, broadened and URL-bearing origins rejected', () => {
  for (const bad of ['https://evil.invalid', 'https://api.openai.com/', 'https://api.openai.com:443',
    'https://other.openai.com', 'https://ilinkai.weixin.qq.com.evil.invalid', 'https://127.0.0.1',
    'https://connectors.api.openai.com?secret=synthetic']) {
    const s = snapshot(); s.routes[2].origin = bad;
    assert.throws(() => validate(s), code('WINDOWS_ROUTE_SNAPSHOT_INVALID'));
  }
  const duplicate = snapshot(); duplicate.routes[2] = { ...duplicate.routes[1] };
  assert.throws(() => validate(duplicate), code('WINDOWS_ROUTE_SNAPSHOT_INVALID'));
  for (const routes of [[], snapshot().routes.slice(0, 2), [...snapshot().routes, snapshot().routes[0]]])
    assert.throws(() => validate({ ...snapshot(), routes }), code('WINDOWS_ROUTE_SNAPSHOT_INVALID'));
});

test('strict snapshot shape rejects arbitrary command, env, authorization and unrecognized provenance', () => {
  for (const s of [null, [], {}, { ...snapshot(), version: 2 }, { ...snapshot(), source: 'cloud-proxy' },
    { ...snapshot(), env: { HTTPS_PROXY: 'http://unapproved.invalid' } }, { ...snapshot(), command: 'ignored?' },
    { ...snapshot(), routes: 'not-list' }]) assert.throws(() => validate(s), code('WINDOWS_ROUTE_SNAPSHOT_INVALID'));
  const s = snapshot(); s.routes[0].Authorization = 'synthetic-not-a-key';
  assert.throws(() => validate(s), code('WINDOWS_ROUTE_SNAPSHOT_INVALID'));
});

test('proxy URL auth, non-HTTP schemes, PAC URLs, paths, query/fragment and control characters fail', () => {
  for (const raw of ['http://user:synthetic@proxy.invalid', 'socks5://127.0.0.1:1080', 'file:///proxy.pac',
    'https://proxy.invalid/config.pac', 'http://proxy.invalid/path', 'http://proxy.invalid/?', 'http://proxy.invalid/#',
    'http://proxy.invalid/?secret=synthetic', 'http://proxy.invalid/#synthetic', 'http://proxy.invalid:0',
    ' http://proxy.invalid', 'http://proxy.invalid\r\n', 'http:\\proxy.invalid', 'not-a-url', undefined, 123]) {
    const s = snapshot(); s.routes[0].proxyUrl = raw;
    assert.throws(() => validate(s), code('WINDOWS_PROXY_CONFIGURATION_INVALID'));
  }
});

test('explicit Windows process HTTPS_PROXY selection is inert and never reads implicit process env', () => {
  for (const env of [undefined, null, {}, { HTTP_PROXY: 'http://other.invalid' }, { HTTPS_PROXY: '' }])
    assert.throws(() => snapshotFromExplicitProxyEnv(env), code('WINDOWS_EXPLICIT_PROXY_REQUIRED'));
  const source = { HTTPS_PROXY: 'http://127.0.0.1:7890', OPENAI_API_KEY: 'synthetic-do-not-copy', NO_PROXY: '*' };
  const s = snapshotFromExplicitProxyEnv(source), result = validate(s);
  assert.equal(s.source, 'explicit-process-https-proxy');
  assert.ok(Object.isFrozen(s) && Object.isFrozen(s.routes) && s.routes.every(Object.isFrozen));
  assert.deepEqual(result.env, { HTTPS_PROXY: 'http://127.0.0.1:7890/' });
  assert.ok(!JSON.stringify(s).includes('synthetic-do-not-copy'));
  source.HTTPS_PROXY = 'http://changed.invalid';
  assert.equal(validate(s).proxyUrl, 'http://127.0.0.1:7890/');
});

test('conflicting current-process proxy spellings reject rather than choosing a potentially different route', () => {
  assert.throws(() => snapshotFromExplicitProxyEnv({ HTTPS_PROXY: 'http://one.invalid', https_proxy: 'http://two.invalid' }), code('WINDOWS_PROXY_CONFIGURATION_CONFLICT'));
  assert.throws(() => snapshotFromExplicitProxyEnv({ HTTPS_PROXY: 123 }), code('WINDOWS_PROXY_CONFIGURATION_INVALID'));
  assert.equal(validate(snapshotFromExplicitProxyEnv({ https_proxy: 'http://127.0.0.1:7890' })).proxyUrl, 'http://127.0.0.1:7890/');
});

test('validated fresh configuration constructs both reviewed transports without changing their protections', () => {
  const selected = validate();
  const request = createIlinkProxyTransport({ env: selected.env, networkActionApproved: true });
  const post = createHostnameProxyCallbackPoster({ proxyUrl: selected.proxyUrl,
    approvedOrigin: WINDOWS_FIXED_ORIGINS[2], hostnameProxyReviewApproved: true });
  assert.equal(typeof request, 'function'); assert.equal(typeof post, 'function');
  assert.throws(() => createIlinkProxyTransport({ env: selected.env }));
  assert.throws(() => createHostnameProxyCallbackPoster({ proxyUrl: selected.proxyUrl, approvedOrigin: WINDOWS_FIXED_ORIGINS[2] }));
});

test('fixed error categories and summary never reveal selected proxy, submitted URL or synthetic values', () => {
  let failure;
  try { validate(snapshot('http://synthetic-user:synthetic-password@secret-proxy.invalid')); } catch (e) { failure = e; }
  assert.ok(failure);
  assert.equal(failure.message, 'WINDOWS_PROXY_CONFIGURATION_INVALID');
  assert.doesNotMatch(JSON.stringify(validate().summary), /127\.0|7890|https?:|proxyUrl/);
});

test('all checks used zero native DNS, TCP, TLS, HTTP or listener operations', () => assert.equal(forbiddenCalls, 0));
