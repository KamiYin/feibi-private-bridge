// Pure Windows routing validation. No environment reads, DNS, PAC evaluation,
// sockets, subprocesses or settings changes occur in this module.
// Resolve DefaultWebProxy.GetProxy only at explicit Run, never at preflight.
// https://learn.microsoft.com/dotnet/api/system.net.webrequest.defaultwebproxy
// https://learn.microsoft.com/dotnet/api/system.net.iwebproxy.getproxy
// GetProxy(null or destination) means DIRECT; this small pilot does NOT support it.

export const WINDOWS_FIXED_ORIGINS = Object.freeze([
  'https://ilinkai.weixin.qq.com',
  'https://api.openai.com',
  'https://connectors.api.openai.com',
]);
export const WINDOWS_MEDIA_ORIGINS=Object.freeze(['https://novac2c.cdn.weixin.qq.com','https://files.oaiusercontent.com','https://files.openai.com','https://sdmntprseasia.oaiusercontent.com']);

const fail = code => { throw Object.assign(new Error(code), { code }); };
const exact = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

function canonicalProxy(raw, origin) {
  if (raw === null || raw === origin || raw === `${origin}/`) fail('WINDOWS_DIRECT_ROUTE_UNSUPPORTED');
  if (typeof raw !== 'string' || raw.length > 2048 || !/^[\x21-\x7e]+$/.test(raw) || /[\\?#]/.test(raw)) fail('WINDOWS_PROXY_CONFIGURATION_INVALID');
  let proxy;
  try { proxy = new URL(raw); } catch { fail('WINDOWS_PROXY_CONFIGURATION_INVALID'); }
  if (!['http:', 'https:'].includes(proxy.protocol) || proxy.username || proxy.password || !proxy.hostname ||
      proxy.pathname !== '/' || proxy.search || proxy.hash || proxy.port === '0') fail('WINDOWS_PROXY_CONFIGURATION_INVALID');
  return proxy.href;
}

/** Explicit alternative to Windows system selection: caller supplies only the
 * CURRENT WINDOWS PROCESS environment after the user selects this route source.
 * No default process.env and no fallback from failed system/PAC selection.
 * Do not serialize the rest of the environment or log proxy URLs.
 */
export function snapshotFromExplicitProxyEnv(env) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) fail('WINDOWS_EXPLICIT_PROXY_REQUIRED');
  const upper = env.HTTPS_PROXY, lower = env.https_proxy;
  if ([upper, lower].some(value => value !== undefined && typeof value !== 'string')) fail('WINDOWS_PROXY_CONFIGURATION_INVALID');
  if (upper && lower && upper !== lower) fail('WINDOWS_PROXY_CONFIGURATION_CONFLICT');
  const selected = upper || lower;
  if (!selected) fail('WINDOWS_EXPLICIT_PROXY_REQUIRED');
  // Validate before constructing a snapshot; still inert, not permission to run.
  const proxyUrl = canonicalProxy(selected, WINDOWS_FIXED_ORIGINS[0]);
  return Object.freeze({ version: 1, source: 'explicit-process-https-proxy',
    routes: Object.freeze(WINDOWS_FIXED_ORIGINS.map(origin => Object.freeze({ origin, proxyUrl }))),
  });
}

/** Consume one local Run-time snapshot, not cloud routing configuration.
 * The caller must resolve all three origins independently with the selected
 * current-user Windows route. PAC may select different routes; fail closed then.
 * The source label is provenance supplied by the trusted launcher, not proof that
 * arbitrary JSON came from Windows. platform is injectable for offline tests;
 * production callers must omit it, retaining the actual process.platform gate.
 */
export function validateWindowsRouting({ snapshot, existingRouteApproved = false, platform = process.platform, mediaApproved = false } = {}) {
  const origins=mediaApproved?[...WINDOWS_FIXED_ORIGINS,...WINDOWS_MEDIA_ORIGINS]:WINDOWS_FIXED_ORIGINS;
  if (platform !== 'win32') fail('WINDOWS_RUNTIME_REQUIRED');
  if (existingRouteApproved !== true) fail('WINDOWS_EXISTING_ROUTE_APPROVAL_REQUIRED');
  if (!exact(snapshot, ['version', 'source', 'routes']) || snapshot.version !== 1 ||
      !['windows-default-web-proxy', 'explicit-process-https-proxy'].includes(snapshot.source) ||
      !Array.isArray(snapshot.routes) || snapshot.routes.length !== origins.length) fail('WINDOWS_ROUTE_SNAPSHOT_INVALID');
  const routes = new Map();
  for (const route of snapshot.routes) {
    if (!exact(route, ['origin', 'proxyUrl']) || !origins.includes(route.origin) || routes.has(route.origin)) fail('WINDOWS_ROUTE_SNAPSHOT_INVALID');
    routes.set(route.origin, canonicalProxy(route.proxyUrl, route.origin));
  }
  if (new Set(routes.values()).size !== 1) fail('WINDOWS_DIFFERING_ROUTES_UNSUPPORTED');
  const proxyUrl = routes.get(WINDOWS_FIXED_ORIGINS[0]);
  // Caller builds a fresh child env; do not merge inherited proxy/no_proxy values.
  // In particular, this is NOT a global Windows proxy/VPN setting change.
  return Object.freeze({ proxyUrl, env: Object.freeze({ HTTPS_PROXY: proxyUrl }),
    summary: Object.freeze({ mode: 'existing-proxy', origins: origins.length }),
  });
}
