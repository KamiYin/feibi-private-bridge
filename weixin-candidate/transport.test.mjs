import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, getEventListeners } from 'node:events';
import { Duplex } from 'node:stream';
import https from 'node:https';import tls from 'node:tls';import net from 'node:net';import dns from 'node:dns';
import { lookup as namedLookup } from 'node:dns/promises';import { syncBuiltinESMExports } from 'node:module';
import { createIlinkProxyTransport } from './transport.mjs';
import { ILINK_ORIGIN, IlinkSession } from './ilink.mjs';
let forbiddenCalls=0;const forbidden=()=>{forbiddenCalls++;throw new Error('REAL_NETWORK_FORBIDDEN');};
const old={nc:net.connect,ncc:net.createConnection,sc:net.Socket.prototype.connect,l:net.Server.prototype.listen,t:tls.connect,d:dns.lookup,dp:dns.promises.lookup};
net.connect=net.createConnection=net.Socket.prototype.connect=net.Server.prototype.listen=tls.connect=dns.lookup=dns.promises.lookup=forbidden;syncBuiltinESMExports();assert.equal(namedLookup,forbidden);
test.after(()=>{net.connect=old.nc;net.createConnection=old.ncc;net.Socket.prototype.connect=old.sc;net.Server.prototype.listen=old.l;tls.connect=old.t;dns.lookup=old.d;dns.promises.lookup=old.dp;syncBuiltinESMExports();});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const common=()=>({'iLink-App-Id':'bot','iLink-App-ClientVersion':'132106'});
const postHeaders=()=>({...common(),'Content-Type':'application/json',AuthorizationType:'ilink_bot_token','X-WECHAT-UIN':Buffer.from('123456').toString('base64')});
const qr=()=>({origin:ILINK_ORIGIN,path:'/ilink/bot/get_bot_qrcode?bot_type=3',method:'POST',headers:postHeaders(),body:Buffer.from('{"local_token_list":[]}'),redirect:'error',timeoutMs:200});
const updates=()=>({...qr(),path:'/ilink/bot/getupdates',headers:{...postHeaders(),Authorization:'Bearer synthetic-ilink-token'},body:Buffer.from('{"get_updates_buf":"","base_info":{"channel_version":"2.4.10"}}')});
const status=()=>({origin:ILINK_ORIGIN,path:'/ilink/bot/get_qrcode_status?qrcode=synthetic%2Fqr%3Fvalue&verify_code=123456',method:'GET',headers:common(),redirect:'error',timeoutMs:200});
class FakeTls extends Duplex{
  constructor(options={}){super();this.authorized=options.authorized??true;this.alpnProtocol=options.alpn??'http/1.1';this.encrypted=true;this.received=Buffer.alloc(0);this.sent=false;this.options=options;}
  _read(){}
  _write(chunk,_enc,cb){this.received=Buffer.concat([this.received,chunk]);cb();if(this.sent||this.options.stall)return;const at=this.received.indexOf('\r\n\r\n');if(at<0)return;
    const len=Number(/content-length:\s*(\d+)/i.exec(this.received.subarray(0,at).toString())?.[1]??0);if(this.received.length-at-4<len)return;this.sent=true;
    queueMicrotask(()=>{if(this.destroyed)return;const body=Buffer.isBuffer(this.options.responseBody)?this.options.responseBody:Buffer.from(this.options.responseBody??'{"ret":0}');
      this.push(Buffer.concat([Buffer.from(`HTTP/1.1 ${this.options.status??200} Result\r\nContent-Length: ${body.length+(this.options.aborted?10:0)}\r\n${this.options.extraHeaders??''}Connection: close\r\n\r\n`),body]));if(this.options.aborted)this.push(null);});}
  setTimeout(){return this;}setNoDelay(){return this;}setKeepAlive(){return this;}ref(){return this;}unref(){return this;}
}
function fixture(options={}){
  const calls={proxy:[],tls:[],targets:[],sockets:[],requests:[]};
  const proxyRequest=opts=>{calls.proxy.push(opts);const req=new EventEmitter();req.destroyed=false;req.destroy=()=>{req.destroyed=true;};calls.requests.push(req);
    req.end=()=>{if(options.stallProxy)return;queueMicrotask(()=>{const socket=new Duplex({read(){},write(_c,_e,cb){cb();}});calls.sockets.push(socket);req.emit('connect',{statusCode:options.proxyStatus??200},socket,options.head??Buffer.alloc(0));});};return req;};
  const tlsConnect=opts=>{calls.tls.push(opts);const socket=new FakeTls({...options,...options.responses?.shift()});calls.sockets.push(socket);if(!options.stallTls)queueMicrotask(()=>socket.emit('secureConnect'));return socket;};
  const targetRequest=(url,opts,cb)=>{calls.targets.push({url,opts});return https.request(url,opts,cb);};
  const transport=createIlinkProxyTransport({env:options.env??{HTTPS_PROXY:'http://existing.proxy.test:8080'},approvedOrigins:options.approvedOrigins??[ILINK_ORIGIN],networkActionApproved:true,allowLegacyQrGet:options.allowLegacyQrGet===true,proxyHttpRequest:proxyRequest,proxyHttpsRequest:proxyRequest,tlsConnect,targetRequest});
  return{transport,calls};
}
test('construction is closed without explicit network approval and exact existing proxy selection',()=>{
  assert.throws(()=>createIlinkProxyTransport(),e=>e.code==='ILINK_NETWORK_APPROVAL_REQUIRED');
  for(const env of [{},{HTTP_PROXY:'http://other.test'},{HTTPS_PROXY:'http://a.test',https_proxy:'http://b.test'},{HTTPS_PROXY:'http://user:pass@proxy.test'},{HTTPS_PROXY:'socks5://proxy.test'},{HTTPS_PROXY:'https://proxy.test/path'}])assert.throws(()=>fixture({env}));
  for(const approvedOrigins of [[],['https://evil.test'],['https://other.weixin.qq.com']])assert.throws(()=>fixture({approvedOrigins}));
});
test('authenticated API uses only hostname CONNECT; TLS identity/Host exact, no bearer/query/body in CONNECT',async()=>{
  const s=fixture(),request=updates();const result=await s.transport(request);assert.deepEqual(result,{status:200,body:'{"ret":0}'});assert.equal(s.calls.proxy.length,1);
  const opts=s.calls.proxy[0];assert.equal(opts.hostname,'existing.proxy.test');assert.equal(opts.path,'ilinkai.weixin.qq.com:443');assert.deepEqual(opts.headers,{host:'ilinkai.weixin.qq.com:443'});
  for(const privateValue of ['synthetic-ilink-token','getupdates','get_updates_buf'])assert.ok(!JSON.stringify(opts).includes(privateValue));
  const tlsOpts=s.calls.tls[0];assert.equal(tlsOpts.servername,'ilinkai.weixin.qq.com');assert.equal(tlsOpts.rejectUnauthorized,true);assert.equal(tlsOpts.checkServerIdentity,tls.checkServerIdentity);assert.equal(tlsOpts.minVersion,'TLSv1.2');assert.deepEqual(tlsOpts.ALPNProtocols,['http/1.1']);
  const bytes=s.calls.sockets.find(x=>x.encrypted).received;assert.match(bytes.toString(),/^POST \/ilink\/bot\/getupdates HTTP\/1.1\r\n/);assert.match(bytes.toString(),/Host: ilinkai\.weixin\.qq\.com\r\n/i);assert.match(bytes.toString(),/authorization: Bearer synthetic-ilink-token/i);assert.deepEqual(bytes.subarray(bytes.indexOf('\r\n\r\n')+4),request.body);
  assert.ok(s.calls.sockets.every(x=>x.destroyed));assert.ok(s.calls.requests.every(x=>x.destroyed));
});
test('QR POST and GET carry only required application/QR headers, never bearer',async()=>{
  for(const request of [qr(),status()]){const s=fixture();await s.transport(request);const data=s.calls.sockets.find(x=>x.encrypted).received.toString();assert.doesNotMatch(data,/authorization: Bearer/i);assert.ok(!JSON.stringify(s.calls.proxy[0]).includes('synthetic%2Fqr'));}
  const s=fixture();await s.transport(status());const bytes=s.calls.sockets.find(x=>x.encrypted).received.toString();assert.match(bytes,/^GET \/ilink\/bot\/get_qrcode_status\?qrcode=synthetic%2Fqr%3Fvalue&verify_code=123456 HTTP\/1.1/);assert.doesNotMatch(bytes,/authorizationtype|x-wechat-uin|content-type|content-length/i);
});
test('strict origin/method/path/query validation runs before any connection or credential emission',async()=>{
  const s=fixture();for(const patch of [{origin:'https://other.weixin.qq.com'},{origin:'http://ilinkai.weixin.qq.com'},{origin:'https://127.0.0.1'},{origin:'https://user:pass@ilinkai.weixin.qq.com'},
    {path:'https://evil.test/ilink/bot/getupdates'},{path:'//evil.test/ilink/bot/getupdates'},{path:'/ilink/bot/getupdates?x=1'},{path:'/ilink/bot/getconfig'},{path:'/ilink/bot/sendmessage',method:'GET'},{redirect:'follow'},{method:'PATCH'},
    {path:'/ilink/bot/get_qrcode_status?qrcode=x&qrcode=y',method:'GET',headers:common(),body:undefined},{path:'/ilink/bot/get_qrcode_status?qrcode=x&token=private',method:'GET',headers:common(),body:undefined},
    {path:'/ilink/bot/get_qrcode_status?qrcode=x%0a',method:'GET',headers:common(),body:undefined},{path:'/ilink/bot/get_qrcode_status?qrcode=x#fragment',method:'GET',headers:common(),body:undefined}])await assert.rejects(s.transport({...updates(),...patch}));assert.equal(s.calls.proxy.length,0);assert.equal(s.calls.targets.length,0);
});
test('independently approved exact extra origin allowed only non-QR-start endpoints, not wildcard',async()=>{
  const list=[ILINK_ORIGIN,'https://approved.weixin.qq.com'],s=fixture({approvedOrigins:list});list.push('https://later.weixin.qq.com');
  await s.transport({...updates(),origin:'https://approved.weixin.qq.com'});assert.equal(s.calls.proxy[0].path,'approved.weixin.qq.com:443');
  await assert.rejects(s.transport({...qr(),origin:'https://approved.weixin.qq.com'}));await assert.rejects(s.transport({...updates(),origin:'https://later.weixin.qq.com'}));assert.equal(s.calls.proxy.length,1);
});
test('header allowlist rejects extras/duplicates/CRLF/OpenAI key, missing auth and bearer on QR',async()=>{
  const s=fixture();for(const request of [{...qr(),headers:{...qr().headers,Authorization:'Bearer synthetic'}},{...status(),headers:{...common(),Authorization:'Bearer synthetic'}},
    {...updates(),headers:postHeaders()},{...updates(),headers:{...updates().headers,Authorization:'Bearer sk-synthetic-not-a-real-key'}},{...updates(),headers:{...updates().headers,Host:'evil.test'}},
    {...updates(),headers:{...updates().headers,'X-Secret':'do-not-forward'}},{...updates(),headers:{...updates().headers,authorization:'Bearer duplicate'}},
    {...updates(),headers:{...updates().headers,Authorization:'Bearer bad\r\nvalue'}},{...qr(),headers:{...qr().headers,'X-WECHAT-UIN':'notbase64'}},
    {...qr(),headers:{...qr().headers,'X-WECHAT-UIN':Buffer.from('4294967296').toString('base64')}},{...qr(),headers:{...qr().headers,'iLink-App-ClientVersion':'999'}}])await assert.rejects(s.transport(request));assert.equal(s.calls.proxy.length,0);
});
test('HTTPS proxy uses verified TLS and denial/redirect/auth challenge/pre-read never reaches target TLS',async()=>{
  const verified=fixture({env:{HTTPS_PROXY:'https://existing.proxy.test:8443'}});await verified.transport(qr());assert.equal(verified.calls.proxy[0].servername,'existing.proxy.test');assert.equal(verified.calls.proxy[0].rejectUnauthorized,true);
  for(const spec of [{proxyStatus:403},{proxyStatus:407},{proxyStatus:302},{head:Buffer.from('unexpected')}]){const s=fixture(spec);await assert.rejects(s.transport(updates()),e=>e.code==='ILINK_PROXY_REJECTED');assert.equal(s.calls.proxy.length,1);assert.equal(s.calls.tls.length,0);assert.ok(s.calls.sockets.every(x=>x.destroyed));}
});
test('failed TLS identity/ALPN sends no authenticated HTTP bytes',async()=>{
  for(const spec of [{authorized:false},{alpn:'h2'}]){const s=fixture(spec);await assert.rejects(s.transport(updates()),e=>e.code==='ILINK_TLS_FAILED');assert.equal(s.calls.sockets.find(x=>x.encrypted).received.length,0);}
});
test('one <=35s total deadline covers proxy/TLS/response with cleanup and no late callback',async()=>{
  for(const spec of [{stallProxy:true},{stallTls:true},{stall:true}]){const s=fixture(spec);await assert.rejects(s.transport({...updates(),timeoutMs:10}),e=>e.code==='ILINK_REQUEST_TIMEOUT');assert.ok(s.calls.requests.every(x=>x.destroyed));assert.ok(s.calls.sockets.every(x=>x.destroyed));for(const socket of s.calls.sockets)socket.emit('secureConnect');await sleep(1);}
  const s=fixture();for(const timeoutMs of [0,35001,1.5,NaN])await assert.rejects(s.transport({...qr(),timeoutMs}));assert.equal(s.calls.proxy.length,0);
});
test('AbortSignal pre-abort and in-flight abort close resources, remove listener, and reject late CONNECT',async()=>{
  const before=new AbortController();before.abort();const a=fixture();await assert.rejects(a.transport({...updates(),signal:before.signal}),e=>e.code==='ILINK_REQUEST_ABORTED');assert.equal(a.calls.proxy.length,0);
  for(const spec of [{stallProxy:true},{stallTls:true},{stall:true}]){const ctrl=new AbortController(),s=fixture(spec),pending=s.transport({...updates(),signal:ctrl.signal});await sleep(2);ctrl.abort();await assert.rejects(pending,e=>e.code==='ILINK_REQUEST_ABORTED');assert.ok(s.calls.requests.every(x=>x.destroyed));assert.ok(s.calls.sockets.every(x=>x.destroyed));assert.equal(getEventListeners(ctrl.signal,'abort').length,0);
    if(spec.stallProxy){const socket=new Duplex({read(){},write(_c,_e,cb){cb();}});s.calls.requests[0].emit('connect',{statusCode:200},socket,Buffer.alloc(0));assert.equal(socket.destroyed,true);assert.equal(s.calls.tls.length,0);}}
  const c=new AbortController(),ok=fixture();await ok.transport({...qr(),signal:c.signal});assert.equal(getEventListeners(c.signal,'abort').length,0);
});
test('response bounds/truncation/encoding/redirect fail without alternate request; HTTP error status preserved safely',async()=>{
  for(const [spec,code] of [[{status:302},'ILINK_REDIRECT_BLOCKED'],[{responseBody:'x'.repeat(1048577)},'ILINK_RESPONSE_BOUND'],[{aborted:true},'ILINK_RESPONSE_FAILED'],[{responseBody:Buffer.from([0xff])},'ILINK_RESPONSE_ENCODING'],[{extraHeaders:'X-Large: '+'x'.repeat(20000)+'\r\n'},'ILINK_REQUEST_FAILED']]){const s=fixture(spec);await assert.rejects(s.transport(updates()),e=>e.code===code);assert.equal(s.calls.proxy.length,1);assert.ok(s.calls.sockets.every(x=>x.destroyed));}
  const s=fixture({status:401,responseBody:'{"ret":1}'});assert.deepEqual(await s.transport(updates()),{status:401,body:'{"ret":1}'});
});
test('body bounds and immutable byte/header snapshot',async()=>{
  const s=fixture();for(const request of [{...qr(),body:Buffer.alloc(262145)},{...qr(),body:'rawstring'},{...qr(),body:Buffer.alloc(0)},{...status(),body:Buffer.alloc(1)}])await assert.rejects(s.transport(request));assert.equal(s.calls.proxy.length,0);
  const req=updates(),expected=Buffer.from(req.body),pending=s.transport(req);req.body.fill(32);req.headers.Authorization='Bearer changed-after-call';await pending;const bytes=s.calls.sockets.find(x=>x.encrypted).received;assert.deepEqual(bytes.subarray(bytes.indexOf('\r\n\r\n')+4),expected);assert.doesNotMatch(bytes.toString(),/changed-after-call/);
});
test('actual IlinkSession QR builder composes with candidate transport over memory sockets only',async()=>{
  const s=fixture({responseBody:'{"qrcode":"synthetic-qr","qrcode_img_content":"synthetic-display-only"}'});const session=new IlinkSession({request:s.transport,qrApproved:true,ownerConfirmationNonce:'bind:synthetic_nonce_for_tests',deadline:Date.now()+10000});
  const qrInfo=await session.startQr();assert.equal(qrInfo.qrPayload,'synthetic-display-only');assert.equal(session.status().phase,'wait');session.stop();assert.equal(s.calls.proxy.length,1);
});
test('no native DNS, TCP, TLS or listen call occurred in any transport test',()=>assert.equal(forbiddenCalls,0));

test('legacy QR GET remains opt-in, fixed initial origin/path, bodyless/application-only; other GET or bearer rejected',async()=>{
  const request={...qr(),method:'GET',headers:common(),body:undefined};const closed=fixture();await assert.rejects(closed.transport(request));assert.equal(closed.calls.proxy.length,0);
  const s=fixture({allowLegacyQrGet:true,approvedOrigins:[ILINK_ORIGIN,'https://approved.weixin.qq.com']});await s.transport(request);
  const bytes=s.calls.sockets.find(x=>x.encrypted).received.toString();assert.match(bytes,/^GET \/ilink\/bot\/get_bot_qrcode\?bot_type=3 HTTP\/1.1/);assert.doesNotMatch(bytes,/authorization|x-wechat-uin|content-type|content-length/i);
  for(const patch of [{origin:'https://approved.weixin.qq.com'},{path:'/ilink/bot/get_bot_qrcode?bot_type=3&local_token_list=secret'},{path:'/ilink/bot/getupdates'},{headers:postHeaders()},{headers:{...common(),Authorization:'Bearer secret'}},{body:Buffer.from('{}')}])await assert.rejects(s.transport({...request,...patch}));assert.equal(s.calls.proxy.length,1);
});
test('real session POST405->GET compatibility composes with reviewed proxy HTTP parser on memory sockets',async()=>{
  const s=fixture({allowLegacyQrGet:true,responses:[{status:405,responseBody:''},{status:200,responseBody:'{"qrcode":"synthetic-qr","qrcode_img_content":"synthetic-display"}'}]});
  const session=new IlinkSession({request:s.transport,qrApproved:true,qrGet405Compatibility:true,ownerConfirmationNonce:'bind:synthetic_nonce_for_tests',deadline:Date.now()+10000});
  assert.equal((await session.startQr()).qrPayload,'synthetic-display');assert.equal(s.calls.proxy.length,2);assert.ok(s.calls.proxy.every(x=>x.path==='ilinkai.weixin.qq.com:443'));
  assert.equal(session.status().last_http_status,200);assert.equal(forbiddenCalls,0);session.stop();
});
