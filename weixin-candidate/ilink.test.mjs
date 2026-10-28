import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';import tls from 'node:tls';import http from 'node:http';import https from 'node:https';import dns from 'node:dns';import {syncBuiltinESMExports} from 'node:module';
import {IlinkSession,ILINK_ORIGIN,parseIlinkJson,approvedIlinkOrigin} from './ilink.mjs';
let forbidden=0;const deny=()=>{forbidden++;throw new Error('NO_REAL_NETWORK');};
net.connect=net.createConnection=net.Socket.prototype.connect=net.Server.prototype.listen=tls.connect=http.request=https.request=globalThis.fetch=dns.lookup=dns.promises.lookup=deny;syncBuiltinESMExports();
const NONCE='bind:current_chat_synthetic_123',TOKEN='synthetic-bot-token-never-real',OWNER='synthetic-owner@im.wechat',BOT='synthetic-bot@im.bot',QR='synthetic-qr-value';
const confirmed=extra=>({status:'confirmed',bot_token:TOKEN,ilink_bot_id:BOT,ilink_user_id:OWNER,baseurl:ILINK_ORIGIN,...extra});
function fixture(extra={}){
  let now=1000000;const calls=[],queue=[];
  const session=new IlinkSession({qrApproved:true,ownerConfirmationNonce:NONCE,deadline:now+1800000,now:()=>now,request:async req=>{calls.push(req);const item=queue.shift();if(item instanceof Error)throw item;return item?.status?item:{status:200,body:JSON.stringify(item??{})};},...extra});
  const respond=data=>queue.push({status:200,body:typeof data==='string'?data:JSON.stringify(data)});
  const start=async()=>{respond({qrcode:QR,qrcode_img_content:'synthetic QR display payload'});return session.startQr();};
  const connect=async()=>{await start();respond(confirmed());await session.pollQr();session.confirmOwner({nonce:NONCE,userConfirmedScan:true});};
  return{session,calls,queue,respond,start,connect,advance:ms=>{now+=ms;}};
}
test('default no approval/transport and missing current-chat nonce or bounds fail closed',async()=>{
  const s=fixture({qrApproved:false});await assert.rejects(s.start(),e=>e.code==='QR_ACTION_APPROVAL_REQUIRED');assert.equal(s.calls.length,0);
  for(const extra of [{ownerConfirmationNonce:'bad'},{deadline:1000000},{deadline:26200001},{approvedApiOrigins:['https://evil.test']}])assert.throws(()=>fixture(extra));
  const noTransport=new IlinkSession({ownerConfirmationNonce:NONCE,deadline:Date.now()+10000,qrApproved:true});await assert.rejects(noTransport.startQr(),e=>e.code==='ILINK_TRANSPORT_FAILED');
});
test('QR fixed POST sends empty token list; secret UI payload returned only to explicit caller; status redacted',async()=>{
  const s=fixture(),display=await s.start();assert.equal(display.qrPayload,'synthetic QR display payload');
  const req=s.calls[0];assert.equal(req.origin,ILINK_ORIGIN);assert.equal(req.path,'/ilink/bot/get_bot_qrcode?bot_type=3');assert.equal(req.method,'POST');assert.deepEqual(JSON.parse(req.body),{local_token_list:[]});
  assert.equal(req.headers.Authorization,undefined);assert.equal(req.headers.AuthorizationType,'ilink_bot_token');assert.equal(req.headers['iLink-App-Id'],'bot');assert.equal(req.headers['iLink-App-ClientVersion'],'132106');assert.match(Buffer.from(req.headers['X-WECHAT-UIN'],'base64').toString(),/^\d+$/);
  assert.equal(req.redirect,'error');assert.equal(req.timeoutMs,15000);assert.ok(!JSON.stringify(s.session.status()).includes(QR));assert.deepEqual(JSON.stringify(s.session),'{}');
});
test('QR GET uses only application headers; verification code never becomes bearer/log/status',async()=>{
  const s=fixture();await s.start();s.respond({status:'need_verifycode'});await s.session.pollQr();s.respond({status:'scaned'});await s.session.pollQr({verifyCode:'123456'});
  const req=s.calls.at(-1);assert.equal(req.method,'GET');assert.equal(req.path,`/ilink/bot/get_qrcode_status?qrcode=${QR}&verify_code=123456`);assert.deepEqual(req.headers,{'iLink-App-Id':'bot','iLink-App-ClientVersion':'132106'});assert.equal(req.timeoutMs,35000);assert.equal(req.body,undefined);
  assert.ok(!JSON.stringify(s.session.status()).includes('123456'));await assert.rejects(s.session.pollQr({verifyCode:'secret text'}));
});
test('confirmed QR alone cannot receive/send; current-chat user confirmation plus exact nonce and scanner ID required',async()=>{
  const s=fixture();await s.start();s.respond(confirmed());const r=await s.session.pollQr();assert.equal(r.phase,'pending_owner_confirmation');assert.equal(r.authenticated,false);
  await assert.rejects(s.session.getUpdates());await assert.rejects(s.session.sendText({text:'test',contextToken:'synthetic-context',clientId:'test-client'}));assert.throws(()=>s.session.bindingForRelay());
  for(const bad of [{nonce:NONCE,userConfirmedScan:false},{nonce:'bind:wrong_current_chat_nonce',userConfirmedScan:true},{}])assert.throws(()=>s.session.confirmOwner(bad));
  s.session.confirmOwner({nonce:NONCE,userConfirmedScan:true});assert.deepEqual(s.session.bindingForRelay(),{ownerUserId:OWNER,botId:BOT,apiOrigin:ILINK_ORIGIN,confirmedAt:1000000});assert.equal(s.session.isAuthenticated(),true);
  const text=JSON.stringify(s.session.status());for(const v of [TOKEN,OWNER,BOT,NONCE])assert.ok(!text.includes(v));
});
test('missing scanner/bot/token and malformed or unapproved returned base cannot bind',async()=>{
  for(const extra of [{ilink_user_id:''},{ilink_user_id:undefined},{ilink_bot_id:''},{bot_token:''},{bot_token:'bad\r\nheader'},{baseurl:undefined},{baseurl:'invalid SECRET'},{baseurl:'https://evil.test'},{baseurl:'https://ilinkai.weixin.qq.com/other'},{baseurl:'https://u:p@ilinkai.weixin.qq.com'},{baseurl:'https://other.weixin.qq.com'}]){
    const s=fixture();await s.start();s.respond(confirmed(extra));await assert.rejects(s.session.pollQr());assert.equal(s.session.isAuthenticated(),false);assert.throws(()=>s.session.confirmOwner({nonce:NONCE,userConfirmedScan:true}));
  }
});
test('no auto-follow of HTTP or QR-origin redirects; independent exact host allowlist only',async()=>{
  for(const origin of ['https://evil.test','https://weixin.qq.com.evil.test','http://ilinkai.weixin.qq.com','https://127.0.0.1','https://ilinkai.weixin.qq.com.','https://ilinkai.weixin.qq.com:444'])assert.throws(()=>approvedIlinkOrigin(origin));
  const s=fixture();await s.start();s.respond({status:'scaned_but_redirect',redirect_host:'other.weixin.qq.com'});await assert.rejects(s.session.pollQr(),e=>e.code==='EXACT_ILINK_ORIGIN_REVIEW_REQUIRED');assert.equal(s.calls.length,2);assert.equal(s.session.status().pending_api_origin,'https://other.weixin.qq.com');
  const allowed=fixture({approvedApiOrigins:[ILINK_ORIGIN,'https://other.weixin.qq.com']});await allowed.start();allowed.respond({status:'scaned_but_redirect',redirect_host:'other.weixin.qq.com'});await allowed.session.pollQr();allowed.respond({status:'wait'});await allowed.session.pollQr();assert.equal(allowed.calls.at(-1).origin,'https://other.weixin.qq.com');assert.equal(allowed.calls.at(-1).headers.Authorization,undefined);
  const redirect=fixture();redirect.queue.push({status:302,body:'private raw body'});await assert.rejects(redirect.session.startQr(),e=>e.code==='ILINK_REDIRECT_BLOCKED'&&!e.message.includes('private'));assert.equal(redirect.calls.length,1);
});
test('expired, verify blocked and already-bound result do not renew QR or adopt unknown credentials',async()=>{
  for(const status of ['expired','verify_code_blocked','binded_redirect']){const s=fixture();await s.start();s.respond({status});await assert.rejects(s.session.pollQr());assert.equal(s.session.isAuthenticated(),false);assert.equal(s.calls.length,2);}
  const s=fixture();await s.start();s.advance(300000);await assert.rejects(s.session.pollQr(),e=>e.code==='QR_EXPIRED');assert.equal(s.calls.length,1);
});
test('updates and replies use pinned owner/token/origin; lossless uint64 IDs and honest agent metadata',async()=>{
  const s=fixture();await s.connect();s.respond('{"ret":0,"msgs":[{"message_id":18446744073709551615}],"get_updates_buf":"synthetic-cursor"}');const result=await s.session.getUpdates('old-cursor');assert.equal(result.msgs[0].message_id,'18446744073709551615');
  let req=s.calls.at(-1);assert.equal(req.headers.Authorization,`Bearer ${TOKEN}`);assert.deepEqual(JSON.parse(req.body),{get_updates_buf:'old-cursor',base_info:{channel_version:'2.4.10',bot_agent:'FeibiBridge/0.1'}});
  s.respond({ret:0,message_id:'12345678901234567890'});const ack=await s.session.sendText({text:'synthetic reply',contextToken:'synthetic-context',clientId:'same-stable-client-id'});assert.deepEqual(ack,{accepted:true,messageId:'12345678901234567890'});
  req=s.calls.at(-1);const body=JSON.parse(req.body);assert.deepEqual(body.msg,{from_user_id:'',to_user_id:OWNER,client_id:'same-stable-client-id',message_type:2,message_state:2,item_list:[{type:1,text_item:{text:'synthetic reply'}}],context_token:'synthetic-context'});assert.equal(req.path,'/ilink/bot/sendmessage');assert.equal(req.origin,ILINK_ORIGIN);
  assert.equal(s.session.status().personal_message_access_started,true);
});
test('API and session errors expose fixed categories; -14 or HTTP auth rejection stops, no auto retry',async()=>{
  const s=fixture();await s.connect();s.respond({ret:-14,errmsg:'sensitive synthetic response'});await assert.rejects(s.session.getUpdates(),e=>e.code==='ILINK_SESSION_INVALIDATED'&&!e.message.includes('sensitive'));assert.equal(s.session.isAuthenticated(),false);await assert.rejects(s.session.getUpdates());assert.equal(s.calls.length,3);
  const auth=fixture();await auth.connect();auth.queue.push({status:401,body:'private'});await assert.rejects(auth.session.getUpdates(),e=>e.code==='ILINK_AUTHORIZATION_STOP');assert.equal(auth.session.isAuthenticated(),false);
  const failed=fixture();await failed.connect();failed.respond({ret:7});await assert.rejects(failed.session.sendText({text:'synthetic',contextToken:'context',clientId:'client'}),e=>e.code==='ILINK_BUSINESS_REJECTED');assert.equal(failed.calls.length,3);
});
test('deadline/stop prevents late response credential adoption and cancels transport signal',async()=>{
  const s=fixture();await s.connect();s.advance(1800000);await assert.rejects(s.session.getUpdates());assert.equal(s.calls.length,2);
  let release;const q=fixture({request:()=>new Promise(r=>{release=r;})});const pending=q.session.startQr();q.session.stop();release({status:200,body:JSON.stringify({qrcode:QR,qrcode_img_content:'safe synthetic'})});await assert.rejects(pending);assert.equal(q.session.status().phase,'stopped');assert.equal(q.session.isAuthenticated(),false);
});
test('bounds and JSON source-aware IDs cannot rewrite user text or silently round IDs',()=>{
  assert.equal(parseIlinkJson('{"text":"message_id:18446744073709551615","message_id":18446744073709551615}').message_id,'18446744073709551615');
  assert.equal(parseIlinkJson('{"text":"message_id:18446744073709551615"}').text,'message_id:18446744073709551615');
  for(const raw of ['{','x'.repeat(1048577),'{"message_id":1.5}','{"message_id":1e5}'])assert.throws(()=>parseIlinkJson(raw));
});
test('no real DNS/TCP/TLS/HTTP/listener or fetch occurred',()=>assert.equal(forbidden,0));

test('payment or quota HTTP status stops session and never automatically retries',async()=>{
  for(const status of [402,429]){const s=fixture();await s.connect();s.queue.push({status,body:'synthetic details never echoed'});await assert.rejects(s.session.getUpdates(),e=>e.code==='ILINK_PAYMENT_OR_QUOTA_STOP');assert.equal(s.session.isAuthenticated(),false);await assert.rejects(s.session.getUpdates());assert.equal(s.calls.length,3);}
});

test('explicit legacy compatibility only retries initial QR POST405 once, same origin with application-only GET',async()=>{
  const s=fixture({qrGet405Compatibility:true});s.queue.push({status:405,body:'private server text'});s.respond({qrcode:QR,qrcode_img_content:'synthetic display'});
  await s.session.startQr();assert.equal(s.calls.length,2);const [post,get]=s.calls;
  assert.equal(post.method,'POST');assert.equal(get.method,'GET');assert.equal(get.origin,post.origin);assert.equal(get.path,post.path);assert.equal(get.body,undefined);
  assert.deepEqual(get.headers,{'iLink-App-Id':'bot','iLink-App-ClientVersion':'132106'});assert.equal(get.redirect,'error');assert.ok(get.timeoutMs<=15000);
  assert.equal(s.session.status().last_http_status,200);await assert.rejects(s.session.startQr());assert.equal(s.calls.length,2);
  const closed=fixture();closed.queue.push({status:405,body:'private'});await assert.rejects(closed.session.startQr(),e=>e.code==='ILINK_HTTP_REJECTED'&&e.httpStatus===405);assert.equal(closed.calls.length,1);assert.equal(closed.session.status().last_http_status,405);
});
test('QR405 compatibility never retries transport/auth/payment/other HTTP/business failures or authenticated calls',async()=>{
  for(const response of [new Error('private failure'),...([301,400,401,402,403,404,408,429,500].map(status=>({status,body:'private'}))),{status:200,body:'{"ret":405}' }]){
    const s=fixture({qrGet405Compatibility:true});s.queue.push(response);await assert.rejects(s.session.startQr());assert.equal(s.calls.length,1);
  }
  const twice=fixture({qrGet405Compatibility:true});twice.queue.push({status:405,body:''},{status:405,body:''});await assert.rejects(twice.session.startQr());assert.equal(twice.calls.length,2);
  const authenticated=fixture({qrGet405Compatibility:true});await authenticated.connect();authenticated.queue.push({status:405,body:''});await assert.rejects(authenticated.session.getUpdates());assert.equal(authenticated.calls.length,3);assert.equal(authenticated.calls.at(-1).method,'POST');
  let now=1000000,calls=0;const elapsed=new IlinkSession({qrApproved:true,qrGet405Compatibility:true,ownerConfirmationNonce:NONCE,deadline:now+1800000,now:()=>now,request:async()=>{calls++;now+=15000;return{status:405,body:''};}});await assert.rejects(elapsed.startQr());assert.equal(calls,1);
});

test('two-hour session stays usable after one hour and expires at the exact limit',async()=>{
 const s=fixture({deadline:1000000+7200000});await s.connect();s.advance(3600001);
 s.respond({ret:0,msgs:[],get_updates_buf:''});await s.session.getUpdates();
 assert.equal(s.session.isAuthenticated(),true);
 const calls=s.calls.length;s.advance(3599999);assert.equal(s.session.isAuthenticated(),false);
 await assert.rejects(s.session.getUpdates(),e=>e.code==='OWNER_CONFIRMATION_REQUIRED');assert.equal(s.calls.length,calls);
 const qr=fixture({deadline:1000000+7200000});assert.equal((await qr.start()).expiresInMs,300000);
 assert.equal(qr.calls[0].timeoutMs,15000);qr.advance(300000);
 await assert.rejects(qr.session.pollQr(),e=>e.code==='QR_EXPIRED');assert.equal(qr.calls.length,1);
});

test('ordinary upstream QR expiry permits explicit fresh login with the same deadline and human confirmation',async()=>{
 const s=fixture({deadline:1000000+7200000});await s.start();s.advance(90000);
 s.respond({status:'expired'});await assert.rejects(s.session.pollQr(),e=>e.code==='QR_EXPIRED');
 assert.equal(s.session.status().phase,'qr_expired');assert.equal(s.calls.length,2);assert.equal(s.session.isAuthenticated(),false);
 assert.throws(()=>s.session.confirmOwner({nonce:NONCE,userConfirmedScan:true}));
 await s.start();assert.equal(s.calls.length,3);assert.equal(s.calls.at(-1).origin,ILINK_ORIGIN);
 s.respond(confirmed());await s.session.pollQr();assert.equal(s.session.status().phase,'pending_owner_confirmation');
 assert.equal(s.session.isAuthenticated(),false);assert.equal(s.session.status().personal_message_access_started,false);
 assert.throws(()=>s.session.confirmOwner({nonce:NONCE,userConfirmedScan:false}));
 s.session.confirmOwner({nonce:NONCE,userConfirmedScan:true});assert.equal(s.session.isAuthenticated(),true);
 s.advance(7110000);assert.equal(s.session.isAuthenticated(),false);await assert.rejects(s.session.startQr());assert.equal(s.calls.length,4);
});
test('local QR expiry permits only explicit refresh and never extends the original run',async()=>{
 for(const pollBeforeRefresh of [true,false]){
  const s=fixture({deadline:1000000+600000});await s.start();s.advance(300000);
  if(pollBeforeRefresh){await assert.rejects(s.session.pollQr(),e=>e.code==='QR_EXPIRED');assert.equal(s.session.status().phase,'qr_expired');}
  assert.equal(s.calls.length,1);await s.start();assert.equal(s.calls.length,2);
  s.advance(300000);await assert.rejects(s.session.startQr(),e=>e.code==='SESSION_STOPPED_OR_EXPIRED');assert.equal(s.calls.length,2);
 }
});
test('QR retry never reopens authentication, verification, origin-review or operator stops',async()=>{
 for(const response of [{status:'verify_code_blocked'},{status:'binded_redirect'}]){
  const s=fixture();await s.start();s.respond(response);await assert.rejects(s.session.pollQr());
  assert.equal(s.session.status().phase,'stopped');await assert.rejects(s.session.startQr());assert.equal(s.calls.length,2);
 }
 for(const status of [401,403,402,429]){
  const s=fixture();await s.start();s.queue.push({status,body:'{}'});await assert.rejects(s.session.pollQr());
  await assert.rejects(s.session.startQr());assert.equal(s.session.status().phase,'stopped');assert.equal(s.calls.length,2);
 }
 const verify=fixture();await verify.start();verify.respond({status:'need_verifycode'});await verify.session.pollQr();
 verify.advance(300000);await assert.rejects(verify.session.startQr());await assert.rejects(verify.session.pollQr());await assert.rejects(verify.session.startQr());assert.equal(verify.calls.length,2);
 const origin=fixture();await origin.start();origin.respond({status:'scaned_but_redirect',redirect_host:'other.weixin.qq.com'});await assert.rejects(origin.session.pollQr());
 origin.advance(300000);await assert.rejects(origin.session.startQr());assert.equal(origin.calls.length,2);
 const stopped=fixture();await stopped.start();stopped.session.stop();await assert.rejects(stopped.session.startQr());assert.equal(stopped.calls.length,1);
});

test('receive diagnostics HTTP status belongs to getupdates and resets on transport failure',async()=>{
 const s=fixture();await s.connect();assert.equal(s.session.status().last_http_status,200);
 s.queue.push(new Error('private transport detail'));await assert.rejects(s.session.getUpdates(),e=>e.code==='ILINK_TRANSPORT_FAILED'&&e.httpStatus===0);
 assert.equal(s.session.updatesHttpStatus(),0);
 s.respond({ret:0,msgs:[],get_updates_buf:'private-cursor'});await s.session.getUpdates();assert.equal(s.session.updatesHttpStatus(),200);
 s.queue.push({status:503,body:'private body'});await assert.rejects(s.session.getUpdates('private-cursor'),e=>e.code==='ILINK_HTTP_REJECTED'&&e.httpStatus===503);
 s.queue.push(new Error('another private detail'));await assert.rejects(s.session.getUpdates(),e=>e.httpStatus===0);
 for(const secret of [TOKEN,OWNER,BOT,'private-cursor','private body'])assert.ok(!JSON.stringify(s.session.status()).includes(secret));
});

test('seven-hour session supports the extended run without extending QR or network timeout',async()=>{
 const s=fixture({deadline:1000000+25200000});await s.connect();s.advance(6*3600000);
 s.respond({ret:0,msgs:[],get_updates_buf:'synthetic-cursor'});await s.session.getUpdates();assert.equal(s.calls.at(-1).timeoutMs,35000);
 s.advance(3600000);await assert.rejects(s.session.getUpdates());assert.equal(s.session.isAuthenticated(),false);
 const qr=fixture({deadline:1000000+25200000});assert.equal((await qr.start()).expiresInMs,300000);
});

test('official optional update fields preserve the cursor and absent send ret is success',async()=>{
 const s=fixture();await s.connect();
 for(const response of [{},{msgs:[]},{msgs:[],get_updates_buf:''}]){s.respond(response);assert.deepEqual(await s.session.getUpdates('previous-cursor'),{msgs:[],cursor:'previous-cursor'});}
 s.respond({msgs:{}});await assert.rejects(s.session.getUpdates('previous-cursor'),e=>e.code==='INVALID_UPDATE_RESPONSE');
 s.respond({get_updates_buf:0});await assert.rejects(s.session.getUpdates('previous-cursor'),e=>e.code==='INVALID_UPDATE_RESPONSE');
 s.respond({});assert.equal((await s.session.sendText({text:'synthetic reply',contextToken:'synthetic-context',clientId:'synthetic-client'})).accepted,true);
 s.queue.push(new Error('synthetic network failure'));await assert.rejects(s.session.sendText({text:'synthetic reply',contextToken:'synthetic-context',clientId:'synthetic-client-2'}),e=>e.code==='ILINK_TRANSPORT_FAILED');
});
