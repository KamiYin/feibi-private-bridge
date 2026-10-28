import test from 'node:test';import assert from 'node:assert/strict';import {EventEmitter} from 'node:events';
import net from 'node:net';import tls from 'node:tls';import dns from 'node:dns';import https from 'node:https';import {syncBuiltinESMExports} from 'node:module';
import {createWeixinRuntime,inspectWeixinRuntime} from './runtime.mjs';
import {createWeixinServer} from './http.mjs';
import {VERSION,VERSION_META,CAPS_META} from './service.mjs';
let attempts=0;const forbidden=()=>{attempts++;throw new Error('NO_REAL_NETWORK');};
net.connect=net.createConnection=net.Socket.prototype.connect=net.Server.prototype.listen=tls.connect=https.request=globalThis.fetch=dns.lookup=dns.promises.lookup=forbidden;syncBuiltinESMExports();
const MCP=Buffer.alloc(32,1).toString('base64'),OP=Buffer.alloc(32,2).toString('base64'),NONCE='bind:current_chat_synthetic_123';
const env=extra=>({WEIXIN_PRIVATE_PILOT_APPROVED:'yes',WEIXIN_QR_APPROVED:'yes',WEIXIN_OWNER_TEXT_TRANSFER_APPROVED:'yes',WEIXIN_OWNER_TEXT_REPLY_APPROVED:'yes',WEIXIN_TUNNEL_ISOLATION:'single-user',WEIXIN_PORT:'8767',WEIXIN_DEADLINE_UNIX_MS:String(Date.now()+30000),WEIXIN_OWNER_NONCE:NONCE,SYNTHETIC_MCP_SECRET:MCP,SYNTHETIC_OPERATOR_SECRET:OP,HTTPS_PROXY:'http://existing.proxy.test:8080',...extra});
class FakeServer extends EventEmitter{listening=false;closed=false;listen(_port,host,cb){assert.equal(host,'127.0.0.1');this.listening=true;queueMicrotask(cb);}address(){return{port:8767};}closeAllConnections(){}close(cb){this.listening=false;this.closed=true;queueMicrotask(cb);}}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
test('runtime preflight requires all exact consent gates, nonce, deadline, proxy and distinct keys',()=>{
  assert.equal(inspectWeixinRuntime({}).canStart,false);assert.equal(inspectWeixinRuntime(env()).canStart,true);
  for(const extra of [{WEIXIN_QR_APPROVED:'no'},{WEIXIN_OWNER_TEXT_TRANSFER_APPROVED:'no'},{WEIXIN_OWNER_TEXT_REPLY_APPROVED:'no'},{WEIXIN_TUNNEL_ISOLATION:'shared'},{WEIXIN_OWNER_NONCE:'bad'},{SYNTHETIC_OPERATOR_SECRET:MCP},{HTTPS_PROXY:''},{NODE_OPTIONS:'--inspect'},{NODE_TLS_REJECT_UNAUTHORIZED:'0'},{WEIXIN_DEADLINE_UNIX_MS:'0'}])assert.equal(inspectWeixinRuntime(env(extra)).canStart,false);
  assert.ok(!JSON.stringify(inspectWeixinRuntime(env())).includes(MCP));
});
test('construct/start never requests QR or reads messages; all state is memory only and clean stop closes fake server',async()=>{
  let options,calls=0;const server=new FakeServer(),runtime=createWeixinRuntime({env:env(),request:async()=>{calls++;throw new Error('not reached');},serverFactory:o=>{options=o;return server;}});
  assert.equal(calls,0);const started=await runtime.start();assert.equal(started.qr_started,false);assert.equal(options.session.status().phase,'idle');await sleep(300);assert.equal(calls,0);await runtime.stop();assert.equal(server.closed,true);assert.equal(options.session.status().phase,'stopped');await runtime.stop();await assert.rejects(runtime.start());
});
test('runtime owns deadline even without supervisor: closes server and stops session',async()=>{
  let options;const server=new FakeServer(),runtime=createWeixinRuntime({env:env({WEIXIN_DEADLINE_UNIX_MS:String(Date.now()+80)}),request:async()=>{throw new Error('must not call');},serverFactory:o=>{options=o;return server;}});
  await runtime.start();await sleep(140);assert.equal(server.closed,true);assert.equal(options.session.status().phase,'stopped');await runtime.stop();
});
function request(server,path,body,auth='operator',extra={}){
  const bytes=Buffer.from(JSON.stringify(body));
  const h={'host':'127.0.0.1:8767','content-type':'application/json',...(auth==='operator'?{'x-synthetic-operator-auth':OP}:auth==='mcp'?{'x-synthetic-mcp-auth':MCP}:{}),...extra};
  const req={socket:{remoteAddress:'127.0.0.1'},url:path,method:'POST',headers:h,rawHeaders:Object.entries(h).flat(),async*[Symbol.asyncIterator](){yield bytes;}};
  return new Promise(resolve=>{const res={headersSent:false,setHeader(){},writeHead(status){this.status=status;this.headersSent=true;},end(raw){resolve({status:this.status,body:raw?JSON.parse(raw):null});}};server.emit('request',req,res);});
}
test('operator QR payload never exposed through MCP auth/status; unknown fields/routes fail closed',async()=>{
  let startCount=0,pollCount=0,confirmed=0;
  const session={startQr:async()=>{startCount++;return{qrPayload:'synthetic secret QR',expiresInMs:300000};},pollQr:async()=>{pollCount++;return{phase:'wait'};},confirmOwner:x=>{confirmed++;return{x};},status:()=>({phase:'idle'})};
  const pilot={authorize:async()=>{},status:()=>({safe:true}),approveCallbackOrigin:async origin=>({approved:true,origin}),rpc:async()=>({jsonrpc:'2.0',id:1,result:{safe:true}})};
  const server=createWeixinServer({pilot,session,principal:{},mcpSecret:MCP,operatorSecret:OP});
  assert.equal((await request(server,'/local/qr-start',{},'mcp')).status,401);assert.equal(startCount,0);
  assert.equal((await request(server,'/local/qr-start',{private:'no'},'operator')).status,400);assert.equal(startCount,0);
  const qr=await request(server,'/local/qr-start',{});assert.equal(qr.body.qrPayload,'synthetic secret QR');assert.equal(startCount,1);
  assert.ok(!JSON.stringify((await request(server,'/local/status',{})).body).includes('secret QR'));
  assert.equal((await request(server,'/local/qr-start',{},'operator',{origin:'https://evil.test'})).status,403);
  assert.equal((await request(server,'/local/qr-poll',{verify_code:'1234'})).status,200);assert.equal(pollCount,1);
  assert.equal((await request(server,'/local/confirm-owner',{nonce:NONCE,user_confirmed_scan:true})).status,200);assert.equal(confirmed,1);
  assert.equal((await request(server,'/local/inject-test',{})).status,404);
});
test('modern MCP header/version matching stays enforced on candidate endpoint',async()=>{
  let calls=0;const pilot={rpc:async()=>{calls++;return{jsonrpc:'2.0',id:1,result:{safe:true}};}};
  const server=createWeixinServer({pilot,session:{},principal:{},mcpSecret:MCP,operatorSecret:OP});
  const body={jsonrpc:'2.0',id:1,method:'tools/call',params:{name:'test_status',arguments:{},_meta:{[VERSION_META]:VERSION,[CAPS_META]:{}}}};
  const headers={accept:'application/json, text/event-stream','mcp-protocol-version':VERSION,'mcp-method':'tools/call','mcp-name':'test_status'};
  assert.equal((await request(server,'/mcp',body,'mcp',headers)).status,200);assert.equal(calls,1);
  assert.equal((await request(server,'/mcp',body,'mcp',{...headers,'mcp-name':'reply_to_owner'})).status,400);assert.equal(calls,1);
  assert.equal((await request(server,'/mcp',body,'operator',headers)).status,401);
});
test('runtime and HTTP tests made no real network/listener/DNS calls',()=>assert.equal(attempts,0));

test('operator validation failures retain fixed safe categories, never arbitrary error messages or body',async()=>{
 const pilot={authorize:async()=>{}};
 for(const code of ['INVALID_ILINK_JSON','INVALID_ILINK_RESPONSE','INVALID_QR_RESPONSE','ILINK_BUSINESS_REJECTED','ILINK_RESPONSE_BOUND','UNRECOGNIZED_PRIVATE_VALUE']){
   const session={startQr:async()=>{throw Object.assign(new Error('private raw body must not appear'),{code});}};
   const server=createWeixinServer({pilot,session,principal:{},mcpSecret:MCP,operatorSecret:OP});
   const reply=await request(server,'/local/qr-start',{});assert.equal(reply.status,400);
   assert.equal(reply.body.reason,code==='UNRECOGNIZED_PRIVATE_VALUE'?'LOCAL_OPERATION_REJECTED':code);assert.ok(!JSON.stringify(reply).includes('private raw'));
 }
 assert.equal(attempts,0);
});

test('seven-hour runtime boundary accepts 25200000 ms and rejects a longer or expired run',async t=>{
 const now=Date.parse('2030-01-01T00:00:00Z');t.mock.method(Date,'now',()=>now);
 const approved=env({WEIXIN_DEADLINE_UNIX_MS:String(now+25200000)});
 assert.equal(inspectWeixinRuntime(approved).canStart,true);
 for(const deadline of [now,now+25200001])assert.ok(inspectWeixinRuntime(env({WEIXIN_DEADLINE_UNIX_MS:String(deadline)})).issues.includes('BOUNDED_DEADLINE_REQUIRED'));
 let options,calls=0;const server=new FakeServer(),runtime=createWeixinRuntime({env:approved,request:async()=>{calls++;throw new Error('must not call');},serverFactory:o=>{options=o;return server;}});
 await runtime.start();assert.equal(options.session.status().phase,'idle');assert.equal(calls,0);
 await runtime.stop();assert.equal(server.closed,true);
});

test('one owner poller and callback retries progress independently in both directions',async t=>{
 let now=Date.now(),cycle,options,releasePoll,releasePost,polls=0,deliveries=0;
 t.mock.method(Date,'now',()=>now);t.mock.method(globalThis,'setInterval',fn=>{cycle=fn;return {unref(){}};});t.mock.method(globalThis,'clearInterval',()=>{});
 const settle=()=>new Promise(resolve=>setImmediate(resolve));const server=new FakeServer();
 const runtime=createWeixinRuntime({env:env(),serverFactory:o=>{options=o;return server;},request:async req=>{
  let data;if(req.path.startsWith('/ilink/bot/get_bot_qrcode'))data={qrcode:'synthetic-qr',qrcode_img_content:'synthetic-qr-display'};
  else if(req.path.startsWith('/ilink/bot/get_qrcode_status'))data={status:'confirmed',bot_token:'synthetic-token',ilink_bot_id:'synthetic-bot',ilink_user_id:'synthetic-owner',baseurl:'https://ilinkai.weixin.qq.com'};
  else {polls++;if(polls===2)return new Promise(resolve=>{releasePoll=()=>resolve({status:200,body:JSON.stringify({msgs:[],get_updates_buf:'second'})});});data={msgs:[{message_id:'1',from_user_id:'synthetic-owner',to_user_id:'synthetic-bot',message_type:1,message_state:2,create_time_ms:now,item_list:[{type:1,text_item:{text:'synthetic text'}}],context_token:'synthetic-context'}],get_updates_buf:'first'};}
  return {status:200,body:JSON.stringify(data)};
 },post:async(_url,req)=>{const body=JSON.parse(req.body);if(body.type==='verification')return {status:200,json:{challenge:body.challenge}};deliveries++;if(deliveries===1)return new Promise(resolve=>{releasePost=()=>resolve({status:503});});return {status:200};}});
 try{
  await runtime.start();await options.session.startQr();await options.session.pollQr();options.session.confirmOwner({nonce:NONCE,userConfirmedScan:true});
  cycle();await settle();assert.equal(polls,1);assert.equal(options.pilot.relay.pollStatus().accepted,1);
  const origin='https://connectors.api.openai.com',p={name:'weixin.message.received',arguments:{},delivery:{mode:'webhook',url:origin+'/synthetic',secret:'whsec_'+Buffer.alloc(32,7).toString('base64')}};
  await assert.rejects(options.pilot.subscribe(options.principal,p));await options.pilot.approveCallbackOrigin(origin);await options.pilot.subscribe(options.principal,p);
  cycle();await settle();assert.equal(deliveries,1);assert.equal(typeof releasePost,'function');
  now+=1100;cycle();await settle();assert.equal(polls,2,'blocked callback does not block next receive');assert.equal(typeof releasePoll,'function');
  releasePost();await settle();now+=1100;cycle();await settle();assert.equal(deliveries,2,'blocked receive does not block callback retry');assert.equal(options.pilot.status().accepted_events,1);
  cycle();await settle();assert.equal(polls,2,'only one receive outstanding');releasePoll();await settle();
 }finally{releasePost?.();releasePoll?.();await runtime.stop();}
});

test('successful receives have no fixed pause while failed receives keep backoff',async t=>{
 let now=Date.now(),cycle,options,calls=0;
 t.mock.method(Date,'now',()=>now);t.mock.method(globalThis,'setInterval',fn=>{cycle=fn;return {unref(){}};});t.mock.method(globalThis,'clearInterval',()=>{});
 const server=new FakeServer(),settle=()=>new Promise(resolve=>setImmediate(resolve));
 const runtime=createWeixinRuntime({env:env(),request:async()=>{throw new Error('no real request');},serverFactory:o=>{options=o;return server;}});
 await runtime.start();options.session.isAuthenticated=()=>true;
 const confirmedAt=now;options.session.bindingForRelay=()=>({ownerUserId:'synthetic-owner',botId:'synthetic-bot',apiOrigin:'https://ilinkai.weixin.qq.com',confirmedAt});
 options.session.getUpdates=async cursor=>{calls++;if(calls===3)throw new Error('synthetic transient failure');return {msgs:[],cursor};};
 try{cycle();await settle();cycle();await settle();assert.equal(calls,2,'next successful poll needs no clock advance');cycle();await settle();assert.equal(calls,3);cycle();await settle();assert.equal(calls,3,'failure still backs off');now+=2000;cycle();await settle();assert.equal(calls,4);}
 finally{await runtime.stop();}
});
