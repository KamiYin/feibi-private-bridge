import test from 'node:test';import assert from 'node:assert/strict';import {createHmac} from 'node:crypto';
import net from 'node:net';import tls from 'node:tls';import http from 'node:http';import https from 'node:https';import dns from 'node:dns';import {syncBuiltinESMExports} from 'node:module';
import {IlinkSession,ILINK_ORIGIN} from './ilink.mjs';import {OwnerTextRelay} from './relay.mjs';import {WeixinMcpService,VERSION,VERSION_META,CAPS_META,EVENT} from './service.mjs';import {MemoryStore} from '../src/store.mjs';
let network=0;const deny=()=>{network++;throw new Error('NETWORK_FORBIDDEN');};net.connect=net.createConnection=net.Socket.prototype.connect=net.Server.prototype.listen=tls.connect=http.request=https.request=globalThis.fetch=dns.lookup=dns.promises.lookup=deny;syncBuiltinESMExports();
const OWNER='synthetic-owner@im.wechat',BOT='synthetic-bot@im.bot',TOKEN='synthetic-token',CONTEXT='synthetic-context-token',NONCE='bind:current_chat_abcdefgh1234',SECRET=`whsec_${Buffer.alloc(32,7).toString('base64')}`,ORIGIN='https://connectors.api.openai.com';
const message=(method,args={})=>({jsonrpc:'2.0',id:1,method,params:{...args,_meta:{[VERSION_META]:VERSION,[CAPS_META]:{}}}});
const params=()=>({name:EVENT.name,arguments:{},delivery:{mode:'webhook',url:ORIGIN+'/synthetic?opaque=secret-url',secret:SECRET},cursor:null});
function setup({durationMs=1800000}={}){
 let now=Date.parse('2026-10-27T00:00:00Z');const principal=Object.freeze({id:'current-owner-dot'}),posts=[],calls=[],responses=[];
 const session=new IlinkSession({request:async req=>{calls.push(req);return {status:200,body:JSON.stringify(responses.shift())};},qrApproved:true,ownerConfirmationNonce:NONCE,deadline:now+durationMs,now:()=>now});
 const relay=new OwnerTextRelay({session,principal,authorize:async()=>true,readApproved:true,repliesApproved:true,eventsApproved:true,now:()=>now,retentionMs:1800000});
 const store=new MemoryStore();const service=new WeixinMcpService({relay,session,principal,store,authorize:()=>true,now:()=>now,runtimeExpiresAt:now+durationMs,originReviewApproved:true,
  post:async()=>{throw new Error('disabled');},postFactory:()=>async(url,req)=>{posts.push({url,...req,data:JSON.parse(req.body)});return {status:200,json:{challenge:JSON.parse(req.body).challenge}};}});
 const connect=async()=>{responses.push({qrcode:'synthetic-qr',qrcode_img_content:'synthetic-QR-only'});await session.startQr();responses.push({status:'confirmed',bot_token:TOKEN,ilink_bot_id:BOT,ilink_user_id:OWNER,baseurl:ILINK_ORIGIN});await session.pollQr();session.confirmOwner({nonce:NONCE,userConfirmedScan:true});};
 const subscribe=async()=>{const first=await service.rpc(principal,message('events/subscribe',params()));assert.equal(first.error.data.reason,'callback_origin_pending_operator_review');await service.approveCallbackOrigin(ORIGIN);return service.rpc(principal,message('events/subscribe',params()));};
 return {service,relay,session,principal,store,posts,calls,responses,connect,subscribe,advance:ms=>{now+=ms;}};
}
const inbound=(extra={})=>({message_id:'18446744073709551615',create_time_ms:Date.parse('2026-10-27T00:00:00Z'),from_user_id:OWNER,to_user_id:BOT,message_type:1,message_state:2,item_list:[{type:1,text_item:{text:'synthetic owner request'}}],context_token:CONTEXT,...extra});
test('candidate modern discovery is authenticated; prelogin status contains no private identity or active channel',async()=>{
 const s=setup();for(const method of ['server/discover','tools/list','events/list'])assert.equal((await s.service.rpc(s.principal,message(method))).result.resultType,'complete');
 assert.equal((await s.service.rpc({},message('events/list'))).error.code,1001);
 const status=(await s.service.rpc(s.principal,message('tools/call',{name:'test_status',arguments:{}}))).result.structuredContent;assert.equal(status.personal_channel_connected,false);assert.equal(status.synthetic_only,false);assert.equal(status.memory_only,true);
 for(const secret of [OWNER,BOT,TOKEN,CONTEXT])assert.ok(!JSON.stringify(status).includes(secret));
 const tools=(await s.service.rpc(s.principal,message('tools/list'))).result.tools;assert.equal(tools.find(x=>x.name==='reply_to_owner').annotations.readOnlyHint,false);
 assert.ok((await s.service.rpc(s.principal,message('tools/call',{name:'get_owner_request',arguments:{request_id:'00000000-0000-4000-8000-000000000001'}}))).error);
});
test('mock full path QR+human confirmation -> owner text -> signed metadata event -> authenticated read -> fixed-owner reply',async()=>{
 const s=setup();await s.connect();const subscription=await s.subscribe();assert.ok(subscription.result.id);assert.equal(s.posts.length,1);
 s.responses.push({ret:0,msgs:[inbound({message_id:undefined,item_list:[{type:1,msg_id:'synthetic-item-id',text_item:{text:'synthetic owner request'},ref_msg:{title:'ignored quote'}}]})],get_updates_buf:'synthetic-cursor'});assert.equal((await s.relay.pollOnce(s.principal)).accepted,1);
 assert.deepEqual(await s.service.collectEvents(),{queued:1});await s.service.deliverDue();assert.equal(s.posts.length,2);
 const event=s.posts[1].data;assert.equal(event.name,EVENT.name);assert.equal(event.data.source,'weixin_private');
 for(const value of [TOKEN,OWNER,BOT,CONTEXT])assert.ok(!JSON.stringify(event).includes(value));
 for(const post of s.posts){const signed=createHmac('sha256',Buffer.alloc(32,7)).update(`${post.headers['webhook-id']}.${post.headers['webhook-timestamp']}.`).update(post.body).digest('base64');assert.equal(post.headers['webhook-signature'],'v1,'+signed);}
 const requestId=event.data.request_id;const read=await s.service.rpc(s.principal,message('tools/call',{name:'get_owner_request',arguments:{request_id:requestId}}));assert.equal(read.result.structuredContent.text,'synthetic owner request');assert.ok(!JSON.stringify(read).includes(CONTEXT));
 s.responses.push({message_id:'12345'});const replyArgs={request_id:requestId,text:'synthetic final reply',idempotency_key:'stable_synthetic_123'};
 const reply=await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:replyArgs}));assert.equal(reply.result.structuredContent.status,'accepted');
 const sent=JSON.parse(s.calls.at(-1).body).msg;assert.equal(sent.to_user_id,OWNER);assert.equal(sent.context_token,CONTEXT);assert.equal(sent.message_type,2);assert.equal(sent.item_list[0].text_item.text,'synthetic final reply');
 const count=s.calls.length;assert.equal((await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:replyArgs}))).result.structuredContent.duplicate,true);assert.equal(s.calls.length,count);assert.equal((await s.relay.events(s.principal)).length,0);
});
test('other sender/group/BOT/media produce no request or callback; no caller-supplied recipient/context accepted',async()=>{
 const s=setup();await s.connect();await s.subscribe();s.responses.push({ret:0,msgs:[inbound({from_user_id:'other'}),inbound({group_id:'group'}),inbound({message_type:2}),inbound({item_list:[{type:2,image_item:{media:{full_url:'https://unapproved.invalid/private'}}}]})],get_updates_buf:'ignored-cursor'});
 assert.equal((await s.relay.pollOnce(s.principal)).accepted,0);await s.service.collectEvents();await s.service.deliverDue();assert.equal(s.posts.length,1);assert.equal(s.calls.length,3);
 const r=await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:{request_id:'00000000-0000-4000-8000-000000000001',text:'test',idempotency_key:'abcdefgh',to_user_id:'other',context_token:'fake'}}));assert.ok(r.error);assert.equal(s.calls.length,3);
});
test('one callback subscription; no private pending event delivered after channel stop or runtime deadline',async()=>{
 const s=setup();await s.connect();await s.subscribe();const other=params();other.delivery={...other.delivery,url:ORIGIN+'/other'};assert.ok((await s.service.rpc(s.principal,message('events/subscribe',other))).error);
 s.responses.push({ret:0,msgs:[inbound()],get_updates_buf:'cursor'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();s.session.stop();assert.equal((await s.service.deliverDue()).attempted,0);assert.equal(s.posts.length,1);
 s.advance(1800000);assert.equal((await s.service.rpc(s.principal,message('tools/call',{name:'test_status',arguments:{}}))).error.code,1001);
});
test('Events store cannot adopt prior synthetic or populated unrelated data',()=>{
 const s=setup(),store=new MemoryStore();store.update(x=>{x.syntheticPilot=1;});assert.throws(()=>new WeixinMcpService({relay:s.relay,session:s.session,principal:s.principal,store,post:async()=>{}}));
});
test('all complete flow calls were injected mocks, no real network/listener',()=>assert.equal(network,0));

test('async authorization cannot re-arm callbacks, subscribe or deliver after stop/deadline; only true authorizes',async()=>{
 for(const action of ['approve','subscribe','deliver'])for(const transition of ['stop','expiry']){
   const s=setup();await s.connect();
   if(action==='approve')await assert.rejects(s.service.subscribe(s.principal,params()));
   else await s.subscribe();
   if(action==='deliver'){s.responses.push({ret:0,msgs:[inbound()],get_updates_buf:'cursor'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();}
   let release;const held=new Promise(r=>{release=r;});s.service.authorizeAccess=()=>held;
   const before=s.posts.length;
   const pending=action==='approve'?s.service.approveCallbackOrigin(ORIGIN):action==='subscribe'?s.service.subscribe(s.principal,params()):s.service.deliverDue();
   await Promise.resolve();if(transition==='stop')s.service.stop();else s.advance(1800000);release(true);
   if(action==='deliver')assert.equal((await pending).attempted,0);else await assert.rejects(pending);
   assert.equal(s.posts.length,before);assert.equal(s.service.status().callbacks_enabled,false);
 }
 const denied=setup();denied.service.authorizeAccess=()=>({truthy:true});assert.equal((await denied.service.rpc(denied.principal,message('events/list'))).error.code,1001);
});

test('two-hour subscription respects requested TTL and the original runtime deadline on renewal',async()=>{
 const base=Date.parse('2026-10-27T00:00:00Z');
 for(const [ttlMs,expected] of [[undefined,7200000],[1800000,1800000],[5400000,5400000],[10800000,7200000]]){
  const s=setup({durationMs:7200000});await s.connect();const initial=await s.subscribe();
  const p=params();if(ttlMs!==undefined)p.ttlMs=ttlMs;
  const result=await s.service.subscribe(s.principal,p);
  assert.equal(result.id,initial.result.id);assert.equal(Date.parse(result.refreshBefore),base+expected);
  assert.equal(Object.keys(s.store.state.subscriptions).length,1);
  s.advance(expected);assert.equal(s.service.status().active_subscriptions,0);
 }
 const s=setup({durationMs:7200000});await s.connect();const first=await s.subscribe();s.advance(3600001);
 assert.equal(s.session.isAuthenticated(),true);assert.equal(s.service.status().active_subscriptions,1);
 const renewed=await s.service.subscribe(s.principal,{...params(),ttlMs:7200000});
 assert.equal(renewed.id,first.result.id);assert.equal(Date.parse(renewed.refreshBefore),base+7200000);
 assert.equal(Object.keys(s.store.state.subscriptions).length,1);
 s.advance(3599999);assert.equal(s.service.status().active_subscriptions,0);
 await assert.rejects(s.service.subscribe(s.principal,params()));
});

test('explicit QR retry preserves the approved callback subscription and original runtime deadline',async()=>{
 const s=setup({durationMs:7200000});const subscription=await s.subscribe();
 const original=structuredClone(s.store.state.subscriptions);const originalDeadline=s.service.runtimeExpiresAt;
 s.responses.push({qrcode:'synthetic-qr',qrcode_img_content:'synthetic-display'});await s.session.startQr();
 s.responses.push({status:'expired'});await assert.rejects(s.session.pollQr(),e=>e.code==='QR_EXPIRED');
 assert.equal(s.session.status().phase,'qr_expired');assert.equal(s.service.status().callbacks_enabled,true);assert.equal(s.service.status().active_subscriptions,1);
 s.advance(60000);await s.connect();
 assert.equal(s.session.isAuthenticated(),true);assert.deepEqual(s.store.state.subscriptions,original);
 assert.equal(s.service.runtimeExpiresAt,originalDeadline);assert.equal(Object.keys(original)[0],subscription.result.id);assert.equal(s.posts.length,1);
 s.advance(7140000);assert.equal(s.session.isAuthenticated(),false);await assert.rejects(s.session.startQr());await assert.rejects(s.service.subscribe(s.principal,params()));
});

test('receive diagnostics reach cloud test_status independently of event delivery counts',async()=>{
 const s=setup();assert.equal(s.service.status().poll_diagnostic.phase,'idle');await s.connect();await s.subscribe();
 s.responses.push({ret:0,msgs:[],get_updates_buf:'private-cursor'});await s.relay.pollOnce(s.principal);
 let state=(await s.service.rpc(s.principal,message('tools/call',{name:'test_status',arguments:{}}))).result.structuredContent;
 assert.equal(state.poll_diagnostic.phase,'empty');assert.equal(state.poll_diagnostic.last_http_status,200);assert.equal(state.accepted_events,0);
 s.responses.push({ret:0,msgs:[inbound({from_user_id:'other-private-owner'})],get_updates_buf:'next-private-cursor'});await s.relay.pollOnce(s.principal);
 state=s.service.status();assert.equal(state.poll_diagnostic.phase,'filtered');assert.equal(state.poll_diagnostic.rejected_identity,1);assert.equal(state.queued_events,0);
 s.session.getUpdates=async()=>{throw Object.assign(new Error('private detail'),{code:'ILINK_TRANSPORT_FAILED'});};
 await assert.rejects(s.relay.pollOnce(s.principal));state=s.service.status();assert.equal(state.poll_diagnostic.phase,'failed');assert.equal(state.poll_diagnostic.reason,'ILINK_TRANSPORT_FAILED');
 for(const secret of [OWNER,BOT,TOKEN,CONTEXT,'other-private-owner','private-cursor','private detail'])assert.ok(!JSON.stringify(state).includes(secret));
});

test('twelve-hour subscription TTL remains clamped to requested TTL and original runtime deadline',async()=>{
 for(const [ttlMs,expected] of [[undefined,43200000],[1800000,1800000],[46800000,43200000]]){
  const s=setup({durationMs:43200000});await s.connect();const initial=await s.subscribe();
  const base=Date.parse(initial.result.refreshBefore)-43200000;
  const args={...params(),...(ttlMs===undefined?{}:{ttlMs})};
  const renewed=await s.service.subscribe(s.principal,args);
  assert.equal(Date.parse(renewed.refreshBefore),base+expected);
 }
 const s=setup({durationMs:19800000});await s.connect();const sub=await s.subscribe();s.advance(6*3600000);
 assert.equal(s.service.status().active_subscriptions,0);assert.ok(Number.isFinite(Date.parse(sub.result.refreshBefore)));
});

test('transient callbacks retry past five with backoff, stable event ID and deadline stop',async()=>{
 const s=setup();await s.connect();await s.subscribe();s.responses.push({msgs:[inbound()],get_updates_buf:'cursor'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();
 let attempts=0;const ids=[];s.service.post=async(_url,req)=>{attempts++;ids.push(req.headers['webhook-id']);return {status:attempts<=6?503:200};};
 for(let i=0;i<6;i++){assert.equal((await s.service.deliverDue()).attempted,1);assert.equal(s.service.status().queued_events,1);assert.equal((await s.service.deliverDue()).attempted,0);s.advance(61000);}
 assert.equal((await s.service.deliverDue()).attempted,1);assert.equal(attempts,7);assert.equal(new Set(ids).size,1);assert.equal(s.service.status().accepted_events,1);assert.equal((await s.relay.events(s.principal)).length,0);
 const e=setup();await e.connect();await e.subscribe();e.responses.push({msgs:[inbound()],get_updates_buf:'cursor'});await e.relay.pollOnce(e.principal);await e.service.collectEvents();let sent=0;e.service.post=async()=>{sent++;return {status:503};};await e.service.deliverDue();e.advance(1800000);assert.equal((await e.service.deliverDue()).attempted,0);assert.equal(sent,1);
});

test('pending inbox MCP discovery and direct reply preserve late-event deduplication',async()=>{
 const s=setup();const tools=(await s.service.rpc(s.principal,message('tools/list'))).result.tools;
 const tool=tools.find(x=>x.name==='list_pending_owner_requests');assert.ok(tool);
 assert.deepEqual(tool.inputSchema,{type:'object',properties:{},required:[],additionalProperties:false});
 assert.equal(tool.annotations.readOnlyHint,true);assert.equal(tool.annotations.destructiveHint,false);
 const list=()=>s.service.rpc(s.principal,message('tools/call',{name:tool.name,arguments:{}}));
 assert.ok((await list()).error);await s.connect();await s.subscribe();
 s.responses.push({msgs:[inbound()],get_updates_buf:'pending-cursor'});await s.relay.pollOnce(s.principal);
 const listed=(await list()).result.structuredContent;assert.equal(listed.requests.length,1);
 const item=listed.requests[0];assert.deepEqual(Object.keys(item).sort(),['received_at','reply_status','request_id','text','text_complete']);assert.equal(item.reply_status,'not_sent');
 const read=(await s.service.rpc(s.principal,message('tools/call',{name:'get_owner_request',arguments:{request_id:item.request_id}}))).result.structuredContent;assert.equal(read.reply_status,'not_sent');
 s.responses.push({});const args={request_id:item.request_id,text:'synthetic inbox reply',idempotency_key:'synthetic_inbox_reply'};
 assert.equal((await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:args}))).result.structuredContent.status,'accepted');
 assert.deepEqual((await list()).result.structuredContent,{requests:[]});
 assert.deepEqual(await s.service.collectEvents(),{queued:0});await s.service.deliverDue();
 assert.equal(s.posts.length,1);
 const late=(await s.service.rpc(s.principal,message('tools/call',{name:'get_owner_request',arguments:{request_id:item.request_id}}))).result.structuredContent;assert.equal(late.reply_status,'accepted');
 const calls=s.calls.length;assert.equal((await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:args}))).result.structuredContent.duplicate,true);assert.equal(s.calls.length,calls);
 assert.ok((await s.service.rpc(s.principal,message('tools/call',{name:tool.name,arguments:{recipient:'other'}}))).error);
 for(const value of [OWNER,BOT,TOKEN,CONTEXT,'pending-cursor'])assert.ok(!JSON.stringify(listed).includes(value));
});

test('inline event stable retry, no stored body copy, direct reply and late duplicate',async()=>{
 const s=setup();await s.connect();await s.subscribe();s.responses.push({msgs:[inbound()],get_updates_buf:'c'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();
 const attempts=[];s.service.post=async(_url,req)=>{attempts.push(JSON.parse(req.body));return {status:attempts.length===1?503:200};};
 await s.service.deliverDue();s.advance(1001);await s.service.deliverDue();
 assert.deepEqual(attempts[0],attempts[1]);assert.equal(attempts[0].data.text,'synthetic owner request');assert.equal(attempts[0].data.text_complete,true);
 assert.ok(!JSON.stringify(s.store.state).includes('synthetic owner request'));
 const args={request_id:attempts[0].data.request_id,text:'direct reply',idempotency_key:'direct_inline_1'};
 s.responses.push({});assert.equal((await s.relay.reply(s.principal,args)).status,'accepted');const n=s.calls.length;
 assert.equal((await s.relay.reply(s.principal,args)).duplicate,true);assert.equal(s.calls.length,n);
});
test('inline event over budget falls back and expired request is never delivered',async()=>{
 for(const expires of [false,true]){
  const s=setup({durationMs:7200000});await s.connect();await s.subscribe();const text='文'.repeat(2000);s.responses.push({msgs:[inbound({item_list:[{type:1,text_item:{text}}]})],get_updates_buf:'c'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();
  const id=Object.values(s.store.state.deliveries)[0].event.data.request_id;
  if(expires)s.advance(1800000);const n=s.posts.length;await s.service.deliverDue();
  if(expires){assert.equal(s.posts.length,n);assert.ok(!JSON.stringify(s.relay.store.snapshot()).includes(text));}
  else{assert.equal(s.posts.at(-1).data.data.text_complete,false);assert.equal(s.posts.at(-1).data.data.text,'');assert.equal((await s.relay.get(s.principal,{request_id:id})).text,text);}
  assert.ok(!JSON.stringify(s.store.state).includes(text));
 }
});
// Injected clock drives the real collect/deliver/reply paths; no wall-clock sleeps.
const pendingQuery=s=>s.service.rpc(s.principal,message('tools/call',{name:'list_pending_owner_requests',arguments:{}}));
async function queueOwner(s){s.responses.push({ret:0,msgs:[inbound()],get_updates_buf:'cursor'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();return Object.values(s.store.state.deliveries)[0];}
test('active direct query + accepted reply cancels only the undelivered notification',async()=>{
 const s=setup();await s.connect();await s.subscribe();await pendingQuery(s);const d=await queueOwner(s);
 const read=await pendingQuery(s);assert.equal(read.result.structuredContent.requests[0].text_complete,true);
 s.advance(17000);s.responses.push({message_id:'12345'});
 const r=await s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:{request_id:d.event.data.request_id,text:'answer',idempotency_key:'active_reply_123'}}));assert.equal(r.result.structuredContent.status,'accepted');
 await s.service.deliverDue();assert.equal(s.store.state.deliveries[d.event.eventId].status,'inactive');s.advance(30000);assert.equal((await s.service.deliverDue()).attempted,0);assert.equal(s.posts.length,1);
});
test('pending queries never add a notification delay',async t=>{
 for(const mode of ['read_no_reply','lost_response','continuous_queries'])await t.test(mode,async()=>{
  const s=setup();await s.connect();await s.subscribe();await pendingQuery(s);await queueOwner(s);
  if(mode!=='lost_response')await pendingQuery(s);
  if(mode==='continuous_queries')for(let i=0;i<3;i++)await pendingQuery(s);
  assert.equal((await s.service.deliverDue()).attempted,1);assert.equal(s.posts.length,2);assert.equal(s.posts[1].data.data.text_complete,true);
 });
});
test('cold, stale and unauthorized queries do not delay events',async t=>{
 for(const mode of ['cold','stale','unauthorized'])await t.test(mode,async()=>{
  const s=setup();await s.connect();await s.subscribe();
  if(mode==='stale'){await pendingQuery(s);s.advance(15001);}
  if(mode==='unauthorized')assert.ok((await s.service.rpc({},message('tools/call',{name:'list_pending_owner_requests',arguments:{}}))).error);
  await queueOwner(s);assert.equal((await s.service.deliverDue()).attempted,1);assert.equal(s.posts.length,2);
 });
});
test('accepted late event retains its real id and duplicate reply never sends again',async()=>{
 const s=setup();await s.connect();await s.subscribe();const d=await queueOwner(s);await s.service.deliverDue();const eventId=s.posts[1].data.eventId;
 await pendingQuery(s);s.responses.push({message_id:'12345'});const args={request_id:d.event.data.request_id,text:'answer',idempotency_key:'late_event_123'};
 const call=()=>s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:args}));assert.equal((await call()).result.structuredContent.status,'accepted');const count=s.calls.length;
 assert.equal((await call()).result.structuredContent.duplicate,true);assert.equal(s.calls.length,count);assert.equal(s.store.state.deliveries[d.event.eventId].status,'accepted');assert.equal(d.event.eventId,eventId);
});
test('unknown send keeps bounded event fallback and cannot retransmit',async()=>{
 const s=setup();await s.connect();await s.subscribe();await pendingQuery(s);const d=await queueOwner(s);let sends=0;s.session.sendText=async()=>{sends++;throw new Error('unknown');};
 const args={request_id:d.event.data.request_id,text:'answer',idempotency_key:'unknown_event_123'};const call=()=>s.service.rpc(s.principal,message('tools/call',{name:'reply_to_owner',arguments:args}));
 assert.equal((await call()).result.structuredContent.status,'unknown');s.advance(30000);assert.equal((await s.service.deliverDue()).attempted,1);assert.equal((await call()).result.structuredContent.status,'unknown');assert.equal(sends,1);
});
test('deferred notification still expires with its original request',async()=>{
 const s=setup();await s.connect();await s.subscribe();s.relay.retentionMs=1000;await pendingQuery(s);const d=await queueOwner(s);s.advance(1000);assert.equal((await s.service.deliverDue()).attempted,0);assert.equal(s.store.state.deliveries[d.event.eventId].status,'inactive');assert.equal(s.posts.length,1);
});

test('quoted text stays separate and consistent in event, pending and get',async()=>{
 const s=setup();await s.connect();await s.subscribe();
 s.responses.push({msgs:[inbound({item_list:[{type:1,text_item:{text:'new instruction'},ref_msg:{svr_id:'18446744073709551615',title:'quoted title',partial_text:true,message_item:{type:1,text_item:{text:'old context'}}}}]})],get_updates_buf:'q'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();await s.service.deliverDue();
 const ev=s.posts[1].data.data;const read=await s.relay.get(s.principal,{request_id:ev.request_id});const pending=await pendingQuery(s);
 assert.equal(read.text,'new instruction');assert.equal(read.quoted[0].text,'old context');assert.equal(read.quoted[0].server_id,'18446744073709551615');assert.equal(read.quoted[0].partial,true);
 assert.deepEqual(ev.quoted,read.quoted);assert.deepEqual(pending.result.structuredContent.requests[0].quoted,read.quoted);
 s.advance(1800000);s.relay.expire();assert.ok(Object.values(s.relay.store.snapshot().requests).every(r=>!r.quoted));
});
test('ID-only quote uses current unexpired cache; never rounds IDs or downloads attachments',async()=>{
 const s=setup({durationMs:7200000});await s.connect();
 const ingest=async(msg)=>{s.responses.push({msgs:[msg],get_updates_buf:'q'});await s.relay.pollOnce(s.principal);return (await s.relay.listPending(s.principal)).requests.at(-1);};
 await ingest(inbound({message_id:'18446744073709551615'}));
 const make=(id,ref)=>inbound({message_id:id,item_list:[{type:1,text_item:{text:'new'},ref_msg:ref}]});
 let r=await ingest(make('2',{svr_id:'18446744073709551615'}));assert.equal(r.quoted[0].status,'cached');assert.equal(r.quoted[0].text,'synthetic owner request');
 r=await ingest(make('3',{svr_id:18446744073709551615,message_item:{type:2,image_item:{url:'https://never.invalid'}}}));assert.equal(r.quoted[0].status,'not_cached');assert.equal(r.quoted[0].server_id,'18446744073709552000');assert.equal(r.quoted[0].text,undefined);
 s.advance(1800001);r=await ingest(make('4',{svr_id:'18446744073709551615'}));assert.equal(r.quoted[0].status,'not_cached');
});
test('oversize quote uses get fallback without truncating the new text or quote',async()=>{
 const s=setup();await s.connect();await s.subscribe();const original='长'.repeat(2000);
 s.responses.push({msgs:[inbound({item_list:[{type:1,text_item:{text:'new'},ref_msg:{message_item:{type:1,text_item:{text:original}}}}]})],get_updates_buf:'q'});await s.relay.pollOnce(s.principal);await s.service.collectEvents();await s.service.deliverDue();const ev=s.posts[1].data.data;
 assert.equal(ev.text_complete,false);assert.equal(ev.quoted,undefined);const p=(await pendingQuery(s)).result.structuredContent.requests[0];assert.equal(p.text_complete,false);assert.equal((await s.relay.get(s.principal,{request_id:ev.request_id})).quoted[0].text,original);
});

test('restored original subscription delivers pending requests without creating a subscription',async()=>{
 const s=setup();await s.connect();await s.subscribe();const pending=await queueOwner(s);const original=structuredClone(s.store.state);const store=new MemoryStore(original),posts=[];
 const restored=new WeixinMcpService({relay:s.relay,session:s.session,principal:s.principal,store,authorize:()=>true,originReviewApproved:true,now:s.service.now,runtimeExpiresAt:s.service.runtimeExpiresAt,post:async()=>{},postFactory:()=>async(_url,req)=>{posts.push(JSON.parse(req.body));return {status:200};}});
 restored.pendingOrigin=ORIGIN;await restored.approveCallbackOrigin(ORIGIN);await restored.deliverDue();assert.equal(posts.length,1);assert.equal(posts[0].data.request_id,pending.event.data.request_id);assert.deepEqual(Object.keys(store.state.subscriptions),Object.keys(original.subscriptions));
});
