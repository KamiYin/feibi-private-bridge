import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import { OwnerTextRelay, RelayMemoryStore, RelayError, EVENT, TOOLS } from './relay.mjs';

let forbiddenCalls = 0;
const forbidden = () => { forbiddenCalls++; throw new Error('network_forbidden_in_offline_test'); };
// No sockets, DNS, listeners, fetch or real iLink client are used in this suite.
for (const [target, names] of [[net, ['connect','createConnection']], [net.Socket.prototype,['connect']],
  [net.Server.prototype,['listen']], [tls,['connect']], [dns,['lookup']], [dns.promises,['lookup']]]) {
  for (const name of names) target[name] = forbidden;
}
globalThis.fetch = forbidden; syncBuiltinESMExports();
const OWNER = 'synthetic-owner@im.wechat', BOT = 'synthetic-bot', ORIGIN = 'https://ilinkai.weixin.qq.com';
const CONTEXT = 'synthetic-context-never-export', BODY = 'synthetic owner text';
const msg = (id = '18446744073709551615', overrides = {}) => ({ message_id: id, from_user_id: OWNER,
  to_user_id: BOT, message_type: 1, message_state: 2, create_time_ms: 100000, context_token: CONTEXT,
  item_list: [{ type: 1, text_item: { text: BODY } }], ...overrides });
function setup(options = {}) {
  const principal = options.principal ?? Object.freeze({ id: 'synthetic-principal' });
  const store = options.store ?? new RelayMemoryStore(), calls = [], batches = [];
  let binding = { ownerUserId: OWNER, botId: BOT, apiOrigin: ORIGIN, confirmedAt: 100000 }, authenticated = true, now = 100000;
  const session = { isAuthenticated: () => authenticated, bindingForRelay: () => ({ ...binding }),
    getUpdates: async cursor => { calls.push({ poll: cursor }); return batches.shift() ?? { msgs: [], cursor }; },
    sendText: async args => { calls.push({ send: args }); return { accepted: true, messageId: '123' }; } };
  const relay = new OwnerTextRelay({ session, principal, store, authorize: () => true,
    readApproved: true, repliesApproved: true, eventsApproved: true, now: () => now, ...options });
  return { principal, store, relay, session, calls, batches,
    binding: value => { binding = value; }, authenticated: value => { authenticated = value; },
    advance: value => { now += value; } };
}
async function ingest(s, messages = [msg()], cursor = 'synthetic-cursor') {
  s.batches.push({ msgs: messages, cursor }); await s.relay.pollOnce(s.principal);
  return (await s.relay.events(s.principal))[0]?.request_id;
}
const reply = (requestId, extra = {}) => ({ request_id: requestId, text: 'synthetic reply', idempotency_key: 'synthetic_intent_1', ...extra });
const code = expected => error => error instanceof RelayError && error.code === expected;

test('all gates and principal identity fail closed by default', async () => {
  const s = setup(), relay = new OwnerTextRelay({ session: s.session, principal: s.principal });
  await assert.rejects(relay.pollOnce(s.principal), code('not_authorized'));
  await assert.rejects(s.relay.status({ ...s.principal }), code('not_authorized'));
  for (const options of [{ readApproved: false }, { eventsApproved: false }]) {
    const closed = setup(options); await assert.rejects(closed.relay.pollOnce(closed.principal)); assert.equal(closed.calls.length, 0);
  }
  s.authenticated(false); await assert.rejects(s.relay.status(s.principal), code('not_authenticated'));
  assert.equal(s.calls.length, 0);
});
test('owner required from confirmed session; account and origin binding cannot change', async () => {
  const s = setup(); s.binding({ ownerUserId: '', botId: BOT, apiOrigin: ORIGIN, confirmedAt: 100000 });
  await assert.rejects(s.relay.pollOnce(s.principal), code('not_authenticated'));
  s.binding({ ownerUserId: OWNER, botId: BOT, apiOrigin: ORIGIN, confirmedAt: 100000 }); await s.relay.status(s.principal);
  for (const binding of [{ ownerUserId: 'another-owner', botId: BOT, apiOrigin: ORIGIN, confirmedAt: 100000 },
    { ownerUserId: OWNER, botId: 'another-bot', apiOrigin: ORIGIN, confirmedAt: 100000 }, { ownerUserId: OWNER, botId: BOT, apiOrigin: 'https://different.example', confirmedAt: 100000 }]) {
    s.binding(binding); await assert.rejects(s.relay.pollOnce(s.principal), code('binding_changed'));
  }
  assert.equal(s.calls.length, 0);
});
test('identity, bot, group and state rejection precedes reading content/context', async () => {
  const s = setup(); let reads = 0;
  const rejected = [{ from_user_id: 'another-owner' }, { to_user_id: 'wrong-bot' }, { message_type: 2 },
    { message_state: 1 }, { group_id: 'synthetic-group' }, { group_id: null }].map(fields => {
      const value = msg('1', fields);
      for (const key of ['context_token','item_list']) Object.defineProperty(value,key,{get(){reads++;throw new Error('must_not_read');}});
      return value;
    });
  s.batches.push({ msgs: rejected, cursor: 'after-ignored' });
  assert.deepEqual(await s.relay.pollOnce(s.principal), { accepted: 0, skipped: 6, duplicates: 0 });
  assert.equal(reads, 0); assert.equal(s.store.snapshot().cursor, 'after-ignored');
});
test('official text metadata and multiple text items do not reject final owner text', async () => {
  const s=setup();
  const accepted=[msg('1',{item_list:[{type:1,text_item:{text:BODY},ref_msg:{title:'ignored quote'}}]}),
    msg('2',{item_list:[{type:1,text_item:{text:BODY},is_completed:false}]}),
    msg('3',{item_list:[{type:1,text_item:{text:'part one'}},{type:1,text_item:{text:'part two'}}]}),
    msg('4',{item_list:[{type:1,text_item:{text:BODY},file_item:{}}]})];
  s.batches.push({msgs:accepted,cursor:'accepted'});
  assert.equal((await s.relay.pollOnce(s.principal)).accepted,4);
  const requests=Object.values(s.store.snapshot().requests);
  assert.equal(requests[2].text,'part one\npart two');
  assert.equal(requests[0].text,BODY);
});
test('text compatibility retains media exclusion and content bounds with exact shape reasons', async () => {
  const s=setup();
  for(const [message,reason] of [
    [msg('7',{item_list:[]}),'item_list'],[msg('8',{item_list:[{type:2,image_item:{}}]}),'non_text_item'],
    [msg('9',{item_list:[{type:1,text_item:{text:1}}]}),'text_item'],
    [msg('10',{item_list:[{type:1,text_item:{text:'x'.repeat(4001)}}]}),'text_content']]){
    s.batches.push({msgs:[message],cursor:'filtered'});
    assert.equal((await s.relay.pollOnce(s.principal)).accepted,0);
    assert.equal(s.relay.pollStatus().last_shape_reason,reason);
  }
  assert.equal((await s.relay.events(s.principal)).length,0);
});

test('metadata-only outbox and owner get; safe status never reveals IDs/body/context', async () => {
  const s = setup(), requestId = await ingest(s);
  const events = await s.relay.events(s.principal);
  assert.deepEqual(Object.keys(events[0]).sort(),['created_at','event_id','name','request_id']);
  assert.equal(events[0].name,EVENT.name);
  const got = await s.relay.tool(s.principal,'get_owner_request',{request_id:requestId});
  assert.equal(got.text,BODY); assert.ok(!JSON.stringify(got).includes(CONTEXT));
  const status = await s.relay.tool(s.principal,'relay_status',{});
  for (const secret of [requestId,OWNER,BOT,BODY,CONTEXT,'synthetic-cursor']) assert.ok(!JSON.stringify(status).includes(secret));
  assert.equal(status.requests,1); assert.equal(status.mcp_events_integrated,false);
});
test('duplicate delivery, replay after object restart and outbox acknowledgement', async () => {
  const s = setup(); await ingest(s,[msg('10'),msg('10')]);
  const next = new OwnerTextRelay({ session:s.session, principal:s.principal, store:s.store,
    authorize:()=>true,readApproved:true,repliesApproved:true,eventsApproved:true,now:()=>100000 });
  s.batches.push({msgs:[msg('10')],cursor:'cursor-2'});
  assert.deepEqual(await next.pollOnce(s.principal),{accepted:0,skipped:0,duplicates:1});
  const [event] = await next.events(s.principal);
  assert.equal((await next.acknowledgeEvent(s.principal,event.event_id)).acknowledged,true);
  assert.equal((await next.acknowledgeEvent(s.principal,event.event_id)).acknowledged,false);
  assert.equal((await next.events(s.principal)).length,0);
});
test('whole batch cursor and admission atomic on capacity/invalid batch failure', async () => {
  const s = setup(); await ingest(s,Array.from({length:99},(_,i)=>msg(String(i+1))),'cursor-99');
  s.batches.push({msgs:[msg('100'),msg('101')],cursor:'must-not-commit'});
  await assert.rejects(s.relay.pollOnce(s.principal),code('capacity_reached'));
  assert.equal(s.store.snapshot().cursor,'cursor-99'); assert.equal((await s.relay.status(s.principal)).requests,99);
  s.batches.push({msgs:[msg('100')],cursor:null}); await assert.rejects(s.relay.pollOnce(s.principal),code('invalid_batch'));
  assert.equal(s.store.snapshot().cursor,'cursor-99');
});
test('only one poll outstanding per shared store; failed poll cannot advance cursor', async () => {
  const s = setup(); let resolve;
  s.session.getUpdates = () => new Promise(r=>{resolve=r;});
  const first=s.relay.pollOnce(s.principal); await new Promise(r=>setImmediate(r));
  await assert.rejects(s.relay.pollOnce(s.principal),code('poll_in_progress'));
  resolve({msgs:[],cursor:'done'}); await first;
  s.session.getUpdates=async()=>{throw new Error(CONTEXT);};
  await assert.rejects(s.relay.pollOnce(s.principal),code('poll_failed'));
  assert.equal(s.store.snapshot().cursor,'done');
});
test('reply reserves before send; no recipient/context supplied by tool; exact duplicates never resend', async () => {
  const s=setup(), requestId=await ingest(s); let sent;
  s.session.sendText=async args=>{
    sent=args; assert.equal(s.store.snapshot().intents[requestId].status,'sending');
    assert.equal(s.store.snapshot().requests[requestId].contextToken,undefined);
    return {accepted:true,messageId:'18446744073709551615'};
  };
  for (const extra of [{recipient:'someone'}, {contextToken:'forged'}]) await assert.rejects(s.relay.reply(s.principal,{...reply(requestId),...extra}),code('invalid_arguments'));
  assert.deepEqual(await s.relay.tool(s.principal,'reply_to_owner',reply(requestId)),{status:'accepted',duplicate:false});
  assert.deepEqual(Object.keys(sent).sort(),['clientId','contextToken','text']); assert.equal(sent.contextToken,CONTEXT);
  const firstId=sent.clientId; sent=undefined;
  assert.deepEqual(await s.relay.reply(s.principal,reply(requestId)),{status:'accepted',duplicate:true});
  assert.equal(sent,undefined); assert.ok(firstId.startsWith('feibi:'));
  await assert.rejects(s.relay.reply(s.principal,reply(requestId,{text:'different'})),code('reply_conflict'));
  await assert.rejects(s.relay.reply(s.principal,reply(requestId,{idempotency_key:'different_key'})),code('reply_conflict'));
});
test('timeout/missing ack/errors remain unknown across restart; late response does not trigger retry', async () => {
  for (const send of [async()=>({}),async()=>{throw new Error(CONTEXT);},()=>new Promise(()=>{})]) {
    const s=setup({sendTimeoutMs:5}),requestId=await ingest(s); let calls=0;
    s.session.sendText=args=>{calls++;return send(args);};
    assert.deepEqual(await s.relay.reply(s.principal,reply(requestId)),{status:'unknown',duplicate:false});
    const next=new OwnerTextRelay({session:s.session,principal:s.principal,store:s.store,authorize:()=>true,
      readApproved:true,repliesApproved:true,eventsApproved:true,now:()=>100000});
    assert.deepEqual(await next.reply(s.principal,reply(requestId)),{status:'unknown',duplicate:true}); assert.equal(calls,1);
  }
});
test('concurrent duplicate/restart while sending returns unknown without additional call', async () => {
  const s=setup(),requestId=await ingest(s); let resolve,calls=0;
  s.session.sendText=()=>{calls++;return new Promise(r=>{resolve=r;});};
  const first=s.relay.reply(s.principal,reply(requestId));await new Promise(r=>setImmediate(r));
  assert.deepEqual(await s.relay.reply(s.principal,reply(requestId)),{status:'unknown',duplicate:true});
  resolve({accepted:true});assert.equal((await first).status,'accepted');assert.equal(calls,1);
});
test('idempotency key cannot be reused across owner requests', async () => {
  const s=setup();await ingest(s,[msg('1'),msg('2')]);const events=await s.relay.events(s.principal);
  await s.relay.reply(s.principal,reply(events[0].request_id));
  await assert.rejects(s.relay.reply(s.principal,reply(events[1].request_id)),code('idempotency_conflict'));
});
test('one-hour maximum local retention is not a Tencent TTL; expired bodies removed but replay tombstones retained', async () => {
  const s=setup({retentionMs:1000}),requestId=await ingest(s);s.advance(1001);
  await assert.rejects(s.relay.get(s.principal,{request_id:requestId}),code('request_unavailable'));
  const snap=s.store.snapshot();assert.equal(snap.requests[requestId].text,undefined);assert.equal(snap.requests[requestId].contextToken,undefined);
  assert.equal((await s.relay.events(s.principal)).length,0);
  await assert.rejects(s.relay.reply(s.principal,reply(requestId)),code('request_unavailable'));
  s.batches.push({msgs:[msg()],cursor:'replay'});assert.equal((await s.relay.pollOnce(s.principal)).duplicates,1);
});
test('revoke gates before send and at async authorization boundary; tool metadata honest', async () => {
  const s=setup(),requestId=await ingest(s);s.relay.repliesApproved=false;
  await assert.rejects(s.relay.reply(s.principal,reply(requestId)),code('not_authorized'));
  assert.equal(s.calls.filter(c=>c.send).length,0);
  s.relay.authorize=async()=>{s.relay.readApproved=false;return true;};
  await assert.rejects(s.relay.get(s.principal,{request_id:requestId}),code('not_authorized'));
  assert.equal(TOOLS.find(t=>t.name==='reply_to_owner').annotations.readOnlyHint,false);
  assert.equal(TOOLS.find(t=>t.name==='relay_status').annotations.readOnlyHint,true);
});
test('outbound UTF-8 byte/NUL validation occurs before reserving intent', async () => {
  const s=setup(),requestId=await ingest(s);
  for (const invalid of ['汉'.repeat(1167),'x'.repeat(3501),'hello\0world']) {
    await assert.rejects(s.relay.reply(s.principal,reply(requestId,{text:invalid})),code('invalid_arguments'));
    assert.equal(s.store.snapshot().intents[requestId],undefined);
    assert.equal(s.store.snapshot().requests[requestId].contextToken,CONTEXT);
  }
  assert.equal(s.calls.filter(c=>c.send).length,0);
  assert.equal((await s.relay.reply(s.principal,reply(requestId,{text:'x'.repeat(3500)}))).status,'accepted');
  const incoming=setup();incoming.batches.push({msgs:[msg('1',{item_list:[{type:1,text_item:{text:'bad\0text'}}]})],cursor:'skip'});
  assert.equal((await incoming.relay.pollOnce(incoming.principal)).accepted,0);
});
test('retention expiry during second authorization prevents send but preserves unknown tombstone', async () => {
  const s=setup({retentionMs:10}),requestId=await ingest(s);let authorizations=0;
  s.relay.authorize=async()=>{if(++authorizations===2)s.advance(11);return true;};
  assert.deepEqual(await s.relay.reply(s.principal,reply(requestId)),{status:'unknown',duplicate:false});
  assert.equal(s.calls.filter(c=>c.send).length,0);
  assert.equal(s.store.snapshot().requests[requestId].contextToken,undefined);
  assert.deepEqual(await s.relay.reply(s.principal,reply(requestId)),{status:'unknown',duplicate:true});
  assert.equal(s.calls.filter(c=>c.send).length,0);
});
test('known pre-consent, malformed and too-future timestamps are discarded before text/context inspection', async () => {
  const s=setup();let reads=0;
  const timestamps=[99999,null,100000+300001,1.5,Number.MAX_SAFE_INTEGER+1];
  const messages=timestamps.map((stamp,index)=>{
    const message=msg(String(index+1),{create_time_ms:stamp});
    for(const key of ['item_list','context_token'])Object.defineProperty(message,key,{get(){reads++;throw new Error('old_content_must_not_be_read');}});
    return message;
  });
  s.batches.push({msgs:messages,cursor:'backlog-skipped'});
  assert.deepEqual(await s.relay.pollOnce(s.principal),{accepted:0,skipped:5,duplicates:0});
  assert.equal(reads,0);assert.equal(s.store.snapshot().cursor,'backlog-skipped');
  s.batches.push({msgs:[msg('7',{create_time_ms:100000}),msg('8',{create_time_ms:400000})],cursor:'fresh'});
  assert.equal((await s.relay.pollOnce(s.principal)).accepted,2);
});
test('current consent timestamp is required and pinned with the QR owner binding', async () => {
  const s=setup();s.binding({ownerUserId:OWNER,botId:BOT,apiOrigin:ORIGIN});
  await assert.rejects(s.relay.status(s.principal),code('not_authenticated'));
  s.binding({ownerUserId:OWNER,botId:BOT,apiOrigin:ORIGIN,confirmedAt:100000});await s.relay.status(s.principal);
  s.binding({ownerUserId:OWNER,botId:BOT,apiOrigin:ORIGIN,confirmedAt:100001});
  await assert.rejects(s.relay.pollOnce(s.principal),code('binding_changed'));
  assert.equal(s.calls.length,0);
});
test('offline suite never attempted network, DNS, sockets or listeners',()=>assert.equal(forbiddenCalls,0));

test('receive diagnostics distinguish empty, accepted, filtered and duplicate batches without private values',async()=>{
 const s=setup();
 await ingest(s,[msg('1'),msg('2',{from_user_id:'other-private-owner'}),msg('3',{create_time_ms:99999}),msg('4',{item_list:[]}),msg('1')]);
 let d=s.relay.pollStatus();assert.equal(d.phase,'accepted');assert.equal(d.received,5);assert.equal(d.accepted,1);assert.equal(d.skipped,3);assert.equal(d.duplicates,1);
 assert.equal(d.rejected_identity,1);assert.equal(d.rejected_freshness,1);assert.equal(d.rejected_shape,1);
 s.advance(1);await s.relay.pollOnce(s.principal);d=s.relay.pollStatus();assert.equal(d.phase,'empty');assert.equal(d.last_started_at_ms,100001);assert.equal(d.last_finished_at_ms,100001);
 await ingest(s,[msg('5',{to_user_id:'another-private-bot'})]);assert.equal(s.relay.pollStatus().phase,'filtered');
 await ingest(s,[msg('1')]);assert.equal(s.relay.pollStatus().phase,'duplicates');
 const status=await s.relay.status(s.principal);assert.equal(status.poll_diagnostic.polls,4);assert.equal(status.poll_diagnostic.successful_polls,4);
 for(const secret of [OWNER,BOT,CONTEXT,'synthetic-cursor','other-private-owner','another-private-bot'])assert.ok(!JSON.stringify(status).includes(secret));
});
test('receive diagnostics retain HTTP failure class despite poll_failed and redact unknown errors',async()=>{
 const s=setup();s.session.getUpdates=async()=>{throw Object.assign(new Error('private raw failure'),{code:'ILINK_HTTP_REJECTED',httpStatus:503});};
 await assert.rejects(s.relay.pollOnce(s.principal),code('poll_failed'));
 let d=s.relay.pollStatus();assert.equal(d.phase,'failed');assert.equal(d.reason,'ILINK_HTTP_REJECTED');assert.equal(d.last_http_status,503);assert.equal(d.failures,1);assert.equal(d.received,0);
 s.session.getUpdates=async()=>{throw Object.assign(new Error(BODY),{code:CONTEXT});};
 await assert.rejects(s.relay.pollOnce(s.principal),code('poll_failed'));d=s.relay.pollStatus();
 assert.equal(d.reason,'poll_failed');assert.equal(d.last_http_status,0);assert.equal(d.failures,2);assert.ok(!JSON.stringify(d).includes(CONTEXT));assert.ok(!JSON.stringify(d).includes(BODY));
});

test('optional official IDs and context do not discard owner text; reply still requires stored context', async()=>{
 const s=setup();
 const itemId=msg(undefined,{message_id:undefined,item_list:[{type:1,msg_id:'item-only-id',text_item:{text:BODY}}]});
 const noId=msg(undefined,{message_id:undefined,context_token:undefined});
 s.batches.push({msgs:[itemId,noId,noId],cursor:'optional-fields'});
 assert.deepEqual(await s.relay.pollOnce(s.principal),{accepted:2,skipped:0,duplicates:1});
 const requests=Object.values(s.store.snapshot().requests);assert.equal(requests[0].messageId,'item-only-id');
 assert.equal((await s.relay.get(s.principal,{request_id:requests[1].requestId})).reply_context_available,false);
 await assert.rejects(s.relay.reply(s.principal,reply(requests[1].requestId)),code('reply_context_unavailable'));
 assert.equal(s.calls.filter(call=>call.send).length,0);assert.equal(Object.keys(s.store.snapshot().intents).length,0);
});

test('optional state and timestamp do not reject owner text and expired bodies release capacity',async()=>{
 const s=setup({retentionMs:10});
 await ingest(s,Array.from({length:100},(_,i)=>msg(String(i+1),{message_state:undefined,create_time_ms:undefined})));
 assert.equal((await s.relay.status(s.principal)).pending,100);
 s.advance(11);s.batches.push({msgs:[msg('101',{create_time_ms:100011})],cursor:'after-expiry'});
 assert.equal((await s.relay.pollOnce(s.principal)).accepted,1);
 const status=await s.relay.status(s.principal);assert.equal(status.expired,100);assert.equal(status.pending,1);assert.equal(status.capacity,100);
 assert.equal(Object.values(s.store.snapshot().requests).filter(r=>r.text!==undefined).length,1);
});

test('pending inbox returns bounded owner text without consuming requests or events', async () => {
  const s=setup();await ingest(s,[msg('pending-first'),msg('other',{from_user_id:'another-owner'})]);s.advance(10);
  await ingest(s,[msg('pending-second')],'next');
  const before=s.store.snapshot(), requests=Object.values(before.requests), calls=s.calls.length;
  const listed=await s.relay.tool(s.principal,'list_pending_owner_requests',{});
  assert.deepEqual(listed,{requests:requests.map(r=>({request_id:r.requestId,received_at:r.receivedAt,reply_status:'not_sent',text:BODY,text_complete:true}))});
  assert.deepEqual(await s.relay.tool(s.principal,'list_pending_owner_requests',{}),listed);
  assert.deepEqual(s.store.snapshot(),before);assert.equal(s.calls.length,calls);
  for(const value of [OWNER,BOT,CONTEXT,'pending-first','pending-second','next'])assert.ok(!JSON.stringify(listed).includes(value));
});

test('pending inbox omits accepted sending unknown and expired requests without deleting data', async () => {
  const s=setup();await ingest(s,[msg('one'),msg('two'),msg('three')]);
  const ids=Object.keys(s.store.snapshot().requests);await s.relay.reply(s.principal,reply(ids[0]));
  let release,started;const sent=new Promise(resolve=>{started=resolve;});
  s.session.sendText=()=>{started();return new Promise(resolve=>{release=resolve;});};
  const pendingReply=s.relay.reply(s.principal,reply(ids[1],{idempotency_key:'synthetic_intent_2'}));await sent;
  const expected={requests:[{request_id:ids[2],received_at:100000,reply_status:'not_sent',text:BODY,text_complete:true}]};
  assert.deepEqual(await s.relay.tool(s.principal,'list_pending_owner_requests',{}),expected);
  release(null);assert.equal((await pendingReply).status,'unknown');
  assert.deepEqual(await s.relay.tool(s.principal,'list_pending_owner_requests',{}),expected);
  s.advance(3600000);const before=s.store.snapshot();
  assert.deepEqual(await s.relay.tool(s.principal,'list_pending_owner_requests',{}),{requests:[]});
  assert.deepEqual(s.store.snapshot(),before);
});

test('pending inbox preserves principal authentication binding and no-argument scope', async () => {
  const s=setup();await ingest(s);
  await assert.rejects(s.relay.tool({...s.principal},'list_pending_owner_requests',{}),code('not_authorized'));
  await assert.rejects(s.relay.tool(s.principal,'list_pending_owner_requests',{recipient:'another-owner'}),code('invalid_arguments'));
  s.relay.readApproved=false;await assert.rejects(s.relay.listPending(s.principal),code('not_authorized'));s.relay.readApproved=true;
  s.authenticated(false);await assert.rejects(s.relay.listPending(s.principal),code('not_authenticated'));s.authenticated(true);
  s.binding({ownerUserId:OWNER,botId:BOT,apiOrigin:ORIGIN,confirmedAt:100001});
  await assert.rejects(s.relay.listPending(s.principal),code('binding_changed'));
  const fresh=setup();assert.deepEqual(await fresh.relay.listPending(fresh.principal),{requests:[]});
});

test('inline pending uses one UTF8 budget, preserves UUID fallback and does not consume',async()=>{
 const s=setup();const a='a'.repeat(3000),b='文'.repeat(1000);
 await ingest(s,[msg('a',{item_list:[{type:1,text_item:{text:a}}]}),msg('b',{item_list:[{type:1,text_item:{text:b}}]})]);
 const before=s.store.snapshot();const list=await s.relay.listPending(s.principal,{});
 assert.equal(list.requests[0].text,a);assert.equal(list.requests[0].text_complete,true);
 assert.equal(list.requests[1].text,'');assert.equal(list.requests[1].text_complete,false);
 assert.equal((await s.relay.get(s.principal,{request_id:list.requests[1].request_id})).text,b);
 assert.deepEqual(s.store.snapshot(),before);
});
test('durable intent commit failure prevents any provider send',async()=>{
 const store=new RelayMemoryStore({commit:state=>{if(Object.values(state.intents).some(i=>i.status==='sending'))throw new Error('synthetic_disk_failure');}});
 const s=setup({store});const requestId=await ingest(s);await assert.rejects(s.relay.reply(s.principal,reply(requestId)),/synthetic_disk_failure/);assert.equal(s.calls.filter(c=>c.send).length,0);assert.equal(Object.keys(store.snapshot().intents).length,0);
});
test('crash after durable reservation restores unknown and never replays send',async()=>{
 let reserved;const store=new RelayMemoryStore({commit:state=>{if(Object.values(state.intents).some(i=>i.status==='sending'))reserved=structuredClone(state);}});
 const s=setup({store});const requestId=await ingest(s);await s.relay.reply(s.principal,reply(requestId));assert.ok(reserved);
 const restored=setup({store:new RelayMemoryStore({restored:reserved})});const outcome=await restored.relay.reply(restored.principal,reply(requestId));assert.equal(outcome.status,'unknown');assert.equal(outcome.duplicate,true);assert.equal(restored.calls.filter(c=>c.send).length,0);
});

test('persistent accepted reply retains context while retaining duplicate outcome',async()=>{
 const s=setup({retentionMs:Number.MAX_SAFE_INTEGER});const id=await ingest(s);const args=reply(id);assert.equal((await s.relay.reply(s.principal,args)).status,'accepted');const state=s.store.snapshot();assert.equal(state.requests[id].text,BODY);assert.equal(state.requests[id].sentText,args.text);assert.equal(state.requests[id].status,'answered');assert.equal(state.requests[id].contextToken,undefined);assert.equal((await s.relay.reply(s.principal,args)).duplicate,true);
});
test('production context survives reply and restart; references use item aliases and optional text type',async()=>{
 const s=setup({retentionMs:Number.MAX_SAFE_INTEGER});
 const first=await ingest(s,[msg('9007199254740993',{item_list:[{type:1,msg_id:'opaque:001',text_item:{text:BODY}}]})]);
 await s.relay.reply(s.principal,reply(first));
 const restored=setup({retentionMs:Number.MAX_SAFE_INTEGER,store:new RelayMemoryStore({restored:s.store.snapshot()})});restored.advance(1);
 await ingest(restored,[msg('9007199254740994',{item_list:[{type:1,text_item:{text:'new'},ref_msg:{svr_id:'opaque:001',partial_text:{startindex:0,endindex:2}}}]})]);
 const pending=(await restored.relay.listPending(restored.principal)).requests[0];
 assert.equal(pending.quoted[0].text,BODY);assert.equal(pending.quoted[0].partial,true);
 const read=await restored.relay.get(restored.principal,{request_id:pending.request_id});assert.equal(read.context,undefined);assert.equal(restored.store.snapshot().requests[first].text,BODY);
 const direct=restored.relay.admit(msg('3',{item_list:[{type:1,text_item:{text:'new'},ref_msg:{message_item:{text_item:{text:'quoted without optional type'}}}}]}),restored.session.bindingForRelay());assert.equal(direct.quoted[0].text,'quoted without optional type');
 const missing=restored.relay.admit(msg('4',{item_list:[{type:1,text_item:{text:'new'},ref_msg:{message_item:{type:2}}}]}),restored.session.bindingForRelay());assert.equal(missing.quoted[0].unavailable_reason,'source_id_absent');assert.equal(missing.quoted[0].text,undefined);
});
test('outbound text is cached only with exact server ID; no conversation history interface',async()=>{
 for(const hasId of [false,true]){
  const s=setup({retentionMs:Number.MAX_SAFE_INTEGER});s.session.sendText=async()=>({accepted:true,...(hasId?{messageId:'9007199254740993123'}:{})});
  const first=await ingest(s);await s.relay.reply(s.principal,reply(first));s.advance(1);
  await ingest(s,[msg('2',{item_list:[{type:1,text_item:{text:'new'},ref_msg:{svr_id:'9007199254740993123'}}]})]);
  const q=(await s.relay.listPending(s.principal)).requests[0].quoted[0];assert.equal(q.status,hasId?'cached':'not_cached');
  const read=await s.relay.get(s.principal,{request_id:first});assert.equal(read.reply_text,undefined);assert.equal(s.store.snapshot().requests[first].sentText,hasId?'synthetic reply':undefined);
 }
});
test('bounded completed context evicts body without changing result or blocking new pending',async()=>{
 const s=setup({retentionMs:Number.MAX_SAFE_INTEGER});let oldest;
 for(let i=0;i<102;i++){
  s.advance(1);const rid=await ingest(s,[msg(String(i+1))]);oldest??=rid;
  await s.relay.reply(s.principal,reply(rid,{idempotency_key:'synthetic_'+i}));
 }
 const state=s.store.snapshot();assert.equal(Object.values(state.requests).filter(r=>typeof r.text==='string').length,100);assert.equal(state.requests[oldest].contextEvicted,true);assert.equal(state.intents[oldest].status,'accepted');
 assert.equal((await s.relay.reply(s.principal,reply(oldest,{idempotency_key:'synthetic_0'}))).duplicate,true);
 const oversized={requests:{large:{receivedAt:1,status:'answered',text:'x'.repeat(4*1024*1024)}}};s.relay.trimContext(oversized);assert.equal(oversized.requests.large.contextEvicted,true);
});

test('official nested reference msg_id resolves cache without svr_id, preserving 64-bit string',async()=>{
 const s=setup();await ingest(s,[msg('9007199254740993123')]);s.advance(1);
 await ingest(s,[msg('2',{item_list:[{type:1,text_item:{text:'new'},ref_msg:{message_item:{msg_id:'9007199254740993123'}}}]})]);
 const ref=(await s.relay.listPending(s.principal)).requests.at(-1).quoted[0];assert.equal(ref.server_id,'9007199254740993123');assert.equal(ref.status,'cached');assert.equal(ref.text,BODY);
 const shape=s.relay.pollStatus().quote_diagnostic;assert.equal(shape.items[0].item_ref.fields.message_item.fields.msg_id,'string');assert.equal(shape.items[0].item_ref.fields.svr_id,undefined);
});
test('reference shape diagnoses title, wrong types, alternative nesting without any payload values',async()=>{
 const s=setup();const raw=msg('2',{ref_msg:{svr_id:'top-private-id'},item_list:[{type:1,text_item:{text:'private new text',ref_msg:{title:'private alternate title'}},ref_msg:{svr_id:null,title:'private title',private_secret_key:'hidden',message_item:{msg_id:{nested:'private value'},text_item:{text:42},type:2}}}]});
 await ingest(s,[raw]);const diag=s.relay.pollStatus().quote_diagnostic;const repr=JSON.stringify(diag);
 for(const value of ['top-private-id','private new text','private alternate title','private title','private_secret_key','hidden','private value','synthetic-context-never-export'])assert.ok(!repr.includes(value));
 assert.equal(diag.message_ref.fields.svr_id,'string');assert.equal(diag.items[0].item_ref.fields.svr_id,'null');assert.equal(diag.items[0].item_ref.fields.message_item.fields.msg_id.type,'object');assert.equal(diag.items[0].item_ref.fields.title,'string');assert.equal(diag.items[0].item_ref.unknown_field_count,1);assert.equal(diag.items[0].text_item_ref.fields.title,'string');
 const saved=JSON.stringify(diag);await ingest(s,[msg('3',{from_user_id:'other-owner',item_list:raw.item_list})]);assert.equal(JSON.stringify(s.relay.pollStatus().quote_diagnostic),saved);
 await s.relay.pollOnce(s.principal);assert.equal(JSON.stringify(s.relay.pollStatus().quote_diagnostic),saved);
});
