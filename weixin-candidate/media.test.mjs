import test from 'node:test';
import assert from 'node:assert/strict';
import {createCipheriv,createDecipheriv,createHash} from 'node:crypto';
import {MediaTransfer,CDN_ORIGIN,mediaKey,mediaUrl} from './media.mjs';
import {OwnerTextRelay,RelayMemoryStore,inlineRequest} from './relay.mjs';
import {IlinkSession,ILINK_ORIGIN} from './ilink.mjs';
import {WeixinMcpService,VERSION,VERSION_META,CAPS_META} from './service.mjs';
import {MemoryStore} from '../src/store.mjs';

const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=','base64');
const file=Buffer.from('synthetic file,\u4e2d\u6587\n');
const aes=Buffer.alloc(16,7), encrypted=bytes=>{const c=createCipheriv('aes-128-ecb',aes,null);return Buffer.concat([c.update(bytes),c.final()]);};
const ref=(query)=>({encrypt_query_param:query,aes_key:aes.toString('base64')});
test('progress final proactive and explicit handled preserve per-send outcomes through restore',async()=>{
  const s=fixture(),{id}=await s.ingest(),first={request_id:id,text:'working',idempotency_key:'progress_1',final:false};
  assert.equal((await s.relay.tool(s.principal,'reply_to_owner',first)).status,'accepted');
  assert.equal((await s.relay.listPending(s.principal,{})).requests.length,1);
  const a=(await s.relay.get(s.principal,{request_id:id})).attachments[0];
  assert.equal((await s.relay.tool(s.principal,'reply_with_owner_attachments',{request_id:id,text:'done',attachments:[{request_id:id,attachment_id:a.attachment_id}],idempotency_key:'final_file_1'})).status,'accepted');
  assert.equal((await s.relay.listPending(s.principal,{})).requests.length,0);
  const restored=fixture({restored:s.store.snapshot()});
  assert.equal((await restored.relay.tool(restored.principal,'reply_to_owner',first)).duplicate,true);
  const proactive={text:'hello',idempotency_key:'proactive_1'};
  assert.equal((await restored.relay.tool(restored.principal,'send_to_owner',proactive)).status,'accepted');
  assert.equal((await restored.relay.tool(restored.principal,'send_to_owner',proactive)).duplicate,true);
  const pending=await restored.ingest([{type:1,text_item:{text:'covered elsewhere'}}]);
  await restored.relay.tool(restored.principal,'mark_owner_requests_handled',{request_ids:[pending.id]});
  assert.equal((await restored.relay.get(restored.principal,{request_id:pending.id})).reply_status,'not_sent');
  assert.equal((await restored.relay.get(restored.principal,{request_id:pending.id})).handled,true);
});
test('mixed unknown items retain supported text and attachments',async()=>{
  const s=fixture(),{id}=await s.ingest([{type:1,text_item:{text:'hello'}},{type:99},image,document]);
  const r=await s.relay.get(s.principal,{request_id:id});assert.equal(r.text,'hello');assert.equal(r.attachments.length,2);assert.deepEqual(r.unsupported_items,[{type:99,content_available:false}]);
});
test('unknown-only owner message is visible as unavailable metadata instead of disappearing',async()=>{
  const s=fixture(),{id}=await s.ingest([{type:99,msg_id:'native-item'}]);
  const r=await s.relay.get(s.principal,{request_id:id});assert.equal(r.text,'');assert.equal(r.unsupported_items[0].type,99);
});
test('host file reuse downloads once and preserves each supplied filename',async()=>{
  const s=fixture(),ref={file_id:'synthetic-host-id',download_url:'https://files.oaiusercontent.com/synthetic',file_name:'first.txt'};
  const [a,b]=await Promise.all([s.media.fromHost(ref),s.media.fromHost({...ref,file_name:'second.txt'})]);
  assert.equal(s.calls.filter(c=>c.io==='GET').length,1);assert.equal(a.bytes,b.bytes);assert.equal(b.file_name,'second.txt');
  await s.media.fromHost(ref);assert.equal(s.calls.filter(c=>c.io==='GET').length,1);
});
test('legacy unknown survives migration and handled without fabricating a send',async()=>{
  const s=fixture(),{id}=await s.ingest();s.session.sendText=async()=>{throw new Error('unknown');};
  const args={request_id:id,text:'hello',idempotency_key:'legacy_unknown'};
  await s.relay.reply(s.principal,args);const old=s.store.snapshot();delete old.sends;delete old.ownerContext;delete old.requests[id].contextToken;
  const restored=fixture({restored:old});await restored.relay.markHandled(restored.principal,{request_ids:[id]});
  assert.equal((await restored.relay.reply(restored.principal,args)).status,'unknown');
  await assert.rejects(restored.relay.reply(restored.principal,{...args,idempotency_key:'different_new'}),e=>e.code==='reply_context_unavailable');
  assert.equal(restored.calls.length,0);
});
const image={type:2,image_item:{media:ref('image'),thumb_media:ref('never-use-thumbnail')}};
const document={type:4,file_item:{media:ref('file'),file_name:'合成文档.txt',len:String(file.length),md5:createHash('md5').update(file).digest('hex')}};
function fixture({request,sendItems,restored}={}){
  const principal={},calls=[],batches=[],store=new RelayMemoryStore({restored});let authenticated=true;
  const session={isAuthenticated:()=>authenticated,bindingForRelay:()=>({ownerUserId:'owner',botId:'bot',apiOrigin:ILINK_ORIGIN,confirmedAt:1}),
    getUpdates:async cursor=>batches.shift()??{msgs:[],cursor},getUploadUrl:async fields=>{calls.push({upload:fields});return {upload_param:'upload'};},
    sendText:async args=>{calls.push({text:args});return {accepted:true};},sendItems:sendItems??(async args=>{calls.push({items:args});return {accepted:true,messageId:'123'};})};
  const media=new MediaTransfer({session,request:request??(async r=>{calls.push({io:r.method,path:r.path});if(r.method==='POST')return {status:200,body:Buffer.alloc(0),headers:{'x-encrypted-param':'uploaded'}};return {status:200,body:encrypted(r.path.includes('image')?png:file)};})});
  const relay=new OwnerTextRelay({session,principal,store,media,now:()=>100,authorize:()=>true,readApproved:true,repliesApproved:true,eventsApproved:true,retentionMs:Number.MAX_SAFE_INTEGER});
  async function ingest(items=[{type:1,text_item:{text:'caption'}},image,document],message_id=String(batches.length+Object.keys(store.snapshot().requests).length+1),overrides={}){
    batches.push({cursor:message_id,msgs:[{message_id,from_user_id:'owner',to_user_id:'bot',message_type:1,message_state:2,create_time_ms:100,context_token:'context',item_list:items,...overrides}]});
    const result=await relay.pollOnce(principal);return {result,id:store.snapshot().seen[message_id]};
  }
  return {relay,media,principal,store,session,calls,ingest,stop:()=>{authenticated=false;media.clear();}};
}
test('all original attachments admitted without downloads; event/pending/get have metadata only; persistent restore preserves refs',async()=>{
  const s=fixture(),{id}=await s.ingest();assert.equal(s.calls.length,0);
  const pending=(await s.relay.listPending(s.principal)).requests[0],get=await s.relay.get(s.principal,{request_id:id});
  assert.equal(get.attachments.length,2);assert.equal(get.attachments[1].file_name,'合成文档.txt');
  assert.deepEqual(inlineRequest(get).attachments,pending.attachments);
  assert.doesNotMatch(JSON.stringify(get),/encrypt_query|aes_key|context"|never-use-thumbnail/);
  const restored=fixture({restored:s.store.snapshot()});assert.deepEqual((await restored.relay.get(restored.principal,{request_id:id})).attachments,get.attachments);
  const only=await s.ingest([image]);assert.equal((await s.relay.get(s.principal,{request_id:only.id})).text,'');
  const quote=await s.ingest([{type:1,text_item:{text:'which image'},ref_msg:{svr_id:'2'}}]);
  const quoted=(await s.relay.get(s.principal,{request_id:quote.id})).quoted[0];
  assert.equal(quoted.request_id,only.id);assert.equal(quoted.attachments.length,1);assert.equal(s.calls.length,0);
  const wrong=await s.ingest([image],'wrong',{from_user_id:'other'});assert.equal(wrong.result.accepted,0);
});
test('original image becomes MCP image; file bytes and name preserved; simultaneous reads download once',async()=>{
  const s=fixture(),{id}=await s.ingest(),data=await s.relay.get(s.principal,{request_id:id});
  const args={request_id:id,attachment_id:data.attachments[0].attachment_id};
  const [a,b]=await Promise.all([s.relay.tool(s.principal,'get_owner_attachment',args),s.relay.tool(s.principal,'get_owner_attachment',args)]);
  assert.equal(a.content[1].type,'image');assert.equal(a.content[1].mimeType,'image/png');assert.deepEqual(Buffer.from(a.content[1].data,'base64'),png);assert.deepEqual(a,b);
  assert.equal(s.calls.filter(c=>c.io==='GET').length,1);assert.ok(!s.calls[0].path.includes('thumbnail'));
  const f=await s.relay.tool(s.principal,'get_owner_attachment',{request_id:id,attachment_id:data.attachments[1].attachment_id});
  assert.equal(f.content[1].type,'resource');assert.deepEqual(Buffer.from(f.content[1].resource.blob,'base64'),file);assert.equal(f.structuredContent.file_name,'合成文档.txt');
});
test('AES key raw and hex-base64 variants; original bytes pass through without extra content verification',async()=>{
  assert.deepEqual(mediaKey(aes.toString('base64')),aes);assert.deepEqual(mediaKey(Buffer.from(aes.toString('hex')).toString('base64')),aes);assert.throws(()=>mediaKey('bad'));
  const s=fixture(),{id}=await s.ingest([{...document,file_item:{...document.file_item,len:'1'}}]);
  const a=(await s.relay.get(s.principal,{request_id:id})).attachments[0];const result=await s.relay.tool(s.principal,'get_owner_attachment',{request_id:id,attachment_id:a.attachment_id});assert.deepEqual(Buffer.from(result.content[1].resource.blob,'base64'),file);
});
test('file ranges reconstruct the original in order and reuse one download',async()=>{
  const s=fixture(),{id}=await s.ingest([document]),attachment=(await s.relay.get(s.principal,{request_id:id})).attachments[0];
  const chunks=[];let offset=0;
  for(;;){
    const result=await s.relay.tool(s.principal,'get_owner_attachment',{request_id:id,attachment_id:attachment.attachment_id,offset,length:7});
    assert.equal(result.structuredContent.offset,offset);assert.equal(result.structuredContent.size_bytes,file.length);
    assert.equal(result.content[1].type,'resource');chunks.push(Buffer.from(result.content[1].resource.blob,'base64'));
    offset=result.structuredContent.next_offset;if(result.structuredContent.eof)break;
  }
  assert.deepEqual(Buffer.concat(chunks),file);assert.equal(s.calls.filter(c=>c.io==='GET').length,1);
});
test('media URL check rejects alternate services, redirect endpoints and credentials',()=>{
  for(const url of ['http://novac2c.cdn.weixin.qq.com/c2c/download','https://evil.test/file','https://novac2c.cdn.weixin.qq.com.evil.test/c2c/download','https://u:p@novac2c.cdn.weixin.qq.com/c2c/download','https://novac2c.cdn.weixin.qq.com/c2c/other'])assert.throws(()=>mediaUrl(url));
  assert.equal(mediaUrl(CDN_ORIGIN+'/c2c/download?encrypted_query_param=x').origin,CDN_ORIGIN);
  for(const host of ['sdmntprseasia.oaiusercontent.com','sdmntprwestus.oaiusercontent.com'])assert.equal(mediaUrl('https://'+host+'/file?signature=x','openai').hostname,host);
  for(const host of ['sdmntprseasia.oaiusercontent.com.evil.test','evil-sdmntprseasia.oaiusercontent.com','sdmntprseasia.evil.oaiusercontent.com'])assert.throws(()=>mediaUrl('https://'+host+'/file','openai'));
});
test('host origin rejection exposes only origin and happens before upload or send',async()=>{
  const s=fixture(),{id}=await s.ingest();
  await assert.rejects(s.relay.tool(s.principal,'reply_with_files_to_owner',{request_id:id,text:'',files:[{download_url:'https://unsupported.example/path?signature=secret',file_id:'file-1'}],idempotency_key:'origin-test'}),e=>e.code==='media_origin_not_supported'&&e.origin==='https://unsupported.example');
  assert.equal(s.calls.length,0);assert.equal((await s.relay.get(s.principal,{request_id:id})).reply_status,'not_sent');
});
test('multiple media replies send one group; no lost name; same-key replay does not download/upload/send again',async()=>{
  const s=fixture(),{id}=await s.ingest(),incoming=await s.relay.get(s.principal,{request_id:id});
  const args={request_id:id,text:'two attachments',attachments:incoming.attachments.map(a=>({request_id:id,attachment_id:a.attachment_id})),idempotency_key:'media_reply_one'};
  const [first,simultaneous]=await Promise.all([s.relay.tool(s.principal,'reply_with_owner_attachments',args),s.relay.tool(s.principal,'reply_with_owner_attachments',args)]);
  assert.equal(first.status,'accepted');assert.equal(simultaneous.status,'accepted');
  const sent=s.calls.find(c=>c.items).items;assert.equal(sent.items.length,2);assert.equal(sent.items[1].file_item.file_name,'合成文档.txt');
  const count=s.calls.length;assert.equal((await s.relay.tool(s.principal,'reply_with_owner_attachments',args)).duplicate,true);assert.equal(s.calls.length,count);
  await assert.rejects(s.relay.tool(s.principal,'reply_with_owner_attachments',{...args,text:'changed'}),e=>e.code==='reply_conflict');
  const {id:second}=await s.ingest([{type:1,text_item:{text:'again'}}]);await s.relay.tool(s.principal,'reply_with_owner_attachments',{...args,request_id:second,idempotency_key:'media_reply_two'});
  assert.equal(s.calls.filter(c=>c.upload).length,2); // reused both uploaded references
});
test('upload encryption matches original bytes and API media types',async()=>{
  let fields,ciphertext;
  const media=new MediaTransfer({session:{getUploadUrl:async p=>{fields=p;return {upload_param:'x'};}},request:async p=>{ciphertext=p.body;return {status:200,headers:{'x-encrypted-param':'download'},body:Buffer.alloc(0)};}});
  const item=await media.upload({bytes:file,file_name:'合成.txt',mime_type:'text/plain'});
  const decipher=createDecipheriv('aes-128-ecb',Buffer.from(fields.aeskey,'hex'),null);
  assert.deepEqual(Buffer.concat([decipher.update(ciphertext),decipher.final()]),file);assert.equal(fields.media_type,3);assert.equal(fields.rawsize,file.length);assert.equal(fields.filesize,ciphertext.length);
  assert.deepEqual(mediaKey(item.file_item.media.aes_key),Buffer.from(fields.aeskey,'hex'));
});
test('unknown media send persists across restart and never retries; upload failure before send remains pending',async()=>{
  const s=fixture({sendItems:async()=>{throw Error('uncertain');}}),{id}=await s.ingest([image]),a=(await s.relay.get(s.principal,{request_id:id})).attachments[0];
  const args={request_id:id,text:'',attachments:[{request_id:id,attachment_id:a.attachment_id}],idempotency_key:'unknown_media_1'};
  assert.equal((await s.relay.tool(s.principal,'reply_with_owner_attachments',args)).status,'unknown');
  const next=fixture({restored:s.store.snapshot()});assert.equal((await next.relay.tool(next.principal,'reply_with_owner_attachments',args)).status,'unknown');assert.equal(next.calls.length,0);
  const failed=fixture({request:async()=>{throw Error('download failed');}}),r=await failed.ingest([image]),f=(await failed.relay.get(failed.principal,{request_id:r.id})).attachments[0];
  await assert.rejects(failed.relay.tool(failed.principal,'reply_with_owner_attachments',{...args,request_id:r.id,attachments:[{request_id:r.id,attachment_id:f.attachment_id}]}));
  assert.equal((await failed.relay.get(failed.principal,{request_id:r.id})).reply_status,'not_sent');
});
test('stalled media I/O does not block text poll/reply; revoked owner cannot receive late bytes',async()=>{
  let finish;const s=fixture({request:()=>new Promise(r=>{finish=r;})}),{id}=await s.ingest([image]);
  const a=(await s.relay.get(s.principal,{request_id:id})).attachments[0],pending=s.relay.tool(s.principal,'get_owner_attachment',{request_id:id,attachment_id:a.attachment_id});
  while(!finish)await new Promise(r=>setImmediate(r));
  const {id:textId}=await s.ingest([{type:1,text_item:{text:'ordinary'}}]);
  assert.equal((await s.relay.reply(s.principal,{request_id:textId,text:'fast reply',idempotency_key:'text_parallel_1'})).status,'accepted');
  s.stop();finish({status:200,body:encrypted(png)});await assert.rejects(pending);
});
test('real session pins upload recipient and sequential media send; no poll lock reuse',async()=>{
  const calls=[];let unblock;
  const session=new IlinkSession({persistent:true,qrApproved:true,ownerConfirmationNonce:'bind:synthetic_nonce_for_media',deadline:Date.now()+10000,
    restored:{token:'synthetic-token',owner:'owner',bot:'bot',origin:ILINK_ORIGIN,confirmedAt:1},request:async r=>{calls.push({path:r.path,body:JSON.parse(r.body)});if(r.path.endsWith('getupdates'))await new Promise(resolve=>{unblock=resolve;});return {status:200,body:'{"ret":0,"upload_param":"x"}'};}});
  const poll=session.getUpdates();await session.getUploadUrl({filekey:'x',to_user_id:'override'});assert.equal(calls[1].body.to_user_id,'owner');
  await session.sendItems({items:[{type:2,image_item:{media:ref('x')}},document],contextToken:'context',clientId:'media-test'});
  assert.equal(calls.filter(c=>c.path.endsWith('sendmessage')).length,2);for(const c of calls.filter(c=>c.body.msg))assert.equal(c.body.msg.to_user_id,'owner');
  unblock();await poll;session.stop();
});
test('MCP wrapper returns native image blocks and advertises media only when enabled',async()=>{
  const s=fixture(),{id}=await s.ingest([image]);s.session.status=()=>({authenticated:true,storage:'memory_only'});
  const service=new WeixinMcpService({relay:s.relay,session:s.session,principal:s.principal,authorize:()=>true,store:new MemoryStore(),post:async()=>({status:200})});
  const rpc=(method,p={})=>service.rpc(s.principal,{jsonrpc:'2.0',id:1,method,params:{...p,_meta:{[VERSION_META]:VERSION,[CAPS_META]:{}}}});
  const tools=await rpc('tools/list'),tool=tools.result.tools.find(t=>t.name==='reply_with_files_to_owner');assert.deepEqual(tool._meta['openai/fileParams'],['files']);
  const a=(await s.relay.get(s.principal,{request_id:id})).attachments[0];const result=await rpc('tools/call',{name:'get_owner_attachment',arguments:{request_id:id,attachment_id:a.attachment_id}});
  assert.equal(result.result.content[1].type,'image');assert.equal(result.result.structuredContent.mime_type,'image/png');
});
