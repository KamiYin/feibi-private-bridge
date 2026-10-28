// Windows-only bounded supervisor. Importing and --preflight perform no network/listen.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import http from 'node:http';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {StringDecoder} from 'node:string_decoder';
import {validateWindowsRouting} from './network.mjs';
import {POLL_FAILURE_CODES,SHAPE_REASONS} from '../weixin-candidate/relay.mjs';

export const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export const ORIGINS=Object.freeze(['https://api.openai.com','https://ilinkai.weixin.qq.com','https://connectors.api.openai.com']);
const NONCE=/^bind:[A-Za-z0-9_-]{16,80}$/;
const TUNNEL=/^tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}$/;
const KEY=/^sk-[A-Za-z0-9_-]{20,1021}$/;
const REASONS=new Set(['QR_ACTION_APPROVAL_REQUIRED','SESSION_STOPPED_OR_EXPIRED','QR_ALREADY_STARTED','QR_NOT_POLLABLE','QR_EXPIRED','INVALID_VERIFICATION_INPUT','CURRENT_CHAT_OWNER_CONFIRMATION_REQUIRED','OWNER_CONFIRMATION_REQUIRED','EXACT_ILINK_ORIGIN_REVIEW_REQUIRED','ILINK_AUTHORIZATION_STOP','ILINK_PAYMENT_OR_QUOTA_STOP','ILINK_SESSION_INVALIDATED','NO_REUSABLE_LOCAL_SESSION','VERIFICATION_BLOCKED','ILINK_TRANSPORT_FAILED','ILINK_REDIRECT_BLOCKED','ILINK_HTTP_REJECTED','INVALID_ILINK_JSON','INVALID_ILINK_RESPONSE','INVALID_QR_RESPONSE','ILINK_BUSINESS_REJECTED','ILINK_RESPONSE_BOUND','CONFIRMED_IDENTITY_REQUIRED','CONFIRMED_API_ORIGIN_REQUIRED','LOCAL_OPERATION_REJECTED']);
const PHASES=new Set(['idle','wait','scaned','qr_expired','need_verifycode','pending_owner_confirmation','connected','stopped']);
const CALLBACK_REASONS=new Set(['none','accepted','challenge_failed','transport_failed','timeout','proxy_connect_failed','proxy_connect_rejected','callback_tls_failed','callback_request_failed','redirect_blocked','response_too_large','response_failed','invalid_callback_request','http_rejected']);
const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join(',')===[...keys].sort().join(',');
export const validOrigin=x=>typeof x==='string'&&x.length<=261&&/^https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*(?:openai\.com|chatgpt\.com)$/.test(x);
export const EXPECTED_BINARY_SHA256='30e10e36956085c6c73f88e30942d1b96c2645f1ad6cea3b7697cb2de5ce5c48';
export function preflight({root=ROOT,platform=process.platform,arch=process.arch,node=process.versions.node,read=fs.readFileSync,stat=fs.lstatSync}={}){
  const issues=[];let binaryHash=null;
  if(platform!=='win32'||arch!=='x64')issues.push('WINDOWS_X64_REQUIRED');
  if(Number(node.split('.')[0])<24)issues.push('NODE_24_REQUIRED');
  for(const rel of ['weixin-candidate/run.mjs','weixin-candidate/qr-render.mjs','weixin-candidate/reference/qr-renderer/vendor/QRCode/index.js'])try{const s=stat(path.join(root,rel));if(!s.isFile()||s.isSymbolicLink())throw 0;}catch{issues.push('PACKAGE_FILE_MISSING');}
  try{const p=path.join(root,'windows-pilot/bin/tunnel-client-runtime-origin-guard.exe'),s=stat(p);if(!s.isFile()||s.isSymbolicLink())throw 0;
    const expected=EXPECTED_BINARY_SHA256;
    binaryHash=crypto.createHash('sha256').update(read(p)).digest('hex');if(binaryHash!==expected)issues.push('REVIEWED_BINARY_HASH_MISMATCH');
  }catch{issues.push('REVIEWED_BINARY_MISSING');}
  return{mode:'windows_preflight_only',can_prepare_run:issues.length===0,issues,binary_sha256:binaryHash,credential_read:false,launched:false,qr_started:false,maximum_seconds:25200,windows_execution_verified:false};
}
export function validateBootstrap(x,{platform=process.platform}={}){
  const fields=['action','runtime_key','expected_suffix','tunnel_id','nonce','seconds','directory','routing_snapshot','acl_verified','tunnel_approved','qr_approved','text_transfer_approved','reply_approved'];
  if(obj(x)&&Object.hasOwn(x,'deadline_utc'))fields.push('deadline_utc');
  if(!exact(x,fields)||x.action!=='bootstrap'||!KEY.test(x.runtime_key??'')||!TUNNEL.test(x.tunnel_id??'')||!NONCE.test(x.nonce??'')||!Number.isInteger(x.seconds)||x.seconds<1||x.seconds>25200)fail('BOOTSTRAP_REJECTED');
  if(Object.hasOwn(x,'deadline_utc')&&(typeof x.deadline_utc!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(x.deadline_utc)||!Number.isFinite(Date.parse(x.deadline_utc))||new Date(Date.parse(x.deadline_utc)).toISOString()!==x.deadline_utc))fail('BOOTSTRAP_REJECTED');
  if(x.expected_suffix!==''&&(!/^[A-Za-z0-9_-]{4}$/.test(x.expected_suffix)||!x.runtime_key.endsWith(x.expected_suffix)))fail('KEY_PASTE_CHECK_FAILED');
  for(const k of ['acl_verified','tunnel_approved','qr_approved','text_transfer_approved','reply_approved'])if(x[k]!==true)fail('ACTION_APPROVAL_REQUIRED');
  if(typeof x.directory!=='string'||!path.isAbsolute(x.directory)||!/^feibi-private-[0-9a-f]{32}$/.test(path.basename(x.directory)))fail('PRIVATE_DIRECTORY_REQUIRED');
  return{...x,routing:validateWindowsRouting({snapshot:x.routing_snapshot,existingRouteApproved:true,platform})};
}
export function parseControl(line){
  if(typeof line!=='string'||Buffer.byteLength(line)>1024)fail('INVALID_OPERATOR_CONTROL');
  let x;try{x=JSON.parse(line);}catch{fail('INVALID_OPERATOR_CONTROL');}
  // Canonical JSON prevents duplicate-key override and escaped key aliases.
  if(!obj(x)||line.trim()!==JSON.stringify(x))fail('INVALID_OPERATOR_CONTROL');
  const shapes={status:['action'],stop:['action'],qr_start:['action'],qr_poll:['action'],confirm_owner:['action','nonce','user_confirmed_scan'],approve_callback:['action','origin']};
  if(!Object.hasOwn(shapes,x.action)||!exact(x,shapes[x.action]))fail('INVALID_OPERATOR_CONTROL');
  if(x.action==='confirm_owner'&&(!NONCE.test(x.nonce??'')||x.user_confirmed_scan!==true))fail('INVALID_OPERATOR_CONTROL');
  if(x.action==='approve_callback'&&(!validOrigin(x.origin)||!ORIGINS.includes(x.origin)))fail('UNREVIEWED_CALLBACK_ROUTE');
  return x;
}
export function childEnvironments(config,keys,deadline,source={}){
  const common={};for(const k of ['SystemRoot','WINDIR','SYSTEMROOT'])if(source[k])common[k]=source[k];
  Object.assign(common,{HOME:config.directory,USERPROFILE:config.directory,APPDATA:config.directory,LOCALAPPDATA:config.directory,TEMP:config.directory,TMP:config.directory});
  const node={...common,SYNTHETIC_MCP_SECRET:keys.mcp,SYNTHETIC_OPERATOR_SECRET:keys.operator,HTTPS_PROXY:config.routing.proxyUrl,
    WEIXIN_PRIVATE_PILOT_APPROVED:'yes',WEIXIN_QR_APPROVED:'yes',WEIXIN_OWNER_TEXT_TRANSFER_APPROVED:'yes',WEIXIN_OWNER_TEXT_REPLY_APPROVED:'yes',WEIXIN_TUNNEL_ISOLATION:'single-user',WEIXIN_PORT:'8767',WEIXIN_DEADLINE_UNIX_MS:String(deadline),WEIXIN_OWNER_NONCE:config.nonce};
  const runtime={...common,BOUNDED_TUNNEL_RUNTIME_SECRET:config.runtime_key,SYNTHETIC_MCP_SECRET:keys.mcp};
  runtime.BOUNDED_EXISTING_HTTPS_PROXY=config.routing.proxyUrl;
  return{node,runtime,renderer:common};
}
export function runtimeArgs(config){
  const a=['run','--control-plane.api-key','env:BOUNDED_TUNNEL_RUNTIME_SECRET','--control-plane.tunnel-id',config.tunnel_id,
    '--control-plane.base-url','https://api.openai.com','--control-plane.poll-channel','main','--control-plane.max-inflight','1','--control-plane.poll-timeout','10s',
    '--control-plane.initial-poll-timeout','5s','--control-plane.poll-deadline-guardrail','30s','--mcp.server-url','url=http://127.0.0.1:8767/mcp,channel=main',
    '--mcp.extra-headers','X-Synthetic-Mcp-Auth: env:SYNTHETIC_MCP_SECRET','--mcp.discovery-extra-headers','X-Synthetic-Mcp-Auth: env:SYNTHETIC_MCP_SECRET',
    '--mcp.max-concurrent-requests','1','--profile-dir',path.join(config.directory,'empty-profiles'),'--health.listen-addr','127.0.0.1:8768',
    '--health.show-details=false','--log.level','warn','--log.format','json','--log.http-raw-unsafe=false','--tracing.enabled=false','--forward-request-id','none',
    '--harpoon.hosts-include-loopback=false','--harpoon.hosts-include-private=false'];
  a.push('--control-plane.http-proxy','env:BOUNDED_EXISTING_HTTPS_PROXY');
  return a;
}
export function safeSession(x){
  if(!obj(x)||!PHASES.has(x.phase)||x.storage!=='memory_only')fail('LOCAL_RESPONSE_REJECTED');
  const out={phase:x.phase,storage:'memory_only'};for(const k of ['authenticated','owner_bound','personal_message_access_started']){if(typeof x[k]!=='boolean')fail('LOCAL_RESPONSE_REJECTED');out[k]=x[k];}
  if(!Number.isInteger(x.last_http_status)||x.last_http_status!==0&&(x.last_http_status<100||x.last_http_status>599))fail('LOCAL_RESPONSE_REJECTED');out.last_http_status=x.last_http_status;
  if(x.pending_api_origin!==null&&x.pending_api_origin!=='https://ilinkai.weixin.qq.com')out.pending_api_origin_review_required=true;
  return out;
}
export function safeStatus(x){
  if(!obj(x)||!obj(x.mcp))fail('LOCAL_RESPONSE_REJECTED');const v=x.mcp;
  const mcp={service:'feibi-private-weixin-candidate',protocol_version:'2026-07-28',synthetic_only:false,memory_only:true,same_dot_verified:false};
  for(const[k,w]of Object.entries(mcp))if(v[k]!==w)fail('LOCAL_RESPONSE_REJECTED');
  for(const k of ['personal_channel_connected','owner_confirmation_pending','callbacks_enabled']){if(typeof v[k]!=='boolean')fail('LOCAL_RESPONSE_REJECTED');mcp[k]=v[k];}
  for(const k of ['active_subscriptions','queued_events','accepted_events']){if(!Number.isInteger(v[k])||v[k]<0||v[k]>10000)fail('LOCAL_RESPONSE_REJECTED');mcp[k]=v[k];}
  if(v.pending_callback_origin!==null&&!validOrigin(v.pending_callback_origin))fail('LOCAL_RESPONSE_REJECTED');mcp.pending_callback_origin=v.pending_callback_origin;
  const d=v.callback_diagnostic;if(!obj(d)||!['idle','verification','delivery'].includes(d.phase)||!Number.isInteger(d.status)||d.status<0||d.status>599||!CALLBACK_REASONS.has(d.reason))fail('LOCAL_RESPONSE_REJECTED');mcp.callback_diagnostic={phase:d.phase,status:d.status,reason:d.reason};
  if(v.poll_diagnostic!==undefined){
    const p=v.poll_diagnostic;if(!obj(p)||!['idle','pulling','empty','filtered','accepted','duplicates','failed'].includes(p.phase)||!POLL_FAILURE_CODES.includes(p.reason))fail('LOCAL_RESPONSE_REJECTED');
    const poll={phase:p.phase,reason:p.reason};
    for(const k of ['last_started_at_ms','last_finished_at_ms','polls','successful_polls','failures','received','accepted','skipped','duplicates','rejected_identity','rejected_freshness','rejected_shape']){if(!Number.isSafeInteger(p[k])||p[k]<0)fail('LOCAL_RESPONSE_REJECTED');poll[k]=p[k];}
    if(!Number.isInteger(p.last_http_status)||p.last_http_status!==0&&(p.last_http_status<100||p.last_http_status>599))fail('LOCAL_RESPONSE_REJECTED');poll.last_http_status=p.last_http_status;if(p.last_shape_reason!==undefined){if(!SHAPE_REASONS.includes(p.last_shape_reason))fail('LOCAL_RESPONSE_REJECTED');poll.last_shape_reason=p.last_shape_reason;}mcp.poll_diagnostic=poll;
  }
  return{session:safeSession(x.session),mcp};
}
export function safeHealth(x){
  const out={};if(!obj(x))return out;
  if(['ok','degraded','unknown','disabled'].includes(x.status))out.status=x.status;
  if(['polling','waiting','idle','backoff','retrying','starting','stopped'].includes(x.state))out.state=x.state;
  if(typeof x.reason_code==='string'&&/^http_[1-5][0-9]{2}$/.test(x.reason_code))out.reason_code=x.reason_code;
  if(obj(x.details)){out.details={};for(const k of ['http_status','consecutive_failures','attempts','accepted','poll_successes'])if(Number.isSafeInteger(x.details[k])&&x.details[k]>=0)out.details[k]=x.details[k];for(const k of ['last_success','last_success_at'])if(typeof x.details[k]==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(x.details[k]))out.details[k]=x.details[k];}
  return out;
}
export function healthStop(x){const n=x?.details?.http_status??Number(x?.reason_code?.slice(5));return[401,403].includes(n)?'AUTHORIZATION_STOP':[402,429].includes(n)?'PAYMENT_OR_QUOTA_STOP':null;}
export function localRequest({port=8767,path:pathname,key,body={},method='POST',timeoutMs=1000,signal},request=http.request){
  const allowed=method==='GET'?['/readyz','/health/control-plane','/health/response-delivery']:['/local/status','/local/qr-start','/local/qr-poll','/local/confirm-owner','/local/approve-callback'];
  if(!allowed.includes(pathname)||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>36000||![8767,8768].includes(port))return Promise.reject(new Error('LOCAL_REQUEST_REJECTED'));
  return new Promise((resolve,reject)=>{let done=false,timer;const finish=(e,v)=>{if(done)return;done=true;clearTimeout(timer);e?reject(e):resolve(v);};
    const bytes=Buffer.from(JSON.stringify(body));const req=request({host:'127.0.0.1',port,path:pathname,method,agent:false,signal,headers:method==='POST'?{'Content-Type':'application/json','Content-Length':bytes.length,'X-Synthetic-Operator-Auth':key}:{}},res=>{let size=0;const chunks=[];res.on('data',b=>{size+=b.length;if(size>32768){req.destroy();finish(new Error('LOCAL_RESPONSE_BOUND'));}else chunks.push(b);});res.on('error',()=>finish(new Error('LOCAL_OPERATION_FAILED')));res.on('end',()=>{try{const value=pathname==='/readyz'?{}:JSON.parse(Buffer.concat(chunks).toString('utf8'));if(res.statusCode!==200)fail(REASONS.has(value.reason)?value.reason:'LOCAL_OPERATION_REJECTED');finish(null,value);}catch(e){finish(e.code?e:new Error('LOCAL_RESPONSE_REJECTED'));}});});
    req.on('error',()=>finish(new Error('LOCAL_OPERATION_FAILED')));timer=setTimeout(()=>{req.destroy();finish(new Error('LOCAL_OPERATION_TIMEOUT'));},timeoutMs);req.end(method==='POST'?bytes:undefined);
  });
}
export class Supervisor{
  constructor({root=ROOT,spawnChild=spawn,request=localRequest,emit=x=>process.stdout.write(JSON.stringify(x)+'\n'),now=Date.now,source=process.env,fsImpl=fs}={}){Object.assign(this,{root,spawnChild,request,emit,now,source,fs:fsImpl});this.children=[];this.abort=new AbortController();this.stopped=false;this.qrActive=false;this.queue=Promise.resolve();this.done=new Promise(r=>this.resolveDone=r);}
  publish(event,data={}){try{this.emit({event,...data});}catch{void this.stop('OUTPUT_PIPE_CLOSED');}}
  child(file,args,env,{renderer=false}={}){
    const p=this.spawnChild(file,args,{env,cwd:this.config.directory,windowsHide:true,shell:false,stdio:['pipe','pipe','pipe']});this.children.push(p);
    p.on('error',()=>{if(!this.stopped)void this.stop('CHILD_START_FAILED');});
    p.once('exit',()=>{if(!renderer&&!this.stopped)void this.stop('CHILD_EXITED');});
    if(!renderer){p.stdin.end();for(const s of [p.stdout,p.stderr])s.resume();}
    return p;
  }
  async start(input){
    if(this.stopped)fail('SUPERVISOR_STOPPED');this.config=validateBootstrap(input);input.runtime_key='';
    const began=this.now();this.deadline=Math.min(began+this.config.seconds*1000,this.config.deadline_utc===undefined?Infinity:Date.parse(this.config.deadline_utc));
    if(this.deadline<=began)fail('SESSION_STOPPED_OR_EXPIRED');
    this.keys={mcp:crypto.randomBytes(32).toString('base64'),operator:crypto.randomBytes(32).toString('base64')};
    const s=this.fs.lstatSync(this.config.directory);if(!s.isDirectory()||s.isSymbolicLink()||this.fs.readdirSync(this.config.directory).length)fail('PRIVATE_EMPTY_DIRECTORY_REQUIRED');
    this.timer=setTimeout(()=>void this.stop('TIME_LIMIT_REACHED'),Math.max(1,this.deadline-this.now()));
    const env=childEnvironments(this.config,this.keys,this.deadline,this.source);
    try{
      if(this.now()>=this.deadline)fail('SESSION_STOPPED_OR_EXPIRED');
      this.node=this.child(process.execPath,['--use-system-ca',path.join(this.root,'weixin-candidate/run.mjs'),'--serve'],env.node);Object.keys(env.node).forEach(k=>delete env.node[k]);
      let ready=false;const startup=Math.min(this.deadline,this.now()+15000);while(!this.stopped&&this.now()<startup){try{const v=safeStatus(await this.post('/local/status',{},1000));if(v.session.phase==='idle'&&!v.mcp.callbacks_enabled&&!v.mcp.personal_channel_connected){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,100));}
      if(!ready||this.stopped||this.now()>=this.deadline)fail('LOCAL_MCP_START_TIMEOUT');
      this.runtime=this.child(path.join(this.root,'windows-pilot/bin/tunnel-client-runtime-origin-guard.exe'),runtimeArgs(this.config),env.runtime);Object.keys(env.runtime).forEach(k=>delete env.runtime[k]);this.config.runtime_key='';
      this.publish('bounded_windows_started',{maximum_seconds:this.config.seconds,deadline_utc:new Date(this.deadline).toISOString(),local_mcp_authenticated:true,qr_started:false,memory_only:true});
      this.healthTimer=setInterval(()=>{if(!this.healthBusy&&!this.stopped){this.healthBusy=true;void this.health().finally(()=>{this.healthBusy=false;});}},5000);
    }catch{await this.stop('STARTUP_FAILED');}finally{this.config.runtime_key='';for(const v of Object.values(env))for(const k of Object.keys(v))delete v[k];}
    return this.done;
  }
  async post(pathname,body,maximum){if(this.stopped||this.now()>=this.deadline)fail('SESSION_STOPPED_OR_EXPIRED');return this.request({path:pathname,key:this.keys.operator,body,timeoutMs:Math.max(1,Math.min(maximum,this.deadline-this.now())),signal:this.abort.signal});}
  async health(){for(const name of ['control-plane','response-delivery']){if(this.stopped)return;try{const v=safeHealth(await this.request({port:8768,path:'/health/'+name,method:'GET',timeoutMs:1000,signal:this.abort.signal}));if(this.stopped)return;this.publish('bounded_windows_health',{component:name,observations:v});const stop=healthStop(v);if(stop){await this.stop(stop);return;}}catch{if(!this.stopped)this.publish('bounded_windows_health',{component:name,available:false});}}}
  control(line){let x;try{x=parseControl(line);}catch{this.publish('operator_rejected',{reason:'INVALID_OPERATOR_CONTROL'});return;}
    if(x.action==='stop'){void this.stop('OPERATOR_STOP');return;}
    this.queue=this.queue.then(()=>this.operate(x)).catch(e=>{if(!this.stopped)this.publish('operator_rejected',{reason:REASONS.has(e?.code)?e.code:'LOCAL_OPERATION_REJECTED'});});
  }
  async operate(x){if(this.stopped)return;let result;
    if(x.action==='status')result=safeStatus(await this.post('/local/status',{},1000));
    else if(x.action==='qr_poll'){
      clearTimeout(this.qrPollTimer);
      try{result=safeSession(await this.post('/local/qr-poll',{},36000));}
      catch(e){if(e?.code==='QR_EXPIRED')this.removeQr();throw e;}
      if(['pending_owner_confirmation','qr_expired','stopped'].includes(result.phase))this.removeQr();
      else if(['wait','scaned'].includes(result.phase))this.scheduleQrPoll();
    }
    else if(x.action==='confirm_owner'){const v=await this.post('/local/confirm-owner',{nonce:x.nonce,user_confirmed_scan:true},1000);if(!exact(v,['connected','owner_bound','storage'])||v.connected!==true||v.owner_bound!==true||v.storage!=='memory_only')fail('LOCAL_RESPONSE_REJECTED');result=v;}
    else if(x.action==='approve_callback'){const v=await this.post('/local/approve-callback',{origin:x.origin},1000);if(v.approved!==true||v.origin!==x.origin||v.callbacks_enabled!==true)fail('LOCAL_RESPONSE_REJECTED');result={approved:true,origin:x.origin,callbacks_enabled:true};}
    else if(x.action==='qr_start'){await this.qr();return;}
    if(!this.stopped&&this.now()<this.deadline)this.publish('operator_result',{action:x.action,result});
  }
  async qr(){if(this.qrActive)fail('QR_ALREADY_STARTED');const begun=this.now();const raw=await this.post('/local/qr-start',{},16000);let payload;
    try{if(!Number.isInteger(raw.expiresInMs)||raw.expiresInMs<1||raw.expiresInMs>300000||typeof raw.qrPayload!=='string'||Buffer.byteLength(raw.qrPayload)>8192)fail('LOCAL_RESPONSE_REJECTED');
      const expires=Math.min(this.deadline,begun+raw.expiresInMs);if(this.stopped||this.now()>=expires)fail('QR_EXPIRED');payload=raw.qrPayload;raw.qrPayload='';
      const env=childEnvironments({...this.config,runtime_key:''},this.keys,this.deadline,this.source).renderer;
      const p=this.child(process.execPath,[path.join(this.root,'weixin-candidate/qr-render.mjs')],env,{renderer:true});const png=await new Promise((resolve,reject)=>{let n=0;const chunks=[];const t=setTimeout(()=>{p.kill();reject(new Error('QR_RENDER_FAILED'));},10000);p.stdout.on('data',b=>{n+=b.length;if(n>1048576){p.kill();reject(new Error('QR_RENDER_FAILED'));}else chunks.push(b);});p.stderr.resume();p.once('error',()=>{clearTimeout(t);reject(new Error('QR_RENDER_FAILED'));});p.once('exit',code=>{clearTimeout(t);const b=Buffer.concat(chunks);code===0&&b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))?resolve(b):reject(new Error('QR_RENDER_FAILED'));});p.stdin.end(payload);payload='';});
      if(this.stopped||this.now()>=expires)fail('QR_EXPIRED');this.qrActive=true;
      this.qrTimer=setTimeout(()=>this.removeQr(),Math.max(1,expires-this.now()));
      // PRIVATE redirected pipe to trusted PowerShell only. The launcher never
      // logs this record: it decodes locally into WinForms, then drops references.
      this.publish('private_qr_png',{png_base64:png.toString('base64'),expires_at_unix_ms:expires,expires_within_seconds:Math.max(1,Math.floor((expires-this.now())/1000))});
      this.scheduleQrPoll(0);
    }finally{payload='';for(const k of Object.keys(raw))delete raw[k];}
  }
  scheduleQrPoll(delay=1000){
    clearTimeout(this.qrPollTimer);
    if(this.stopped||!this.qrActive||this.now()>=this.deadline)return;
    this.qrPollTimer=setTimeout(()=>{
      if(!this.stopped&&this.qrActive&&this.now()<this.deadline)this.control('{"action":"qr_poll"}');
    },Math.min(delay,this.deadline-this.now()));
  }
  removeQr(){clearTimeout(this.qrTimer);clearTimeout(this.qrPollTimer);if(this.qrActive){this.qrActive=false;this.publish('qr_closed',{reason:'QR_REMOVED'});}}
  async stop(reason){if(this.stopped)return this.done;this.stopped=true;clearTimeout(this.timer);clearInterval(this.healthTimer);this.abort.abort();
    let exited=true;for(const p of [...this.children].reverse()){if(p.exitCode!==null||p.signalCode!==null)continue;let timer;const done=new Promise(r=>p.once('exit',()=>r(true)));try{p.kill();}catch{}const ok=await Promise.race([done,new Promise(r=>{timer=setTimeout(()=>r(false),5000);})]);clearTimeout(timer);if(!ok)exited=false;}
    this.removeQr();let removed=false;if(this.config?.directory){try{const profiles=path.join(this.config.directory,'empty-profiles');if(this.fs.existsSync(profiles))this.fs.rmdirSync(profiles);this.fs.rmdirSync(this.config.directory);}catch{}removed=!this.fs.existsSync(this.config.directory);}
    if(this.keys){this.keys.mcp='';this.keys.operator='';}if(this.config)this.config.runtime_key='';
    this.publish('bounded_windows_stopped',{reason:exited&&removed?reason:'CLEANUP_UNCONFIRMED',children_exited:exited,temporary_files_removed:removed,account_authorization_revoked:false});this.resolveDone();return this.done;
  }
}
export function decodeBootstrapLine(line){if(typeof line!=='string'||Buffer.byteLength(line)>16384)fail('BOOTSTRAP_REJECTED');let x;try{x=JSON.parse(line.startsWith('\ufeff')?line.slice(1):line);}catch{fail('BOOTSTRAP_REJECTED');}if(!obj(x))fail('BOOTSTRAP_REJECTED');return x;}
export async function main(argv=process.argv.slice(2)){
  if(argv.length===0||argv.length===1&&argv[0]==='--preflight'){process.stdout.write(JSON.stringify(preflight())+'\n');return;}
  if(argv.length===1&&argv[0]==='--routing-check'){
    let size=0;const chunks=[];for await(const b of process.stdin){size+=b.length;if(size>16384)fail('ROUTING_INPUT_BOUND');chunks.push(b);}
    try{const r=validateWindowsRouting({snapshot:decodeBootstrapLine(Buffer.concat(chunks).toString('utf8')),existingRouteApproved:true});process.stdout.write(JSON.stringify({event:'routing_validated',...r.summary})+'\n');}
    catch(e){const code=typeof e?.code==='string'&&/^WINDOWS_[A-Z_]{1,64}$/.test(e.code)?e.code:'ROUTING_REJECTED';process.stdout.write(JSON.stringify({event:'routing_rejected',reason:code})+'\n');process.exitCode=1;}return;
  }
  if(argv.length!==1||argv[0]!=='--managed')fail('EXPLICIT_WINDOWS_LAUNCHER_REQUIRED');
  if(process.stdin.isTTY||process.stdout.isTTY)fail('PRIVATE_REDIRECTED_PIPES_REQUIRED');
  const report=preflight();if(!report.can_prepare_run){process.stdout.write(JSON.stringify(report)+'\n');process.exitCode=1;return;}
  const supervisor=new Supervisor(),decoder=new StringDecoder('utf8');let buffer='',booted=false;
  const wait=setTimeout(()=>{process.stdin.destroy();process.exitCode=1;},120000);
  process.stdout.on('error',()=>void supervisor.stop('OUTPUT_PIPE_CLOSED'));
  process.stdin.on('data',chunk=>{buffer+=decoder.write(chunk);if(buffer.length>16384){void supervisor.stop('INPUT_BOUND_STOP');return;}
    while(buffer.includes('\n')){const i=buffer.indexOf('\n'),line=buffer.slice(0,i).replace(/\r$/,'');buffer=buffer.slice(i+1);
      if(!booted){booted=true;clearTimeout(wait);let input;try{input=decodeBootstrapLine(line);}catch{process.stdout.write('{"event":"bootstrap_rejected"}\n');process.stdin.destroy();process.exitCode=1;return;}void supervisor.start(input).then(()=>{process.stdin.destroy();}).catch(()=>{void supervisor.stop('STARTUP_FAILED');});}
      else supervisor.control(line);
    }
  });
  process.stdin.on('end',()=>{clearTimeout(wait);void supervisor.stop('CONTROL_PIPE_CLOSED');});process.stdin.on('error',()=>void supervisor.stop('CONTROL_PIPE_CLOSED'));
  for(const sig of ['SIGINT','SIGTERM'])process.on(sig,()=>void supervisor.stop('OPERATOR_STOP'));
  process.stdout.write('{"event":"supervisor_waiting_for_approved_bootstrap"}\n');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{process.stderr.write('WINDOWS_START_REJECTED\n');process.exitCode=1;});
