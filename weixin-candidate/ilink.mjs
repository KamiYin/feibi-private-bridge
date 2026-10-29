// Isolated offline candidate. No fetch, socket, filesystem, SDK runtime or CLI.
// A reviewed transport must be explicitly injected before any real QR/API use.
import { randomBytes, timingSafeEqual } from 'node:crypto';

export const ILINK_ORIGIN = 'https://ilinkai.weixin.qq.com';
export const REFERENCE_VERSION = '2.4.10';
export const APP_CLIENT_VERSION = '132106';
const MINUTE = 60000;
const STATES = new Set(['wait','scaned','confirmed','expired','scaned_but_redirect','need_verifycode','verify_code_blocked','binded_redirect']);
const fail = (code,httpStatus) => { throw Object.assign(new Error(code), { code, ...(Number.isInteger(httpStatus)&&httpStatus>=100&&httpStatus<=599?{httpStatus}:{}) }); };
const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const equal = (a,b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a),Buffer.from(b));
const identifier = v => typeof v === 'string' && /^[A-Za-z0-9_.:@-]{1,256}$/.test(v);
const opaque = (v,max=8192) => typeof v === 'string' && v.length > 0 && Buffer.byteLength(v) <= max && /^[\x21-\x7e]+$/.test(v);
const nonceValid = v => typeof v === 'string' && /^bind:[A-Za-z0-9_-]{16,80}$/.test(v);
export function approvedIlinkOrigin(raw) {
  let url;try {url=new URL(raw);}catch {fail('INVALID_ILINK_ORIGIN');}
  if(typeof raw!=='string'||raw.length>261||url.origin!==raw||url.protocol!=='https:'||url.port||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+weixin\.qq\.com$/.test(url.hostname))fail('INVALID_ILINK_ORIGIN');
  return raw;
}
export function parseIlinkJson(raw) {
  if(typeof raw!=='string'||Buffer.byteLength(raw)>1024*1024)fail('ILINK_RESPONSE_BOUND');
  try {
    return JSON.parse(raw,(key,value,context)=>{
      if(['message_id','msg_id','svr_id'].includes(key)&&typeof value==='number'){
        // Node's source-aware reviver preserves uint64 lexemes without trusting
        // the already-rounded JavaScript Number. No regex rewriting of text.
        if(!context||!/^\d+$/.test(context.source))fail('LOSSLESS_ID_REQUIRED');
        return context.source;
      }
      return value;
    });
  }catch {fail('INVALID_ILINK_JSON');}
}
function baseInfo(){return {channel_version:REFERENCE_VERSION,bot_agent:'FeibiBridge/0.1'};}
function commonHeaders(){return {'iLink-App-Id':'bot','iLink-App-ClientVersion':APP_CLIENT_VERSION};}
function postHeaders(token){return {'Content-Type':'application/json',AuthorizationType:'ilink_bot_token',
  'X-WECHAT-UIN':Buffer.from(String(randomBytes(4).readUInt32BE())).toString('base64'),...commonHeaders(),...(token?{Authorization:`Bearer ${token}`}:{})};}

export class IlinkSession {
  #save;#persistent=false;#request;#approved;#qrGet405Compatibility;#lastHttpStatus=0;#updatesHttpStatus=0;#now;#deadline;#origins;#origin=ILINK_ORIGIN;#nonce;#state='idle';#qr=null;#qrAt=0;
  #token=null;#owner=null;#bot=null;#confirmedAt=null;#accessStarted=false;#abort=new AbortController();#busy=false;#pendingOrigin=null;
  constructor({request,qrApproved=false,qrGet405Compatibility=false,ownerConfirmationNonce,deadline,approvedApiOrigins=[ILINK_ORIGIN],now=Date.now,persistent=false,restored,onSave}={}){
    this.#request=request??(async()=>fail('REVIEWED_TRANSPORT_REQUIRED'));this.#approved=qrApproved===true;this.#qrGet405Compatibility=qrGet405Compatibility===true;this.#now=now;
    if(typeof this.#request!=='function'||!nonceValid(ownerConfirmationNonce)||!Number.isSafeInteger(deadline)||deadline<=now()||(!persistent&&deadline>now()+720*MINUTE))fail('INVALID_SESSION_CONFIGURATION');
    if(!Array.isArray(approvedApiOrigins)||!approvedApiOrigins.length||approvedApiOrigins.length>4)fail('INVALID_SESSION_CONFIGURATION');
    this.#origins=Object.freeze([...new Set(approvedApiOrigins.map(approvedIlinkOrigin))]);
    if(!this.#origins.includes(ILINK_ORIGIN))fail('FIXED_QR_ORIGIN_REQUIRED');
    this.#deadline=deadline;this.#nonce=ownerConfirmationNonce;this.#persistent=persistent;this.#save=onSave;
    if(restored){
      if(!persistent||!opaque(restored.token)||!identifier(restored.owner)||!identifier(restored.bot)||restored.owner===restored.bot||!Number.isSafeInteger(restored.confirmedAt)||restored.confirmedAt>now())fail('INVALID_SAVED_SESSION');
      this.#origin=this.#validateOrigin(restored.origin);this.#token=restored.token;this.#owner=restored.owner;this.#bot=restored.bot;this.#confirmedAt=restored.confirmedAt;this.#state='connected';this.#nonce=null;
    }
  }
  status(){return {phase:this.#state,authenticated:this.isAuthenticated(),owner_bound:this.#state==='connected',
    pending_api_origin:this.#pendingOrigin,last_http_status:this.#lastHttpStatus,storage:this.#persistent?'dpapi_current_user':'memory_only',personal_message_access_started:this.#accessStarted};}
  updatesHttpStatus(){return this.#updatesHttpStatus;}
  isAuthenticated(){return this.#state==='connected'&&this.#now()<this.#deadline&&!this.#abort.signal.aborted;}
  bindingForRelay(){if(!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');return {ownerUserId:this.#owner,botId:this.#bot,apiOrigin:this.#origin,confirmedAt:this.#confirmedAt};}
  #gate(){if(!this.#approved)fail('QR_ACTION_APPROVAL_REQUIRED');if(this.#now()>=this.#deadline||this.#abort.signal.aborted)fail('SESSION_STOPPED_OR_EXPIRED');}
  async #serial(fn){if(this.#busy)fail('SESSION_OPERATION_IN_PROGRESS');this.#busy=true;try{return await fn();}finally{this.#busy=false;}}
  #validateOrigin(origin){approvedIlinkOrigin(origin);if(!this.#origins.includes(origin)){this.#pendingOrigin=origin;fail('EXACT_ILINK_ORIGIN_REVIEW_REQUIRED');}return origin;}
  async #invoke({origin=this.#origin,path,method='POST',payload,authenticated=false,timeoutMs=15000}){
    this.#gate();this.#validateOrigin(origin);
    if(authenticated&&!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');
    const remaining=this.#deadline-this.#now();if(remaining<=0)fail('SESSION_STOPPED_OR_EXPIRED');
    const request={origin,path,method,headers:method==='GET'?commonHeaders():postHeaders(authenticated?this.#token:null),
      ...(payload===undefined?{}:{body:Buffer.from(JSON.stringify(payload))}),redirect:'error',timeoutMs:Math.min(timeoutMs,remaining),signal:this.#abort.signal};
    let response;try{response=await this.#request(request);}catch {fail('ILINK_TRANSPORT_FAILED');}
    this.#gate();
    if(!object(response)||!Number.isInteger(response.status)||response.status<100||response.status>599)fail('INVALID_ILINK_RESPONSE');
    this.#lastHttpStatus=response.status;
    if(path==='/ilink/bot/getupdates')this.#updatesHttpStatus=response.status;
    if(response.status===401||response.status===403){this.stop();fail('ILINK_AUTHORIZATION_STOP');}
    if(response.status===402||response.status===429){this.stop();fail('ILINK_PAYMENT_OR_QUOTA_STOP');}
    if(response.status>=300&&response.status<400)fail('ILINK_REDIRECT_BLOCKED');
    if(response.status<200||response.status>=300)fail('ILINK_HTTP_REJECTED',response.status);
    const result=parseIlinkJson(response.body);if(!object(result))fail('INVALID_ILINK_RESPONSE');return result;
  }
  #business(result){
    if(result.ret===-14||result.errcode===-14){this.stop();fail('ILINK_SESSION_INVALIDATED');}
    if(result.ret!==undefined&&result.ret!==0||result.errcode!==undefined&&result.errcode!==0)fail('ILINK_BUSINESS_REJECTED');
  }
  #expireQr(){
    if(this.#state==='need_verifycode'||this.#pendingOrigin){this.stop();return;}
    this.#qr=null;this.#qrAt=0;this.#origin=ILINK_ORIGIN;this.#state='qr_expired';
  }
  async startQr(){return this.#serial(async()=>{
    this.#gate();
    if(['wait','scaned'].includes(this.#state)&&this.#now()-this.#qrAt>=5*MINUTE)this.#expireQr();
    if(!['idle','qr_expired'].includes(this.#state))fail('QR_ALREADY_STARTED');
    const started=this.#now();let result;
    try {result=await this.#invoke({origin:ILINK_ORIGIN,path:'/ilink/bot/get_bot_qrcode?bot_type=3',payload:{local_token_list:[]}});}
    catch(e){
      // Official 2.1.10 used this exact GET. Compatibility is initial-login only,
      // opt-in and only after a definite POST 405; never a network/auth fallback.
      if(!this.#qrGet405Compatibility||e?.code!=='ILINK_HTTP_REJECTED'||e.httpStatus!==405)throw e;
      const remaining=15000-(this.#now()-started);if(remaining<=0)fail('ILINK_TRANSPORT_FAILED');
      result=await this.#invoke({origin:ILINK_ORIGIN,path:'/ilink/bot/get_bot_qrcode?bot_type=3',method:'GET',timeoutMs:remaining});
    }
    this.#business(result);
    if(!opaque(result.qrcode,4096)||typeof result.qrcode_img_content!=='string'||!result.qrcode_img_content||Buffer.byteLength(result.qrcode_img_content)>8192)fail('INVALID_QR_RESPONSE');
    this.#qr=result.qrcode;this.#qrAt=this.#now();this.#state='wait';
    // Secret-bearing UI handoff only. No stdout/log/HTTP endpoint in this module.
    // Renderer must encode these bytes locally; never fetch the supplied content URL.
    return {qrPayload:result.qrcode_img_content,expiresInMs:Math.min(5*MINUTE,this.#deadline-this.#now())};
  });}
  async pollQr({verifyCode}={}){return this.#serial(async()=>{
    this.#gate();if(!['wait','scaned','need_verifycode'].includes(this.#state)||!this.#qr)fail('QR_NOT_POLLABLE');
    if(this.#now()-this.#qrAt>=5*MINUTE){this.#expireQr();fail('QR_EXPIRED');}
    if(verifyCode!==undefined&&(this.#state!=='need_verifycode'||typeof verifyCode!=='string'||!/^\d{1,16}$/.test(verifyCode)))fail('INVALID_VERIFICATION_INPUT');
    const path='/ilink/bot/get_qrcode_status?qrcode='+encodeURIComponent(this.#qr)+(verifyCode===undefined?'':'&verify_code='+encodeURIComponent(verifyCode));
    const result=await this.#invoke({path,method:'GET',timeoutMs:35000});this.#business(result);
    if(!STATES.has(result.status))fail('UNKNOWN_QR_STATUS');
    if(result.status==='expired'){this.#expireQr();fail('QR_EXPIRED');}
    if(['verify_code_blocked','binded_redirect'].includes(result.status)){this.stop();fail(result.status==='binded_redirect'?'NO_REUSABLE_LOCAL_SESSION':'VERIFICATION_BLOCKED');}
    if(result.status==='scaned_but_redirect'){
      if(typeof result.redirect_host!=='string')fail('INVALID_REDIRECT_HOST');
      const origin=this.#validateOrigin('https://'+result.redirect_host);this.#origin=origin;this.#state='scaned';return this.status();
    }
    if(result.status==='confirmed'){
      if(!opaque(result.bot_token)||!identifier(result.ilink_bot_id)||!identifier(result.ilink_user_id)||result.ilink_bot_id===result.ilink_user_id)fail('CONFIRMED_IDENTITY_REQUIRED');
      if(typeof result.baseurl!=='string')fail('CONFIRMED_API_ORIGIN_REQUIRED');
      let parsed;try {parsed=new URL(result.baseurl);}catch {fail('INVALID_CONFIRMED_BASEURL');}
      if(parsed.username||parsed.password||parsed.search||parsed.hash||parsed.port||parsed.pathname!=='/')fail('INVALID_CONFIRMED_BASEURL');
      const origin=this.#validateOrigin(parsed.origin);
      this.#token=result.bot_token;this.#bot=result.ilink_bot_id;this.#owner=result.ilink_user_id;this.#origin=origin;
      this.#qr=null;this.#state='pending_owner_confirmation';return this.status();
    }
    this.#state=result.status;return this.status();
  });}
  confirmOwner({nonce,userConfirmedScan}={}){
    this.#gate();if(this.#state!=='pending_owner_confirmation'||userConfirmedScan!==true||!equal(nonce,this.#nonce))fail('CURRENT_CHAT_OWNER_CONFIRMATION_REQUIRED');
    this.#nonce=null;this.#confirmedAt=this.#now();this.#state='connected';this.#save?.({token:this.#token,owner:this.#owner,bot:this.#bot,origin:this.#origin,confirmedAt:this.#confirmedAt});return {connected:true,owner_bound:true,storage:this.#persistent?'dpapi_current_user':'memory_only'};
  }
  async getUpdates(cursor=''){return this.#serial(async()=>{
    if(!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');
    if(typeof cursor!=='string'||Buffer.byteLength(cursor)>65536)fail('INVALID_SYNC_CURSOR');
    this.#accessStarted=true;this.#updatesHttpStatus=0;
    try {
    const result=await this.#invoke({path:'/ilink/bot/getupdates',payload:{get_updates_buf:cursor,base_info:baseInfo()},authenticated:true,timeoutMs:35000});this.#business(result);
    const msgs=result.msgs??[],nextCursor=result.get_updates_buf==null||result.get_updates_buf===''?cursor:result.get_updates_buf;
    if(!Array.isArray(msgs)||msgs.length>100||typeof nextCursor!=='string'||Buffer.byteLength(nextCursor)>65536)fail('INVALID_UPDATE_RESPONSE');
    return {msgs,cursor:nextCursor};
    } catch(e) { e.httpStatus=this.#updatesHttpStatus;throw e; }
  });}
  async getUploadUrl(fields){
    if(!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');
    const result=await this.#invoke({path:'/ilink/bot/getuploadurl',authenticated:true,
      payload:{...fields,to_user_id:this.#owner,base_info:baseInfo()}});
    this.#business(result);return result;
  }
  async sendItems({items,contextToken,clientId}={}){
    if(!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');
    if(!Array.isArray(items)||!items.length||!opaque(contextToken)||!identifier(clientId))fail('INVALID_REPLY');
    let result;
    // Official client sends one item per request; stop the group on uncertainty.
    for(let i=0;i<items.length;i++){
      if(![1,2,4].includes(items[i]?.type))fail('INVALID_REPLY');
      result=await this.#invoke({path:'/ilink/bot/sendmessage',authenticated:true,payload:{msg:{from_user_id:'',to_user_id:this.#owner,
        client_id:clientId+'.'+i,message_type:2,message_state:2,item_list:[items[i]],context_token:contextToken},base_info:baseInfo()}});
      this.#business(result);
    }
    return {accepted:true,...(typeof result.message_id==='string'?{messageId:result.message_id}:{})};
  }
  async sendText({text,contextToken,clientId}={}){
    if(!this.isAuthenticated())fail('OWNER_CONFIRMATION_REQUIRED');
    if(typeof text!=='string'||!text.trim()||text.includes('\0')||!opaque(contextToken)||!identifier(clientId))fail('INVALID_REPLY');
    if(Buffer.byteLength(text)>3500){
      if(!this.#persistent)fail('INVALID_REPLY');
      const parts=[];let part='',size=0;
      for(const character of text){const bytes=Buffer.byteLength(character);if(size+bytes>3500){parts.push(part);part='';size=0;}part+=character;size+=bytes;}if(part)parts.push(part);
      // A failed/uncertain segment stops the group. Relay keeps the whole intent unknown;
      // automatic replay of earlier accepted segments is never attempted.
      for(let i=0;i<parts.length;i++)await this.sendText({text:parts[i],contextToken,clientId:clientId+'.'+i});
      return {accepted:true};
    }
    const result=await this.#invoke({path:'/ilink/bot/sendmessage',authenticated:true,payload:{msg:{from_user_id:'',to_user_id:this.#owner,client_id:clientId,
      message_type:2,message_state:2,item_list:[{type:1,text_item:{text}}],context_token:contextToken},base_info:baseInfo()}});
    this.#business(result);
    // Official sendMessage treats omitted ret as success after the existing
    // HTTP and nonzero business-error checks. Network failures remain unknown.
    return {accepted:true,...(typeof result.message_id==='string'?{messageId:result.message_id}:{})};
  }
  stop({preserve=false}={}){if(!preserve)this.#save?.(null);this.#state='stopped';this.#abort.abort();this.#token=null;this.#owner=null;this.#bot=null;this.#qr=null;this.#nonce=null;}
}
