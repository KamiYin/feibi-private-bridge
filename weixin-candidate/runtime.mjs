import {PersistentState} from '../windows-pilot/persistent-state.mjs';
import {IlinkSession,ILINK_ORIGIN} from './ilink.mjs';
import {createIlinkProxyTransport} from './transport.mjs';
import {OwnerTextRelay,RelayMemoryStore} from './relay.mjs';
import {WeixinMcpService,VERSION} from './service.mjs';
import {MemoryStore} from '../src/store.mjs';
import {makeAudit} from '../src/security.mjs';
import {createHostnameProxyCallbackPoster,existingHttpsProxy} from '../synthetic-pilot/hostname-proxy-callback.mjs';
import {createWeixinServer} from './http.mjs';
import {MediaTransfer,DEFAULT_MEDIA_BYTES} from './media.mjs';
const secret=x=>typeof x==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(x)&&Buffer.from(x,'base64').toString('base64')===x;
export function inspectWeixinRuntime(env={}){
  const issues=[],port=env.WEIXIN_PORT===undefined?8767:Number(env.WEIXIN_PORT),deadline=Number(env.WEIXIN_DEADLINE_UNIX_MS);
  for(const key of ['WEIXIN_PRIVATE_PILOT_APPROVED','WEIXIN_QR_APPROVED','WEIXIN_OWNER_TEXT_TRANSFER_APPROVED','WEIXIN_OWNER_TEXT_REPLY_APPROVED'])if(env[key]!=='yes')issues.push(`${key}_REQUIRED`);
  if(env.WEIXIN_TUNNEL_ISOLATION!=='single-user')issues.push('SINGLE_USER_TUNNEL_REQUIRED');
  if(!secret(env.SYNTHETIC_MCP_SECRET)||!secret(env.SYNTHETIC_OPERATOR_SECRET)||env.SYNTHETIC_MCP_SECRET===env.SYNTHETIC_OPERATOR_SECRET)issues.push('DISTINCT_LOCAL_KEYS_REQUIRED');
  if(typeof env.WEIXIN_OWNER_NONCE!=='string'||!/^bind:[A-Za-z0-9_-]{16,80}$/.test(env.WEIXIN_OWNER_NONCE))issues.push('CURRENT_CHAT_NONCE_REQUIRED');
  if(!Number.isSafeInteger(deadline)||deadline<=Date.now()||(env.WEIXIN_PERSISTENT!=='yes'&&deadline>Date.now()+43200000))issues.push('BOUNDED_DEADLINE_REQUIRED');
  if(!Number.isSafeInteger(port)||port<0||port>65535)issues.push('INVALID_PORT');
  if(env.NODE_TLS_REJECT_UNAUTHORIZED==='0'||env.NODE_OPTIONS||env.DEBUG||env.NODE_DEBUG)issues.push('UNSAFE_RUNTIME_OPTIONS');
  try{existingHttpsProxy(env);}catch{issues.push('EXISTING_HTTPS_PROXY_REQUIRED');}
  return{mode:'weixin_preflight_only',canStart:issues.length===0,issues,protocolVersion:VERSION,host:'127.0.0.1',port,
    memory_only:true,callbacks_enabled:false,qr_started:false,personal_channel_connected:false,secret_values_included:false};
}
export function createWeixinRuntime({env={},auditSink=()=>{},request,mediaRequest,post,serverFactory=createWeixinServer}={}){
  const report=inspectWeixinRuntime(env);if(!report.canStart)throw new Error('WEIXIN_PREFLIGHT_REJECTED');
  const durable=env.WEIXIN_PERSISTENT==='yes'?new PersistentState(env.WEIXIN_STATE_DIRECTORY):null;
  const deadline=Number(env.WEIXIN_DEADLINE_UNIX_MS),principal=Object.freeze({id:'single-private-weixin-owner'}),audit=makeAudit(auditSink);
  request??=createIlinkProxyTransport({env,approvedOrigins:[ILINK_ORIGIN],networkActionApproved:true,allowLegacyQrGet:true});
  const session=new IlinkSession({request,
    persistent:!!durable,restored:durable?.state.session,onSave:durable?v=>durable.set('session',v):undefined,qrApproved:true,qrGet405Compatibility:true,ownerConfirmationNonce:env.WEIXIN_OWNER_NONCE,deadline,approvedApiOrigins:[ILINK_ORIGIN]});
  let stopped=false,started=false,server,timer,deadlineTimer,busy=false,tick=Promise.resolve(),eventBusy=false,eventTick=Promise.resolve(),nextPoll=0,failures=0;
  const authorize=()=>!stopped&&Date.now()<deadline;
  const maxMediaBytes=env.WEIXIN_MEDIA_MAX_BYTES===undefined?DEFAULT_MEDIA_BYTES:Number(env.WEIXIN_MEDIA_MAX_BYTES);
  if(env.WEIXIN_OWNER_MEDIA_APPROVED==='yes')mediaRequest??=createIlinkProxyTransport({env,networkActionApproved:true,mediaOnly:true,maxMediaBytes});
  const media=env.WEIXIN_OWNER_MEDIA_APPROVED==='yes'?new MediaTransfer({session,maxBytes:maxMediaBytes,request:mediaRequest}):undefined;
  const relay=new OwnerTextRelay({session,principal,authorize,readApproved:true,repliesApproved:true,eventsApproved:true,media,
    store:new RelayMemoryStore({restored:durable?.state.relay,commit:durable?v=>durable.set('relay',v):undefined}),retentionMs:durable?Number.MAX_SAFE_INTEGER:Math.max(1,Math.min(1800000,deadline-Date.now())),sendTimeoutMs:15000});
  const eventStore=new MemoryStore(durable?.state.events);if(durable)eventStore.persist=v=>durable.set('events',v);
  const service=new WeixinMcpService({session,relay,principal,authorize,store:eventStore,
    post:async()=>{throw new Error('CALLBACKS_DISABLED');},callbacksApproved:false,injectionApproved:false,originReviewApproved:true,
    runtimeExpiresAt:deadline,postFactory:origin=>post??createHostnameProxyCallbackPoster({proxyUrl:existingHttpsProxy(env),approvedOrigin:origin,hostnameProxyReviewApproved:true}),audit});
  if(durable?.state.callbackOrigin)service.pendingOrigin=durable.state.callbackOrigin;
  const originalApprove=service.approveCallbackOrigin.bind(service);service.approveCallbackOrigin=async origin=>{const result=await originalApprove(origin);if(durable)durable.set('callbackOrigin',origin);return result;};
  const stopRuntime=async()=>{
    if(stopped)return;stopped=true;clearInterval(timer);clearTimeout(deadlineTimer);session.stop({preserve:true});service.stop();media?.clear();request.close?.();mediaRequest?.close?.();
    if(server?.listening){const closed=new Promise(r=>server.close(r));const force=setTimeout(()=>server.closeAllConnections(),12000);force.unref();await closed;clearTimeout(force);}
    await Promise.allSettled([tick,eventTick]);
  };
  return{
    async start(){
      if(started||stopped)throw new Error('RUNTIME_NOT_STARTABLE');started=true;
      try{
        if(durable?.state.callbackOrigin)await service.approveCallbackOrigin(durable.state.callbackOrigin);
        server=serverFactory({pilot:service,session,principal,mcpSecret:env.SYNTHETIC_MCP_SECRET,operatorSecret:env.SYNTHETIC_OPERATOR_SECRET});
        await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(report.port,'127.0.0.1',()=>{server.removeListener('error',reject);resolve();});});
        if(stopped||Date.now()>=deadline)throw new Error('STARTUP_STOPPED');
        deadlineTimer=setInterval(()=>{if(Date.now()>=deadline)void stopRuntime().catch(()=>audit('deadline_stop','failed'));},Math.min(1000,Math.max(1,deadline-Date.now())));deadlineTimer.unref();
        timer=setInterval(()=>{
          if(stopped||Date.now()>=deadline||!session.isAuthenticated())return;
          // One owner poller; callback retries have a separate in-flight guard.
          // Existing retention, capacity, authorization and deadline still apply.
          if(!busy&&Date.now()>=nextPoll){
            busy=true;
            tick=relay.pollOnce(principal).then(()=>{failures=0;nextPoll=Date.now();})
              .catch(()=>{failures++;nextPoll=Date.now()+(failures>=3?30000:2000);audit('weixin_poll','failed');})
              .finally(()=>{busy=false;});
          }
          if(!eventBusy){
            eventBusy=true;
            eventTick=(async()=>{await service.collectEvents();await service.deliverDue();})()
              .catch(()=>audit('weixin_events','failed')).finally(()=>{eventBusy=false;});
          }
        },250);timer.unref();
        return{mode:'private_weixin_candidate',host:'127.0.0.1',port:server.address().port,memory_only:!durable,callbacks_enabled:service.callbacksApproved,qr_started:false};
      }catch(e){stopped=true;session.stop();service.stop();clearInterval(timer);clearTimeout(deadlineTimer);if(server?.listening){server.closeAllConnections();await new Promise(r=>server.close(r));}throw e;}
    },
    stop:stopRuntime,
  };
}
