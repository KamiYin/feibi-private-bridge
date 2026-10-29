import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {EventEmitter} from 'node:events';
import {PersistentState} from '../windows-pilot/persistent-state.mjs';import {createWeixinRuntime} from './runtime.mjs';
class Server extends EventEmitter{listening=false;listen(_p,_h,cb){this.listening=true;cb();}address(){return{port:0};}close(cb){this.listening=false;cb();}closeAllConnections(){}}
test('encrypted persistent runtime restores owner without QR and survives normal shutdown',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'feibi-runtime-synthetic-'));
 try{const saved=new PersistentState(dir);saved.set('session',{token:'synthetic-token',owner:'synthetic-owner',bot:'synthetic-bot',origin:'https://ilinkai.weixin.qq.com',confirmedAt:Date.now()-1000});
 const env={WEIXIN_PERSISTENT:'yes',WEIXIN_STATE_DIRECTORY:dir,WEIXIN_PRIVATE_PILOT_APPROVED:'yes',WEIXIN_QR_APPROVED:'yes',WEIXIN_OWNER_TEXT_TRANSFER_APPROVED:'yes',WEIXIN_OWNER_TEXT_REPLY_APPROVED:'yes',WEIXIN_TUNNEL_ISOLATION:'single-user',WEIXIN_PORT:'0',WEIXIN_OWNER_NONCE:'bind:synthetic_owner_123456',WEIXIN_DEADLINE_UNIX_MS:'253402300799000',SYNTHETIC_MCP_SECRET:Buffer.alloc(32,1).toString('base64'),SYNTHETIC_OPERATOR_SECRET:Buffer.alloc(32,2).toString('base64'),HTTPS_PROXY:'http://synthetic.invalid:8080'};
 for(let i=0;i<2;i++){let state;const run=createWeixinRuntime({env,request:async()=>{throw Error('NO_NETWORK');},serverFactory:o=>{state=o;return new Server();}});await run.start();assert.equal(state.session.isAuthenticated(),true);assert.equal(state.session.status().storage,'dpapi_current_user');await run.stop();assert.ok(new PersistentState(dir).state.session);}
 }finally{for(const file of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,file));fs.rmdirSync(dir);}
});
