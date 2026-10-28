import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
// DPAPI protects one envelope key; individual commits use fast authenticated encryption.
export function dpapi(bytes,mode){
 const host=path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe');
 const r=spawnSync(host,['-NoLogo','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',fileURLToPath(new URL('./state-dpapi.ps1',import.meta.url)),'-Mode',mode],{input:bytes.toString('base64'),windowsHide:true,encoding:'utf8',timeout:15000,maxBuffer:1048576});
 if(r.status!==0||r.error)throw new Error('STATE_DPAPI_FAILED');
 return Buffer.from(r.stdout.trim(),'base64');
}
export class PersistentState {
 constructor(directory,{protect=b=>dpapi(b,'Protect'),unprotect=b=>dpapi(b,'Unprotect')}={}){
  this.file=path.join(directory,'runtime-state.enc');this.state={version:1};
  const kp=path.join(directory,'runtime-state-key.dpapi');
  if(fs.existsSync(kp))this.key=unprotect(fs.readFileSync(kp));
  else{this.key=crypto.randomBytes(32);this.atomic(kp,protect(this.key));}
  if(this.key.length!==32)throw new Error('STATE_KEY_INVALID');
  if(fs.existsSync(this.file)){
   const b=fs.readFileSync(this.file),d=crypto.createDecipheriv('aes-256-gcm',this.key,b.subarray(0,12));d.setAAD(Buffer.from('feibi-runtime-v1'));d.setAuthTag(b.subarray(12,28));
   this.state=JSON.parse(Buffer.concat([d.update(b.subarray(28)),d.final()]));if(this.state.version!==1)throw new Error('STATE_VERSION_INVALID');
  }
 }
 atomic(file,bytes){const tmp=file+'.next';const fd=fs.openSync(tmp,'w',0o600);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(tmp,file);}
 set(name,value){const next={...this.state,[name]:structuredClone(value)},iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',this.key,iv);c.setAAD(Buffer.from('feibi-runtime-v1'));const b=Buffer.concat([c.update(JSON.stringify(next)),c.final()]);this.atomic(this.file,Buffer.concat([iv,c.getAuthTag(),b]));this.state=next;}
}
