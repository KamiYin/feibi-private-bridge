import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {PersistentState} from './persistent-state.mjs';
test('real CurrentUser DPAPI synthetic roundtrip, atomic restore and ciphertext tamper rejection',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'feibi-synthetic-state-'));
 try{const a=new PersistentState(dir);a.set('session',{token:'synthetic-only'});a.set('relay',{intent:'unknown',text:'synthetic pending'});const b=new PersistentState(dir);assert.deepEqual(b.state,a.state);assert.ok(!fs.readFileSync(a.file).includes(Buffer.from('synthetic')));const bytes=fs.readFileSync(a.file);bytes[bytes.length-1]^=1;fs.writeFileSync(a.file,bytes);assert.throws(()=>new PersistentState(dir));}finally{for(const name of fs.readdirSync(dir))fs.unlinkSync(path.join(dir,name));fs.rmdirSync(dir);}
});
