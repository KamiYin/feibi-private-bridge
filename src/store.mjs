import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync, chmodSync, statSync } from 'node:fs';
import { dirname } from 'node:path';

export const emptyState = () => ({ version: 1, requests: {}, subscriptions: {}, deliveries: {}, verification: {}, echoes: {} });
export class MemoryStore {
  constructor(state = emptyState()) { this.state = structuredClone(state); }
  update(fn) { const next = structuredClone(this.state); const result = fn(next); this.persist(next); this.state = next; return result; }
  persist() {}
}
// One process only. Crash-consistent encrypted snapshot; production must add managed backups/key rotation.
export class EncryptedFileStore extends MemoryStore {
  constructor(path, key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('state_key_must_be_32_bytes');
    super(); this.path = path; this.key = key;
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (existsSync(path)) {
      if (statSync(path).mode & 0o077) throw new Error('state_permissions_too_broad');
      const envelope = JSON.parse(readFileSync(path, 'utf8'));
      if (envelope.version !== 1) throw new Error('state_version_invalid');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from('wecom-dot-bridge-state-v1'));
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      this.state = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]));
      if (this.state.version !== 1) throw new Error('state_version_invalid');
    }
  }
  persist(state) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from('wecom-dot-bridge-state-v1'));
    const data = Buffer.concat([cipher.update(JSON.stringify(state)), cipher.final()]);
    const bytes = JSON.stringify({ version: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') });
    const tmp = `${this.path}.${randomBytes(8).toString('hex')}.tmp`;
    const fd = openSync(tmp, 'wx', 0o600);
    try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
    chmodSync(tmp, 0o600); renameSync(tmp, this.path);
    const dir = openSync(dirname(this.path), 'r'); try { fsyncSync(dir); } finally { closeSync(dir); }
  }
}
