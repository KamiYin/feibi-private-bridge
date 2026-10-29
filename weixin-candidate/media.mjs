// Tencent openclaw-weixin 2.4.10 protocol; no OpenClaw runtime or extra model.
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { setImmediate as yieldTurn } from 'node:timers/promises';

export const CDN_ORIGIN = 'https://novac2c.cdn.weixin.qq.com';
// Deployment memory budget, NOT a claimed Tencent service limit. Override at runtime.
export const DEFAULT_MEDIA_BYTES = 256 * 1024 * 1024;
const fail = code => { throw Object.assign(new Error(code), {code}); };
export function mediaUrl(raw, source = 'cdn') {
  let url; try { url = new URL(raw); } catch { fail('media_url_invalid'); }
  const allowed = source === 'cdn' ? url.origin === CDN_ORIGIN && /^\/c2c\/(download|upload)$/.test(url.pathname)
    : (url.hostname === 'files.oaiusercontent.com' || url.hostname === 'files.openai.com' || /^sdmntpr[a-z0-9-]*\.oaiusercontent\.com$/.test(url.hostname));
  if (!allowed || url.protocol !== 'https:' || url.port || url.username || url.password || url.hash) throw Object.assign(new Error('media_origin_not_supported'), {code:'media_origin_not_supported',origin:url.origin});
  return url;
}
export function mediaKey(value) {
  const bytes = Buffer.from(value ?? '', 'base64');
  if (bytes.length === 16) return bytes;
  if (bytes.length === 32 && /^[a-f0-9]{32}$/i.test(bytes.toString('ascii'))) return Buffer.from(bytes.toString('ascii'), 'hex');
  fail('media_key_invalid');
}
export function mimeForName(name = '') {
  const ext = name.split('.').pop().toLowerCase();
  return ({png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',webp:'image/webp',pdf:'application/pdf',
    docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    doc:'application/msword',xls:'application/vnd.ms-excel',txt:'text/plain',csv:'text/csv',zip:'application/zip'})[ext] ?? 'application/octet-stream';
}
export function imageMime(bytes) {
  if (bytes.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'))) return 'image/png';
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return 'image/jpeg';
  if (/^GIF8[79]a$/.test(bytes.subarray(0,6).toString('ascii'))) return 'image/gif';
  if (bytes.subarray(0,4).toString() === 'RIFF' && bytes.subarray(8,12).toString() === 'WEBP') return 'image/webp';
  return null;
}
export function attachmentFromItem(item, index) {
  const image = item.type === 2, source = image ? item.image_item : item.file_item;
  const media = source?.media;
  const name = image ? `image-${index + 1}` : typeof source?.file_name === 'string' ? source.file_name : 'file.bin';
  const size = !image && /^\d+$/.test(source?.len ?? '') && Number.isSafeInteger(Number(source.len)) ? Number(source.len) : undefined;
  return {attachment_id:randomUUID(),kind:image?'image':'file',file_name:name,mime_type:image?'application/octet-stream':mimeForName(name),
    ...(size === undefined ? {} : {size_bytes:size}),
    source:media && {encrypt_query_param:media.encrypt_query_param,full_url:media.full_url,
      aes_key:image && /^[0-9a-f]{32}$/i.test(source.aeskey ?? '') ? Buffer.from(source.aeskey,'hex').toString('base64') : media.aes_key},
    };
}
export function publicAttachments(attachments) {
  return attachments.map(({attachment_id,kind,file_name,mime_type,size_bytes}) => ({attachment_id,kind,file_name,mime_type,...(size_bytes===undefined?{}:{size_bytes})}));
}
async function transform(bytes, transform) {
  const chunks=[];
  // Yield between blocks so a large crypto operation cannot monopolize text I/O.
  for(let offset=0;offset<bytes.length;offset+=256*1024){const out=transform.update(bytes.subarray(offset,offset+256*1024));if(Buffer.isBuffer(out))chunks.push(out);await yieldTurn();}
  return typeof transform.final === 'function' ? Buffer.concat([...chunks,transform.final()]) : transform.digest('hex');
}
export const mediaDigest = (bytes, algorithm='md5') => transform(bytes,createHash(algorithm));
export class MediaTransfer {
  constructor({request,session,maxBytes=DEFAULT_MEDIA_BYTES}={}) {
    if(typeof request!=='function'||!session||!Number.isSafeInteger(maxBytes)||maxBytes<1)fail('media_configuration_invalid');
    Object.assign(this,{request,session,maxBytes});this.downloads=new Map();this.cache=new Map();this.cacheBytes=0;this.uploads=new Map();this.abort=new AbortController();
  }
  async fetchBytes(url,source='cdn') {
    const target=mediaUrl(url,source);
    const response=await this.request({origin:target.origin,path:target.pathname+target.search,method:'GET',headers:{},redirect:'error',timeoutMs:300000,signal:this.abort.signal});
    if(response.status!==200)fail(Number.isInteger(response.status)?`media_download_http_${response.status}`:'media_download_failed');
    if(!Buffer.isBuffer(response.body))fail('media_download_failed');
    if(response.body.length>this.maxBytes+16)fail('media_local_size_budget_exceeded');
    return response.body;
  }
  async read(attachment) {
    const key=attachment.attachment_id;
    if(this.cache.has(key)){const value=this.cache.get(key);this.cache.delete(key);this.cache.set(key,value);return value;}
    if(this.downloads.has(key))return this.downloads.get(key);
    const operation=(async()=>{
      const source=attachment.source;
      if(!source?.full_url&&!source?.encrypt_query_param)fail('attachment_source_unavailable');
      if(attachment.size_bytes>this.maxBytes)fail('media_local_size_budget_exceeded');
      const url=source.full_url || `${CDN_ORIGIN}/c2c/download?encrypted_query_param=${encodeURIComponent(source.encrypt_query_param)}`;
      let bytes=await this.fetchBytes(url);
      if(source.aes_key) {try{bytes=await transform(bytes,createDecipheriv('aes-128-ecb',mediaKey(source.aes_key),null));}catch{fail('media_decryption_failed');}}
      else if(attachment.kind==='file')fail('media_key_invalid');
      if(bytes.length>this.maxBytes)fail('media_local_size_budget_exceeded');
      const mime=attachment.kind==='image'?imageMime(bytes)??'application/octet-stream':attachment.mime_type;
      const value={bytes,mime_type:mime,file_name:attachment.kind==='image'&&mime.startsWith('image/')?`${attachment.file_name}.${mime.split('/')[1]}`:attachment.file_name};
      return this.remember(key,value);
    })();
    this.downloads.set(key,operation);try{return await operation;}finally{this.downloads.delete(key);}
  }
  remember(key,value){
    while(this.cacheBytes+value.bytes.length>this.maxBytes&&this.cache.size){const oldest=this.cache.keys().next().value;this.cacheBytes-=this.cache.get(oldest).bytes.length;this.cache.delete(oldest);}
    if(this.abort.signal.aborted)fail('media_stopped');
    this.cache.set(key,value);this.cacheBytes+=value.bytes.length;return value;
  }
  async upload({bytes,file_name,mime_type,kind}) {
    if(!Buffer.isBuffer(bytes)||bytes.length>this.maxBytes)fail('media_local_size_budget_exceeded');
    kind ??= mime_type?.startsWith('image/')?'image':'file';
    if(kind==='image'&&!imageMime(bytes))fail('image_format_not_supported');
    const digest=await mediaDigest(bytes), cacheKey=kind+':'+digest+':'+bytes.length;
    let pending=this.uploads.get(cacheKey);
    if(!pending){
      pending=(async()=>{
        const aeskey=randomBytes(16),filekey=randomBytes(16).toString('hex');
        const encrypted=await transform(bytes,createCipheriv('aes-128-ecb',aeskey,null));
        const response=await this.session.getUploadUrl({filekey,media_type:kind==='image'?1:3,rawsize:bytes.length,
          rawfilemd5:digest,filesize:encrypted.length,no_need_thumb:true,aeskey:aeskey.toString('hex')});
        if(!response.upload_full_url&&!response.upload_param)fail('media_upload_url_missing');
        const target=mediaUrl(response.upload_full_url||`${CDN_ORIGIN}/c2c/upload?encrypted_query_param=${encodeURIComponent(response.upload_param)}&filekey=${filekey}`);
        const result=await this.request({origin:target.origin,path:target.pathname+target.search,method:'POST',headers:{'Content-Type':'application/octet-stream'},body:encrypted,redirect:'error',timeoutMs:300000,signal:this.abort.signal});
        if(result.status!==200||!result.headers?.['x-encrypted-param'])fail('media_upload_failed');
        return {media:{encrypt_query_param:result.headers['x-encrypted-param'],aes_key:Buffer.from(aeskey.toString('hex')).toString('base64'),encrypt_type:1},size:bytes.length,cipherSize:encrypted.length};
      })();
      this.uploads.set(cacheKey,pending);
      // Reference-only cache: no plaintext retained here.
      if(this.uploads.size>100)this.uploads.delete(this.uploads.keys().next().value);
      pending.catch(()=>this.uploads.delete(cacheKey));
    }
    const uploaded=await pending;
    return kind==='image'?{type:2,image_item:{media:uploaded.media,mid_size:uploaded.cipherSize}}:
      {type:4,file_item:{media:uploaded.media,file_name,len:String(uploaded.size)}};
  }
  async fromHost(file) {
    if(!file||typeof file.file_id!=='string'||!file.file_id||typeof file.download_url!=='string'||Object.keys(file).some(k=>!['download_url','file_id','mime_type','file_name'].includes(k)))fail('invalid_file_input');
    if(['file_name','mime_type'].some(k=>file[k]!==undefined&&(typeof file[k]!=='string'||file[k].includes('\0'))))fail('invalid_file_input');
    mediaUrl(file.download_url,'openai');
    const key='host:'+file.file_id;
    let value=this.cache.get(key);
    if(!value){
      let pending=this.downloads.get(key);
      if(!pending){pending=this.fetchBytes(file.download_url,'openai').then(bytes=>this.remember(key,{bytes}));this.downloads.set(key,pending);}
      try{value=await pending;}finally{if(this.downloads.get(key)===pending)this.downloads.delete(key);}
    }
    const bytes=value.bytes;
    return {bytes,file_name:file.file_name||'file.bin',mime_type:file.mime_type||mimeForName(file.file_name)};
  }
  clear(){this.abort.abort();this.cache.clear();this.cacheBytes=0;this.uploads.clear();}
}
