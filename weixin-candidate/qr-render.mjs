// Local PNG encoder only: takes QR payload on stdin, emits PNG bytes on stdout.
// No URL retrieval, argument payload, credential file, logger or external process.
import {createRequire} from 'node:module';
import {deflateSync} from 'node:zlib';
const require=createRequire(import.meta.url);
const QRCode=require('./reference/qr-renderer/vendor/QRCode');
const Level=require('./reference/qr-renderer/vendor/QRCode/QRErrorCorrectLevel');
const chunks=[];let size=0;
try {
  for await(const chunk of process.stdin){size+=chunk.length;if(size>8192)throw new Error();chunks.push(chunk);}
  const payload=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks));if(!payload||!/[\x21-\x7e]/.test(payload)||!/^[\x20-\x7e]+$/.test(payload))throw new Error();
  const qr=new QRCode(-1,Level.M);qr.addData(payload);qr.make();
  const cells=qr.getModuleCount(),scale=6,border=4,width=(cells+border*2)*scale;
  if(width>1800)throw new Error();
  const raw=Buffer.alloc(width*(width+1),255);
  for(let y=0;y<width;y++){
    raw[y*(width+1)]=0;
    for(let x=0;x<width;x++){
      const row=Math.floor(y/scale)-border,col=Math.floor(x/scale)-border;
      if(row>=0&&col>=0&&row<cells&&col<cells&&qr.isDark(row,col))raw[y*(width+1)+1+x]=0;
    }
  }
  const crc32=bytes=>{let crc=0xffffffff;for(const b of bytes){crc^=b;for(let j=0;j<8;j++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}return(crc^0xffffffff)>>>0;};
  const piece=(name,data)=>{const type=Buffer.from(name),len=Buffer.alloc(4),crc=Buffer.alloc(4);len.writeUInt32BE(data.length);crc.writeUInt32BE(crc32(Buffer.concat([type,data])));return Buffer.concat([len,type,data,crc]);};
  const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(width,0);ihdr.writeUInt32BE(width,4);ihdr[8]=8;
  process.stdout.write(Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),piece('IHDR',ihdr),piece('IDAT',deflateSync(raw)),piece('IEND',Buffer.alloc(0))]));
}catch {process.stderr.write('QR_RENDER_FAILED\n');process.exitCode=1;}
