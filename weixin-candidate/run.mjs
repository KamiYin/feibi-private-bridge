import {inspectWeixinRuntime,createWeixinRuntime} from './runtime.mjs';
const args=process.argv.slice(2);
if(args.length===0||args.length===1&&args[0]==='--preflight')console.log(JSON.stringify(inspectWeixinRuntime(process.env),null,2));
else if(args.length===1&&args[0]==='--serve'){
  let runtime,stopping=false;
  try{
    runtime=createWeixinRuntime({env:process.env,auditSink:entry=>console.log(JSON.stringify(entry))});
    const stop=async()=>{if(stopping)return;stopping=true;await runtime.stop();};
    process.once('SIGINT',stop);process.once('SIGTERM',stop);
    console.log(JSON.stringify(await runtime.start()));
  }catch{console.error(JSON.stringify({error:'weixin_start_failed',reason:'STARTUP_REJECTED'}));process.exitCode=1;}
}else{console.error('Usage: node weixin-candidate/run.mjs [--preflight|--serve]');process.exitCode=1;}
