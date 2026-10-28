import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import {syncBuiltinESMExports} from 'node:module';
import {EventEmitter} from 'node:events';
import {PassThrough} from 'node:stream';
import {StringDecoder} from 'node:string_decoder';
import {spawnSync} from 'node:child_process';
import {preflight,validateBootstrap,decodeBootstrapLine,parseControl,childEnvironments,runtimeArgs,safeSession,safeStatus,safeHealth,healthStop,localRequest,Supervisor,EXPECTED_BINARY_SHA256,ROOT,ORIGINS} from './supervisor.mjs';
let networkCalls=0;const denied=()=>{networkCalls++;throw new Error('TEST_NETWORK_FORBIDDEN');};
net.connect=net.createConnection=net.Socket.prototype.connect=net.Server.prototype.listen=tls.connect=dns.lookup=dns.promises.lookup=denied;syncBuiltinESMExports();
const key='sk-'+'SYNTHETIC_ONLY_NOT_REAL_CREDENTIAL_abcd';
const snapshot={version:1,source:'windows-default-web-proxy',routes:ORIGINS.map(origin=>({origin,proxyUrl:'http://proxy.invalid:8080'}))};
const input=()=>({action:'bootstrap',runtime_key:key,expected_suffix:'abcd',tunnel_id:'tunnel_'+'a'.repeat(32),nonce:'bind:synthetic_nonce_123456',seconds:1800,directory:'/tmp/feibi-private-'+'a'.repeat(32),routing_snapshot:structuredClone(snapshot),acl_verified:true,tunnel_approved:true,qr_approved:true,text_transfer_approved:true,reply_approved:true});
const config=()=>validateBootstrap(input(),{platform:'win32'});
const session=()=>({phase:'idle',authenticated:false,owner_bound:false,personal_message_access_started:false,storage:'memory_only',last_http_status:0,pending_api_origin:null});
const status=()=>({session:session(),mcp:{service:'feibi-private-weixin-candidate',protocol_version:'2026-07-28',synthetic_only:false,memory_only:true,same_dot_verified:false,personal_channel_connected:false,owner_confirmation_pending:false,callbacks_enabled:false,active_subscriptions:0,queued_events:0,accepted_events:0,pending_callback_origin:null,callback_diagnostic:{phase:'idle',status:0,reason:'none'}}});
function child(){const p=new EventEmitter();p.stdin=new PassThrough();p.stdout=new PassThrough();p.stderr=new PassThrough();p.pid=77;p.exitCode=null;p.signalCode=null;p.kill=()=>{p.exitCode=0;p.emit('exit',0);};return p;}

test('source-only preflight is inert and missing reviewed binary cannot launch',()=>{
 const report=preflight({platform:'linux',arch:'x64',node:'24.22.1'});assert.equal(report.launched,false);assert.equal(report.credential_read,false);assert.equal(report.binary_sha256,null);assert.deepEqual(report.issues,['WINDOWS_X64_REQUIRED','REVIEWED_BINARY_MISSING']);assert.equal(networkCalls,0);
 assert.equal(preflight({platform:'win32',arch:'x64',node:'24.22.1'}).can_prepare_run,false);
});
test('preflight rejects missing/tampered package and unsupported Node without executing binary',()=>{
 const r=preflight({platform:'win32',arch:'x64',node:'22.1.1',read:()=>Buffer.from('not the binary'),stat:()=>({isFile:()=>true,isSymbolicLink:()=>false})});assert.ok(r.issues.includes('NODE_24_REQUIRED'));assert.ok(r.issues.includes('REVIEWED_BINARY_HASH_MISMATCH'));
});
test('bootstrap requires all explicit action gates and synthetic paste guard',()=>{
 assert.equal(config().routing.proxyUrl,'http://proxy.invalid:8080/');
 for(const field of ['acl_verified','tunnel_approved','qr_approved','text_transfer_approved','reply_approved'])assert.throws(()=>validateBootstrap({...input(),[field]:false},{platform:'win32'}));
 for(const patch of [{runtime_key:'not-key'},{expected_suffix:'wrong'},{expected_suffix:'zzzz'},{seconds:25201},{nonce:'guess'},{tunnel_id:'x'},{directory:'/tmp/not-owned'},{extra:'x'}])assert.throws(()=>validateBootstrap({...input(),...patch},{platform:'win32'}));
 assert.throws(()=>validateBootstrap(input(),{platform:'linux'}));
});
test('bootstrap preserves route policy: DIRECT, different proxies, extra origin all fail closed',()=>{
 for(const routes of [snapshot.routes.map((x,i)=>({...x,proxyUrl:i===0?null:x.proxyUrl})),snapshot.routes.map((x,i)=>({...x,proxyUrl:i===0?'http://other.invalid:1234':x.proxyUrl})),[...snapshot.routes,{origin:'https://unapproved.invalid',proxyUrl:'http://proxy.invalid:8080'}]])assert.throws(()=>validateBootstrap({...input(),routing_snapshot:{...snapshot,routes}},{platform:'win32'}));
});
test('strict controls reject duplicate keys, URLs/code input, stale broad callback origins and verification codes',()=>{
 for(const line of ['{"action":"status","action":"stop"}','{"action":"status","url":"https://bad.invalid"}','{"action":"qr_poll","verify_code":"123"}','{"action":"approve_callback","origin":"https://other.openai.com"}','{"action":"confirm_owner","nonce":"bind:synthetic_nonce_123456","user_confirmed_scan":false}','{"action":"status", "extra":true}'])assert.throws(()=>parseControl(line));
 assert.deepEqual(parseControl('{"action":"stop"}'),{action:'stop'});assert.equal(parseControl('{"action":"approve_callback","origin":"https://connectors.api.openai.com"}').action,'approve_callback');
});
test('child environments never copy arbitrary credentials/proxies/options; Node/renderer never get runtime key',()=>{
 const env=childEnvironments(config(),{mcp:'MCP',operator:'OPERATOR'},123,{SystemRoot:'C:\\Windows',OPENAI_API_KEY:'real-looking',NODE_OPTIONS:'--evil',NO_PROXY:'*',PATH:'inherited',https_proxy:'bad'});
 assert.equal(env.runtime.BOUNDED_TUNNEL_RUNTIME_SECRET,key);assert.equal(env.node.HTTPS_PROXY,'http://proxy.invalid:8080/');
 for(const e of [env.node,env.renderer])assert.ok(!JSON.stringify(e).includes(key));
 for(const e of Object.values(env)){for(const k of ['OPENAI_API_KEY','NODE_OPTIONS','NO_PROXY','PATH','https_proxy'])assert.ok(!Object.hasOwn(e,k));}
 assert.ok(!Object.hasOwn(env.runtime,'SYNTHETIC_OPERATOR_SECRET'));assert.ok(!Object.hasOwn(env.renderer,'SYNTHETIC_MCP_SECRET'));
});
test('every child confines profile and temporary paths to the same private project directory',()=>{
 const directory='C:\\synthetic-project\\feibi-private-'+'b'.repeat(32);
 const names=['HOME','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP'];
 const inherited=Object.fromEntries(names.map(name=>[name,'C:\\synthetic-outside-project\\'+name]));
 Object.assign(inherited,{SystemRoot:'C:\\Windows',WINDIR:'C:\\Windows',tmp:'C:\\synthetic-lowercase-temp'});
 const original=structuredClone(inherited);
 const env=childEnvironments({...config(),directory},{mcp:'MCP',operator:'OPERATOR'},123,inherited);
 assert.deepEqual(Object.keys(env).sort(),['node','renderer','runtime']);
 for(const [kind,values] of Object.entries(env)){
  for(const name of names)assert.equal(values[name],directory,kind+' '+name);
  assert.equal(values.SystemRoot,'C:\\Windows');
  assert.equal(values.WINDIR,'C:\\Windows');
  assert.ok(!Object.hasOwn(values,'tmp'));
  assert.doesNotMatch(JSON.stringify(values),/synthetic-outside-project|synthetic-lowercase-temp/);
 }
 assert.deepEqual(inherited,original,'source environment remains unchanged');
 env.node.TEMP='SYNTHETIC_MUTATION';
 assert.equal(env.runtime.TEMP,directory);
 assert.equal(env.renderer.TEMP,directory);
});
test('runtime flags are one fixed HTTPS origin, envref auth and single loopback HTTP; no literal stdout file',()=>{
 const a=runtimeArgs(config());const joined=a.join(' ');assert.ok(!joined.includes(key));assert.ok(joined.includes('--control-plane.base-url https://api.openai.com'));assert.ok(joined.includes('--control-plane.http-proxy env:BOUNDED_EXISTING_HTTPS_PROXY'));
 assert.ok(joined.includes('url=http://127.0.0.1:8767/mcp,channel=main'));assert.ok(!joined.includes('--log.file'));assert.ok(!joined.includes('stdio'));assert.ok(!joined.includes('--command'));
});
test('safe status/health retains typed evidence and strips text/token/IDs; typed 401/402 stop',()=>{
 const raw=status();raw.session.bot_token=key;raw.mcp.body='PRIVATE';assert.ok(!JSON.stringify(safeStatus(raw)).includes('PRIVATE'));assert.ok(!JSON.stringify(safeStatus(raw)).includes(key));
 assert.throws(()=>safeSession({...session(),phase:key}));
 const h=safeHealth({status:'degraded',state:'backoff',reason_code:'http_401',details:{http_status:401,consecutive_failures:4,last_success:'2026-10-27T09:50:01Z',error:key}});assert.equal(healthStop(h),'AUTHORIZATION_STOP');assert.equal(healthStop(safeHealth({details:{http_status:429}})),'PAYMENT_OR_QUOTA_STOP');assert.ok(!JSON.stringify(h).includes(key));
});
test('local HTTP adapter pins loopback, bounded body and header; no network fixture',async()=>{
 let observed;const req=(options,cb)=>{observed=options;const r=new EventEmitter();r.end=()=>{const res=new EventEmitter();res.statusCode=200;cb(res);queueMicrotask(()=>{res.emit('data',Buffer.from('{"ok":true}'));res.emit('end');});};r.destroy=()=>{};return r;};
 assert.deepEqual(await localRequest({path:'/local/status',key:'LOCAL_ONLY'},req),{ok:true});assert.equal(observed.host,'127.0.0.1');assert.equal(observed.headers['X-Synthetic-Operator-Auth'],'LOCAL_ONLY');
 await assert.rejects(localRequest({path:'/arbitrary',key:'x'},req));await assert.rejects(localRequest({path:'/local/status',timeoutMs:40000},req));
});
test('typed local known errors are redacted, including payment/quota and new parser diagnostics',async()=>{
 for(const reason of ['ILINK_PAYMENT_OR_QUOTA_STOP','INVALID_ILINK_JSON','INVALID_QR_RESPONSE']){
 const req=(_o,cb)=>{const r=new EventEmitter();r.end=()=>{const res=new EventEmitter();res.statusCode=400;cb(res);queueMicrotask(()=>{res.emit('data',Buffer.from(JSON.stringify({reason,message:key})));res.emit('end');});};r.destroy=()=>{};return r;};
 await assert.rejects(localRequest({path:'/local/qr-start',key:'LOCAL'},req),e=>e.code===reason&&!e.message.includes(key));}
});
test('normal cleanup waits own children and only removes empty owned directories',async()=>{
 const events=[],calls=[];let exists=true;const fakeFs={existsSync:p=>p.endsWith('empty-profiles')?false:exists,rmdirSync:p=>{calls.push(p);exists=false;}};
 const s=new Supervisor({emit:x=>events.push(x),fsImpl:fakeFs});s.config=config();s.keys={mcp:'M',operator:'O'};s.children=[child(),child()];
 await s.stop('OPERATOR_STOP');assert.equal(events.at(-1).temporary_files_removed,true);assert.equal(events.at(-1).children_exited,true);assert.equal(events.at(-1).account_authorization_revoked,false);assert.equal(s.config.runtime_key,'');assert.equal(s.keys.operator,'');assert.deepEqual(calls,[s.config.directory]);
 await s.stop('OPERATOR_STOP');assert.equal(events.filter(x=>x.event==='bounded_windows_stopped').length,1);
});
test('cleanup cannot report success if unexpected files prevent empty-directory removal',async()=>{
 const events=[];const s=new Supervisor({emit:x=>events.push(x),fsImpl:{existsSync:()=>true,rmdirSync:()=>{throw new Error('not empty');}}});s.config=config();await s.stop('OPERATOR_STOP');assert.equal(events.at(-1).reason,'CLEANUP_UNCONFIRMED');assert.equal(events.at(-1).temporary_files_removed,false);
});
test('late QR response is never rendered or displayed after session/QR deadline',async()=>{
 let now=100;const events=[];const s=new Supervisor({emit:x=>events.push(x),now:()=>now,request:async()=>{now=1000;return{qrPayload:'SYNTHETIC_SECRET_QR',expiresInMs:100};},spawnChild:()=>{throw new Error('must not spawn');},fsImpl:{existsSync:()=>false,rmdirSync:()=>{}}});s.config=config();s.keys={operator:'O'};s.deadline=500;
 await assert.rejects(s.qr());assert.equal(events.length,0);await s.stop('TIME_LIMIT_REACHED');
});
test('stop while QR call is pending prevents late output',async()=>{
 let respond;const events=[];const s=new Supervisor({emit:x=>events.push(x),request:()=>new Promise(r=>{respond=r;}),spawnChild:()=>{throw new Error('must not spawn');},fsImpl:{existsSync:()=>false,rmdirSync:()=>{}}});s.config=config();s.keys={operator:'O'};s.deadline=Date.now()+10000;
 const q=s.qr();await s.stop('OPERATOR_STOP');respond({qrPayload:'SYNTHETIC',expiresInMs:10000});await assert.rejects(q);assert.ok(!events.some(x=>x.event==='private_qr_png'));
});
test('PS5.1 launcher uses hidden input, only private IPC QR and Job Object before credentials, no policy bypass',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');assert.ok(ps.includes('-AsSecureString'));assert.ok(ps.includes('ZeroFreeBSTR'));assert.ok(ps.includes('AssignProcessToJobObject'));assert.ok(ps.includes('LimitFlags=0x2000'));
 const runBranch=ps.indexOf('if ($Standalone) { Start-StandaloneHost; return }');
 assert.ok(runBranch>=0);
 assert.ok(ps.indexOf('if (-not [FeibiJob]::AssignProcessToJobObject',runBranch)<ps.indexOf('$script:secureKey = Read-Host',runBranch));
 assert.ok(ps.includes('SetAccessRuleProtection($true,$false)'));assert.ok(ps.includes("$info.EnvironmentVariables.Clear()"));assert.ok(ps.includes("$event.event -eq 'private_qr_png'"));assert.ok(!ps.includes('Image]::FromFile'));assert.ok(!ps.includes('login-qr.png'));assert.ok(!ps.includes('.Kill($true)'));assert.ok(!ps.includes('Start-Process -Environment'));
 assert.ok(!/powershell[^\n]*-ExecutionPolicy\s+(?:Bypass|Unrestricted)/i.test(ps));assert.ok(!/\bInvoke-Expression\b|\bIEX\s+/.test(ps.split('\n').filter(x=>!x.trim().startsWith('#')).join('\n')));
});
test('PowerShell selects one Node executable in PATH order before assigning the launch filename',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 assert.match(ps,/\$script:nodePath\s*=\s*\(Get-Command node -CommandType Application -ErrorAction Stop\s*\|\s*Select-Object -First 1\)\.Source/);
 assert.ok(ps.includes('$info.FileName = $script:nodePath'));
 const check=ps.indexOf('if (-not [IO.Path]::IsPathRooted($script:nodePath))');
 assert.ok(check>=0&&check<ps.indexOf("$preflight = New-NodeProcess '--preflight'"));
});
test('startup-only validation requires Run before the offline-preflight return or any process launch',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 assert.match(ps,/\[switch\]\$ValidateStartupOnly/);
 const guard="if ($ValidateStartupOnly -and -not $Run) { throw 'STARTUP_VALIDATION_REQUIRES_RUN' }";
 assert.ok(ps.includes(guard));
 assert.ok(ps.indexOf(guard)<ps.indexOf("$preflight = New-NodeProcess '--preflight'"));
 assert.ok(ps.indexOf(guard)<ps.indexOf('if (-not $Run) { return }'));
 assert.match(ps,/\$allowed = @\([^\r\n]*'STARTUP_VALIDATION_REQUIRES_RUN'/);
});
test('startup-only validation cannot skip approval, parameters, interactive console, routing, private directory or Job guards',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const branch=ps.indexOf('if ($ValidateStartupOnly) {');
 assert.ok(branch>0);
 const required=[
  "if (-not $report.can_prepare_run) { throw 'PREFLIGHT_BLOCKED' }",
  "if (-not ($ApprovePrivateTunnel -and $ApproveQrLogin -and $ApproveOwnerTextTransfer -and $ApproveOwnerReply)) { throw 'EXPLICIT_ACTION_APPROVAL_REQUIRED' }",
  "throw 'INVALID_RUN_PARAMETERS'",
  "if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'INTERACTIVE_NATIVE_CONSOLE_REQUIRED' }",
  '$routing = Get-ExistingRouting',
  "$routingCheck = New-NodeProcess '--routing-check'",
  "if ($routingCheck.ExitCode -ne 0 -or $routingResult.event -ne 'routing_validated')",
  '$script:directory = New-PrivateDirectory',
  '$script:job = [FeibiJob]::Create()',
  "if ($script:job -eq [IntPtr]::Zero) { throw 'WINDOWS_JOB_REQUIRED' }"
 ];
 let previous=ps.indexOf('if (-not $Run) { return }');
 for(const guard of required){const at=ps.indexOf(guard,previous);assert.ok(at>=previous&&at<branch,guard);previous=at;}
 assert.match(ps,/\[ValidateRange\(1,25200\)\]\[int\]\$Seconds = 25200/);
});
test('startup-only success is a fixed precredential record then return before managed start and hidden input, with finally cleanup retained',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const branch=ps.match(/if \(\$ValidateStartupOnly\) \{\s*Write-Host '([^'\r\n]+)'\s*return\s*\}/);
 assert.ok(branch);
 assert.deepEqual(JSON.parse(branch[1]),{event:'startup_validated',validation_scope:'before_credentials',credential_read:false,managed_supervisor_started:false});
 const managed=ps.indexOf("$script:process = New-NodeProcess '--managed'");
 const secret=ps.indexOf('$script:secureKey = Read-Host',managed);
 assert.ok(branch.index+branch[0].length<managed&&managed<secret);
 const cleanup=ps.slice(ps.lastIndexOf('} finally {'));
 assert.ok(cleanup.includes('Stop-LocalQr'));
 assert.ok(cleanup.includes('$script:jobClosed = [FeibiJob]::CloseHandle($script:job)'));
 assert.ok(cleanup.includes('[IO.Directory]::Delete($script:directory,$false)'));
 assert.ok(cleanup.includes("event='windows_launcher_cleanup'"));
 assert.ok(!cleanup.includes('$ValidateStartupOnly'));
});
test('launcher failure diagnostics expose only allowlisted reason/type and a numeric line, never raw exception text',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const diagnostic=ps.slice(ps.indexOf('  # No raw exceptions,'),ps.lastIndexOf('} finally {'));
 assert.ok(diagnostic.includes("$reason = 'CHECK_PREREQUISITES_OR_SAFE_STATUS'"));
 assert.ok(diagnostic.includes('if ($allowed -ccontains $_.Exception.Message) { $reason = $_.Exception.Message }'));
 assert.ok(diagnostic.includes("$errorType = 'UNCLASSIFIED'"));
 assert.ok(diagnostic.includes('if ($allowedTypes -ccontains $typeName) { $errorType = $typeName }'));
 const types=diagnostic.match(/\$allowedTypes = @\(([^\r\n]+)\)/);
 assert.ok(types);
 assert.match(types[1],/^'System\.[A-Za-z0-9.]+Exception'(?:,'System\.[A-Za-z0-9.]+Exception')*$/);
 assert.ok(diagnostic.includes('$sourceLine = 0'));
 assert.ok(diagnostic.includes('$sourceLine = [Math]::Max(0,[int]$_.InvocationInfo.ScriptLineNumber)'));
 const output=diagnostic.split('\n').filter(line=>line.includes('Write-Host'));
 assert.equal(output.length,1);
 assert.ok(output[0].includes("event='windows_launcher_blocked';reason=$reason;error_type=$errorType;source_line=$sourceLine"));
 assert.doesNotMatch(output[0],/\$_|\$typeName|\.Exception|\.Message|StackTrace|InvocationInfo|Format-List|Out-String/);
 assert.doesNotMatch(diagnostic,/\.StackTrace|\.ScriptStackTrace|\.ToString\(|Format-List|Out-String|Get-Variable|Get-ChildItem Env:/);
});
test('private directory is pinned to the existing project without environment changes or fallback paths',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const body=ps.slice(ps.indexOf('function New-PrivateDirectory {'),ps.indexOf('function Show-LocalQr('));
 assert.ok(body.includes("$parent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))"));
 assert.match(body,/\$parent\s*=\s*\[IO\.Path\]::GetFullPath\(\$parent\)/);
 assert.match(body,/if\s*\(-not\s+\[IO\.Directory\]::Exists\(\$parent\)\)\s*\{\s*throw 'PROJECT_DIRECTORY_REQUIRED'\s*\}/);
 assert.ok(body.indexOf("throw 'PROJECT_DIRECTORY_REQUIRED'")<body.indexOf('::CreateDirectory('));
 assert.doesNotMatch(body,/\$env:|GetTempPath|CreateTempSubdirectory|New-Item/i);
 const executable=ps.split('\n').filter(line=>!line.trim().startsWith('#')).join('\n');
 assert.doesNotMatch(executable,/\$env:[A-Za-z_][A-Za-z0-9_]*\s*=|SetEnvironmentVariable/i);
 assert.match(ps,/\$allowed\s*=\s*@\([^\r\n]*'PROJECT_DIRECTORY_REQUIRED'/);
 assert.ok(!ps.includes('LOCAL_NTFS_DIRECTORY_REQUIRED'));
});
test('project directory retains ancestor, NTFS, random-name, protected-owner ACL and empty-only cleanup guards',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const body=ps.slice(ps.indexOf('function New-PrivateDirectory {'),ps.indexOf('function Show-LocalQr('));
 for(const guard of ["$drive.DriveFormat -ne 'NTFS'",'while ($null -ne $ancestor)','[IO.FileAttributes]::ReparsePoint','$ancestor = $ancestor.Parent',"'feibi-private-' + [Guid]::NewGuid().ToString('N')",'$acl.SetOwner($sid)','$acl.SetAccessRuleProtection($true,$false)','[IO.Directory]::CreateDirectory($directory,$acl)','Get-Acl -LiteralPath $directory','$check.AreAccessRulesProtected','$check.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value','$rules.Count -ne 1',"$rules[0].FileSystemRights -ne 'FullControl'","throw 'PRIVATE_ACL_VERIFICATION_FAILED'"])assert.ok(body.includes(guard),guard);
 for(const target of ['$profiles','$script:directory'])assert.ok(ps.includes('[IO.Directory]::Delete('+target+',$false)'));
 assert.ok(body.includes('[IO.Directory]::Delete($directory,$false)'));
 assert.doesNotMatch(ps,/\[IO\.Directory\]::Delete\([^\r\n]*,\s*\$true\)|Remove-Item\b[^\r\n]*-Recurse/i);
});
test('ACL readback loads only the current PowerShell security module and fails before directory creation if it cannot load',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const body=ps.slice(ps.indexOf('function New-PrivateDirectory {'),ps.indexOf('function Show-LocalQr('));
 const imports=body.split('\n').filter(line=>/^\s*Import-Module\b/.test(line));
 assert.deepEqual(imports.map(line=>line.trim()),["Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -Scope Local -ErrorAction Stop"]);
 assert.ok(body.indexOf(imports[0])<body.indexOf('[IO.Directory]::CreateDirectory('));
 assert.ok(body.indexOf(imports[0])<body.indexOf('Get-Acl -LiteralPath $directory'));
 assert.doesNotMatch(body,/PSModulePath\s*=|-SkipEditionCheck|-Force\b|ErrorAction\s+(?:Continue|SilentlyContinue|Ignore)/i);
});
test('a newly created private directory is registered before fallible ACL readback so failure uses existing empty-only cleanup',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const body=ps.slice(ps.indexOf('function New-PrivateDirectory {'),ps.indexOf('function Show-LocalQr('));
 const executable=body.split('\n').filter(line=>!line.trim().startsWith('#')).join('\n');
 assert.match(executable,/\$null = \[IO\.Directory\]::CreateDirectory\(\$directory,\$acl\)\s*\$script:directory = \$directory\s*\$check = Get-Acl -LiteralPath \$directory/);
 assert.equal((body.match(/\$script:directory\s*=/g)||[]).length,1);
 assert.doesNotMatch(body,/\bcatch\b/);
 const cleanup=ps.slice(ps.lastIndexOf('} finally {'));
 assert.ok(cleanup.includes('if ($null -ne $script:directory -and (Test-Path -LiteralPath $script:directory))'));
 assert.ok(cleanup.includes('[IO.Directory]::Delete($script:directory,$false)'));
 assert.ok(cleanup.includes('$removed = -not (Test-Path -LiteralPath $script:directory)'));
});
test('native clipboard stdin is explicit, requires Run, and preserves the default console and hidden-input path',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 assert.match(ps,/\[switch\]\$NativeClipboard/);
 const guard="if ($NativeClipboard -and -not $Run) { throw 'NATIVE_STDIN_REQUIRES_RUN' }";
 assert.ok(ps.indexOf(guard)<ps.indexOf("$preflight = New-NodeProcess '--preflight'"));
 assert.ok(ps.includes('if ($NativeClipboard) { Assert-NativeStdinHost; Assert-NativeClipboardRetention }'));
 assert.ok(ps.includes("elseif ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'INTERACTIVE_NATIVE_CONSOLE_REQUIRED' }"));
 assert.match(ps,/\} else \{\s*\$script:secureKey = Read-Host '[^']+' -AsSecureString/);
 assert.ok(ps.includes('} else { while ([Console]::KeyAvailable) {'));
});
test('native stdin requires an exact dedicated File host and STA, rejecting abbreviated or persistent shell flags',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const host=ps.slice(ps.indexOf('function Assert-NativeStdinHost {'),ps.indexOf('function Assert-ControlInputOpen {'));
 assert.ok(host.includes("[Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA'"));
 assert.ok(host.includes("@('-nologo','-noprofile','-sta','-noninteractive') -ccontains $flag"));
 assert.ok(host.includes("$flag -ceq '-file'"));
 assert.ok(host.includes('[IO.Path]::GetFullPath($PSCommandPath),[StringComparison]::OrdinalIgnoreCase'));
 assert.ok(host.includes("$arguments[$index] -ine 'RemoteSigned'"));
 assert.ok(host.includes("if (-not $fileFound) { throw 'NATIVE_STDIN_HOST_REQUIRED' }"));
 assert.doesNotMatch(host,/Write-Host|Write-Output|Out-String|-like|-match|StartsWith\(/);
});
test('clipboard retention conditions fail closed before managed start and never read or alter clipboard content',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const gate=ps.slice(ps.indexOf('function Assert-NativeClipboardRetention {'),ps.indexOf('function Receive-StopReceipt('));
 assert.ok(gate.includes('::IsHistoryEnabled()'));
 assert.ok(gate.includes('::IsRoamingEnabled()'));
 assert.ok(gate.includes('$historyEnabled -isnot [bool] -or $roamingEnabled -isnot [bool] -or $historyEnabled -or $roamingEnabled'));
 assert.ok(gate.includes("} catch { throw 'NATIVE_CLIPBOARD_RETENTION_BLOCKED' }"));
 assert.doesNotMatch(gate,/GetText|GetContent|SetText|Clear\(|SetHistory|Write-Host|Write-Output/);
 const use=ps.indexOf('if ($NativeClipboard) { Assert-NativeStdinHost; Assert-NativeClipboardRetention }');
 assert.ok(use<ps.indexOf('$routing = Get-ExistingRouting'));
 assert.ok(use<ps.indexOf("$script:process = New-NodeProcess '--managed'"));
});
test('native credential read occurs once only after all gates, startup-only return, Job assignment and supervisor handshake',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const get='$script:runtimeKey = [Windows.Forms.Clipboard]::GetText([Windows.Forms.TextDataFormat]::UnicodeText)';
 const run=ps.slice(ps.indexOf("$script:startupStage = 'credential_check'"));
 const at=ps.indexOf(get,ps.indexOf("$script:startupStage = 'credential_check'"));
 assert.equal((run.match(/Clipboard\]::GetText\(/g)||[]).length,1);
 for(const guard of ['Assert-NativeStdinHost; Assert-NativeClipboardRetention',"throw 'EXPLICIT_ACTION_APPROVAL_REQUIRED'","throw 'INVALID_RUN_PARAMETERS'",'$script:directory = New-PrivateDirectory','if ($ValidateStartupOnly) {','if (-not [FeibiJob]::AssignProcessToJobObject',"throw 'SUPERVISOR_NOT_READY'"]){assert.ok(ps.indexOf(guard)>=0&&ps.indexOf(guard)<at,guard);}
 assert.match(ps,new RegExp('if \\(\\$NativeClipboard\\) \\{\\s*Assert-ControlInputOpen\\s*Assert-NativeClipboardRetention\\s*\\$script:runtimeKey = \\[Windows.Forms.Clipboard\\]::GetText'));
 assert.ok(ps.includes("$script:runtimeKey -cnotmatch '\\Ask-[A-Za-z0-9_-]{20,1021}\\z'"));
 assert.doesNotMatch(ps,/Get-Clipboard|Clipboard\]::(?:Clear|SetText|GetDataObject)|Write-Host[^\r\n]*\$script:runtimeKey/);
});
test('native control polling is bounded, never implicitly confirms scanning, and retains the original runtime deadline',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 assert.ok(ps.includes('for ($count = 0; $count -lt 4 -and $script:controlInput.TryTake([ref]$control); $count++)'));
 assert.match(ps,/Assert-ControlInputOpen\s*Send-Control \$control/);
 assert.doesNotMatch(ps,/Console\]::In\.ReadLineAsync|Send-Control\s+['"]confirm['"]|pending_owner_confirmation/);
 assert.match(ps,/\[ValidateRange\(1,25200\)\]\[int\]\$Seconds = 25200/);
 assert.ok(ps.includes('$clock.Elapsed.TotalSeconds -ge $Seconds'));
 const js=fs.readFileSync(new URL('./supervisor.mjs',import.meta.url),'utf8');
 assert.ok(js.includes('process.stdin.destroy();process.exitCode=1;},120000)'));
});
test('startup handshake and cleanup drain are bounded and reuse pending reads without exposing late QR payloads',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 assert.ok(ps.includes('$startupWait.Elapsed.TotalSeconds -ge 10'));
 const cleanup=ps.slice(ps.lastIndexOf('} finally {'));
 assert.ok(cleanup.includes('$script:writeOperation.Wait(1000)'));
 assert.ok(cleanup.includes('$finishWait.Elapsed.TotalSeconds -lt 12 -and $drainCount -lt 128'));
 assert.ok(cleanup.includes('if ($null -eq $script:pending) { $script:pending = $script:process.StandardOutput.ReadLineAsync() }'));
 assert.ok(cleanup.includes('$script:pending.GetAwaiter().GetResult()'));
 assert.ok(cleanup.includes('$finalLine.Length -le 4096'));
 assert.ok(cleanup.includes('Receive-StopReceipt $finalEvent'));
 assert.doesNotMatch(cleanup,/Show-LocalQr|Write-Host[^\r\n]*\$(?:finalLine|finalEvent|message)|WaitForExit\(12000\)|\.ReadLine\(|\.ReadToEnd\(/);
 assert.ok(cleanup.indexOf('Receive-StopReceipt $finalEvent')<cleanup.indexOf('[FeibiJob]::CloseHandle'));
});
test('stop evidence is typed before publication and only reconstructed fields reach stdout',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const validate=ps.slice(ps.indexOf('function Receive-StopReceipt('),ps.indexOf('function Stop-LocalQr {'));
 assert.ok(validate.includes('$Event.$name -isnot [bool]'));
 assert.ok(validate.includes("$Event.reason -cnotmatch '\\A[A-Z][A-Z_]{0,63}\\z'"));
 assert.ok(validate.includes("$Event.reason -cne 'CLEANUP_UNCONFIRMED'"));
 const branch=ps.match(/elseif \(\$event.event -eq 'bounded_windows_stopped'\) \{([\s\S]*?)\n      \}/);
 assert.ok(branch);
 assert.ok(branch[1].indexOf('Receive-StopReceipt $event')<branch[1].indexOf('Write-Host'));
 assert.doesNotMatch(branch[1],/Write-Host \$message/);
 assert.ok(branch[1].includes("event='bounded_windows_stopped';reason=$event.reason;children_exited=$event.children_exited;temporary_files_removed=$event.temporary_files_removed;account_authorization_revoked=$event.account_authorization_revoked"));
});
test('every private write has one pending operation, a short bound, and deadline/QR/EOF checks; pending failures skip graceful writes and drain',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const write=ps.slice(ps.indexOf('function Write-PrivateLine('),ps.indexOf('function New-NodeProcess('));
 assert.ok(write.includes('$null -ne $script:writeOperation -and -not $script:writeOperation.IsCompleted'));
 assert.ok(write.includes('$writeWait.ElapsedMilliseconds -ge 1000'));
 assert.ok(write.includes('[FeibiPipeWrite]::Start($Target.StandardInput.BaseStream,$bytes)'));
 assert.ok(write.includes('Assert-ControlInputOpen'));
 assert.ok(write.includes('$script:activityClock.Elapsed.TotalSeconds -ge $Seconds'));
 assert.ok(write.includes('$script:activityClock.Elapsed.TotalSeconds -ge $script:qrDeadline'));
 assert.ok(write.includes('[Windows.Forms.Application]::DoEvents()'));
 assert.ok(write.includes('if ($null -eq $script:writeOperation) { [Array]::Clear($bytes,0,$bytes.Length) }'));
 assert.doesNotMatch(write,/\.Write\(|\.Flush\(|\.Wait\(|\.Result[^\r\n]*=/);
 assert.ok(ps.indexOf('public static class FeibiPipeWrite')<ps.indexOf('$routing = Get-ExistingRouting'));
 const cleanup=ps.slice(ps.lastIndexOf('} finally {'));
 const guard='if (-not $script:pipeWriteFailed -and ($null -eq $script:writeOperation -or $script:writeOperation.IsCompleted))';
 assert.ok(cleanup.includes(guard));
 assert.ok(cleanup.indexOf(guard)<cleanup.indexOf('[FeibiPipeWrite]::Start'));
 assert.ok(cleanup.indexOf(guard)<cleanup.indexOf('$finishWait ='));
});
test('PS5.1 pure .NET private writes stay asynchronous and retain buffers until actual delayed completion or failure',{skip:process.platform!=='win32'},()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const source=[...ps.matchAll(/Add-Type -TypeDefinition @'\r?\n([\s\S]*?)\r?\n'@/g)].map(x=>x[1]).find(x=>x.includes('public static class FeibiPipeWrite'));
 assert.ok(source);
 assert.doesNotMatch(source,/Clipboard|DllImport|Process\.Start|File\.|Console\./);
 const checks=`
public sealed class SyntheticWriteStream : Stream {
 private readonly TaskCompletionSource<int> write = new TaskCompletionSource<int>();
 private readonly TaskCompletionSource<int> flush = new TaskCompletionSource<int>();
 public volatile bool Writing, Flushing; public byte[] Observed;
 public override Task WriteAsync(byte[] bytes,int offset,int count,System.Threading.CancellationToken cancellation) { Observed=bytes; Writing=true; return write.Task; }
 public override Task FlushAsync(System.Threading.CancellationToken cancellation) { Flushing=true; return flush.Task; }
 public void FinishWrite() { write.SetResult(0); } public void FinishFlush() { flush.SetResult(0); } public void FailWrite() { write.SetException(new IOException("SYNTHETIC_WRITE_FAILURE")); }
 public override bool CanRead { get { return false; } } public override bool CanSeek { get { return false; } } public override bool CanWrite { get { return true; } }
 public override long Length { get { throw new NotSupportedException(); } } public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
 public override void Flush() { throw new InvalidOperationException("SYNCHRONOUS_FLUSH_FORBIDDEN"); } public override int Read(byte[] b,int o,int n) { throw new NotSupportedException(); } public override long Seek(long offset,SeekOrigin origin) { throw new NotSupportedException(); } public override void SetLength(long value) { throw new NotSupportedException(); } public override void Write(byte[] b,int o,int n) { throw new InvalidOperationException("SYNCHRONOUS_WRITE_FORBIDDEN"); }
}
public static class FeibiPipeWriteChecks {
 private static void Check(bool value,string label) { if(!value) throw new Exception("PIPE_WRITE_CHECK_FAILED_"+label); }
 private static void Wait(Func<bool> done) { var watch=System.Diagnostics.Stopwatch.StartNew(); while(!done()) { if(watch.ElapsedMilliseconds>2000) throw new Exception("PIPE_WRITE_CHECK_TIMEOUT"); System.Threading.Thread.Sleep(1); } }
 public static string Run() {
  using(var stream=new SyntheticWriteStream()) {
   byte[] bytes=new byte[]{65,66,67}; var watch=System.Diagnostics.Stopwatch.StartNew(); Task<bool> pending=FeibiPipeWrite.Start(stream,bytes);
   Check(watch.ElapsedMilliseconds<500,"START_NONBLOCKING"); Wait(()=>stream.Writing); Check(!pending.Wait(30),"BOUNDED_WAIT"); Check(bytes[0]==65&&bytes[1]==66&&bytes[2]==67,"PENDING_BYTES_RETAINED");
   stream.FinishWrite(); Wait(()=>stream.Flushing); Check(!pending.Wait(30),"FLUSH_WAIT"); Check(bytes[0]==65,"FLUSH_PENDING_RETAINED");
   stream.FinishFlush(); Check(pending.Wait(1000)&&pending.Result,"COMPLETED"); Check(Array.TrueForAll(bytes,b=>b==0),"COMPLETED_CLEARED");
  }
  using(var stream=new SyntheticWriteStream()) { byte[] bytes=new byte[]{68,69}; Task<bool> pending=FeibiPipeWrite.Start(stream,bytes); Wait(()=>stream.Writing); Check(bytes[0]==68,"FAIL_PENDING_RETAINED"); stream.FailWrite(); Check(pending.Wait(1000)&&!pending.Result,"FAILURE_FIXED_RESULT"); Check(Array.TrueForAll(bytes,b=>b==0),"FAILED_CLEARED"); }
  return "PIPE_WRITE_CHECKS_OK";
 }
}`;
 const command="$ErrorActionPreference='Stop'; Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop; Add-Type -TypeDefinition @'\n"+source+'\n'+checks+"\n'@; [FeibiPipeWriteChecks]::Run()";
 const result=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-Command',command],{encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:16384});
 assert.equal(result.error,undefined);
 assert.equal(result.status,0,result.stderr);
 assert.equal(result.stdout.trim(),'PIPE_WRITE_CHECKS_OK');
});
test('PS5.1 pure .NET control reader handles real byte boundaries, bounded queues, EOF and idle reads without blocking its caller',{skip:process.platform!=='win32'},()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const source=[...ps.matchAll(/Add-Type -TypeDefinition @'\r?\n([\s\S]*?)\r?\n'@/g)].map(x=>x[1]).find(x=>x.includes('public sealed class FeibiControlInput'));
 assert.ok(source);
 assert.doesNotMatch(source,/Clipboard|DllImport|Process\.Start|File\.|Console\./);
 const keyPattern=ps.match(/\$script:runtimeKey -cnotmatch '([^']+)'/)[1];
 assert.equal(keyPattern,'\\Ask-[A-Za-z0-9_-]{20,1021}\\z');
 const checks=`
public sealed class SyntheticControlStream : Stream {
 private readonly object gate = new object(); private readonly Queue<byte> bytes = new Queue<byte>(); private bool ended, fault; public volatile bool Reading;
 public void Send(byte[] value) { lock(gate) { foreach(byte b in value) bytes.Enqueue(b); Monitor.PulseAll(gate); } }
 public void Send(string value) { Send(System.Text.Encoding.ASCII.GetBytes(value)); }
 public void End() { lock(gate) { ended=true; Monitor.PulseAll(gate); } }
 public void Fail() { lock(gate) { fault=true; Monitor.PulseAll(gate); } }
 public override int Read(byte[] buffer,int offset,int count) { lock(gate) { Reading=true; while(bytes.Count==0&&!ended&&!fault) Monitor.Wait(gate); if(fault) throw new IOException("SYNTHETIC_READ_FAILURE"); int n=0; while(n<count&&bytes.Count>0) buffer[offset+n++]=bytes.Dequeue(); return n; } }
 protected override void Dispose(bool disposing) { End(); base.Dispose(disposing); }
 public override bool CanRead { get { return true; } } public override bool CanSeek { get { return false; } } public override bool CanWrite { get { return false; } }
 public override long Length { get { throw new NotSupportedException(); } } public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
 public override void Flush() {} public override long Seek(long offset,SeekOrigin origin) { throw new NotSupportedException(); } public override void SetLength(long value) { throw new NotSupportedException(); } public override void Write(byte[] b,int o,int n) { throw new NotSupportedException(); }
}
public static class FeibiControlInputChecks {
 private static void Check(bool value,string label) { if(!value) throw new Exception("CONTROL_READER_CHECK_FAILED_"+label); }
 private static void Wait(Func<bool> done,string label) { var watch=System.Diagnostics.Stopwatch.StartNew(); while(!done()) { if(watch.ElapsedMilliseconds>2000) throw new Exception("CONTROL_READER_TIMEOUT_"+label); Thread.Sleep(1); } }
 private static void Expect(FeibiControlInput reader,string expected) { string value=null; Wait(()=>reader.TryTake(out value),"COMMAND"); Check(value==expected,"COMMAND"); }
 private static void Rejected(byte[] bytes,string expected,bool end) { using(var stream=new SyntheticControlStream()) using(var reader=new FeibiControlInput(stream)) { reader.Start(); stream.Send(bytes); if(end) stream.End(); Wait(()=>reader.StopReason!="","REJECT"); Check(reader.StopReason==expected,"REASON"); string value; Check(!reader.TryTake(out value),"NO_QUEUED_COMMAND"); } }
 public static string Run() {
  using(var stream=new SyntheticControlStream()) using(var reader=new FeibiControlInput(stream)) {
   var watch=System.Diagnostics.Stopwatch.StartNew(); reader.Start(); Check(watch.ElapsedMilliseconds<500,"START_NONBLOCKING"); Wait(()=>stream.Reading,"IDLE_READ"); Check(reader.StopReason=="","IDLE_OPEN");
   stream.Send("sta"); Thread.Sleep(10); string pending; Check(!reader.TryTake(out pending),"PARTIAL"); stream.Send("tus\\r"); Expect(reader,"status"); stream.Send("\\n");
   foreach(string command in new[]{"approve","qr","poll","confirm"}) { stream.Send(command+"\\n"); Expect(reader,command); }
   stream.Send("stop\\n"); Wait(()=>reader.StopReason!="","STOP"); Check(reader.StopReason=="OPERATOR_STOP","STOP_REASON"); Check(!reader.TryTake(out pending),"STOP_PRIORITY");
  }
  Rejected(System.Text.Encoding.ASCII.GetBytes("aaaaaaaa"),"INPUT_BOUND_STOP",false);
  foreach(byte invalid in new byte[]{0,9,32,65,128,255}) Rejected(new byte[]{invalid},"INVALID_OPERATOR_CONTROL",false);
  Rejected(System.Text.Encoding.ASCII.GetBytes("unknown\\n"),"INVALID_OPERATOR_CONTROL",false);
  Rejected(System.Text.Encoding.ASCII.GetBytes("\\n"),"INVALID_OPERATOR_CONTROL",false);
  Rejected(System.Text.Encoding.ASCII.GetBytes("stat"),"CONTROL_PIPE_CLOSED",true);
  Rejected(new byte[0],"CONTROL_PIPE_CLOSED",true);
  string flood=""; for(int i=0;i<17;i++) flood+="status\\n"; Rejected(System.Text.Encoding.ASCII.GetBytes(flood),"INPUT_BOUND_STOP",false);
  using(var stream=new SyntheticControlStream()) using(var reader=new FeibiControlInput(stream)) { reader.Start(); for(int i=0;i<600;i++) { stream.Send("status\\n"); Expect(reader,"status"); } Check(reader.StopReason=="","NO_LIFETIME_INPUT_LIMIT"); stream.Send("stop\\n"); Wait(()=>reader.StopReason!="","STOP"); Check(reader.StopReason=="OPERATOR_STOP","STOP_AFTER_MANY_COMMANDS"); }
  using(var stream=new SyntheticControlStream()) using(var reader=new FeibiControlInput(stream)) { reader.Start(); stream.Fail(); Wait(()=>reader.StopReason!="","READ_FAILURE"); Check(reader.StopReason=="CONTROL_PIPE_CLOSED","READ_FAILURE_REASON"); }
  string pattern=@"${keyPattern}", synthetic="sk-"+new String('A',20);
  Check(System.Text.RegularExpressions.Regex.IsMatch(synthetic,pattern),"SYNTHETIC_KEY_ACCEPTED");
  Check(System.Text.RegularExpressions.Regex.IsMatch("sk-"+new String('A',1021),pattern),"MAXIMUM_KEY_ACCEPTED");
  foreach(string rejected in new[]{synthetic+"\\n",synthetic+"\\r\\n",synthetic+"\\0","sk-"+new String('A',19),"sk-"+new String('A',1022)," "+synthetic}) Check(!System.Text.RegularExpressions.Regex.IsMatch(rejected,pattern),"SYNTHETIC_KEY_REJECTED");
  return "CONTROL_READER_CHECKS_OK";
 }
}`;
 const command="$ErrorActionPreference='Stop'; Import-Module (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Utility\\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop; Add-Type -TypeDefinition @'\n"+source+'\n'+checks+"\n'@; [FeibiControlInputChecks]::Run()";
 const result=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-Command',command],{encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:16384});
 assert.equal(result.error,undefined);
 assert.equal(result.status,0,result.stderr);
 assert.equal(result.stdout.trim(),'CONTROL_READER_CHECKS_OK');
});
test('no native socket/listener/DNS attempts occurred',()=>assert.equal(networkCalls,0));

test('main bootstrap decoding preserves exact schema for the single start validation boundary',()=>{const line=JSON.stringify(input());const decoded=decodeBootstrapLine(line);assert.ok(!Object.hasOwn(decoded,'routing'));const validated=validateBootstrap(decoded,{platform:'win32'});assert.equal(validated.routing.proxyUrl,'http://proxy.invalid:8080/');const code=fs.readFileSync(new URL('./supervisor.mjs',import.meta.url),'utf8');assert.ok(code.includes('input=decodeBootstrapLine(line);'));assert.ok(!code.includes('input=validateBootstrap(JSON.parse(line))'));});

test('PowerShell own wallclock bound and ANY stopped receipt reach Job cleanup',()=>{const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');assert.ok(ps.includes('[Diagnostics.Stopwatch]::StartNew()'));assert.ok(ps.includes('$clock.Elapsed.TotalSeconds -ge $Seconds'));assert.match(ps,/if \(\$event.event -eq 'bounded_windows_stopped'\)[\s\S]*?break/);assert.ok(ps.includes('supervisor_cleanup_confirmed=$script:cleanupConfirmed'));});

test('PowerShell independently closes QR at bounded expiry without later IPC',()=>{const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');assert.ok(ps.includes('$clock.Elapsed.TotalSeconds -ge $script:qrDeadline'));assert.ok(ps.includes('$event.expires_at_unix_ms'));assert.ok(ps.includes('$script:jobClosed = [FeibiJob]::CloseHandle'));assert.ok(ps.includes('supervisor_exited=$script:supervisorExited'));});

test('private stdin writes UTF-8 bytes, and streaming decoder protects split Chinese paths',()=>{const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8'),js=fs.readFileSync(new URL('./supervisor.mjs',import.meta.url),'utf8');assert.ok(ps.includes('[Text.Encoding]::UTF8.GetBytes'));assert.ok(ps.includes('[FeibiPipeWrite]::Start($Target.StandardInput.BaseStream,$bytes)'));assert.ok(!ps.includes('StandardInput.WriteLine'));assert.ok(js.includes("new StringDecoder('utf8')"));assert.ok(js.includes('decoder.write(chunk)'));const x={...input(),directory:'/tmp/用户/feibi-private-'+'a'.repeat(32)};const bytes=Buffer.from(JSON.stringify(x));const decoder=new StringDecoder('utf8');let out='';for(const byte of bytes)out+=decoder.write(Buffer.from([byte]));out+=decoder.end();assert.equal(decodeBootstrapLine(out).directory,x.directory);});

test('only initial routing/bootstrap stream accepts one UTF-8 preamble, including byte splits',()=>{
 for(const value of [input(),snapshot]){const bytes=Buffer.concat([Buffer.from([0xef,0xbb,0xbf]),Buffer.from(JSON.stringify(value))]),decoder=new StringDecoder('utf8');let text='';for(const byte of bytes)text+=decoder.write(Buffer.from([byte]));text+=decoder.end();assert.deepEqual(decodeBootstrapLine(text),value);assert.throws(()=>decodeBootstrapLine('\ufeff'+text));}
 assert.throws(()=>parseControl('\ufeff{"action":"stop"}'));
 const js=fs.readFileSync(new URL('./supervisor.mjs',import.meta.url),'utf8');assert.ok(js.includes("snapshot:decodeBootstrapLine(Buffer.concat(chunks).toString('utf8'))"));
});

test('seven-hour bootstrap accepts the limit and retains shorter durations',()=>{
 assert.equal(preflight({platform:'win32',arch:'x64',node:'24.22.1'}).maximum_seconds,25200);
 for(const seconds of [1,1800,7200,25200])assert.equal(validateBootstrap({...input(),seconds},{platform:'win32'}).seconds,seconds);
 for(const seconds of [0,25201,1.5])assert.throws(()=>validateBootstrap({...input(),seconds},{platform:'win32'}));
});

test('started receipt reports the existing UTC deadline without resetting the run',async()=>{
 const began=Date.parse('2030-01-01T00:00:00Z');let now=began,resolveStarted,rejectStarted;const environments=[];
 const started=new Promise((resolve,reject)=>{resolveStarted=resolve;rejectStarted=reject;});
 const s=new Supervisor({now:()=>now,
  emit:event=>{if(event.event==='bounded_windows_started')resolveStarted(event);else if(event.event==='bounded_windows_stopped')rejectStarted(new Error(event.reason));},
  request:async()=>{now+=375;return status();},
  spawnChild:(_file,_args,options)=>{environments.push({...options.env});return child();},
  fsImpl:{lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>false}),readdirSync:()=>[],existsSync:()=>false,rmdirSync:()=>{}}
 });
 const running=s.start({...input(),seconds:7200});
 try {
  const receipt=await started;
  assert.deepEqual(receipt,{event:'bounded_windows_started',maximum_seconds:7200,deadline_utc:'2030-01-01T02:00:00.000Z',local_mcp_authenticated:true,qr_started:false,memory_only:true});
  assert.equal(Date.parse(receipt.deadline_utc),s.deadline);
  assert.equal(environments[0].WEIXIN_DEADLINE_UNIX_MS,String(Date.parse(receipt.deadline_utc)));
  assert.equal(s.deadline,began+7200000);assert.equal(now,began+375);
 } finally {await s.stop('OPERATOR_STOP');await running;}
});

function qrPollingFixture(request,emit=()=>{}){
 const s=new Supervisor({now:()=>1000000,request,emit,spawnChild:()=>{
  const p=child();p.stdin.on('finish',()=>{p.stdout.emit('data',Buffer.from([137,80,78,71,13,10,26,10]));p.exitCode=0;p.emit('exit',0);});return p;
 },fsImpl:{existsSync:()=>false,rmdirSync:()=>{}}});
 s.config=config();s.keys={operator:'SYNTHETIC_OPERATOR'};s.deadline=8200000;return s;
}
test('QR display immediately starts serial long polling and pauses for human owner confirmation',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const events=[],paths=[],phases=['wait','scaned','pending_owner_confirmation'];
 const s=qrPollingFixture(async request=>{paths.push(request.path);if(request.path==='/local/qr-start')return{qrPayload:'SYNTHETIC_QR',expiresInMs:300000};return{...session(),phase:phases.shift()};},event=>events.push(event));
 try{
  await s.qr();assert.equal(events[0].event,'private_qr_png');assert.deepEqual(paths,['/local/qr-start']);
  for(const delay of [0,1000,1000]){t.mock.timers.tick(delay);await s.queue;}
  assert.deepEqual(paths,['/local/qr-start','/local/qr-poll','/local/qr-poll','/local/qr-poll']);
  assert.equal(events.filter(x=>x.event==='qr_closed').length,1);assert.equal(s.qrActive,false);
  assert.equal(events.findLast(x=>x.event==='operator_result').result.phase,'pending_owner_confirmation');
  t.mock.timers.tick(10000);await s.queue;assert.equal(paths.length,4);assert.equal(s.deadline,8200000);
 }finally{await s.stop('OPERATOR_STOP');}
});
test('automatic and manual QR polls never overlap or leave duplicate polling loops',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 let release,active=0,maximumActive=0,calls=0;
 const s=qrPollingFixture(async()=>{calls++;active++;maximumActive=Math.max(maximumActive,active);if(calls===1)await new Promise(r=>{release=r;});active--;return{...session(),phase:calls===1?'wait':'pending_owner_confirmation'};});
 s.qrActive=true;
 try{
  s.scheduleQrPoll(0);t.mock.timers.tick(0);await Promise.resolve();assert.equal(calls,1);
  s.control('{"action":"qr_poll"}');t.mock.timers.tick(10000);assert.equal(calls,1);
  release();await s.queue;assert.equal(calls,2);assert.equal(maximumActive,1);
  t.mock.timers.tick(10000);await s.queue;assert.equal(calls,2);
 }finally{await s.stop('OPERATOR_STOP');}
});
test('automatic QR polling pauses on verification or errors and respects stop and deadline',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const reason of ['need_verifycode','QR_EXPIRED','ILINK_AUTHORIZATION_STOP','ILINK_PAYMENT_OR_QUOTA_STOP','EXACT_ILINK_ORIGIN_REVIEW_REQUIRED','ILINK_TRANSPORT_FAILED']){
  let calls=0;const events=[];const s=qrPollingFixture(async()=>{calls++;if(reason==='need_verifycode')return{...session(),phase:reason};throw Object.assign(new Error(reason),{code:reason});},e=>events.push(e));s.qrActive=true;
  try{
   s.scheduleQrPoll(0);t.mock.timers.tick(0);await s.queue;t.mock.timers.tick(10000);await s.queue;
   assert.equal(calls,1,reason);assert.equal(s.stopped,false);
   if(reason==='QR_EXPIRED'){assert.equal(s.qrActive,false);assert.ok(events.some(x=>x.event==='qr_closed'));}
  }finally{await s.stop('OPERATOR_STOP');}
 }
 let calls=0;const expired=qrPollingFixture(async()=>{calls++;});expired.qrActive=true;expired.deadline=1000000;
 expired.scheduleQrPoll(0);t.mock.timers.tick(1000);await expired.queue;assert.equal(calls,0);await expired.stop('TIME_LIMIT_REACHED');
 const stopped=qrPollingFixture(async()=>{calls++;});stopped.qrActive=true;stopped.scheduleQrPoll(1000);await stopped.stop('OPERATOR_STOP');t.mock.timers.tick(1000);await stopped.queue;assert.equal(calls,0);
 assert.equal(safeSession({...session(),phase:'qr_expired'}).phase,'qr_expired');
});

test('optional absolute deadline validates canonical UTC without changing existing bootstrap fields',()=>{
 const cutoff='2030-01-01T05:00:00.000Z';assert.equal(validateBootstrap({...input(),deadline_utc:cutoff},{platform:'win32'}).deadline_utc,cutoff);
 assert.equal(validateBootstrap(input(),{platform:'win32'}).deadline_utc,undefined);
 for(const deadline_utc of ['',null,123,'2030-01-01T04:46:03Z','2026-02-30T05:00:00.000Z','2030-01-01T05:00:00.000+00:00'])assert.throws(()=>validateBootstrap({...input(),deadline_utc},{platform:'win32'}));
});
test('absolute deadline uses the earlier bound for the receipt, child and stop timer',async t=>{
 t.mock.timers.enable({apis:['setTimeout','setInterval']});
 const began=Date.parse('2030-01-01T03:00:00Z');
 for(const absoluteMs of [1000,10000]){
  let started;const receipt=new Promise(resolve=>{started=resolve;}),events=[],envs=[];
  const s=new Supervisor({now:()=>began,emit:e=>{events.push(e);if(e.event==='bounded_windows_started')started(e);},request:async()=>status(),spawnChild:(_file,_args,options)=>{envs.push({...options.env});return child();},fsImpl:{lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>false}),readdirSync:()=>[],existsSync:()=>false,rmdirSync:()=>{}}});
  const running=s.start({...input(),seconds:5,deadline_utc:new Date(began+absoluteMs).toISOString()});
  try{
   const actual=await receipt,remaining=Math.min(5000,absoluteMs);
   assert.equal(Date.parse(actual.deadline_utc),began+remaining);assert.equal(envs[0].WEIXIN_DEADLINE_UNIX_MS,String(began+remaining));
   t.mock.timers.tick(remaining-1);assert.equal(s.stopped,false);
   t.mock.timers.tick(1);await running;assert.equal(events.at(-1).reason,'TIME_LIMIT_REACHED');
  }finally{await s.stop('OPERATOR_STOP');}
 }
});
test('expired absolute deadline rejects bootstrap before any child or private filesystem access',async()=>{
 const began=Date.parse('2030-01-01T03:00:00Z');let touched=0;
 for(const cutoff of [began-1,began]){
  const s=new Supervisor({now:()=>began,spawnChild:()=>{touched++;throw new Error('must not spawn');},fsImpl:{lstatSync:()=>{touched++;throw new Error('must not read');}}});
  await assert.rejects(s.start({...input(),deadline_utc:new Date(cutoff).toISOString()}),e=>e.code==='SESSION_STOPPED_OR_EXPIRED');
 }
 assert.equal(touched,0);
});

test('standalone launcher forwards only existing nonsecret run parameters to a separate console', {skip:process.platform!=='win32'},()=>{
 const path=new URL('./start.ps1',import.meta.url).pathname.replace(/^\/([A-Z]:)/i,'$1').replaceAll('/','\\');
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const fixtureDir=fs.mkdtempSync(process.env.TEMP+'\\feibi-standalone-test-');
 const fixturePath=fixtureDir+'\\launcher fixture.ps1';
 const script=[
  "$ErrorActionPreference='Stop';$tokens=$null;$errors=$null",
  "$ast=[Management.Automation.Language.Parser]::ParseFile('"+path.replaceAll("'","''")+"',[ref]$tokens,[ref]$errors)",
  "if($errors.Count){throw 'PARSE_FAILED'}",
  ps.slice(ps.indexOf('function Quote-Argument('),ps.indexOf('function Write-PrivateLine(')),
  "$NativeClipboard=$true;$StoredCredential=$false;$ApprovePrivateTunnel=$true;$ApproveQrLogin=$true;$ApproveOwnerTextTransfer=$true;$ApproveOwnerReply=$true",
  "$TunnelId='tunnel_'+('a'*32);$OwnerNonce='bind:synthetic_nonce_123456';$ExpectedSuffix='abcd';$Seconds=77;$DeadlineUtc='2030-01-02T03:04:05.006Z'",
  "function Start-Process { param($FilePath,$ArgumentList,$WorkingDirectory,$WindowStyle,[switch]$PassThru) $script:launch=@{file=$FilePath;arguments=$ArgumentList;directory=$WorkingDirectory;style=$WindowStyle;pass_thru=[bool]$PassThru};$p=[pscustomobject]@{Id=123};Add-Member -InputObject $p -MemberType ScriptMethod -Name Dispose -Value {};return $p }",
  "function Write-Host {param($Object) $script:receipt=$Object | ConvertFrom-Json}",
  "Start-StandaloneHost",
  "if($launch.style -ne 'Normal' -or -not $launch.pass_thru){throw 'CONSOLE_MODE'}",
  "$want='-File \"'+$PSCommandPath+'\" -Run -StandaloneChild'",
  "if(-not $launch.arguments.Contains($want) -or $launch.arguments -match '(?:^| )-(?:Standalone(?: |$)|NoExit|NoNewWindow|Redirect)'){throw 'HOST_ARGUMENTS'}",
  "foreach($flag in @('-NativeClipboard','-ApprovePrivateTunnel','-ApproveQrLogin','-ApproveOwnerTextTransfer','-ApproveOwnerReply','-Seconds 77','-DeadlineUtc \"2030-01-02T03:04:05.006Z\"')){if(-not $launch.arguments.Contains($flag)){throw 'PARAMETER_LOST'}}",
  "if($receipt.backend_started -ne $false -or $receipt.control -ne 'local_console' -or $receipt.pid -ne 123){throw 'MISLEADING_RECEIPT'}",
  "$NativeClipboard=$false;$ExpectedSuffix='';$DeadlineUtc='';Start-StandaloneHost",
  "if($launch.arguments -match '-NativeClipboard|-ExpectedSuffix|-DeadlineUtc'){throw 'OPTIONAL_PARAMETER_LEAK'}",
  "$StoredCredential=$true;Start-StandaloneHost;if(-not $launch.arguments.Contains('-StoredCredential') -or $launch.arguments.Contains('-NativeClipboard')){throw 'STORED_MODE_LOST'}",
  "[Console]::WriteLine('STANDALONE_ARGUMENTS_OK')"
 ].join('\n');
 fs.writeFileSync(fixturePath,script);
 let r;
 try {
  r=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',fixturePath],{encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:8192});
 } finally { fs.unlinkSync(fixturePath);fs.rmdirSync(fixtureDir); }
 assert.equal(r.status,0,r.stderr||r.stdout);assert.match(r.stdout,/STANDALONE_ARGUMENTS_OK/);
});

test('standalone handoff precedes credentials and actual hosts retain single-instance, stop and deadline cleanup',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const main=ps.slice(ps.indexOf("  if ($Standalone -and (-not $Run"));
 const handoff=main.indexOf('if ($Standalone) { Start-StandaloneHost; return }');
 for(const guard of ["throw 'EXPLICIT_ACTION_APPROVAL_REQUIRED'","throw 'INVALID_RUN_PARAMETERS'",'$script:absoluteDeadline = $parsedDeadline.ToUnixTimeMilliseconds()'])assert.ok(main.indexOf(guard)<handoff,guard);
 assert.ok(handoff>=0);
 for(const operation of ['Enter-RunInstance','Assert-NativeStdinHost; Assert-NativeClipboardRetention','$routing = Get-ExistingRouting','$script:directory = New-PrivateDirectory','[Windows.Forms.Clipboard]::GetText'])assert.ok(main.indexOf(operation,handoff)>handoff,operation);
 assert.match(ps,/if \(\$Run -and -not \$Standalone\) \{ Write-Host/);
 assert.ok(ps.includes("'BRIDGE_ALREADY_RUNNING'"));assert.ok(ps.includes('$script:instanceMutex.WaitOne(0)'));
 const finallyAt=ps.lastIndexOf('  if ($script:job -ne [IntPtr]::Zero)');
 assert.ok(ps.indexOf('$script:instanceMutex.ReleaseMutex()',finallyAt)>finallyAt);
 assert.ok(ps.includes('if(command == "stop") { Stop("OPERATOR_STOP"); return false; }'));
 assert.ok(ps.includes('[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() -ge $script:absoluteDeadline'));
});

test('standalone result keeps a failed host exit readable without credentials or raw exceptions', {skip:process.platform!=='win32'},()=>{
 const dir=fs.mkdtempSync(process.env.TEMP+'\\feibi-result-failure-');
 const script=dir+'\\start.ps1',stub=dir+'\\supervisor.mjs',resultFile=dir+'\\standalone-result.json';
 fs.copyFileSync(new URL('./start.ps1',import.meta.url),script);
 fs.writeFileSync(stub,'console.log(JSON.stringify({can_prepare_run:true}));');
 try {
  const r=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-STA','-ExecutionPolicy','RemoteSigned','-File',script,'-Run','-StandaloneChild'],{encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:8192});
  assert.equal(r.status,1,r.stderr||r.stdout);
  const result=JSON.parse(fs.readFileSync(resultFile,'utf8'));
  assert.equal(result.pid,r.pid);assert.equal(result.event,'blocked');assert.equal(result.stage,'preflight');
  assert.equal(result.code,'EXPLICIT_ACTION_APPROVAL_REQUIRED');assert.equal(result.exit_code,1);
  assert.equal(result.deadline_utc,'');assert.match(result.error_type,/RuntimeException$/);
  assert.deepEqual(Object.keys(result).sort(),['pid','event','stage','error_type','code','exit_code','deadline_utc','control_directory'].sort());
 } finally {for(const file of [resultFile,script,stub])if(fs.existsSync(file))fs.unlinkSync(file);fs.rmdirSync(dir);}
});

test('standalone success result copies only the confirmed deadline and survives a normal exit', {skip:process.platform!=='win32'},()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8');
 const start=ps.indexOf("      elseif ($event.event -eq 'bounded_windows_started') {");
 const end=ps.indexOf("\n      elseif (@('operator_result'",start);
 assert.ok(start>=0&&end>start);
 const branch=ps.slice(start,end).replace('elseif','if');
 const fn=ps.slice(ps.indexOf('function Write-StandaloneResult('),ps.indexOf('function Start-StandaloneHost {'));
 const dir=fs.mkdtempSync(process.env.TEMP+'\\feibi-result-success-');
 const script=dir+'\\fixture.ps1',resultFile=dir+'\\standalone-result.json';
 fs.writeFileSync(script,[
 "$ErrorActionPreference='Stop';$StandaloneChild=$true;$script:startupStage='bootstrap';$script:confirmedDeadline=''",
 fn,
 "$event=[pscustomobject]@{event='bounded_windows_started';deadline_utc='2030-01-02T03:04:05.006Z';token='SYNTHETIC_SECRET_MUST_NOT_PERSIST'};$message=''",
 branch,
 "$r=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'standalone-result.json') -Raw | ConvertFrom-Json",
 "if($r.event -ne 'started' -or $r.stage -ne 'running' -or $null -ne $r.exit_code){throw 'START_RECEIPT_FAILED'}",
 "Write-StandaloneResult 'stopped' 'OPERATOR_STOP' '' 0",
 "exit 0"
 ].join('\n'));
 try{
  const r=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-ExecutionPolicy','RemoteSigned','-File',script],{encoding:'utf8',windowsHide:true,timeout:15000,maxBuffer:8192});
  assert.equal(r.status,0,r.stderr||r.stdout);
  const raw=fs.readFileSync(resultFile,'utf8'),result=JSON.parse(raw);
  assert.equal(result.event,'stopped');assert.equal(result.exit_code,0);
  assert.equal(result.deadline_utc,'2030-01-02T03:04:05.006Z');
  assert.equal(result.code,'OPERATOR_STOP');assert.ok(!raw.includes('SYNTHETIC_SECRET'));
  assert.deepEqual(Object.keys(result).sort(),['pid','event','stage','error_type','code','exit_code','deadline_utc','control_directory'].sort());
 } finally {for(const file of [resultFile,script])if(fs.existsSync(file))fs.unlinkSync(file);fs.rmdirSync(dir);}
});

test('receive diagnostics reach local safe status with only fixed codes and numeric counts',()=>{
 const x=status(),d={phase:'filtered',reason:'none',last_started_at_ms:1000,last_finished_at_ms:1001,last_http_status:200,polls:1,successful_polls:1,failures:0,received:1,accepted:0,skipped:1,duplicates:0,rejected_identity:1,rejected_freshness:0,rejected_shape:0,last_shape_reason:'text_item'};
 x.mcp.poll_diagnostic={...d,token:'synthetic-private-token',body:'synthetic private body'};
 assert.deepEqual(safeStatus(x).mcp.poll_diagnostic,d);
 x.mcp.poll_diagnostic.last_shape_reason='private raw value';assert.throws(()=>safeStatus(x));x.mcp.poll_diagnostic.last_shape_reason='text_item';
 x.mcp.poll_diagnostic.reason='private_unknown_error';assert.throws(()=>safeStatus(x));
});

test('seven-hour startup still honors the exact extended absolute cutoff',async()=>{
 const began=Date.parse('2030-01-01T04:30:00Z'),cutoff='2030-01-01T10:00:00.000Z';let ready;const started=new Promise(r=>{ready=r;}),envs=[];
 const s=new Supervisor({now:()=>began,emit:e=>{if(e.event==='bounded_windows_started')ready(e);},request:async()=>status(),spawnChild:(_file,_args,o)=>{envs.push({...o.env});return child();},fsImpl:{lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>false}),readdirSync:()=>[],existsSync:()=>false,rmdirSync:()=>{}}});
 const running=s.start({...input(),seconds:25200,deadline_utc:cutoff});
 try{const result=await started;assert.equal(result.deadline_utc,cutoff);assert.equal(result.maximum_seconds,25200);assert.equal(envs[0].WEIXIN_DEADLINE_UNIX_MS,String(Date.parse(cutoff)));}
 finally{await s.stop('OPERATOR_STOP');await running;}
});

const DPAPI_TEST_SOURCE="$ErrorActionPreference='Stop'\n$tokens=$null;$errors=$null\n$ast=[Management.Automation.Language.Parser]::ParseFile('__SOURCE__',[ref]$tokens,[ref]$errors)\nif($errors.Count){throw 'PARSE_FAILED'}\n$names=@('Get-FeibiCredentialPath','Get-CredentialExpiry','Assert-CredentialPrivatePath','Initialize-FeibiCredentialDirectory','Save-FeibiCredential','Read-FeibiCredential')\n$ast.FindAll({param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $a.Name},$true) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }\nfunction Get-FeibiCredentialPath { return Join-Path $PSScriptRoot 'credentials\\tunnel-key.dpapi' }\nfunction Expect-Code([scriptblock]$Action,[string]$Code) {\n  try { & $Action; throw 'EXPECTED_FAILURE_MISSING' } catch { if($_.Exception.Message -cne $Code){throw 'UNEXPECTED_FIXED_CODE'} }\n}\nfunction Put-SyntheticBlob([string]$Expiry) {\n  $bytes=[Text.Encoding]::UTF8.GetBytes((@{version=1;key='sk-SYNTHETIC_DPAPI_FIXTURE_ONLY_123456789';expires_utc=$Expiry}|ConvertTo-Json -Compress))\n  try {$blob=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);[IO.File]::WriteAllBytes((Get-FeibiCredentialPath),$blob)}\n  finally{[Array]::Clear($bytes,0,$bytes.Length)}\n}\nExpect-Code {Read-FeibiCredential} 'STORED_CREDENTIAL_MISSING'\n$key=New-Object Security.SecureString\nforeach($ch in 'sk-SYNTHETIC_DPAPI_FIXTURE_ONLY_123456789'.ToCharArray()){$key.AppendChar($ch)}\n$key.MakeReadOnly()\n$expiry=[DateTime]::UtcNow.AddDays(1).ToString(\"yyyy-MM-dd'T'HH:mm:ss.fff'Z'\")\nExpect-Code {Save-FeibiCredential $key '2000-01-01T00:00:00.000Z'} 'STORED_CREDENTIAL_EXPIRED'\nExpect-Code {Save-FeibiCredential $key ([DateTime]::UtcNow.AddDays(31).ToString(\"yyyy-MM-dd'T'HH:mm:ss.fff'Z'\"))} 'STORED_CREDENTIAL_INVALID'\n$saved=Save-FeibiCredential $key $expiry\nif(-not $saved.saved -or $saved.storage -ne 'windows_dpapi_current_user'){throw 'SAVE_RESULT_FAILED'}\nExpect-Code {Save-FeibiCredential $key $expiry} 'STORED_CREDENTIAL_ALREADY_EXISTS'\n$raw=[IO.File]::ReadAllBytes((Get-FeibiCredentialPath))\nif([Text.Encoding]::UTF8.GetString($raw).Contains('SYNTHETIC_DPAPI_FIXTURE')){throw 'PLAINTEXT_ON_DISK'}\n$loaded=Read-FeibiCredential\nif($loaded.key -isnot [Security.SecureString] -or $loaded.expires_utc -cne $expiry){throw 'LOAD_SHAPE_FAILED'}\n$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($loaded.key)\ntry{if([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) -cne 'sk-SYNTHETIC_DPAPI_FIXTURE_ONLY_123456789'){throw 'ROUNDTRIP_FAILED'}}\nfinally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$loaded.key.Dispose()}\n[IO.File]::WriteAllBytes((Get-FeibiCredentialPath),[byte[]](1,2,3))\nExpect-Code {Read-FeibiCredential} 'STORED_CREDENTIAL_DECRYPT_FAILED'\nPut-SyntheticBlob '2000-01-01T00:00:00.000Z'\nExpect-Code {Read-FeibiCredential} 'STORED_CREDENTIAL_EXPIRED'\n$script:nonPrivatePath=Join-Path $PSScriptRoot 'unsafe-key.dpapi'\n[IO.File]::WriteAllBytes($script:nonPrivatePath,$raw)\nfunction Get-FeibiCredentialPath { return $script:nonPrivatePath }\nExpect-Code {Read-FeibiCredential} 'STORED_CREDENTIAL_NOT_PRIVATE'\n$key.Dispose()\n[Console]::WriteLine('DPAPI_VIRTUAL_CHECKS_OK')\n";

test('DPAPI virtual values roundtrip with private ACL and fixed missing/decrypt/expiry failures', {skip:process.platform!=='win32'},()=>{
 const dir=fs.mkdtempSync(process.env.TEMP+'\\feibi-dpapi-test-'),file=dir+'\\fixture.ps1',data=dir+'\\credentials\\tunnel-key.dpapi';
 const source=new URL('./start.ps1',import.meta.url).pathname.replace(/^\/([A-Z]:)/i,'$1').replaceAll('/','\\');
 fs.writeFileSync(file,DPAPI_TEST_SOURCE.replace('__SOURCE__',source.replaceAll("'","''")));
 try{
  const r=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-STA','-ExecutionPolicy','RemoteSigned','-File',file],{encoding:'utf8',windowsHide:true,timeout:20000,maxBuffer:8192});
  assert.equal(r.status,0,r.stderr||r.stdout);assert.match(r.stdout,/DPAPI_VIRTUAL_CHECKS_OK/);
 }finally{for(const p of [data,file,dir+'\\unsafe-key.dpapi'])if(fs.existsSync(p))fs.unlinkSync(p);if(fs.existsSync(dir+'\\credentials'))fs.rmdirSync(dir+'\\credentials');fs.rmdirSync(dir);}
});
test('stored credential startup preserves gates, private IPC and deadline, without a clipboard fallback',()=>{
 const ps=fs.readFileSync(new URL('./start.ps1',import.meta.url),'utf8').replace(/\r\n/g,'\n');
 assert.ok(ps.includes("'NativeClipboard','StoredCredential','ApprovePrivateTunnel'"));
 assert.ok(ps.includes("if ($StoredCredential -and (-not $Run -or $NativeClipboard -or $StoreCredential))"));
 const at=ps.indexOf('$stored = Read-FeibiCredential');
 for(const guard of ["throw 'EXPLICIT_ACTION_APPROVAL_REQUIRED'","$script:directory = New-PrivateDirectory",'if ($ValidateStartupOnly) {','if (-not [FeibiJob]::AssignProcessToJobObject',"throw 'SUPERVISOR_NOT_READY'"])assert.ok(ps.indexOf(guard)<at,guard);
 const branch=ps.slice(at,ps.indexOf("    } else {\n      $script:secureKey = Read-Host",at));
 assert.ok(!branch.includes('Clipboard'));assert.ok(branch.includes('$credentialDeadline -lt $script:absoluteDeadline'));
 assert.ok(ps.indexOf('Write-PrivateLine $script:process ($bootstrap',at)>at);
 const storage=ps.slice(ps.indexOf('function Save-FeibiCredential('),ps.indexOf('function Send-Control('));
 assert.ok(!/Write-Host|Write-Output|Set-Content|Out-File/.test(storage));
 assert.ok(storage.includes('DataProtectionScope]::CurrentUser'));assert.ok(!storage.includes('DataProtectionScope]::LocalMachine'));
 assert.ok(ps.includes("'FeibiPrivateBridge\\credentials\\tunnel-key.dpapi'"));
});

const FILE_CONTROL_TEST_SOURCE="param([string]$Mode='Client',[string]$Directory='',[int]$ParentId=0)\n$ErrorActionPreference='Stop'\n$tokens=$null;$errors=$null\n$script:fixtureSource='__SOURCE__'\n$ast=[Management.Automation.Language.Parser]::ParseFile($script:fixtureSource,[ref]$tokens,[ref]$errors)\nif($errors.Count){throw 'SOURCE_PARSE_FAILED'}\n$names=@('Get-CredentialExpiry','Assert-CredentialPrivatePath','New-PrivateDirectory','Invoke-FileControl','Receive-FileControl','Write-FileControlResult')\n$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $n.Name},$true) | ForEach-Object {$body=$_.Extent.Text.Replace('$PSScriptRoot',(\"'\"+$PSScriptRoot.Replace(\"'\",\"''\")+\"'\")); . ([scriptblock]::Create($body))}\n$script:fileControlRequest=$null\n$receiptPath=Join-Path $PSScriptRoot 'standalone-result.json'\nif($Mode -ceq 'Responder'){\n $StandaloneChild=$true;$script:directory=$Directory\n function Send-Control([string]$Command){\n  if($Command -ceq 'stop'){\n   [IO.File]::WriteAllText($receiptPath,(@{pid=$ParentId;event='stopped';code='OPERATOR_STOP';deadline_utc=$script:fixtureDeadline}|ConvertTo-Json -Compress))\n   $script:fixtureDone=$true;return\n  }\n  if($Command -ceq 'qr'){\n   $text=[IO.File]::ReadAllText($script:fixtureSource)\n   $begin=$text.IndexOf('      if ($event.event -eq ''private_qr_png'') {')\n   $end=$text.IndexOf('      elseif ($event.event -eq ''qr_closed'')',$begin)\n   if($begin-lt0 -or $end-le$begin){throw 'QR_BRANCH_MISSING'}\n   $event=[pscustomobject]@{event='private_qr_png';png_base64='SYNTHETIC_QR_BYTES';expires_at_unix_ms=[DateTimeOffset]::UtcNow.AddMinutes(1).ToUnixTimeMilliseconds();expires_within_seconds=60}\n   $clock=[Diagnostics.Stopwatch]::StartNew();$Seconds=60;$message='';$script:displayCalled=$false\n   function Show-LocalQr([string]$Encoded){if($Encoded-cne'SYNTHETIC_QR_BYTES'){throw 'WRONG_QR_PAYLOAD'};$script:displayCalled=$true}\n   . ([scriptblock]::Create($text.Substring($begin,$end-$begin)))\n   if(-not$script:displayCalled -or $event.png_base64-cne''){throw 'QR_DISPLAY_CLEAR_FAILED'}\n   return\n  }\n  $action=@{status='status';approve='approve_callback';confirm='confirm_owner'}[$Command]\n  Write-FileControlResult ([pscustomobject]@{event='operator_result';action=$action;result=@{received=$Command;approved=($Command-ceq'approve');origin='https://connectors.api.openai.com'}})\n }\n $script:fixtureDeadline=([IO.File]::ReadAllText($receiptPath)|ConvertFrom-Json).deadline_utc\n $script:fixtureDone=$false;$timer=[Diagnostics.Stopwatch]::StartNew()\n while(-not$script:fixtureDone -and $timer.Elapsed.TotalSeconds-lt15){Receive-FileControl;Start-Sleep -Milliseconds 20}\n if(-not$script:fixtureDone){throw 'RESPONDER_TIMEOUT'}\n exit 0\n}\n$helper=$null;$script:directory=$null\ntry{\n $script:directory=New-PrivateDirectory\n $deadline=[DateTime]::UtcNow.AddMinutes(1).ToString(\"yyyy-MM-dd'T'HH:mm:ss.fff'Z'\")\n [IO.File]::WriteAllText($receiptPath,(@{pid=$PID;event='started';control_directory=$script:directory;deadline_utc=$deadline}|ConvertTo-Json -Compress))\n $argsText='-NoLogo -NoProfile -STA -ExecutionPolicy RemoteSigned -File \"'+$PSCommandPath+'\" -Mode Responder -Directory \"'+$script:directory+'\" -ParentId '+$PID\n $helper=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $argsText -WindowStyle Hidden -PassThru\n Invoke-FileControl 'status'\n Invoke-FileControl 'approve'\n Invoke-FileControl 'qr'\n Invoke-FileControl 'confirm'\n Invoke-FileControl 'stop'\n if(-not$helper.WaitForExit(5000) -or $helper.ExitCode-ne0){throw 'RESPONDER_FAILED'}\n $StandaloneChild=$true\n $requestPath=Join-Path $script:directory 'operator-request.json'\n [IO.File]::WriteAllText($requestPath,(@{id=('a'*32);command='poll'}|ConvertTo-Json -Compress))\n try{Receive-FileControl;throw 'UNSUPPORTED_COMMAND_WAS_NOT_REJECTED'}catch{if($_.Exception.Message-cne'INVALID_OPERATOR_CONTROL'){throw}}\n $sendAst=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Send-Control'},$true)\n . ([scriptblock]::Create($sendAst.Extent.Text))\n function Write-PrivateLine($Target,[string]$Value){$script:captured=$Value|ConvertFrom-Json}\n $script:process=$null;$OwnerNonce='bind:SYNTHETIC_ONLY_12345678'\n Send-Control 'qr'\n if($script:captured.action-cne'qr_start' -or $null-ne$script:captured.PSObject.Properties['user_confirmed_scan']){throw 'QR_BOUND_OWNER'}\n Send-Control 'confirm'\n if($script:captured.action-cne'confirm_owner' -or $script:captured.user_confirmed_scan-ne$true -or $script:captured.nonce-cne$OwnerNonce){throw 'CONFIRM_MAPPING_CHANGED'}\n [Console]::WriteLine('FILE_CONTROL_CHECKS_OK')\n} finally{\n if($null-ne$helper){if(-not$helper.HasExited){$helper.Kill();$null=$helper.WaitForExit(1000)};$helper.Dispose()}\n if($null-ne$script:directory -and [IO.Directory]::Exists($script:directory)){\n  foreach($file in [IO.Directory]::GetFiles($script:directory,'operator-*')){[IO.File]::Delete($file)}\n  [IO.Directory]::Delete($script:directory,$false)\n }\n if([IO.File]::Exists($receiptPath)){[IO.File]::Delete($receiptPath)}\n}\n";
test('PS5 file controls display QR safely, forward explicit confirm, and preserve stop', {skip:process.platform!=='win32'},()=>{
 const dir=fs.mkdtempSync(process.env.TEMP+'\\feibi-control-test-'),file=dir+'\\fixture.ps1';
 const source=new URL('./start.ps1',import.meta.url).pathname.replace(/^\/([A-Z]:)/i,'$1').replaceAll('/','\\');
 fs.writeFileSync(file,FILE_CONTROL_TEST_SOURCE.replace('__SOURCE__',source.replaceAll("'","''")));
 try{
  const r=spawnSync(process.env.SystemRoot+'\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',['-NoLogo','-NoProfile','-STA','-ExecutionPolicy','RemoteSigned','-File',file],{encoding:'utf8',windowsHide:true,timeout:25000,maxBuffer:8192});
  assert.equal(r.status,0,r.stderr||r.stdout);assert.match(r.stdout,/FILE_CONTROL_CHECKS_OK/);
  assert.match(r.stdout,/"received":"status"/);assert.match(r.stdout,/"approved":true/);assert.match(r.stdout,/"code":"OPERATOR_STOP"/);assert.match(r.stdout,/"displayed_locally":true/);assert.match(r.stdout,/"action":"confirm_owner"/);assert.ok(!r.stdout.includes("SYNTHETIC_QR_BYTES"));
 }finally{for(const p of [file,dir+'\\standalone-result.json'])if(fs.existsSync(p))fs.unlinkSync(p);fs.rmdirSync(dir);}
});

test('drained child logs cannot stop the bridge after cumulative 64KB',async()=>{
 const p=child(),s=new Supervisor({spawnChild:()=>p,emit:()=>{}});s.config={directory:'synthetic-directory'};s.child('synthetic.exe',[],{});
 for(let i=0;i<20;i++){p.stdout.write(Buffer.alloc(8192));p.stderr.write(Buffer.alloc(8192));}
 await new Promise(resolve=>setImmediate(resolve));assert.equal(s.stopped,false);assert.equal(p.stdout.readableLength,0);assert.equal(p.stderr.readableLength,0);
 p.stdin.destroy();p.stdout.destroy();p.stderr.destroy();
});
