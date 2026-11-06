'use strict';
const $ = id => document.getElementById(id);
let state = null, mode = 'remote', choosing = false;
const errors = {
 dns_failed:'域名无法解析。请检查地址、DNS 或 VPN。',
 connection_refused:'连接被拒绝。请检查实际端口、服务是否运行及监听地址。',
 connection_timeout:'连接超时。请检查服务器实际端口的安全组、防火墙和网络路由。客户端无法据此确认是哪一项阻挡。',
 network_unavailable:'网络不可达。请检查网络、VPN 和服务状态。',
 tls_failed:'TLS 证书验证失败。请检查域名和证书信任链，不要关闭验证。',
 https_required:'远程金库请使用 HTTPS 地址。',
 invalid_server_url:'服务器地址格式不正确，请填写完整 HTTPS 地址。',
 vault_service_not_verified:'端点可访问，但未确认是兼容的金库服务。请检查路径前缀或服务版本。',
 login_rejected:'账号或密码被拒绝，请重新输入。',
 login_unconfirmed:'登录响应无法确认，请核对服务接口。',
 session_expired:'无法恢复登录，密码或账户权限可能已经改变，请重新登录。',
 reconnect_pending:'正在等待恢复连接，请稍后点击重试。',
 remote_auth_unavailable:'服务器暂时无法完成认证。此设备的登录记忆仍保留，服务恢复后可自动连接。',
 remembered_login_rejected:'记住的登录凭据已被拒绝，密码或账户权限可能已经改变。请重新登录。',
 remembered_device_unavailable:'此设备的加密登录记忆无法打开，请重新登录。',
 device_protection_unavailable:'无法安全保存设备凭据，登录记忆未启用。请检查本机保护设置。',
 invalid_passphrase:'主口令不正确。', unlock_blocked:'尝试次数过多，请稍后再试。',
 invalid_username:'请输入金库账号。', invalid_password:'请输入登录密码。',
 target_selection_changed:'目标已被其他会话更改。本次密码没有提交到服务器，请刷新页面并核对地址后重新登录。',
 target_selection_pending:'正在切换目标，请先登录新目标或保留原连接。',
 target_config_unavailable:'无法保存目标配置，原连接已保留。请检查本机配置目录权限。',
 passphrase_mismatch:'两次主口令需要一致，创建时至少 12 位。',
 local_backend_unavailable:'已有本地金库无法打开，可能是权限、完整性或版本问题。不会覆盖或重建。',
 local_directory_not_empty:'本地目标目录已有文件，不能作为新金库覆盖创建。',
 remote_creation_unsupported:'服务器未提供兼容的创建接口，请先由服务管理员初始化。',
 inventory_unavailable:'无法读取凭据元数据，请检查服务状态。',
 request_not_found:'请求不存在，或已因切换目标/退出而失效。请回到对话重新发起。',
 request_not_pending:'该录入请求已处理或过期，请勿重复提交。',
 save_unconfirmed:'保存结果未确认。请先查询记录再决定重试，避免重复写入。',
 login_required:'请先登录金库。', forbidden:'安全会话失效，请重新加载页面。',
 backend_unavailable:'金库服务暂时不可用，请检查连接。',
 remote_response_invalid:'服务返回不符合已知契约，操作未确认。'
};
function notice(text, busy=false){$('feedback').hidden=!text;$('feedback').textContent=text||'';$('feedback').className=busy?'busy':'';}
async function request(path,data){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),25000);
 try{const response=await fetch(path,{method:data===undefined?'GET':'POST',credentials:'same-origin',signal:controller.signal,
 headers:data===undefined?{}:{'Content-Type':'application/json','X-Vault-CSRF':document.querySelector('meta[name=vault-csrf]').content},
 body:data===undefined?undefined:JSON.stringify(data)});
 const value=await response.json();if(!response.ok)throw new Error(errors[value.error]||'操作失败，请检查服务连接。');return value;
 }finally{clearTimeout(timer);}
}
async function run(button,work,message){
 button.disabled=true;notice(message||'正在处理…',true);
 try{await work();notice('');}catch(error){notice(error.name==='AbortError'?'请求超时，结果可能尚未确认。请先刷新状态再重试。':error.message);}
 finally{button.disabled=false;}
}
function choose(next){mode=next;$('remote-choice').setAttribute('aria-pressed',mode==='remote');$('local-choice').setAttribute('aria-pressed',mode==='local');$('url-field').hidden=mode!=='remote';}
function showSelection(){choosing=true;render();$('server-url').focus();}
function render(){
 if(!state)return;
 const selecting=choosing||state.phase==='needs_target';
 $('selection').hidden=!selecting;
 const auth=!selecting&&['needs_login','needs_unlock','needs_create'].includes(state.phase);
 $('authentication').hidden=!auth;$('ready').hidden=selecting||auth||!state.connected;
 $('reconnecting').hidden=selecting||state.phase!=='reconnecting';
 $('session-hint').textContent=state.remember_device?'此设备已记住。重启、关机及服务器会话更新后会自动重新认证；关闭网页不会退出。密码改变、设备记忆被删除或服务器拒绝认证时需重新登录。':'未记住设备：本次认证最多一小时，核心重启后需重新登录。关闭网页不会自动退出。';
 $('target-label').hidden=!(state.candidate_url||state.server_url||state.mode==='local'||state.candidate_mode==='local');
 $('target-label').textContent=(state.candidate_url||state.server_url||'本机金库');
 $('cancel').hidden=!state.connected;
 if(selecting){$('step').textContent='01 / CONNECT';$('title').textContent=state.connected?'选择新的存储位置':'连接你的金库';$('subtitle').textContent='先检查服务，再登录。切换成功前，原连接会保留。';}
 else if(auth){
  const creating=state.phase==='needs_create',remote=state.candidate_mode==='remote';
  $('step').textContent='02 / AUTHENTICATE';$('title').textContent=creating?'创建金库':remote?'登录远程金库':'解锁本机金库';
  $('subtitle').textContent=creating?'确认存储目标后，设置你的主口令。':'登录信息只交给所选金库，不会发送到聊天。';
  $('username-field').hidden=!remote;$('confirmation').hidden=!creating;
  $('passphrase').autocomplete=creating?'new-password':'current-password';
  $('password-label').textContent=remote?'登录密码':'主口令';
  $('authenticate').textContent=creating?'确认创建':'登录并连接';
  $('authenticate').disabled=creating&&!state.creation_supported;
  $('auth-note').hidden=!(remote&&(state.initialization==='unknown'||(creating&&!state.creation_supported)));
  $('auth-note').textContent=creating?'服务确认尚未初始化，但没有提供兼容的创建接口。请由服务管理员完成初始化。':'服务已确认可达，但没有公开初始化状态接口。先使用已有账户登录；不会自动创建或覆盖数据库。';
 }else if(state.phase==='reconnecting'){$('step').textContent='02 / RECONNECT';$('title').textContent='恢复此设备的连接';$('subtitle').textContent='正在使用本机受保护的登录记忆，无需重复输入密码。';}
 else if(state.connected){$('step').textContent='03 / READY';$('title').textContent='你的金库已连接';$('subtitle').textContent='现在可以安全录入凭据，或回到 Agent 对话继续。';renderRequests();}
 if(state.error)notice(errors[state.error]||'已保存的连接暂时无法使用，请重新检查目标。');
}
function element(tag,text,cls){const item=document.createElement(tag);if(text!==undefined)item.textContent=text;if(cls)item.className=cls;return item;}
function renderRequests(){
 const root=$('requests');root.replaceChildren();
 const requested=location.pathname.startsWith('/connect/')?location.pathname.split('/')[2]:null;
 const pending=state.pending||[];
 if(requested&&!pending.some(x=>x.request_id===requested)){
  const info=element('p','本页请求已完成、过期或失效。可回到对话查询结果。','note');root.append(info);
 }
 for(const item of pending){
  const card=element('div',undefined,'request');card.id='request-'+item.request_id;
  card.append(element('h3',item.service),element('p','账户 '+item.account+' · '+item.credential_type+' · '+item.expires_in+' 秒内完成'));
  const input=element('input');input.type='password';input.autocomplete='off';input.setAttribute('aria-label','凭据内容');
  const save=element('button','安全保存','primary');save.type='button';
  const decline=element('button','拒绝此请求','secondary');decline.type='button';
  save.addEventListener('click',()=>run(save,async()=>{
   if(!input.value)throw new Error('请输入凭据内容。');
   const value=input.value;input.value='';
   try{await request('/api/submit',{request_id:item.request_id,secret:value});await refresh();}
   catch(error){await refresh().catch(()=>{});throw error;}
  },'正在保存到所选金库…'));
  decline.addEventListener('click',()=>run(decline,async()=>{input.value='';await request('/api/decline',{request_id:item.request_id});await refresh();}));
  card.append(input,save,decline);root.append(card);
 }
}
async function refresh(){state=await request('/api/status');render();}
$('remote-choice').addEventListener('click',()=>choose('remote'));
$('local-choice').addEventListener('click',()=>choose('local'));
$('probe').addEventListener('click',()=>run($('probe'),async()=>{
 const value=await request('/api/select',{mode,server_url:mode==='remote'?$('server-url').value.trim():null});
 state={...value,pending:state?.pending||[]};choosing=false;render();$('passphrase').focus();
},'正在检查服务器连接与金库状态…'));
$('authenticate').addEventListener('click',()=>run($('authenticate'),async()=>{
 const action=state.phase==='needs_create'?'create':'login';
 const payload={selection_id:state.selection_id,username:$('username').value,passphrase:$('passphrase').value,confirm:$('confirm').value,remember_device:$('remember-device').checked};
 $('passphrase').value='';$('confirm').value='';
 try{await request('/api/'+action,payload);choosing=false;await refresh();}
 finally{payload.passphrase='';payload.confirm='';}
},'正在验证并建立连接…'));
$('change-target').addEventListener('click',()=>{$('passphrase').value='';$('confirm').value='';showSelection();});
$('switch').addEventListener('click',showSelection);
$('cancel').addEventListener('click',()=>run($('cancel'),async()=>{await request('/api/cancel-selection',{});choosing=false;await refresh();}));
$('logout').addEventListener('click',()=>run($('logout'),async()=>{await request('/api/logout',{});await refresh();}));
$('retry-connection').addEventListener('click',()=>run($('retry-connection'),refresh,'正在恢复设备连接…'));
$('forget-device').addEventListener('click',()=>run($('forget-device'),async()=>{await request('/api/logout',{});await refresh();}));
for(const button of document.querySelectorAll('.reveal'))button.addEventListener('click',()=>{const input=$(button.dataset.for);input.type=input.type==='password'?'text':'password';button.textContent=input.type==='password'?'显示':'隐藏';});
$('passphrase').addEventListener('keydown',event=>{if(event.key==='Enter'&&!$('authenticate').disabled)$('authenticate').click();});
window.addEventListener('focus',()=>{const editing=!$('authentication').hidden||[...document.querySelectorAll('.request input')].some(input=>input.value);if(!editing&&!document.querySelector('button:disabled'))refresh().catch(()=>notice('无法刷新状态，请检查本地服务。'));});
refresh().catch(()=>notice('无法连接本地核心服务，请检查 Agent 中的 MCP 状态。'));
