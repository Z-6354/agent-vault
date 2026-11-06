// Real Chrome/Edge CDP acceptance. Only synthetic fixture credentials are used.
const fs = require('node:fs');
const path = require('node:path');
const [debugPort, base, remote, output, fixture] = process.argv.slice(2);
let socket, nextId = 1;
const pending = new Map();
async function connect() {
  let target;
  for (let attempt=0;attempt<60;attempt++) {
    try { target=await (await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(base)}`,{method:'PUT'})).json(); break; }
    catch { await new Promise(r=>setTimeout(r,100)); }
  }
  if (!target) throw Error('Browser debugging endpoint not ready');
  socket=new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
  socket.addEventListener('message',event=>{const message=JSON.parse(event.data);if(message.id&&pending.has(message.id)){const entry=pending.get(message.id);pending.delete(message.id);clearTimeout(entry.timer);message.error?entry.reject(Error(message.error.message)):entry.resolve(message.result);}});
}
function command(method, params={}) {
 return new Promise((resolve,reject)=>{const id=nextId++;const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout '+method));},15000);pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));});
}
async function evaluate(expression) {
 const result=await command('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
 if(result.exceptionDetails)throw Error(result.exceptionDetails.text+' '+(result.exceptionDetails.exception?.description||''));
 return result.result.value;
}
async function wait(expression) {
 for(let i=0;i<100;i++) { if(await evaluate(expression))return;await new Promise(r=>setTimeout(r,100)); }
 throw Error('UI condition timed out: '+expression);
}
function click(id){return evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);}
function fill(id,value){return evaluate(`document.getElementById(${JSON.stringify(id)}).value=${JSON.stringify(value)}`);}
async function screenshot(name){const {data}=await command('Page.captureScreenshot',{format:'png'});fs.writeFileSync(path.join(output,name),Buffer.from(data,'base64'));}
async function main(){
 await connect();await command('Page.enable');await command('Runtime.enable');
 await wait(`document.getElementById('selection') && !document.getElementById('selection').hidden`);
 await screenshot('01-select.png');
 await fill('server-url',remote);await click('probe');
 await wait(`!document.getElementById('authentication').hidden`);
 await screenshot('02-login.png');
 if(!await evaluate(`document.getElementById('remember-device').checked`))throw Error('Remember device must default to enabled');
 await fill('username','synthetic-user');await fill('passphrase','synthetic-wrong-password');await click('authenticate');
 await wait(`document.getElementById('feedback').textContent.includes('拒绝')`);
 if(await evaluate(`document.getElementById('passphrase').value!==''`))throw Error('Password retained after failure');
 await screenshot('03-login-error.png');
 await fill('passphrase','synthetic-login-password');await click('authenticate');
 await wait(`!document.getElementById('ready').hidden`);
 await screenshot('04-connected.png');
 if(!await evaluate(`document.getElementById('session-hint').textContent.includes('已记住')`))throw Error('Remembered device state not shown');
 const restored=await(await fetch(fixture+'/restart',{method:'POST'})).json();
 if(!restored.connected||!restored.remember_device)throw Error('Device login did not survive core restart');
 await command('Page.reload');
 await wait(`!document.getElementById('ready').hidden`);
 await screenshot('04-restarted-remembered.png');
 // Use a fixture-only callback in the harness to start a real MCP request.
 const request=await (await fetch(fixture+'/request',{method:'POST'})).json();
 await command('Page.navigate',{url:base+'/connect/'+request.request_id});
 await wait(`document.querySelector('.request input')!==null`);
 await evaluate(`document.querySelector('.request input').value='synthetic-secret-canary-not-for-model';document.querySelector('.request .primary').click()`);
 await wait(`document.querySelector('.request input')===null`);
 await screenshot('05-saved.png');
 const result=await (await fetch(fixture+'/result?id='+request.request_id)).json();
 if(result.status!=='captured')throw Error('MCP did not observe browser save');
 // Mobile layout must not overflow.
 await command('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
 await screenshot('06-mobile.png');
 if(await evaluate(`document.documentElement.scrollWidth>window.innerWidth`))throw Error('Mobile horizontal overflow');
 await click('logout');await wait(`!document.getElementById('authentication').hidden`);
 if(await evaluate(`document.querySelector('.request')!==null`))throw Error('Secret form available after logout');
 console.log('BROWSER ACCEPTANCE OK: remote probe, login failure + secret clear, login, real save, MCP result, remembered-device restart, mobile, logout');
}
main().then(()=>{socket?.close();}).catch(error=>{console.error(error.message);socket?.close();process.exitCode=1;});
