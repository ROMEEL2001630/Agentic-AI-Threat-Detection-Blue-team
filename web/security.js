const toolsState = {network:null};
async function api(path, body) {
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const payload=await response.json(); if(!response.ok)throw Error(payload.error || 'Request failed'); return payload;
}
document.querySelectorAll('[data-panel]').forEach(button=>button.onclick=()=>{
  document.querySelectorAll('[data-panel]').forEach(b=>b.removeAttribute('aria-current'));
  button.setAttribute('aria-current','page');
  document.querySelectorAll('.panel').forEach(panel=>panel.hidden=panel.id!==`panel-${button.dataset.panel}`);
});
function aiButton(context) {
  const section=node('section',undefined,'ai-result'), button=node('button','Explain with local AI'), output=node('p'); output.setAttribute('role','status');
  button.onclick=async()=>{button.disabled=true;output.textContent='Requesting a local AI draft…';try {const r=await api('/api/explain',{context});output.textContent=`${r.text}\n\n${r.note} Model: ${r.model}`;}catch(e){output.textContent=e.message;}finally{button.disabled=false;}};
  section.append(button,output);return section;
}
function resultCard(target, title, note, context) {
  const card=node('section',undefined,'result-card'); card.append(node('h3',title),node('p',note));target.replaceChildren(card);
  if(context)card.append(aiButton(context));return card;
}
function downloadReport(data, name) {
  const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
  const a=node('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$('scam-form').onsubmit=async e=>{e.preventDefault();const target=$('scam-result');target.textContent='Checking…';try{
  const r=await api('/api/check',{text:$('scam-text').value});
  const card=resultCard(target,`${r.verdict} · heuristic score ${r.score}/100`,r.note,r);
  const download=node('button','Download check report');download.onclick=()=>downloadReport(r,'aegis-message-check.json');card.append(download);
  if(!r.findings.length)card.append(node('p','No listed patterns matched. Absence of warnings does not mean safe.'));
  r.findings.forEach(f=>card.append(block(f.reason,`Observed: ${f.evidence}`)));
}catch(err){target.textContent=err.message;}};
const metricOptions={AV:['Attack vector',{N:'Network',A:'Adjacent',L:'Local',P:'Physical'}],AC:['Attack complexity',{L:'Low',H:'High'}],PR:['Privileges required',{N:'None',L:'Low',H:'High'}],UI:['User interaction',{N:'None',R:'Required'}],S:['Scope',{U:'Unchanged',C:'Changed'}],C:['Confidentiality',{H:'High',L:'Low',N:'None'}],I:['Integrity',{H:'High',L:'Low',N:'None'}],A:['Availability',{H:'High',L:'Low',N:'None'}]};
Object.entries(metricOptions).forEach(([key,[title,options]])=>{const label=node('label',title),select=node('select');select.id=`metric-${key}`;Object.entries(options).forEach(([value,title])=>{const o=node('option',title);o.value=value;select.append(o);});select.onchange=()=>{$('vector').value='CVSS:3.1/'+Object.keys(metricOptions).map(k=>`${k}:${$(`metric-${k}`).value}`).join('/');};label.append(select);$('cvss-metrics').append(label);});
$('vector').oninput=()=>{const parts=$('vector').value.split('/').slice(1);parts.forEach(part=>{const [k,v]=part.split(':');const select=$(`metric-${k}`);if(select&&[...select.options].some(o=>o.value===v))select.value=v;});};
$('cvss-form').onsubmit=async e=>{e.preventDefault();try{const r=await api('/api/cvss',{vector:$('vector').value.trim()});const card=resultCard($('cvss-result'),`${r.score.toFixed(1)} / 10 · ${r.severity}`,r.note);card.append(node('pre',r.vector));const b=node('button','Download score');b.onclick=()=>downloadReport(r,'aegis-cvss.json');card.append(b);}catch(err){$('cvss-result').textContent=err.message;}};
$('network-sample').onclick=async()=>{try{const r=await fetch('/api/network-sample');if(!r.ok)throw Error('Sample unavailable');$('network-text').value=await r.text();}catch(e){$('network-result').textContent=e.message;}};
$('network-file').onchange=async e=>{const f=e.target.files[0];if(!f)return;try{if(f.size>1_000_000)throw Error('CSV exceeds 1 MB');$('network-text').value=await f.text();}catch(err){$('network-result').textContent=err.message;}e.target.value='';};
$('network-form').onsubmit=async e=>{e.preventDefault();try{const r=await api('/api/network',{csv:$('network-text').value});toolsState.network=r;const card=resultCard($('network-result'),`${r.events} events · ${r.findings.length} findings`,r.note);const b=node('button','Download investigation');b.onclick=()=>downloadReport(r,'aegis-network.json');card.append(b);
  if(!r.findings.length)card.append(node('p','No configured rules matched. This does not establish that the network is safe.'));
  r.findings.forEach(f=>{const section=block(`${f.severity.toUpperCase()} · ${f.rule}`,f.reason);const details=node('details');details.append(node('summary',`Source rows: ${f.source_rows.join(', ')}`),node('pre',JSON.stringify(f.evidence,null,2)));section.append(details,aiButton(f));card.append(section);});
}catch(err){$('network-result').textContent=err.message;}};
const platformGuides={Windows:'Use system updates, Windows Security and MFA. This page does not inspect antivirus state or running processes. The separate desktop Chrome/Edge extension can apply its starter browser rules.',macOS:'Use software updates, FileVault and built-in security controls. Aegis does not inspect apps, files or system settings. The separate Chrome/Edge extension works only inside that browser.',Linux:'Keep packages and browsers updated; review firewall and account permissions using your distribution tools. Aegis has no root access, installed agent or live network sensor.','iPhone / iPad':'This local server is on your computer, not your phone. Mobile access needs secure hosting first. Safari content blocking requires a separate native extension. iOS sandboxing prevents this webpage from inspecting other apps.',Android:'This local server is not a phone protection service. Mobile access needs secure hosting first. Device-wide network filtering requires a separately installed VPN/DNS service with user approval; no Android agent is built yet.'};
function platformGuide(){resultCard($('platform-detail'),$('platform').value,platformGuides[$('platform').value]);}
$('platform').onchange=platformGuide;platformGuide();
['Install OS and browser updates','Use unique passwords or passkeys','Enable MFA on email and important accounts','Keep a tested backup','Review app permissions and remove unused apps','Verify unexpected payment or login requests independently'].forEach(text=>{const label=node('label',undefined,'check-item'),input=node('input');input.type='checkbox';label.append(input,document.createTextNode(' '+text));$('safety-checklist').append(label);});
fetch('/api/health').then(r=>r.json()).then(r=>{$('ai-state').textContent=r.ai_configured?'Local model configured; availability is checked on request.':'Local AI not configured. Set AEGIS_OLLAMA_MODEL and restart to enable.';}).catch(()=>{$('ai-state').textContent='Server unavailable. Start Aegis and refresh.';});
