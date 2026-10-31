const $ = id => document.getElementById(id);
let results = [], selected = null, busy = false;
function node(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function block(title, text) { const section = node('section'); section.append(node('h3', title), node('p', text)); return section; }
function showDetail(r) {
  selected = r.source_row; renderList();
  const d = $('detail'); d.replaceChildren();
  d.append(node('p', `${r.alert.id} · SOURCE ROW ${r.source_row}`, 'eyebrow'), node('h2', r.alert.rule), node('span', `${r.band} · ${r.score}/100`, 'badge'));
  d.append(block('Observed context', `Host: ${r.alert.host} · User: ${r.alert.user || 'Unknown'} · Time: ${r.alert.timestamp || 'Not supplied'}`));
  d.append(block('Why this priority', r.reasons.join(' · ')));
  d.append(block('ATT&CK mapping', `${r.alert.technique || 'Not supplied'} · ${r.tech_name} · ${r.tactic}`));
  d.append(block('Triage note · rule-based', r.note));
  const actions = node('section'); actions.append(node('h3', 'Suggested checks · review required'));
  const ul = node('ul'); r.actions.forEach(a => ul.append(node('li', a))); actions.append(ul); d.append(actions);
  const evidence = node('details'); evidence.open = true; evidence.append(node('summary', 'Original source record'), node('pre', JSON.stringify(r.alert, null, 2))); d.append(evidence);
  d.append(block('Intelligence coverage', 'Offline: IP reputation was not checked. Priority is a triage aid, not a confirmed malicious verdict.'));
}
function renderList() {
  const q = $('search').value.toLowerCase(), band = $('band').value;
  const visible = results.filter(r => (!band || r.band.startsWith(band)) && [r.alert.id, r.alert.rule, r.alert.host, r.alert.user].join(' ').toLowerCase().includes(q));
  $('list').replaceChildren();
  visible.forEach(r => { const b = node('button', undefined, 'alert' + (selected === r.source_row ? ' selected' : '')); b.setAttribute('aria-pressed', String(selected === r.source_row)); b.append(node('span', `${r.band.slice(0, 2)} / ${r.score}`, 'priority'), node('strong', r.alert.rule), node('small', `${r.alert.id} · ${r.alert.host}`)); b.onclick = () => showDetail(r); $('list').append(b); });
  if (!visible.length) $('list').append(node('p', 'No matching alerts.', 'empty'));
}
async function load(data) {
  if (busy) return;
  busy = true; $('sample').disabled = true; $('file').disabled = true; $('message').textContent = 'Analyzing locally…';
  try {
    const res = await fetch('/api/triage', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data)});
    const body = await res.json(); if (!res.ok) throw Error(body.error);
    results = body.results; selected = null; $('search').value = ''; $('band').value = '';
    $('metrics').replaceChildren();
    [['Alerts in queue', results.length], ['Critical priority', results.filter(r=>r.band.startsWith('P1')).length], ['Hosts observed', new Set(results.map(r=>r.alert.host)).size], ['Actions executed', 0]].forEach(([label, value]) => { const card=node('div'); card.append(node('span',label),node('strong',String(value))); $('metrics').append(card); });
    $('export').disabled = false; showDetail(results[0]); $('message').textContent = `${results.length} alerts ready · offline analysis complete`;
  } catch(e) { $('message').textContent = `Import failed: ${e.message}. Previous queue retained.`; }
  finally {busy=false; $('sample').disabled=false; $('file').disabled=false;}
}
$('sample').onclick = async () => {try {const res=await fetch('/api/sample'); if(!res.ok) throw Error('Sample unavailable'); await load(await res.json());} catch(e) {$('message').textContent=e.message;}};
$('file').onchange = async e => {const file=e.target.files[0]; if(!file)return; try {if(file.size>2*1024*1024)throw Error('File exceeds 2 MB'); await load(JSON.parse(await file.text()));}catch(err){$('message').textContent=`Import failed: ${err.message}`;}e.target.value='';};
$('search').oninput=renderList; $('band').onchange=renderList;
$('export').onclick=()=>{const blob=new Blob([JSON.stringify({generated_at:new Date().toISOString(),mode:'offline; rule-based',actions_executed:0,results},null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=node('a');a.href=url;a.download='aegis-triage-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
