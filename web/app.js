const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const busy = (btn, text) => { btn.disabled = true; btn.dataset.l = btn.textContent; btn.innerHTML = `<span class="spin"></span>${text}`; };
const idle = btn => { btn.disabled = false; btn.textContent = btn.dataset.l; };
const banner = (kind, text) => `<div class="banner ${kind}">${esc(text)}</div>`;

// When the page is opened from Live Server (port 5500) or a file, talk to Flask on :5000.
const BASE = location.port === '5000' || location.protocol.startsWith('http') && !['5500','5501','5502'].includes(location.port) ? '' : 'http://localhost:5000';
const asset = u => u.startsWith('/') ? BASE + u : u;

async function api(path, body, isForm) {
  const opts = body === undefined ? {} : isForm
    ? { method: 'POST', body }
    : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  let res;
  try { res = await fetch(BASE + path, opts); }
  catch (_) { throw new Error('Cannot reach the Crypt server. Run `python app.py` in the project folder, then open http://localhost:5000'); }
  const data = await res.json().catch(() => ({ error: `Server error (${res.status})` }));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ---------------- tabs
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + t.dataset.tab));
  if (t.dataset.tab === 'risk') { renderCodeRisk(); updateMosca(); }
  if (t.dataset.tab === 'defense') loadSavedBench();
}));

api('/api/info').then(i => {
  $('#ver').textContent = 'v' + i.version;
  $('#exts').textContent = i.extensions.join(', ');
}).catch(() => {});

// ---------------- scan
let picked = [], lastScan = null;
const drop = $('#drop'), fileInput = $('#files');
function setFiles(list) {
  picked = [...list];
  $('#fileList').textContent = picked.map(f => f.name).join(', ');
  $('#scanBtn').disabled = !picked.length;
}
fileInput.addEventListener('change', () => setFiles(fileInput.files));
['dragenter', 'dragover'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', ev => setFiles(ev.dataTransfer.files));

$('#scanBtn').addEventListener('click', async () => {
  const btn = $('#scanBtn'), out = $('#scanOut');
  const fd = new FormData();
  picked.forEach(f => fd.append('files', f));
  busy(btn, 'Scanning…');
  try {
    const r = await api('/api/scan', fd, true);
    lastScan = r;
    out.innerHTML = renderScan(r);
    $('#dl')?.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(r.findings, null, 2)], { type: 'application/json' }));
      a.download = 'crypt-scan.json'; a.click();
    });
  } catch (e) { out.innerHTML = banner('err', e.message); }
  idle(btn);
});

function renderScan(r) {
  const head = `<div class="metrics">
    <div class="metric"><span>Risk score</span><b>${r.score}/100</b> <span class="pill ${r.label}">${r.label}</span></div>
    <div class="metric"><span>Findings</span><b>${r.findings.length}</b></div>
    <div class="metric"><span>Files scanned</span><b>${r.scanned}</b></div></div>`;
  if (!r.findings.length) return head + banner('ok', 'No quantum-vulnerable cryptography found.');
  const rows = r.findings.map(f => `<tr><td><span class="pill ${f.severity}">${f.severity}</span></td>
    <td>${esc(f.file)}:${f.line}</td><td>${esc(f.algorithm)}</td><td>${esc(f.rule_id)}</td><td class="wrap">${esc(f.fix)}</td></tr>`).join('');
  const details = r.findings.map(f => `<div class="find"><span class="pill ${f.severity}">${f.rule_id}</span> <code>${esc(f.file)}:${f.line}</code>
    <pre>${esc(f.code)}</pre><span class="muted">${esc(f.why)}</span></div>`).join('');
  return head + `<div class="tablewrap"><table><thead><tr><th>Severity</th><th>Location</th><th>Algorithm</th><th>Rule</th><th>Recommended fix</th></tr></thead><tbody>${rows}</tbody></table></div>
    <details><summary>Details: code and reasoning</summary>${details}</details>
    <button class="btn" id="dl">Download JSON report</button>
    ${banner('info', 'See the Risk tab for how exposed this makes you.')}`;
}

// ---------------- risk
function renderCodeRisk() {
  const el = $('#codeRisk'), r = lastScan;
  if (!r) return;
  if (!r.findings.length) { el.innerHTML = banner('ok', 'Clean: score 0/100.'); return; }
  const byAlgo = {};
  r.findings.forEach(f => byAlgo[f.algorithm] = (byAlgo[f.algorithm] || 0) + 1);
  const max = Math.max(...Object.values(byAlgo));
  const bars = Object.entries(byAlgo).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
    `<div class="hbar"><span>${esc(k)}</span><i style="width:${v / max * 100}%"></i><b>${v}</b></div>`).join('');
  el.innerHTML = `<div class="metric"><span>Score</span><b>${r.score}/100</b> <span class="pill ${r.label}">${r.label}</span></div>
    <div class="bar"><i style="width:${r.score}%"></i></div>${bars}
    <p class="muted">Score = weighted count (HIGH 10, MEDIUM 4, LOW 1), capped at 100.</p>`;
}

const sliders = ['shelf', 'mig', 'threat'];
let moscaTimer;
sliders.forEach(id => $('#' + id).addEventListener('input', () => {
  $('#v-' + id).textContent = $('#' + id).value;
  clearTimeout(moscaTimer); moscaTimer = setTimeout(updateMosca, 120);
}));
async function updateMosca() {
  try {
    const r = await api('/api/mosca', {
      shelf_life: +$('#shelf').value, migration_time: +$('#mig').value, years_to_threat: +$('#threat').value });
    $('#moscaOut').innerHTML = banner(r.exposed ? 'err' : 'ok', r.verdict);
    const total = Math.max(r.shelf_life + r.migration_time, r.years_to_threat, 1) * 1.1;
    const pct = v => v / total * 100;
    $('#timeline').innerHTML =
      `<div class="seg" style="left:0;width:${pct(r.shelf_life)}%;background:#7c3aed">shelf life</div>
       <div class="seg" style="left:${pct(r.shelf_life)}%;width:${pct(r.migration_time)}%;background:#d97706">migration</div>
       <div class="line" style="left:${pct(r.years_to_threat)}%" title="quantum threat"></div>`;
  } catch (e) { $('#moscaOut').innerHTML = banner('err', e.message); }
}

// ---------------- attack
let seed = 1;
$('#newKey').addEventListener('click', () => { seed++; $('#shorOut').innerHTML = banner('info', 'New key generated. Run the attack.'); });
$('#shorBtn').addEventListener('click', async () => {
  const btn = $('#shorBtn'), out = $('#shorOut');
  busy(btn, 'Attacking…');
  try {
    const r = await api('/api/shor', { bits: +$('#bits').value, seed, message: $('#secret').value });
    const ct = r.ciphertext.slice(0, 8).join(', ') + (r.ciphertext.length > 8 ? ' …' : '');
    let h = `<div class="step"><i>1</i>The victim's public key and intercepted ciphertext</div>
      <pre>N = ${r.n}\ne = ${r.e}\nciphertext = [${ct}]</pre>
      <p class="muted">An RSA-2048 modulus has 617 digits. Breaking it for real needs a large fault-tolerant quantum computer.</p>
      <div class="step"><i>2</i>Factor N with Shor's method</div>
      <div class="tablewrap"><table><thead><tr><th>a</th><th>period r</th><th>outcome</th></tr></thead><tbody>${
        r.attempts.map(a => `<tr><td>${a.a}</td><td>${a.order ?? '–'}</td><td>${esc(a.outcome)}</td></tr>`).join('')}</tbody></table></div>`;
    if (!r.success) h += banner('err', 'No factor found in the attempt limit. Try a new key.');
    else h += `<div class="step"><i>3</i>Private key rebuilt, message decrypted</div>
      <pre>N = ${r.n} = ${r.p} × ${r.q}\nd = e⁻¹ mod (p−1)(q−1) = ${r.d}\ndecrypted = ${esc(JSON.stringify(r.recovered))}</pre>
      ${banner('err', `RSA broken in ${(r.seconds * 1000).toFixed(1)} ms.`)}
      <p class="muted">Elliptic-curve keys (ECDSA, ECDH, X25519) fall to the same family of attacks. See the Defense tab for what survives.</p>`;
    out.innerHTML = h;
  } catch (e) { out.innerHTML = banner('err', e.message); }
  idle(btn);
});

// ---------------- defense
$('#hybridBtn').addEventListener('click', async () => {
  const btn = $('#hybridBtn'), out = $('#hybridOut');
  busy(btn, 'Encrypting…');
  try {
    const r = await api('/api/hybrid', { message: $('#msg').value, tamper: $('#tamper').checked });
    const k = r.keys;
    out.innerHTML = `<div class="metrics">
      <div class="metric"><span>X25519 public</span><b>${k.x25519_public} B</b></div>
      <div class="metric"><span>ML-KEM-768 public</span><b>${k.mlkem_public} B</b></div>
      <div class="metric"><span>X25519 private</span><b>${k.x25519_private} B</b></div>
      <div class="metric"><span>ML-KEM-768 private</span><b>${k.mlkem_private} B</b></div></div>
      <div class="tablewrap"><table><thead><tr><th>Envelope field</th><th>Size (B)</th><th>Preview (hex)</th></tr></thead><tbody>${
        r.envelope.map(e => `<tr><td>${esc(e.field)}</td><td>${e.size}</td><td><code>${esc(e.preview)}</code></td></tr>`).join('')}</tbody></table></div>` +
      (r.error ? banner('err', r.error) : banner('ok', 'Decrypted: ' + r.decrypted));
  } catch (e) { out.innerHTML = banner('err', e.message); }
  idle(btn);
});

$('#iters').addEventListener('input', () => $('#v-iters').textContent = $('#iters').value);
function renderBench(r) {
  const rows = Object.entries(r.data.results).map(([n, x]) => `<tr><td>${esc(n)}</td><td>${x.keygen_ms.toFixed(3)}</td><td>${x.encaps_ms.toFixed(3)}</td>
    <td>${x.decaps_ms.toFixed(3)}</td><td>${x.public_key_bytes}</td><td>${x.ciphertext_bytes}</td>
    <td><span class="pill ${x.quantum_safe ? 'CLEAN' : 'HIGH'}">${x.quantum_safe ? 'Yes' : 'No'}</span></td></tr>`).join('');
  $('#benchOut').innerHTML = `<p class="muted">${r.live ? `Live run, ${r.data.iterations} iterations.` : 'Saved results from docs/benchmarks.json. Press Run to measure on this server.'}</p>
    <div class="tablewrap"><table><thead><tr><th>Scheme</th><th>Keygen (ms)</th><th>Encrypt (ms)</th><th>Decrypt (ms)</th><th>Public key (B)</th><th>Ciphertext (B)</th><th>Quantum-safe</th></tr></thead><tbody>${rows}</tbody></table></div>
    <img class="chart" src="${asset(r.chart)}" alt="Benchmark chart"><p class="muted">${esc(r.data.note)}</p>`;
}
let benchLive = false;
async function loadSavedBench() {
  if (benchLive || $('#benchOut').innerHTML) return;
  try { renderBench(await api('/api/bench/saved')); } catch (_) {}
}
$('#benchBtn').addEventListener('click', async () => {
  const btn = $('#benchBtn');
  busy(btn, 'Benchmarking…');
  try { renderBench(await api('/api/bench', { iterations: +$('#iters').value })); benchLive = true; }
  catch (e) { $('#benchOut').innerHTML = banner('err', e.message); }
  idle(btn);
});

updateMosca();
