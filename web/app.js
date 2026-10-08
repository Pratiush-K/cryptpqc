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

// ---------------- website
let lastSite = null;
const siteBtn = $('#siteBtn'), siteInput = $('#siteTarget');

async function runSite(target) {
  const out = $('#siteOut');
  busy(siteBtn, 'Checking…');
  out.innerHTML = '';
  try {
    const r = await api('/api/endpoint', { target });
    lastSite = r;
    out.innerHTML = renderSite(r);
    $('#siteDl')?.addEventListener('click', () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }));
      a.download = `crypt-${r.host}.json`; a.click();
    });
  } catch (e) { out.innerHTML = banner('err', e.message); }
  idle(siteBtn);
}
siteBtn.addEventListener('click', () => runSite(siteInput.value));
siteInput.addEventListener('keydown', e => { if (e.key === 'Enter' && !siteBtn.disabled) siteBtn.click(); });
document.querySelectorAll('.chip').forEach(c => c.addEventListener('click', () => {
  if (siteBtn.disabled) return;
  siteInput.value = c.dataset.site;
  runSite(c.dataset.site);
}));

const pqText = v => v === true ? 'Supported' : v === false ? 'Not supported' : 'No clear answer';
const kv = rows => `<ul class="kv">${rows.map(([k, v]) => `<li><span>${esc(k)}</span><b>${esc(v)}</b></li>`).join('')}</ul>`;

function renderSite(r) {
  const std = r.pq_groups.X25519MLKEM768, draft = r.pq_groups.X25519Kyber768Draft00, c = r.cert;
  const kexPill = std === true ? ['CLEAN', 'Hybrid post-quantum']
    : draft === true ? ['MEDIUM', 'Draft hybrid only']
    : std === false ? ['HIGH', 'Classical only'] : ['MEDIUM', 'Not confirmed'];
  const certPill = !c ? ['MEDIUM', 'Unreadable']
    : c.key_type === 'RSA' && c.key_bits < 2048 ? ['HIGH', `RSA ${c.key_detail}`]
    : ['LOW', `${c.key_type} ${c.key_detail}`];
  const pill = ([cls, text]) => `<span class="pill ${cls}">${esc(text)}</span>`;

  const head = `${banner(r.verdict_kind, r.verdict)}
    <div class="metrics">
      <div class="metric"><span>Exposure score</span><b>${r.score}/100</b> <span class="pill ${r.label}">${r.label}</span></div>
      <div class="metric"><span>TLS version</span><b>${esc(r.tls_version.replace('TLSv', 'TLS '))}</b></div>
      <div class="metric"><span>Cipher</span><b class="sm">${esc(r.cipher)}</b></div></div>`;

  const kexLane = `<div class="card lane"><h3>Key exchange ${pill(kexPill)}</h3>
    <p class="muted">Protects the data you send. Attackers can record it today and break it later.</p>
    ${kv([
      ['X25519MLKEM768 (standard)', pqText(std)],
      ['X25519Kyber768 (old draft)', pqText(draft)],
      ['Classical key exchange', r.key_exchange],
    ])}</div>`;
  const certLane = `<div class="card lane"><h3>Certificate ${pill(certPill)}</h3>
    <p class="muted">Proves who the server is. Forging it needs a quantum computer during the connection, so it is less urgent.</p>
    ${c ? kv([
      ['Issued to', c.subject],
      ['Issued by', c.issuer + (c.self_signed ? ' (self-signed)' : '')],
      ['Expires', c.days_left < 0 ? `${c.not_after} (expired)` : `${c.not_after} (${c.days_left} days)`],
      ['Signature hash', c.sig_hash],
    ]) : '<p class="muted">The certificate could not be read.</p>'}</div>`;

  const rows = r.findings.map(f => `<tr><td><span class="pill ${f.severity}">${f.severity}</span></td>
    <td>${esc(f.rule_id)}</td><td class="wrap">${esc(f.title)}</td><td>${f.points}</td><td class="wrap">${esc(f.fix)}</td></tr>`).join('');
  const why = r.findings.map(f => `<div class="find"><span class="pill ${f.severity}">${esc(f.rule_id)}</span> <b>${esc(f.title)}</b><br>
    <span class="muted">${esc(f.why)}</span></div>`).join('');
  const names = c && c.names.length ? `<p class="muted">Names covered: ${c.names.map(n => `<code>${esc(n)}</code>`).join(' ')}</p>` : '';

  return head + `<div class="grid2">${kexLane}${certLane}</div>
    <div class="tablewrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Points</th><th>What to do</th></tr></thead><tbody>${rows}</tbody></table></div>
    <details><summary>Details: what each finding means</summary>${why}</details>
    ${names}
    <p class="muted">Scanned ${esc(r.host)}:${r.port} (${esc(r.ip)}) in ${r.seconds}s. The score adds up the points above, capped at 100.</p>
    <button class="btn" id="siteDl">Download JSON report</button>`;
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
      `<div class="seg seg-shelf" style="left:0;width:${pct(r.shelf_life)}%">shelf life</div>
       <div class="seg seg-mig" style="left:${pct(r.shelf_life)}%;width:${pct(r.migration_time)}%">migration</div>
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


// ---------------- Ask Crypt (chat assistant grounded in the current results)
const askPanel = $('#askPanel'), askLog = $('#askLog'), askInput = $('#askInput'), askSend = $('#askSend');
let askHistory = [], askBusy = false;

// Everything the assistant is allowed to see: the last scan, last TLS result, and the Mosca sliders.
function askContext() {
  return { scan: lastScan, site: lastSite,
    mosca: { shelf_life: +$('#shelf').value, migration_time: +$('#mig').value, years_to_threat: +$('#threat').value } };
}

// Minimal, XSS-safe markdown: escape first, then **bold**, `code`, lists, paragraphs.
function mdLite(text) {
  const inline = t => esc(t).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  const out = []; let list = null;
  const close = () => { if (list) { out.push(`</${list}>`); list = null; } };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    const ul = line.match(/^[-*•]\s+(.*)/), ol = line.match(/^\d+[.)]\s+(.*)/);
    if (ul || ol) {
      const kind = ul ? 'ul' : 'ol';
      if (list !== kind) { close(); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${inline((ul || ol)[1])}</li>`);
    } else { close(); if (line) out.push(`<p>${inline(line)}</p>`); }
  }
  close();
  return out.join('');
}

function addMsg(kind, html) {
  const d = document.createElement('div');
  d.className = 'msg ' + kind;
  if (kind === 'user') d.textContent = html; else d.innerHTML = html;
  askLog.appendChild(d); askLog.scrollTop = askLog.scrollHeight;
  return d;
}

function askSuggestions() {
  const q = [];
  if (lastScan) {
    q.push(lastScan.findings.length ? 'What should I migrate first?' : 'Is my code safe?');
    q.push(`Why is my code rated ${lastScan.label}?`);
  }
  if (lastSite) { q.push(`Why is my site rated ${lastSite.label}?`); q.push('What should I fix on my site first?'); }
  q.push('Am I exposed to harvest-now-decrypt-later?');
  if (!lastScan && !lastSite) q.push('What does Crypt do?');
  return q.slice(0, 4);
}

function refreshAskUi() {
  const have = [lastScan && 'scan', lastSite && 'website', 'Mosca'].filter(Boolean);
  $('#askCtx').textContent = 'Using: ' + have.join(', ');
  $('#askChips').innerHTML = askSuggestions().map(q => `<button type="button" class="chip">${esc(q)}</button>`).join('');
}

function resetAsk() {
  askHistory = []; askLog.innerHTML = '';
  addMsg('bot', mdLite("Hi, I'm Crypt's assistant. I can see your latest scan, website check and Mosca settings, so ask me things like “Why is my site rated HIGH?” or “What should I migrate first?”"));
  refreshAskUi();
}

function toggleAsk(open) {
  askPanel.hidden = !open;
  $('#askFab').setAttribute('aria-expanded', open);
  if (open) { refreshAskUi(); askInput.focus(); }
}

async function sendAsk(question) {
  question = question.trim();
  if (!question || askBusy) return;
  askBusy = true; askSend.disabled = true; askInput.value = '';
  addMsg('user', question);
  const wait = addMsg('bot', '<span class="typing"><i></i><i></i><i></i></span>');
  try {
    const r = await api('/api/ask', { question, history: askHistory, context: askContext() });
    wait.innerHTML = mdLite(r.answer);
    askHistory.push({ role: 'user', content: question }, { role: 'assistant', content: r.answer });
    askHistory = askHistory.slice(-10);
  } catch (e) { wait.className = 'msg err'; wait.textContent = e.message; }
  askBusy = false; askSend.disabled = false; askLog.scrollTop = askLog.scrollHeight; askInput.focus();
}

$('#askFab').addEventListener('click', () => toggleAsk(askPanel.hidden));
$('#askClose').addEventListener('click', () => toggleAsk(false));
$('#askClear').addEventListener('click', resetAsk);
$('#askForm').addEventListener('submit', e => { e.preventDefault(); sendAsk(askInput.value); });
$('#askChips').addEventListener('click', e => { if (e.target.classList.contains('chip')) sendAsk(e.target.textContent); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !askPanel.hidden) toggleAsk(false); });
resetAsk();


// ---------------- landing <-> dashboard
const landing = $('#landing'), appView = $('#app');
function showApp(tab) {
  landing.hidden = true; appView.hidden = false; $('#askFab').hidden = false;
  document.body.classList.remove('on-landing');
  if (tab) document.querySelector(`.tab[data-tab="${tab}"]`).click();
  scrollTo(0, 0);
}
function showLanding() {
  appView.hidden = true; landing.hidden = false; $('#askFab').hidden = true; toggleAsk(false);
  document.body.classList.add('on-landing'); scrollTo(0, 0);
}
document.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => showApp(b.dataset.open)));
$('#home').addEventListener('click', showLanding);

// ---------------- hero: a lattice that behaves like a wavefunction
(() => {
  const cv = $('#lattice'), ctx = cv.getContext('2d');
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const GAP = 34; let W, H, cols, rows, waves = [], mouse = null, t0 = performance.now();
  function size() {
    const d = devicePixelRatio || 1; W = innerWidth; H = innerHeight;
    cv.width = W * d; cv.height = H * d; ctx.setTransform(d, 0, 0, d, 0, 0);
    cols = Math.ceil(W / GAP) + 2; rows = Math.ceil(H / GAP) + 2;
  }
  addEventListener('resize', size); size();
  cv.parentElement.addEventListener('pointermove', e => { mouse = { x: e.clientX, y: e.clientY }; });
  cv.parentElement.addEventListener('pointerleave', () => mouse = null);
  cv.parentElement.addEventListener('pointerdown', e => waves.push({ x: e.clientX, y: e.clientY, t: performance.now() }));
  function frame(now) {
    if (landing.hidden) { requestAnimationFrame(frame); return; }
    ctx.clearRect(0, 0, W, H);
    const s = (now - t0) / 1000;
    waves = waves.filter(w => now - w.t < 4000);
    const src = [{ x: W * .72, y: H * .3, ph: s * 2.2, k: 1, amp: 1 }];
    waves.forEach(w => src.push({ x: w.x, y: w.y, ph: (now - w.t) / 1000 * 5, k: 1 - (now - w.t) / 4000, amp: 2 }));
    if (mouse) src.push({ x: mouse.x, y: mouse.y, ph: s * 3, k: .6, amp: 1 });
    for (let i = 0; i < cols; i++) for (let j = 0; j < rows; j++) {
      const x = i * GAP, y = j * GAP; let h = 0;
      for (const w of src) {
        const d = Math.hypot(x - w.x, y - w.y);
        h += Math.sin(d / 26 - w.ph) * Math.exp(-d / 420) * w.k * w.amp;
      }
      const a = Math.min(1, Math.abs(h)), px = x + h * 5, py = y + h * 5;
      ctx.fillStyle = h > 0 ? `rgba(92,225,255,${.12 + a * .75})` : `rgba(155,124,255,${.12 + a * .75})`;
      ctx.beginPath(); ctx.arc(px, py, 1.2 + a * 2, 0, 6.283); ctx.fill();
    }
    if (!still) requestAnimationFrame(frame);
  }
  if (still) frame(performance.now()); else requestAnimationFrame(frame);
})();
