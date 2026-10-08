// Harvest Now, Decrypt Later simulator. Pure client-side; no backend needed.
(() => {
  const cv = document.getElementById('hvCanvas');
  if (!cv) return;
  const ctx = cv.getContext('2d');
  const slider = document.getElementById('hvSlider');
  const qSel = document.getElementById('hvQday');
  const panel = document.getElementById('tab-harvest');
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const Y0 = 2026, Y1 = 2040;

  const css = getComputedStyle(document.documentElement);
  const C = n => css.getPropertyValue(n).trim();
  const col = { bg: C('--bg'), surf: C('--surface2'), line: C('--line'), ink: C('--ink'), muted: C('--muted'),
    ok: C('--photon'), bad: C('--bad'), warn: C('--warn') };
  const mono = '"JetBrains Mono", ui-monospace, Menlo, monospace';

  const secrets = ['pw: hunter2', 'card 4111 1111 1111', 'api_key=sk_live_9f3a', 'Dr. note: patient 4471', 'bank PIN 2048', 'ssh id_rsa ...'];
  const hex = n => Array.from({ length: n }, () => '0123456789abcdef'[Math.random() * 16 | 0]).join('');

  let W = 0, H = 0, running = false, last = 0, spawn = 0;
  let year = Y0, crackRsa = 0, shake = 0;
  const packets = [];          // in flight
  const vault = { rsa: { n: 0, rows: [] }, pqc: { n: 0, rows: [] } };
  let layout = {};

  function resize() {
    const r = cv.getBoundingClientRect();
    if (!r.width) return;
    const d = Math.min(devicePixelRatio || 1, 2);
    W = r.width; H = Math.round(Math.max(300, Math.min(380, W * 0.5)));
    cv.style.height = H + 'px';
    cv.width = W * d; cv.height = H * d;
    ctx.setTransform(d, 0, 0, d, 0, 0);
    const narrow = W < 560;
    const vw = narrow ? W * 0.4 : Math.min(230, W * 0.28), vh = H * (narrow ? 0.4 : 0.36);
    layout = {
      narrow, vw, vh,
      src: { x: narrow ? 28 : 56, y: H / 2 },
      tap: { x: W * (narrow ? 0.4 : 0.4), y: H / 2 },
      rsa: { x: W - vw - 14, y: H * 0.06 },
      pqc: { x: W - vw - 14, y: H * 0.58 },
    };
    draw();
  }

  const qday = () => +qSel.value;
  const cracked = () => year >= qday();

  function status() {
    const q = qday(), el = document.getElementById('hvStatus');
    document.getElementById('hvYear').textContent = year;
    const m = document.getElementById('hvQmark');
    m.style.left = ((q - Y0) / (Y1 - Y0) * 100) + '%';
    if (!cracked()) {
      const n = q - year;
      el.innerHTML = `<b>${year}.</b> The attacker is quietly recording. Everything looks safe, and ${n} year${n === 1 ? '' : 's'} remain before Q-day.`;
    } else {
      const ago = year - q;
      el.innerHTML = `<b>${year}.</b> Q-day ${ago ? `was ${ago} year${ago === 1 ? '' : 's'} ago` : 'is here'}. <span class="bad">The RSA vault is open and every recorded secret is readable.</span> <span class="good">The ML-KEM hybrid vault is still locked.</span>`;
    }
  }

  function setYear(y) { year = y; slider.value = y; if (still) crackRsa = cracked() ? 1 : 0; status(); if (!running) draw(); }
  slider.addEventListener('input', () => setYear(+slider.value));
  qSel.addEventListener('change', () => { status(); if (!running) draw(); });
  document.getElementById('hvReset').addEventListener('click', () => {
    stopPlay(); setYear(Y0); crackRsa = 0;
    vault.rsa = { n: 0, rows: [] }; vault.pqc = { n: 0, rows: [] }; packets.length = 0; draw();
  });

  let playT = null;
  const playBtn = document.getElementById('hvPlay');
  function stopPlay() { clearInterval(playT); playT = null; playBtn.textContent = 'Fast-forward to 2035'; }
  playBtn.addEventListener('click', () => {
    if (playT) return stopPlay();
    if (year >= 2035) setYear(Y0);
    playBtn.textContent = 'Pause';
    playT = setInterval(() => {
      if (year >= 2035) return stopPlay();
      setYear(year + 1);
    }, 650);
  });

  function capture(kind) {
    const v = vault[kind];
    v.n++;
    v.rows.unshift({ ct: hex(18), pt: secrets[Math.random() * secrets.length | 0] });
    if (v.rows.length > 4) v.rows.pop();
  }

  function step(dt) {
    spawn -= dt;
    if (spawn <= 0 && !still) {
      spawn = 0.45;
      packets.push({ stage: 0, t: 0, ct: hex(6) });
    }
    for (let i = packets.length - 1; i >= 0; i--) {
      const p = packets[i];
      p.t += dt / (p.stage === 0 ? 1.0 : 0.8);
      if (p.t >= 1) {
        if (p.stage === 0) { p.stage = 1; p.t = 0; capture('rsa'); capture('pqc'); }
        else packets.splice(i, 1);
      }
    }
    const target = cracked() ? 1 : 0;
    const prev = crackRsa;
    crackRsa += (target - crackRsa) * Math.min(1, dt * 2.2);
    if (Math.abs(target - crackRsa) < 0.002) crackRsa = target;
    if (prev < 0.3 && crackRsa >= 0.3) shake = 0.5;
    shake = Math.max(0, shake - dt);
  }

  function lerp(a, b, t) { return a + (b - a) * t; }

  function node(x, y, label, color) {
    ctx.fillStyle = col.surf; ctx.strokeStyle = color; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.arc(x, y, 20, 0, 7); ctx.fill(); ctx.stroke();
    ctx.fillStyle = col.ink; ctx.font = `600 11px ${mono}`; ctx.textAlign = 'center';
    ctx.fillText(label, x, y + 38);
  }

  function pkt(x, y, text, color) {
    ctx.font = `10px ${mono}`;
    const w = ctx.measureText(text).width + 12;
    ctx.fillStyle = col.bg; ctx.strokeStyle = color; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.roundRect(x - w / 2, y - 9, w, 18, 5); ctx.fill(); ctx.stroke();
    ctx.fillStyle = color; ctx.textAlign = 'center'; ctx.fillText(text, x, y + 3.5);
  }

  function drawVault(pos, kind, c, title, sub) {
    const { vw, vh } = layout, v = vault[kind];
    const open = kind === 'rsa' ? c : 0;
    const edge = kind === 'rsa' ? (open > 0.5 ? col.bad : col.line) : col.ok;
    let ox = 0;
    if (kind === 'rsa' && shake > 0) ox = Math.sin(shake * 90) * 3 * shake * 2;
    const x = pos.x + ox, y = pos.y;

    ctx.fillStyle = col.surf; ctx.strokeStyle = edge; ctx.lineWidth = 1.5;
    if (kind === 'pqc') { ctx.shadowColor = col.ok; ctx.shadowBlur = 10 + 6 * Math.sin(performance.now() / 500); }
    ctx.beginPath(); ctx.roundRect(x, y, vw, vh, 10); ctx.fill(); ctx.stroke();
    ctx.shadowBlur = 0;

    ctx.textAlign = 'left';
    ctx.fillStyle = col.ink; ctx.font = `700 ${layout.narrow ? 10 : 12}px ${mono}`;
    ctx.fillText(title, x + 10, y + 18);
    ctx.fillStyle = col.muted; ctx.font = `10px ${mono}`;
    ctx.fillText(layout.narrow ? `${v.n} captured` : `${sub} · ${v.n} captured`, x + 10, y + 32);

    // stored rows
    const rows = v.rows, fs = layout.narrow ? 9 : 10.5;
    ctx.font = `${fs}px ${mono}`;
    rows.forEach((r, i) => {
      const ry = y + 52 + i * (fs + 6);
      if (ry > y + vh - 30) return;
      const readable = kind === 'rsa' && open > 0.6;
      ctx.fillStyle = readable ? col.warn : col.muted;
      const t = readable ? r.pt : r.ct;
      ctx.fillText(t.length > 20 && layout.narrow ? t.slice(0, 16) + '…' : t, x + 10, ry);
    });

    // lock, top-right
    const lx = x + vw - 24, ly = y + 22;
    ctx.strokeStyle = kind === 'rsa' ? (open > 0.5 ? col.bad : col.ink) : col.ok; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(lx, ly - 5 - open * 4, 5, Math.PI, 0);
    ctx.moveTo(lx + 5, ly - 5 - open * 4); ctx.lineTo(lx + 5, ly - 2 - open * 4 * (open > 0.5 ? 1 : 0));
    ctx.stroke();
    ctx.fillStyle = ctx.strokeStyle; ctx.fillRect(lx - 7, ly - 2, 14, 10);

    // cracks
    if (kind === 'rsa' && open > 0.05) {
      ctx.save(); ctx.beginPath(); ctx.roundRect(x, y, vw, vh, 10); ctx.clip();
      ctx.strokeStyle = col.bad; ctx.lineWidth = 1.5; ctx.globalAlpha = Math.min(1, open * 1.5);
      const cx = x + vw / 2, cy = y + vh / 2, L = open * vh * 0.7;
      [[-1, -1], [1, -0.6], [-0.7, 1], [1, 1]].forEach(([dx, dy], i) => {
        ctx.beginPath(); ctx.moveTo(cx, cy);
        let px = cx, py = cy;
        for (let s = 1; s <= 4; s++) {
          px += dx * L / 4 + (((i + s) % 3) - 1) * 7; py += dy * L / 4 + (((i * s) % 3) - 1) * 6;
          ctx.lineTo(px, py);
        }
        ctx.stroke();
      });
      ctx.globalAlpha = 1; ctx.restore();
    }

    // verdict badge
    const badge = kind === 'rsa' ? (open > 0.6 ? 'DECRYPTED' : open > 0.05 ? 'CRACKING…' : 'LOCKED') : 'STILL LOCKED';
    const bc = kind === 'rsa' ? (open > 0.05 ? col.bad : col.muted) : col.ok;
    ctx.font = `700 10px ${mono}`;
    const bw = ctx.measureText(badge).width + 14;
    ctx.fillStyle = bc; ctx.globalAlpha = .16; ctx.fillRect(x + vw - bw - 8, y + vh - 24, bw, 18); ctx.globalAlpha = 1;
    ctx.fillStyle = bc; ctx.textAlign = 'right'; ctx.fillText(badge, x + vw - 15, y + vh - 11);
  }

  function draw() {
    if (!W) return;
    ctx.clearRect(0, 0, W, H);
    const { src, tap, rsa, pqc, vw, vh } = layout;

    // wires
    ctx.strokeStyle = col.line; ctx.lineWidth = 2; ctx.setLineDash([5, 5]);
    ctx.beginPath(); ctx.moveTo(src.x + 22, src.y); ctx.lineTo(tap.x - 22, tap.y); ctx.stroke();
    const mid = tap.x + 22;
    [[rsa, 'rsa'], [pqc, 'pqc']].forEach(([p]) => {
      ctx.beginPath(); ctx.moveTo(mid, tap.y);
      ctx.bezierCurveTo(mid + 40, tap.y, p.x - 40, p.y + vh / 2, p.x, p.y + vh / 2); ctx.stroke();
    });
    ctx.setLineDash([]);

    node(src.x, src.y, 'You', col.ok);
    node(tap.x, tap.y, 'Interceptor', col.bad);
    // interceptor "eye"
    ctx.fillStyle = col.bad; ctx.beginPath(); ctx.arc(tap.x, tap.y, 5, 0, 7); ctx.fill();

    packets.forEach(p => {
      if (p.stage === 0) {
        const x = lerp(src.x + 22, tap.x - 22, p.t);
        pkt(x, src.y - (layout.narrow ? 34 : 14), p.ct, col.ok);
      } else {
        [[rsa, col.bad], [pqc, col.warn]].forEach(([t]) => {
          const x0 = mid, y0 = tap.y, x1 = t.x, y1 = t.y + vh / 2;
          const u = p.t, x = lerp(x0, x1, u), y = lerp(y0, y1, u * u * (3 - 2 * u));
          ctx.fillStyle = col.bad; ctx.globalAlpha = 1 - u * 0.4;
          ctx.beginPath(); ctx.arc(x, y, 3.5, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
        });
      }
    });

    drawVault(rsa, 'rsa', crackRsa, 'RSA-2048', 'classical');
    drawVault(pqc, 'pqc', 0, layout.narrow ? 'X25519+ML-KEM' : 'X25519 + ML-KEM-768', 'hybrid');

    // year watermark
    ctx.fillStyle = col.muted; ctx.globalAlpha = .35; ctx.font = `800 ${layout.narrow ? 34 : 54}px Syne, sans-serif`;
    ctx.textAlign = 'left'; ctx.fillText(year, 14, H - 16); ctx.globalAlpha = 1;
  }

  function loop(ts) {
    if (!running) return;
    const dt = Math.min(0.05, (ts - last) / 1000 || 0); last = ts;
    step(dt); draw();
    requestAnimationFrame(loop);
  }
  function start() {
    if (running) return;
    resize(); status();
    if (still) { // reduced motion: pre-fill and render a static frame
      for (let i = 0; i < 4; i++) { capture('rsa'); capture('pqc'); }
      crackRsa = cracked() ? 1 : 0; draw(); return;
    }
    running = true; last = performance.now(); requestAnimationFrame(loop);
  }
  function stop() { running = false; stopPlay(); }

  // run only while the Harvest tab is visible
  new MutationObserver(() => panel.classList.contains('active') ? start() : stop())
    .observe(panel, { attributes: true, attributeFilter: ['class'] });
  new ResizeObserver(() => { if (panel.classList.contains('active')) resize(); }).observe(cv);
  document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); else if (panel.classList.contains('active')) start(); });
  status();
})();
