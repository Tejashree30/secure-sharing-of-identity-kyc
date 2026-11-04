'use strict';
/* AI Cyber Defense Console: vanilla JS single-page app (no build step, no CDN, works offline). */

// ---------------------------------------------------------------- helpers
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const clock = ts => new Date(ts * 1000).toLocaleTimeString();
const when = ts => { const s = Math.max(0, Date.now() / 1000 - ts); return s < 60 ? Math.floor(s) + 's ago' : s < 3600 ? Math.floor(s / 60) + 'm ago' : Math.floor(s / 3600) + 'h ago'; };
const TYPE = {port_scan: 'Port scan', brute_force: 'Brute force', ddos: 'DDoS flood', exfiltration: 'Data exfiltration', unknown_anomaly: 'Unknown anomaly', c2_beacon: 'C2 beacon'};
const typeName = t => TYPE[t] || t;
const STATUS = {open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved', false_positive: 'False positive', pending_approval: 'Needs approval'};
const RANK = {viewer: 1, analyst: 2, admin: 3};
const can = r => !!ME && RANK[ME.role] >= RANK[r];
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const store = {get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }};

let ME = null, current = null, pollTimer = null, es = null, soundOn = store.get('sound') !== 'off', connOk = null;

// ---------------------------------------------------------------- api
async function api(path, {method = 'GET', body, quiet = false} = {}) {
  let r;
  try {
    r = await fetch('/api' + path, {method, credentials: 'same-origin', headers: body ? {'Content-Type': 'application/json'} : {}, body: body ? JSON.stringify(body) : undefined});
  } catch (e) {
    if (!quiet) toast('danger', 'Cannot reach the server', 'Check that server.py is still running.');
    throw e;
  }
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && !path.startsWith('/login')) { showLogin(); throw new Error('Session expired'); }
  if (!r.ok) {
    const err = new Error(j.error || 'Request failed (' + r.status + ')');
    err.status = r.status;
    if (!quiet) toast(r.status === 403 ? 'warning' : 'danger', r.status === 403 ? 'Not allowed' : 'Request failed', err.message);
    throw err;
  }
  return j;
}
const act = async (fn, okMsg) => { try { const r = await fn(); if (okMsg) toast('success', okMsg); return r; } catch (e) { return null; } };

// ---------------------------------------------------------------- toasts, banner, sound
const ICON = {info: '&#8505;', success: '&#10004;', warning: '&#9888;', danger: '&#9940;'};
function beep() {
  if (!soundOn) return;
  try { const c = new (window.AudioContext || window.webkitAudioContext)(), o = c.createOscillator(), g = c.createGain();
    o.connect(g); g.connect(c.destination); o.frequency.value = 880; g.gain.value = 0.04; o.start(); o.stop(c.currentTime + 0.18); } catch (e) { /* audio blocked */ }
}
function toast(level, title, text = '', opts = {}) {
  const box = $('#toasts');
  while (box.children.length >= 5) box.firstChild.remove();
  const ms = level === 'danger' ? 12000 : level === 'warning' ? 9000 : 6000;
  const el = document.createElement('div');
  el.className = 'toast ' + level + (opts.incident_id ? ' link' : '');
  el.innerHTML = `<div class="t-ico">${ICON[level] || ICON.info}</div><div><b>${esc(title)}</b><div>${esc(text)}</div></div><button class="t-x" aria-label="Dismiss">&times;</button><span class="bar" style="animation-duration:${ms}ms"></span>`;
  const close = () => { el.classList.add('out'); setTimeout(() => el.remove(), 250); };
  $('.t-x', el).onclick = e => { e.stopPropagation(); close(); };
  if (opts.incident_id) el.onclick = () => { close(); openIncident(opts.incident_id); };
  box.appendChild(el);
  setTimeout(close, ms);
  if (level === 'danger') beep();
}
function banner(text, id) {
  const b = $('#banner');
  b.innerHTML = `<span>&#9940; CRITICAL: ${esc(text)}</span><button aria-label="Dismiss">&times;</button>`;
  b.classList.remove('hidden');
  $('button', b).onclick = () => b.classList.add('hidden');
  b.style.cursor = id ? 'pointer' : '';
  b.onclick = id ? e => { if (e.target.tagName !== 'BUTTON') openIncident(id); } : null;
  clearTimeout(banner.t); banner.t = setTimeout(() => b.classList.add('hidden'), 20000);
}
window.addEventListener('unhandledrejection', e => { if (e.reason && !e.reason.status && e.reason.message !== 'Session expired') console.warn(e.reason); });
window.addEventListener('error', e => toast('danger', 'Display error', e.message));

// ---------------------------------------------------------------- charts
function lineChart(cv, series, colors) {
  const dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight;
  if (!w || !h) return;
  cv.width = w * dpr; cv.height = h * dpr;
  const g = cv.getContext('2d'); g.scale(dpr, dpr); g.clearRect(0, 0, w, h);
  const n = Math.max(1, ...series.map(s => s.length)), max = Math.max(4, ...series.flat());
  g.font = '11px system-ui'; g.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = 8 + (h - 20) * i / 4;
    g.strokeStyle = css('--line'); g.beginPath(); g.moveTo(30, y); g.lineTo(w, y); g.stroke();
    g.fillStyle = css('--mute'); g.fillText(Math.round(max * (1 - i / 4)), 2, y + 4);
  }
  series.forEach((s, k) => {
    g.beginPath();
    s.forEach((v, i) => { const x = 30 + (n > 1 ? i * (w - 36) / (n - 1) : 0), y = 8 + (h - 20) * (1 - v / max); i ? g.lineTo(x, y) : g.moveTo(x, y); });
    g.strokeStyle = colors[k]; g.lineWidth = 2; g.stroke();
  });
}
const barRows = (items, label = k => k) => {
  const max = Math.max(1, ...items.map(i => i.n));
  return items.length ? `<div class="bars">${items.map(i => `<div class="bar-row"><span>${esc(label(i.k))}</span><div class="bar-track"><div class="bar-fill" style="width:${i.n / max * 100}%"></div></div><b>${i.n}</b></div>`).join('')}</div>` : '<div class="empty">No data yet.</div>';
};

// ---------------------------------------------------------------- small renderers
const sevPill = s => `<span class="sev s${s}">${s}</span>`;
const statusPill = s => `<span class="pill ${esc(s)}">${esc(STATUS[s] || s)}</span>`;
const actionTags = a => (a || []).map(x => `<span class="tag">${esc(x.replace('_', ' ').replace(':', ': '))}</span>`).join('');
const table = (head, rows, empty) => rows.length ? `<table class="tbl"><thead><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table>` : `<div class="empty">${empty}</div>`;

// ---------------------------------------------------------------- pages
const pages = {};

pages.overview = {
  title: 'Overview', every: 1200,
  mount(el) {
    el.innerHTML = `<div class="kpis" id="kpis"></div>
      <div class="card"><h3>Traffic per second</h3><canvas id="ch" style="height:150px"></canvas>
        <div class="legend"><i style="color:var(--blue)">&#9632;</i>events &nbsp; <i style="color:var(--bad)">&#9632;</i>threats &nbsp; <i style="color:var(--warn)">&#9632;</i>dropped by firewall</div></div>
      <div class="grid2">
        <div class="card"><h3>Live traffic</h3><div class="scroll" id="feed"></div></div>
        <div class="card"><h3>Recent incidents</h3><div id="recent"></div></div>
      </div>`;
  },
  async tick() {
    const [s, inc] = await Promise.all([api('/overview', {quiet: true}), api('/incidents?limit=7', {quiet: true})]);
    const q = s.quality, pc = v => v == null ? '&ndash;' : (v * 100).toFixed(1) + '%';
    $('#kpis').innerHTML = [
      [s.counters.events, 'events analysed', ''], [s.counters.threats, 'threats detected', 'var(--bad)'],
      [s.db_open, 'open incidents', 'var(--warn)'], [s.blocked.length + s.isolated.length, 'sources contained now', ''],
      [s.counters.dropped, 'malicious packets stopped', ''], [pc(q.precision), 'precision (simulation)', ''], [pc(q.recall), 'recall (simulation)', '']
    ].map(([v, l, c]) => `<div class="card kpi"><b style="${c ? 'color:' + c : ''}">${v}</b><span>${l}</span></div>`).join('');
    lineChart($('#ch'), [0, 1, 2].map(i => s.timeline.map(t => t[i])), [css('--blue'), css('--bad'), css('--warn')]);
    $('#feed').innerHTML = table(['Time', 'Source', 'Destination', 'Port', 'Verdict', 'Type', 'Agent action'],
      s.feed.map(e => `<tr class="${esc(e.verdict)}"><td>${esc(e.time)}</td><td class="mono">${esc(e.src)}</td><td class="mono">${esc(e.dst)}</td><td>${e.port}</td><td class="v">${esc(e.verdict)}</td><td>${esc(typeName(e.type))}</td><td>${esc(e.action)}</td></tr>`), 'Waiting for traffic&hellip;');
    $('#recent').innerHTML = inc.items.length ? inc.items.map(i => `<div class="row click" style="padding:8px 0;border-top:1px solid var(--line);cursor:pointer" data-id="${i.id}">${sevPill(i.severity)}<div class="grow"><b>${esc(typeName(i.threat_type))}</b> <span class="muted mono">${esc(i.src_ip)}</span><div class="muted small">${when(i.ts)} &middot; ${esc(i.owner || '')}</div></div>${statusPill(i.status)}</div>`).join('') : '<div class="empty">No incidents yet. Start an attack from the simulator.</div>';
    $$('#recent [data-id]').forEach(r => r.onclick = () => openIncident(r.dataset.id));
    setBadge(s.db_open);
  }
};

pages.incidents = {
  title: 'Incidents', every: 3000,
  mount(el) {
    el.innerHTML = `<div class="card"><div class="row">
        <input id="f-q" class="grow" placeholder="Search IP, threat type or owner&hellip;" value="${esc(pages.incidents.q || '')}">
        <select id="f-s" style="width:auto"><option value="">All statuses</option>${Object.entries(STATUS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
        <select id="f-v" style="width:auto"><option value="">Any severity</option><option value="2">Severity 2+</option><option value="3">Severity 3+</option><option value="4">Severity 4+</option></select>
        <a class="btn small" href="/api/export/incidents.csv">Export CSV</a><a class="btn small" href="/api/export/report.json">Full report (JSON)</a></div>
      <div id="list" style="margin-top:12px"></div></div>`;
    let t; $('#f-q').oninput = e => { pages.incidents.q = e.target.value; clearTimeout(t); t = setTimeout(() => pages.incidents.tick(), 250); };
    $('#f-s').onchange = $('#f-v').onchange = () => pages.incidents.tick();
  },
  async tick() {
    const p = new URLSearchParams();
    if ($('#f-q').value) p.set('q', $('#f-q').value);
    if ($('#f-s').value) p.set('status', $('#f-s').value);
    if ($('#f-v').value) p.set('severity', $('#f-v').value);
    const d = await api('/incidents?' + p, {quiet: true});
    $('#list').innerHTML = table(['#', 'Time', 'Threat', 'Source &rarr; Destination', 'Sev', 'Status', 'Agent actions', 'Owner', 'Response'],
      d.items.map(i => `<tr class="click" data-id="${i.id}"><td>${i.id}</td><td>${clock(i.ts)}<div class="muted small">${when(i.ts)}</div></td><td><b>${esc(typeName(i.threat_type))}</b><div class="muted small">&times;${i.count}</div></td><td class="mono">${esc(i.src_ip)} &rarr; ${esc(i.dst_ip)}</td><td>${sevPill(i.severity)}</td><td>${statusPill(i.status)}</td><td>${actionTags(i.actions)}</td><td>${esc(i.owner || '')}</td><td>${i.response_ms != null ? i.response_ms + ' ms' : ''}</td></tr>`),
      'No incidents match. Start an attack from the simulator or clear the filters.');
    $$('#list tr[data-id]').forEach(r => r.onclick = () => openIncident(r.dataset.id));
  }
};

pages.blocklist = {
  title: 'Blocklist', every: 2000,
  mount(el) {
    el.innerHTML = `<div class="card"><h3>Block or isolate manually</h3>
        <form id="bf" class="row"><input id="b-ip" class="grow" placeholder="IP address, e.g. 203.0.113.9" required>
          <select id="b-kind" style="width:auto"><option value="block">Block (external)</option><option value="isolate">Isolate (internal host)</option></select>
          <input id="b-ttl" type="number" min="0" max="1440" value="60" style="width:130px" title="Minutes until the block expires (0 = never)">
          <input id="b-reason" class="grow" placeholder="Reason (optional)">
          <button class="btn primary" ${can('analyst') ? '' : 'disabled'}>Apply</button></form>
        <div class="muted small" style="margin-top:6px">TTL is in minutes (0 = never expires). Loopback, reserved and allowlisted addresses are refused.</div></div>
      <div class="card"><h3>Currently contained <span id="mode-note" class="muted"></span></h3><div id="bl"></div></div>
      <div class="card"><h3>Firewall command log</h3><div id="cmds" class="scroll"></div></div>`;
    $('#bf').onsubmit = async e => {
      e.preventDefault();
      const r = await act(() => api('/blocklist', {method: 'POST', body: {ip: $('#b-ip').value, kind: $('#b-kind').value, reason: $('#b-reason').value, ttl_minutes: Number($('#b-ttl').value)}}));
      if (r) { $('#b-ip').value = ''; this.tick(); }
    };
  },
  async tick() {
    const d = await api('/blocklist', {quiet: true});
    $('#mode-note').textContent = d.dry_run ? '(dry-run: commands are recorded, not applied)' : '(REAL enforcement)';
    $('#bl').innerHTML = table(['Address', 'Type', 'Reason', 'By', 'Since', 'Expires', ''],
      d.items.map(b => `<tr><td class="mono">${esc(b.ip)}</td><td><span class="pill ${b.kind}">${b.kind === 'block' ? 'blocked' : 'isolated'}</span></td><td>${esc(b.reason)}</td><td>${esc(b.by)}</td><td>${clock(b.ts)}</td><td>${b.expires ? Math.max(0, Math.round((b.expires - Date.now() / 1000) / 60)) + ' min' : 'never'}</td><td><button class="btn small" data-ip="${esc(b.ip)}" ${can('analyst') ? '' : 'disabled'}>Unblock</button></td></tr>`), 'Nothing is blocked right now.');
    $$('#bl [data-ip]').forEach(b => b.onclick = async () => { if (await act(() => api('/blocklist/' + encodeURIComponent(b.dataset.ip), {method: 'DELETE'}))) this.tick(); });
    $('#cmds').innerHTML = table(['Time', 'Action', 'Result', 'Commands'], d.commands.map(c => `<tr><td>${clock(c.ts)}</td><td>${esc(c.action)} ${esc(c.ip)}</td><td>${c.ok ? (c.dry_run ? 'dry-run' : 'applied') : '<span style="color:var(--bad)">failed: ' + esc(c.error) + '</span>'}</td><td class="mono">${c.commands.map(esc).join('<br>')}</td></tr>`), 'No firewall commands yet.');
  }
};

pages.notifications = {
  title: 'Owner messages', every: 4000,
  mount(el) { el.innerHTML = '<div id="nl" class="grid2 even"></div>'; },
  async tick() {
    const d = await api('/notifications', {quiet: true});
    $('#nl').innerHTML = d.items.length ? d.items.map(n => `<div class="card"><div class="row"><b class="grow">${esc(n.subject)}</b><span class="muted small">${clock(n.ts)}</span></div>
        <div class="muted small">To: ${esc(n.owner)} &lt;${esc(n.to_addr)}&gt; &middot; written by ${esc(n.written_by)} &middot; incident <a href="#" data-inc="${n.incident_id}">#${n.incident_id}</a></div>
        <div class="msg" style="margin:10px 0">${esc(n.message)}</div>
        <div class="row">${Object.entries(n.channels || {}).map(([k, v]) => `<span class="pill" style="${String(v).startsWith('failed') ? 'background:#7a1f2a;color:#fff' : ''}">${esc(k)}: ${esc(v)}</span>`).join('')}
        <span class="grow"></span><button class="btn small" data-n="${n.id}" ${can('analyst') ? '' : 'disabled'}>Resend</button></div></div>`).join('') : '<div class="card empty">No owner messages yet. They are sent automatically for incidents at or above the notification severity.</div>';
    $$('#nl [data-inc]').forEach(a => a.onclick = e => { e.preventDefault(); openIncident(a.dataset.inc); });
    $$('#nl [data-n]').forEach(b => b.onclick = () => act(() => api('/notifications/' + b.dataset.n + '/resend', {method: 'POST'})));
  }
};

pages.owners = {
  title: 'Owners & assets', every: 0,
  mount(el) {
    el.innerHTML = `<div class="card"><h3>Who gets told when their data is affected</h3>
        <p class="muted small" style="margin-top:0">The agent maps the affected internal IP to the longest matching prefix. Criticality 3 raises incident severity by one level.</p>
        <form id="of" class="row"><input id="o-p" placeholder="IP prefix e.g. 10.0.5." style="width:150px" required><input id="o-n" class="grow" placeholder="Owner or team name" required>
          <input id="o-e" type="email" class="grow" placeholder="owner@company.com" required>
          <select id="o-c" style="width:auto"><option value="1">Criticality 1 (normal)</option><option value="2">Criticality 2 (important)</option><option value="3">Criticality 3 (critical)</option></select>
          <button class="btn primary" ${can('admin') ? '' : 'disabled title="Admin only"'}>Save</button></form></div>
      <div class="card" id="ol"></div>`;
    $('#of').onsubmit = async e => { e.preventDefault(); if (await act(() => api('/owners', {method: 'PUT', body: {prefix: $('#o-p').value, name: $('#o-n').value, email: $('#o-e').value, criticality: Number($('#o-c').value)}}), 'Owner saved')) { e.target.reset(); this.tick(); } };
  },
  async tick() {
    const d = await api('/owners', {quiet: true});
    $('#ol').innerHTML = table(['Prefix', 'Owner', 'E-mail', 'Criticality', ''], d.items.map(o => `<tr><td class="mono">${esc(o.prefix)}</td><td>${esc(o.name)}</td><td>${esc(o.email)}</td><td>${'&#9679;'.repeat(o.criticality)}</td><td><button class="btn small" data-e="${esc(o.prefix)}">Edit</button> <button class="btn small danger" data-d="${esc(o.prefix)}" ${can('admin') ? '' : 'disabled'}>Delete</button></td></tr>`), 'No owners defined.');
    $$('#ol [data-e]').forEach(b => b.onclick = () => { const o = d.items.find(x => x.prefix === b.dataset.e); $('#o-p').value = o.prefix; $('#o-n').value = o.name; $('#o-e').value = o.email; $('#o-c').value = o.criticality; scrollTo(0, 0); });
    $$('#ol [data-d]').forEach(b => b.onclick = async () => { if (confirm('Delete owner mapping ' + b.dataset.d + '?') && await act(() => api('/owners/' + encodeURIComponent(b.dataset.d), {method: 'DELETE'}), 'Owner deleted')) this.tick(); });
  }
};

pages.simulator = {
  title: 'Attack simulator', every: 0,
  mount(el) {
    const A = [['port_scan', 'Port scan', 'An outside host probes hundreds of ports looking for open doors.'], ['brute_force', 'Brute-force login', 'Rapid password guessing against SSH/RDP/FTP.'],
      ['ddos', 'DDoS flood', 'Huge packet floods to knock a web service offline.'], ['exfiltration', 'Data exfiltration', 'An internal machine sends a large amount of data out at night.'],
      ['c2_beacon', 'Zero-day (unknown C2)', 'Low-and-slow beaconing the supervised model has never seen. Only the anomaly model can catch it.']];
    el.innerHTML = `<div class="card"><p class="muted" style="margin-top:0">Launch a simulated attack and watch the dashboard, toasts, blocklist and owner messages react in real time.</p>
        <div class="row"><label class="muted">Intensity</label><select id="cnt" style="width:auto"><option value="1">1 campaign</option><option value="2">2 campaigns</option><option value="3">3 campaigns</option><option value="5">5 campaigns</option></select>
        <button class="btn danger" id="all" ${can('analyst') ? '' : 'disabled'}>&#9889; Launch every attack type</button></div></div>
      <div class="grid3">${A.map(([k, n, d]) => `<div class="card attack"><b>${n}</b><p>${d}</p><button class="btn primary" data-k="${k}" ${can('analyst') ? '' : 'disabled'}>Launch</button></div>`).join('')}</div>
      ${can('analyst') ? '' : '<div class="card empty">Your role is read-only. Sign in as analyst or admin to launch attacks.</div>'}`;
    const go = k => act(() => api('/simulate', {method: 'POST', body: {kind: k, count: Number($('#cnt').value)}}));
    $$('[data-k]').forEach(b => b.onclick = () => go(b.dataset.k));
    $('#all').onclick = () => go('all');
  }
};

pages.analytics = {
  title: 'Analytics', every: 5000,
  mount(el) {
    el.innerHTML = `<div class="kpis" id="ak"></div>
      <div class="card"><h3>Incidents per minute (last 30 min)</h3><canvas id="tl" style="height:140px"></canvas></div>
      <div class="grid2 even"><div class="card"><h3>By threat type</h3><div id="bt"></div></div><div class="card"><h3>By severity</h3><div id="bs"></div></div></div>
      <div class="grid2 even"><div class="card"><h3>Top attacking sources</h3><div id="ts"></div></div><div class="card"><h3>Analyst feedback</h3><div id="st"></div></div></div>`;
  },
  async tick() {
    const d = await api('/analytics', {quiet: true});
    $('#ak').innerHTML = [[d.total, 'incidents total'], [d.mean_response_ms + ' ms', 'mean time to respond'], [d.max_response_ms + ' ms', 'slowest response'], [d.notifications, 'owner messages sent'],
      [d.fp_rate == null ? '&ndash;' : (d.fp_rate * 100).toFixed(0) + '%', 'false-positive rate (reviewed)'], [d.llm_reviews, 'AI analyst reviews']].map(([v, l]) => `<div class="card kpi"><b>${v}</b><span>${l}</span></div>`).join('');
    lineChart($('#tl'), [d.timeline.map(t => t.n)], [css('--blue')]);
    $('#bt').innerHTML = barRows(d.by_type, typeName);
    $('#bs').innerHTML = barRows(d.by_severity, k => 'Severity ' + k);
    $('#ts').innerHTML = table(['Source', 'Incidents', 'Max sev', 'Type'], d.top_sources.map(s => `<tr><td class="mono">${esc(s.src_ip)}</td><td>${s.n}</td><td>${sevPill(s.sev)}</td><td>${esc(typeName(s.type))}</td></tr>`), 'No data yet.');
    $('#st').innerHTML = barRows(Object.entries(d.status).map(([k, n]) => ({k, n})), k => STATUS[k] || k);
  }
};

pages.audit = {
  title: 'Audit log', every: 5000,
  mount(el) { el.innerHTML = '<div class="card"><h3>Every automatic and manual action</h3><div id="au"></div></div>'; },
  async tick() {
    const d = await api('/audit', {quiet: true});
    $('#au').innerHTML = table(['Time', 'Who', 'Action', 'Target', 'Detail'], d.items.map(a => `<tr><td>${new Date(a.ts * 1000).toLocaleString()}</td><td>${esc(a.actor)}</td><td><span class="tag">${esc(a.action)}</span></td><td class="mono">${esc(a.target)}</td><td>${esc(a.detail)}</td></tr>`), 'Nothing logged yet.');
  }
};

pages.settings = {
  title: 'Settings & health', every: 0,
  async mount(el) {
    const [{settings: S, real_firewall_allowed: realFw}, H] = await Promise.all([api('/settings'), api('/health')]);
    const ro = can('admin') ? '' : 'disabled';
    const sw = (k, t, d, extra = '') => `<div class="switch"><div>${t}<small>${d}</small></div><input type="checkbox" data-s="${k}" ${S[k] ? 'checked' : ''} ${ro} ${extra}></div>`;
    el.innerHTML = `<div class="grid2 even"><div>
      <div class="card"><h3>Agent behaviour</h3>
        ${sw('auto_response', 'Automatic response', 'Let the agent block IPs and isolate hosts by itself. Off = recommend only.')}
        ${sw('approval_for_isolation', 'Require approval to isolate hosts', 'Isolation waits for an analyst to approve it in the incident panel.')}
        ${sw('llm_agent', 'AI analyst review', 'Claude reviews serious incidents with tools (needs ANTHROPIC_API_KEY).')}
        ${sw('auto_attacks', 'Background demo attacks', 'Random attack campaigns appear on their own.')}
        ${sw('dry_run', 'Firewall dry-run (safe mode)', realFw ? 'Turn OFF to really run iptables / netsh commands.' : 'Locked. Start the server with ALLOW_REAL_FIREWALL=1 to allow real enforcement.', realFw ? '' : 'disabled')}
        <div class="field"><label>Notify owners at severity &ge;</label><input type="number" min="1" max="5" data-s="notify_min_severity" value="${S.notify_min_severity}" ${ro}></div>
        <div class="field"><label>Escalate after N repeated detections</label><input type="number" min="2" max="50" data-s="escalate_after" value="${S.escalate_after}" ${ro}></div>
        <div class="field"><label>Block expiry (minutes, 0 = never)</label><input type="number" min="0" max="1440" data-s="block_ttl_minutes" value="${S.block_ttl_minutes}" ${ro}></div>
        <div class="field"><label>Webhook URL (Slack / Teams / Discord incoming webhook)</label><input data-s="webhook_url" value="${esc(S.webhook_url)}" placeholder="https://hooks.slack.com/..." ${ro}></div>
        <button class="btn primary" id="save" ${ro}>Save settings</button> ${ro ? '<span class="muted small">Admin only</span>' : ''}</div>
      <div class="card"><h3>Allowlist (never blocked)</h3><div>${(S.allowlist || []).map(ip => `<span class="tag mono">${esc(ip)}</span>`).join('') || '<span class="muted">empty</span>'}</div></div>
      <div class="card"><h3>Change my password</h3><form id="pf"><div class="field"><label>Current password</label><input type="password" id="pw-o" autocomplete="current-password" required></div>
        <div class="field"><label>New password (8+ characters)</label><input type="password" id="pw-n" autocomplete="new-password" minlength="8" required></div><button class="btn">Update password</button></form></div></div>
      <div class="card"><h3>System health</h3>${H.components.map(c => `<div class="health"><span class="dot ${c.status}"></span><div><b>${esc(c.name)}</b><div class="muted small">${esc(c.detail)}</div></div></div>`).join('')}
        <div class="muted small" style="margin-top:10px">Uptime ${Math.floor(H.uptime / 60)} min &middot; ${H.events} events analysed &middot; ${H.eps} events/s</div></div></div>`;
    $('#save').onclick = async () => {
      const body = {};
      $$('[data-s]').forEach(i => body[i.dataset.s] = i.type === 'checkbox' ? i.checked : i.type === 'number' ? Number(i.value) : i.value);
      await act(() => api('/settings', {method: 'PUT', body}));
    };
    $('#pf').onsubmit = async e => { e.preventDefault(); if (await act(() => api('/password', {method: 'POST', body: {old: $('#pw-o').value, new: $('#pw-n').value}}), 'Password updated')) e.target.reset(); };
  }
};

// ---------------------------------------------------------------- incident drawer
const KIND = {observe: 'Observed', tool: 'Tool call', thought: 'Reasoning', decision: 'Decision', summary: 'Result', llm: 'AI analyst', llm_tool: 'AI tool call'};
async function openIncident(id) {
  let d;
  try { d = await api('/incidents/' + id); } catch (e) { return; }
  const dr = $('#drawer'), pend = d.status === 'pending_approval', ok = can('analyst') ? '' : 'disabled';
  const intel = d.intel || {};
  dr.innerHTML = `<div class="row"><h2 class="grow">Incident #${d.id}</h2><button class="btn small" id="dx">Close</button></div>
    <div class="row" style="margin-bottom:6px">${sevPill(d.severity)} <b>${esc(typeName(d.threat_type))}</b> ${statusPill(d.status)}</div>
    <dl class="kv"><dt>Source</dt><dd class="mono">${esc(d.src_ip)} ${d.contained ? '<span class="pill block">contained</span>' : ''}</dd><dt>Destination</dt><dd class="mono">${esc(d.dst_ip)}</dd>
      <dt>Detected</dt><dd>${new Date(d.ts * 1000).toLocaleString()} (&times;${d.count} detections)</dd><dt>Owner</dt><dd>${esc(d.owner || '')}</dd>
      <dt>Model</dt><dd>confidence ${Number(d.confidence).toFixed(2)}, anomaly score ${Number(d.anomaly_score).toFixed(2)}</dd>
      <dt>Reputation</dt><dd>${esc(intel.detail || '')} (${esc(intel.source || '')})</dd><dt>Response time</dt><dd>${d.response_ms != null ? d.response_ms + ' ms' : ''}</dd>
      <dt>Actions</dt><dd>${actionTags(d.actions)}</dd></dl>
    <div class="row">${pend ? `<button class="btn ok" data-a="approve" ${ok}>Approve isolation</button><button class="btn danger" data-a="deny" ${ok}>Deny</button>` : ''}
      <button class="btn small" data-a="ack" ${ok}>Acknowledge</button><button class="btn small" data-a="resolve" ${ok}>Resolve</button>
      <button class="btn small" data-a="fp" ${ok}>False positive</button><button class="btn small" data-a="fpa" ${ok} title="Release and never block this address again">False positive + allowlist</button>
      ${d.contained ? `<button class="btn small" data-a="unblock" ${ok}>Unblock source</button>` : ''}</div>
    <h3 style="margin:20px 0 4px;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--mute)">Agent reasoning</h3>
    <ul class="timeline">${(d.trace || []).map(t => `<li class="${esc(t.kind)}"><div class="k">${esc(KIND[t.kind] || t.kind)}${t.t ? ' &middot; +' + t.t + ' ms' : ''}</div>${esc(t.text)}</li>`).join('')}</ul>
    ${d.notifications.length ? `<h3 style="margin:20px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.07em;color:var(--mute)">Message sent to the owner</h3>${d.notifications.map(n => `<div class="msg">${esc(n.message)}</div><div class="muted small" style="margin:4px 0 10px">To ${esc(n.owner)} &lt;${esc(n.to_addr)}&gt; &middot; ${Object.entries(n.channels || {}).map(([k, v]) => esc(k + ': ' + v)).join(', ')}</div>`).join('')}` : ''}`;
  dr.classList.add('open'); $('#scrim').classList.remove('hidden'); dr.setAttribute('aria-hidden', 'false');
  const close = () => { dr.classList.remove('open'); $('#scrim').classList.add('hidden'); dr.setAttribute('aria-hidden', 'true'); };
  $('#dx').onclick = $('#scrim').onclick = close;
  $$('[data-a]', dr).forEach(b => b.onclick = async () => {
    const a = b.dataset.a;
    const call = {approve: () => api(`/incidents/${id}/approve`, {method: 'POST'}), deny: () => api(`/incidents/${id}/deny`, {method: 'POST'}),
      ack: () => api(`/incidents/${id}/status`, {method: 'POST', body: {status: 'acknowledged'}}), resolve: () => api(`/incidents/${id}/status`, {method: 'POST', body: {status: 'resolved'}}),
      fp: () => api(`/incidents/${id}/status`, {method: 'POST', body: {status: 'false_positive'}}), fpa: () => api(`/incidents/${id}/status`, {method: 'POST', body: {status: 'false_positive', allowlist: true}}),
      unblock: () => api('/blocklist/' + encodeURIComponent(d.src_ip), {method: 'DELETE'})}[a];
    if (await act(call)) { await openIncident(id); if (current && current.tick) current.tick(); }
  });
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') { $('#drawer').classList.remove('open'); $('#scrim').classList.add('hidden'); } });

// ---------------------------------------------------------------- shell: router, SSE, login
function setBadge(n) { const b = $('#b-inc'); b.textContent = n; b.classList.toggle('hidden', !n); }

function route() {
  if (!ME) return;
  const name = (location.hash.replace('#/', '') || 'overview').split('?')[0];
  const page = pages[name] || pages.overview;
  clearInterval(pollTimer);
  current = page;
  $$('#nav a').forEach(a => a.classList.toggle('active', a.dataset.r === name));
  $('#page-title').textContent = page.title;
  const view = $('#view');
  view.innerHTML = '';
  Promise.resolve(page.mount(view)).then(() => { if (page.tick) page.tick().catch(() => {}); });
  if (page.every) pollTimer = setInterval(() => { if (!document.hidden && current === page && page.tick) page.tick().catch(() => {}); }, page.every);
}
window.addEventListener('hashchange', route);

function connect() {
  if (es) es.close();
  es = new EventSource('/api/stream');
  es.onopen = () => { if (connOk === false) toast('success', 'Live connection restored'); connOk = true; $('#conn').classList.remove('off'); $('#conn-t').textContent = 'live'; };
  es.onerror = () => { if (connOk !== false) toast('warning', 'Live connection lost', 'Reconnecting automatically…'); connOk = false; $('#conn').classList.add('off'); $('#conn-t').textContent = 'reconnecting…'; };
  es.onmessage = ev => {
    let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
    if (m.type === 'toast') { toast(m.level, m.title, m.text, {incident_id: m.incident_id}); if (m.critical) banner(`${m.title}. ${m.text}`, m.incident_id); }
    else if (m.type === 'refresh' && current && current.tick && current !== pages.overview) current.tick().catch(() => {});
  };
}

function showLogin() {
  if (es) { es.close(); es = null; }
  clearInterval(pollTimer);
  ME = null;
  $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); $('#lp').value = '';
}

async function enter(user, defaultPw) {
  ME = user;
  $('#login').classList.add('hidden'); $('#app').classList.remove('hidden');
  $('#u-name').textContent = user.username; $('#u-role').textContent = user.role;
  $('#sound').classList.toggle('off', !soundOn);
  try { const o = await api('/overview', {quiet: true}); const c = $('#mode-chip'); c.textContent = (o.mode === 'live' ? 'LIVE CAPTURE' : 'SIMULATION') + (o.dry_run ? ' · dry-run firewall' : ' · real firewall'); c.className = 'chip ' + (o.mode === 'live' ? 'live' : 'sim'); } catch (e) { /* ignore */ }
  connect();
  if (!location.hash) location.hash = '#/overview'; else route();
  if (defaultPw) setTimeout(() => toast('warning', 'Default password in use', 'Change it under Settings & health.'), 1200);
}

$('#login-form').onsubmit = async e => {
  e.preventDefault();
  $('#login-err').textContent = '';
  try { const r = await api('/login', {method: 'POST', body: {username: $('#lu').value, password: $('#lp').value}, quiet: true}); await enter(r.user, r.default_password); }
  catch (err) { $('#login-err').textContent = err.message; }
};
$('#logout').onclick = async () => { await api('/logout', {method: 'POST', quiet: true}).catch(() => {}); showLogin(); };
$('#sound').onclick = () => { soundOn = !soundOn; store.set('sound', soundOn ? 'on' : 'off'); $('#sound').classList.toggle('off', !soundOn); if (soundOn) beep(); };
setInterval(async () => { if (ME && current !== pages.overview) { try { setBadge((await api('/overview', {quiet: true})).db_open); } catch (e) { /* ignore */ } } }, 5000);

(async () => {
  try { const r = await api('/me', {quiet: true}); await enter(r.user, r.default_password); } catch (e) { showLogin(); }
})();
