'use strict';
// NetSentinel dashboard. Everything that came off the network or out of a
// scanned file is put on the page as text (textContent), never as HTML.

let token = document.querySelector('meta[name="netsentinel-token"]').content;
const TOKEN_REFUSED = 'missing or wrong token';   // the server's words, in headless.py
const $ = (id) => document.getElementById(id);
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const COLOURS = { red: '#f85149', orange: '#db6d28', yellow: '#d29922', green: '#3fb950' };

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') Object.assign(el.style, v);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const fmtNum = (n) => Number(n || 0).toLocaleString();
function fmtBytes(b) {
  b = Number(b || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(i && b < 10 ? 1 : 0)} ${units[i]}`;
}
function fmtDuration(s) {
  s = Math.max(0, Math.floor(s || 0));
  const d = Math.floor(s / 86400), hr = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${hr}h` : hr ? `${hr}h ${m}m` : `${m}m ${s % 60}s`;
}

// Each NetSentinel process makes its own token, so a page left open across a
// restart holds a dead one and every button failed until a reload. The page
// it would reload carries the new one; read it from there. Returns whether
// the token changed, so a refusal for any other reason is not retried.
async function renewToken() {
  const res = await fetch('/', { cache: 'no-store' });
  if (!res.ok) return false;
  const page = new DOMParser().parseFromString(await res.text(), 'text/html');
  const meta = page.querySelector('meta[name="netsentinel-token"]');
  if (!meta || !meta.content || meta.content === token) return false;
  token = meta.content;
  return true;
}

async function api(path, options = {}, renewed = false) {
  const headers = Object.assign({}, options.headers);
  if (options.method === 'POST') headers['X-NetSentinel-Token'] = token;
  const res = await fetch(path, Object.assign({ cache: 'no-store' }, options, { headers }));
  const body = await res.json().catch(() => ({}));
  // The server checks the token before doing anything, so trying again
  // cannot do the action twice.
  if (res.status === 403 && body.error === TOKEN_REFUSED && !renewed
      && await renewToken().catch(() => false)) {
    return api(path, options, true);
  }
  if (!res.ok) throw new Error(body.error || `${res.status} ${res.statusText}`);
  return body;
}

function toast(message) {
  const el = $('toast');
  el.textContent = message;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { el.hidden = true; }, 4000);
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ─── Charts ──────────────────────────────────────────────────────────────

function fmtRate(v) {
  v = Number(v || 0);
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`;
  if (v >= 1e4) return `${Math.round(v / 1e3)}k`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}k`;
  return v >= 10 ? String(Math.round(v)) : v.toFixed(1).replace(/\.0$/, '');
}
const fmtPps = (v) => `${fmtRate(v)} pkt/s`;
const fmtBps = (v) => `${fmtBytes(v)}/s`;
const fmtClock = (t, seconds) => new Date(t * 1000).toLocaleTimeString([],
  seconds ? { hour: '2-digit', minute: '2-digit', second: '2-digit' } : { hour: '2-digit', minute: '2-digit' });

// An axis step of 1, 2 or 5 times a power of ten, for about `ticks` lines.
function niceStep(max, ticks) {
  const raw = Math.max(max, 1e-9) / ticks;
  const power = 10 ** Math.floor(Math.log10(raw));
  const unit = raw / power;
  return (unit <= 1 ? 1 : unit <= 2 ? 2 : unit <= 5 ? 5 : 10) * power;
}
const TIME_STEPS = [60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600];

// A time series on a time axis: the average per bucket as a filled line, the
// peak as a faint line above it, and a readout under the pointer. The line
// breaks where samples are missing (monitoring stopped) rather than diving to 0.
class TimeChart {
  constructor(canvas, { colour, format, axis, base }) {
    this.canvas = canvas;
    this.colour = colour;
    this.format = format;       // full value for the readout
    this.axis = axis;           // short value for the axis
    this.base = base;           // 1024 for bytes: steps of 256 KB, not 244.1
    this.points = [];           // {t, v, peak}
    this.from = 0; this.to = 0; this.bucket = 5;
    this.hover = null;
    this.tip = h('div', { class: 'chart-tip', hidden: true });
    canvas.after(this.tip);
    const move = (e) => this.pointAt(e);
    canvas.addEventListener('pointermove', move);
    canvas.addEventListener('pointerdown', move);
    canvas.addEventListener('pointerleave', () => { this.hover = null; this.tip.hidden = true; this.draw(); });
  }

  set(points, from, to, bucket) {
    Object.assign(this, { points, from, to, bucket });
    if (this.hover != null && this.hover >= points.length) this.hover = null;
    this.draw();
    if (this.hover != null) this.showTip();
  }

  frame() {
    const w = this.canvas.clientWidth, ht = this.canvas.clientHeight;
    return { w, ht, left: 56, right: w - 10, top: 10, bottom: ht - 24 };
  }

  x(t, f) { return f.left + (f.right - f.left) * (t - this.from) / Math.max(1, this.to - this.from); }

  draw() {
    const c = this.canvas, dpr = window.devicePixelRatio || 1;
    const f = this.frame();
    if (!f.w || !f.ht) return;
    if (c.width !== Math.round(f.w * dpr) || c.height !== Math.round(f.ht * dpr)) {
      c.width = Math.round(f.w * dpr); c.height = Math.round(f.ht * dpr);
    }
    const g = c.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, f.w, f.ht);
    g.font = '11px "Segoe UI", system-ui, sans-serif';

    const peakMax = Math.max(0, ...this.points.map((p) => p.peak));
    const scale = this.base && peakMax >= this.base
      ? this.base ** Math.floor(Math.log(peakMax) / Math.log(this.base)) : 1;
    const step = niceStep((peakMax || 1) / scale, 4) * scale;
    const top = Math.max(step, Math.ceil(peakMax * 1.08 / step) * step);
    const y = (v) => f.bottom - (f.bottom - f.top) * v / top;

    // Value axis: lines and labels.
    g.textAlign = 'right'; g.textBaseline = 'middle';
    for (let v = 0; v <= top + step / 2; v += step) {
      const yy = Math.round(y(v)) + .5;
      g.strokeStyle = v === 0 ? '#3d444d' : '#262c35'; g.lineWidth = 1;
      g.beginPath(); g.moveTo(f.left, yy); g.lineTo(f.right, yy); g.stroke();
      g.fillStyle = '#7d8590'; g.fillText(this.axis(v), f.left - 8, yy);
    }

    // Time axis: the smallest round step that leaves room for each label.
    const span = Math.max(1, this.to - this.from);
    const room = Math.max(2, Math.floor((f.right - f.left) / 78));
    const tstep = TIME_STEPS.find((s) => span / s <= room) || 21600;
    const offset = new Date().getTimezoneOffset() * 60;   // label on local round times
    g.textAlign = 'center'; g.textBaseline = 'top';
    for (let t = Math.ceil((this.from - offset) / tstep) * tstep + offset; t <= this.to; t += tstep) {
      const xx = Math.round(this.x(t, f)) + .5;
      if (xx < f.left + 16 || xx > f.right - 16) continue;
      g.strokeStyle = '#1e242c';
      g.beginPath(); g.moveTo(xx, f.top); g.lineTo(xx, f.bottom); g.stroke();
      g.fillStyle = '#7d8590'; g.fillText(fmtClock(t), xx, f.bottom + 7);
    }

    if (!this.points.length) {
      g.fillStyle = '#7d8590'; g.textAlign = 'center'; g.textBaseline = 'middle';
      g.font = '13px "Segoe UI", system-ui, sans-serif';
      g.fillText('No traffic recorded in this range yet', (f.left + f.right) / 2, (f.top + f.bottom) / 2);
      return;
    }

    // Runs of points with no gap longer than a few buckets between them.
    const runs = [];
    let run = [];
    for (const p of this.points) {
      if (run.length && p.t - run[run.length - 1].t > Math.max(3 * this.bucket, 20)) { runs.push(run); run = []; }
      run.push(p);
    }
    runs.push(run);

    const path = (pts, key) => {
      g.beginPath();
      pts.forEach((p, i) => (i ? g.lineTo : g.moveTo).call(g, this.x(p.t, f), y(p[key])));
    };
    const grad = g.createLinearGradient(0, f.top, 0, f.bottom);
    grad.addColorStop(0, this.colour + '50'); grad.addColorStop(1, this.colour + '05');
    for (const pts of runs) {
      if (this.bucket > 5) {
        path(pts, 'peak');
        g.strokeStyle = this.colour + '66'; g.lineWidth = 1; g.stroke();
      }
      path(pts, 'v');
      if (pts.length > 1) {
        g.lineTo(this.x(pts[pts.length - 1].t, f), f.bottom);
        g.lineTo(this.x(pts[0].t, f), f.bottom);
        g.closePath(); g.fillStyle = grad; g.fill();
        path(pts, 'v');
      }
      g.strokeStyle = this.colour; g.lineWidth = 1.75; g.lineJoin = 'round'; g.stroke();
      if (pts.length === 1) {
        g.fillStyle = this.colour;
        g.beginPath(); g.arc(this.x(pts[0].t, f), y(pts[0].v), 2.5, 0, 2 * Math.PI); g.fill();
      }
    }

    if (this.hover != null && this.points[this.hover]) {
      const p = this.points[this.hover], xx = Math.round(this.x(p.t, f)) + .5;
      g.strokeStyle = '#8b949e'; g.setLineDash([3, 3]);
      g.beginPath(); g.moveTo(xx, f.top); g.lineTo(xx, f.bottom); g.stroke();
      g.setLineDash([]);
      g.fillStyle = '#0d1117'; g.strokeStyle = this.colour; g.lineWidth = 2;
      g.beginPath(); g.arc(xx, y(p.v), 4, 0, 2 * Math.PI); g.fill(); g.stroke();
    }
  }

  pointAt(e) {
    if (!this.points.length) return;
    const rect = this.canvas.getBoundingClientRect(), f = this.frame();
    const px = e.clientX - rect.left;
    const t = this.from + (px - f.left) / Math.max(1, f.right - f.left) * (this.to - this.from);
    let lo = 0, hi = this.points.length - 1;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (this.points[mid].t < t) lo = mid + 1; else hi = mid; }
    if (lo > 0 && Math.abs(this.points[lo - 1].t - t) < Math.abs(this.points[lo].t - t)) lo--;
    this.hover = lo;
    this.draw();
    this.showTip();
  }

  showTip() {
    const p = this.points[this.hover];
    if (!p) { this.tip.hidden = true; return; }
    const f = this.frame();
    const when = this.bucket > 5
      ? `${fmtClock(p.t - this.bucket + 5, true)} – ${fmtClock(p.t, true)}` : fmtClock(p.t, true);
    // replaceChildren writes a null as the text "null"; h() skips it.
    this.tip.replaceChildren(...[
      h('div', { class: 'when' }, when),
      h('div', { class: 'val' }, h('span', { class: 'swatch', style: { background: this.colour } }),
        this.bucket > 5 ? 'average ' : '', h('b', null, this.format(p.v))),
      this.bucket > 5 ? h('div', { class: 'peak' }, `peak ${this.format(p.peak)}`) : null,
    ].filter(Boolean));
    this.tip.hidden = false;
    const x = this.x(p.t, f);
    const width = this.tip.offsetWidth;
    this.tip.style.left = `${Math.min(Math.max(x - width / 2, 0), f.w - width)}px`;
  }
}

const charts = {};
const RANGES = [[15, '15 min'], [60, '1 hour'], [360, '6 hours'], [1440, '24 hours']];
const chartView = { minutes: 60, fetched: 0 };
try {
  const saved = Number(localStorage.getItem('ns-range'));
  if (RANGES.some(([m]) => m === saved)) chartView.minutes = saved;
} catch (e) { /* storage blocked: the default range */ }

function renderRanges() {
  $('ranges').replaceChildren(...RANGES.map(([m, label]) => h('button', {
    type: 'button', class: `chip${chartView.minutes === m ? ' on' : ''}`,
    onclick: () => {
      chartView.minutes = m;
      try { localStorage.setItem('ns-range', String(m)); } catch (e) { /* private mode */ }
      renderRanges();
      refreshHistory(true);
    },
  }, label)));
}

function summary(points, format) {
  if (!points.length) return '';
  const avg = points.reduce((s, p) => s + p.v, 0) / points.length;
  const peak = Math.max(...points.map((p) => p.peak));
  return `now ${format(points[points.length - 1].v)}  ·  average ${format(avg)}  ·  peak ${format(peak)}`;
}

async function refreshHistory(force) {
  // Every few seconds is plenty: the server samples every 5.
  if (!force && Date.now() - chartView.fetched < 4500) return;
  chartView.fetched = Date.now();
  const d = await api(`/api/history?minutes=${chartView.minutes}`);
  const i = Object.fromEntries((d.fields || []).map((k, n) => [k, n]));
  const series = (avg, peak) => (d.points || []).map((p) => ({ t: p[i.t], v: p[i[avg]], peak: p[i[peak]] }));
  const pps = series('pps', 'pps_peak'), bps = series('bps', 'bps_peak');
  charts.pps.set(pps, d.from, d.to, d.bucket_sec);
  charts.bw.set(bps, d.from, d.to, d.bucket_sec);
  $('pps-summary').textContent = summary(pps, fmtPps);
  $('bw-summary').textContent = summary(bps, fmtBps);
}

// ─── Shared pieces ───────────────────────────────────────────────────────

function card(key, value, sub, colour, link) {
  return h(link ? 'a' : 'div', { class: `card${link ? ' link' : ''}`, href: link || null },
    h('div', { class: 'k' }, key),
    h('div', { class: 'v', style: colour ? { color: colour } : null }, value),
    sub ? h('div', { class: 's' }, sub) : null);
}

// "5 min ago", for a timestamp in seconds.
function ago(ts) {
  const s = Math.max(0, Date.now() / 1000 - Number(ts || 0));
  if (!ts) return '';
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

function bars(container, rows, format) {
  container.replaceChildren();
  if (!rows.length) { container.append(h('div', { class: 'empty' }, 'Nothing yet.')); return; }
  const top = Math.max(...rows.map((r) => r.value)) || 1;
  for (const r of rows) {
    container.append(h('div', { class: 'bar-row' },
      h('span', { class: 'name', title: r.name }, r.name),
      h('span', { class: 'track' }, h('span', { class: 'fill', style: { width: `${100 * r.value / top}%`, display: 'block' } })),
      h('span', { class: 'num' }, format(r))));
  }
}

const expanded = new Set();   // survives the list being redrawn on every refresh

function ackButton(a) {
  if (a.acknowledged) return h('span', { class: 'acked-tag' }, 'acknowledged');
  if (!overview || !overview.controls || a.id == null) return null;
  return h('button', {
    type: 'button', class: 'ack secondary',
    onclick: (e) => {
      e.stopPropagation();   // the row's own click opens the evidence
      control(`/api/alerts/ack?id=${encodeURIComponent(a.id)}`, refreshCurrent);
    },
  }, 'Acknowledge');
}

function verdictButtons(a) {
  const mine = (a.evidence || {}).your_verdict;
  if (mine) return h('span', { class: 'acked-tag' }, mine === 'false_positive' ? 'false positive' : 'real');
  if (!overview || !overview.controls || a.id == null) return null;
  const send = (verdict) => (e) => {
    e.stopPropagation();
    if (verdict === 'false_positive' &&
        !confirm(`Never alert on ${a.rule_id} for this host or domain again?`)) return;
    control(`/api/alerts/verdict?id=${encodeURIComponent(a.id)}&verdict=${verdict}`, refreshCurrent);
  };
  return [
    h('button', { type: 'button', class: 'ack secondary', onclick: send('real') }, 'Real'),
    h('button', { type: 'button', class: 'ack secondary', onclick: send('false_positive') }, 'False positive'),
  ];
}

// "dst_ip" → "Dst IP", "cves" → "CVEs": evidence keys as labels.
const ACRONYMS = { ip: 'IP', ips: 'IPs', cve: 'CVE', cves: 'CVEs', sni: 'SNI', ja3: 'JA3', ja4: 'JA4',
  tls: 'TLS', dns: 'DNS', http: 'HTTP', url: 'URL', mac: 'MAC', ttl: 'TTL', ml: 'ML', id: 'ID', pid: 'PID' };
function label(key) {
  const words = String(key).split('_').map((w) => ACRONYMS[w.toLowerCase()] || w);
  const first = words[0] || '';
  words[0] = first === first.toLowerCase() ? first.charAt(0).toUpperCase() + first.slice(1) : first;
  return words.join(' ');
}

// Evidence as labelled fields, the advice first; nested values as indented JSON.
const EVIDENCE_FIRST = ['recommendation', 'how_to_fix', 'how_this_is_exploited', 'is_this_malicious'];
function evidenceView(ev) {
  const keys = Object.keys(ev || {});
  const order = [...EVIDENCE_FIRST.filter((k) => k in ev), ...keys.filter((k) => !EVIDENCE_FIRST.includes(k))];
  return h('dl', { class: 'evidence' }, order.flatMap((k) => {
    const v = ev[k];
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) return [];
    const text = typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v);
    return [h('dt', null, label(k)),
      h('dd', { class: typeof v === 'object' ? 'json' : null }, text)];
  }));
}

function alertItem(a) {
  const key = a.id || `${a.timestamp}|${a.rule_id}|${a.title}`;
  const evidence = h('div', { class: 'evidence-wrap', hidden: !expanded.has(key) }, evidenceView(a.evidence));
  const where = [a.src_ip, a.dst_ip ? `→ ${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}` : null]
    .filter(Boolean).join(' ');
  return h('div', {
    class: `alert sev-${a.severity}${a.acknowledged ? ' acked' : ''}`,
    onclick: (e) => {
      if (evidence.contains(e.target) || window.getSelection().toString()) return;
      evidence.hidden = !evidence.hidden;
      if (evidence.hidden) expanded.delete(key); else expanded.add(key);
    },
  },
  h('div', { class: 'head' },
    h('span', { class: `badge ${a.severity}` }, a.severity),
    h('span', { class: 'title' }, a.title),
    h('span', { class: 'time', title: a.time_str || '' }, ago(a.timestamp) || a.time_str || ''),
    h('span', { class: 'actions' }, verdictButtons(a), ackButton(a))),
  a.description ? h('div', { class: 'desc' }, a.description) : null,
  h('div', { class: 'meta' }, [where, a.rule_id, a.category].filter(Boolean).join('  ·  ')),
  evidence);
}

function table(headers, rows) {
  return h('table', null,
    h('thead', null, h('tr', null, headers.map((t) => h('th', null, t)))),
    h('tbody', null, rows));
}

// ─── Overview ────────────────────────────────────────────────────────────

let overview = null;

async function refreshOverview() {
  const status = $('status');
  try {
    overview = await api('/api/overview');
  } catch (e) {
    status.className = 'status down';
    status.querySelector('.label').textContent = 'Disconnected';
    return;
  }
  const o = overview;
  status.className = o.monitoring ? 'status live' : 'status';
  status.querySelector('.label').textContent = o.monitoring ? `Monitoring · ${fmtDuration(o.uptime_sec)}` : 'Stopped';
  renderControls(o);

  const sev = o.alerts.by_severity || {};
  const open = o.alerts.unacknowledged;
  document.title = open ? `(${open}) NetSentinel` : 'NetSentinel';
  $('cards').replaceChildren(
    card('Traffic', fmtPps(o.capture.packets_per_sec), `${fmtNum(o.capture.packets_captured)} packets since start`),
    card('Bandwidth', fmtBps(o.capture.bytes_per_sec), `${fmtBytes(o.capture.bytes_captured)} since start`),
    card('Open alerts', fmtNum(open), `${sev.CRITICAL || 0} critical · ${sev.HIGH || 0} high · ${fmtNum(o.alerts.total)} in all`,
      (sev.CRITICAL || sev.HIGH) && open ? COLOURS.red : open ? COLOURS.yellow : null, '#alerts'),
    card('Threat level', o.threat.label, `anomaly score ${o.threat.score.toFixed(2)}`, COLOURS[o.threat.colour]),
    card('Active flows', fmtNum(o.capture.flows_active), `${fmtNum(o.incidents_active)} open incidents`, null, '#incidents'),
    card('Devices', fmtNum(o.devices.total), `${fmtNum(o.devices.active_last_hour)} active in the last hour`, null, '#devices'));

  refreshHistory().catch(() => {});
  bars($('protocols'), o.protocols.map((p) => ({ name: p.name, value: p.count, fraction: p.fraction })),
    (r) => `${(r.fraction * 100).toFixed(1)}%`);
  bars($('talkers'), o.top_talkers.map((t) => ({
    name: [t.ip, t.country, t.as_org].filter(Boolean).join(' · '), value: t.bytes,
  })), (r) => fmtBytes(r.value));
  $('geoip-credit').hidden = !o.geoip_attribution;
  $('geoip-credit').textContent = o.geoip_attribution || '';
  const res = o.resources || {};
  const rate = Number(o.capture.sample_rate || 1);
  const cap = o.capture;
  const facts = [
    'NetSentinel',
    ['Version', o.update ? `${o.version} · ${o.update.version} is out` : o.version,
      o.update ? 'Install it from the Update button in the desktop app.' : null],
    ['Monitoring', o.monitoring ? `Yes, for ${fmtDuration(o.uptime_sec)}` : 'No'],
    ['Review mode', o.review && o.review.enabled ? 'Recording' : 'Off'],
    ['ML model', o.ml.is_trained ? 'Trained' : 'Learning',
      `${fmtNum(o.ml.baseline_samples)} baseline samples`],
    ['Alerts a minute', fmtNum(o.alerts.per_minute)],
    ['Silenced by verdicts', fmtNum(o.suppressed_alerts),
      'Alerts not raised again because you marked them false positives.'],
    'Analysis',
    ['Analysing', rate > 1 ? `1 in ${rate} packets (busy)` : 'Every packet'],
    ['Bulk not inspected', fmtNum(cap.packets_shed),
      `Past ${fmtNum(cap.max_pps)} packets a second, the middle of a download is counted to its flow but not read.`],
    ['Dropped', fmtNum(cap.packets_dropped),
      `${fmtNum(cap.packets_dropped_cap)} past twice the cap, ${fmtNum(cap.packets_dropped_queue)} with the queue full.`],
    ['Skipped by sampling', fmtNum(cap.packets_sampled_out)],
    'This process',
    ['CPU', res.available ? `${res.cpu_percent}%${res.low_priority ? ' (low priority)' : ''}` : '—'],
    ['Memory', res.available ? fmtBytes(res.rss_bytes) : '—'],
    ['Threads', res.available ? fmtNum(res.threads) : '—'],
  ];
  $('engine').replaceChildren(...facts.flatMap((f) => typeof f === 'string'
    ? [h('div', { class: 'group' }, f)]
    : [h('dt', null, f[0]), h('dd', { title: f[2] || null }, f[1])]));
}

async function refreshRecentAlerts() {
  const data = await api('/api/alerts?limit=8');
  const list = $('recent-alerts');
  list.replaceChildren(...data.alerts.map(alertItem));
  if (!data.alerts.length) list.append(h('div', { class: 'empty' }, 'No alerts. Quiet is good.'));
}

// ─── Alerts ──────────────────────────────────────────────────────────────

const alertView = { severity: 'ALL', search: '', alerts: [] };

async function refreshAlerts() {
  const data = await api('/api/alerts?limit=1000');
  alertView.alerts = data.alerts;
  renderAlerts();
}

function renderAlerts() {
  const counts = { ALL: alertView.alerts.length };
  for (const a of alertView.alerts) counts[a.severity] = (counts[a.severity] || 0) + 1;
  $('severity-chips').replaceChildren(...['ALL', ...SEVERITIES].map((s) => h('button', {
    type: 'button', class: `chip${alertView.severity === s ? ' on' : ''}`,
    onclick: () => { alertView.severity = s; renderAlerts(); },
  }, s === 'ALL' ? 'All' : s[0] + s.slice(1).toLowerCase(), h('span', { class: 'n' }, counts[s] || 0))));

  const q = alertView.search.toLowerCase();
  const shown = alertView.alerts.filter((a) =>
    (alertView.severity === 'ALL' || a.severity === alertView.severity) &&
    (!q || [a.title, a.description, a.src_ip, a.dst_ip, a.rule_id, a.category]
      .some((f) => String(f || '').toLowerCase().includes(q))));
  const list = $('alert-list');
  list.replaceChildren(...shown.slice(0, 300).map(alertItem));
  if (!shown.length) list.append(h('div', { class: 'empty' }, 'No alerts match.'));
  else if (shown.length > 300) list.append(h('div', { class: 'empty' }, `Showing 300 of ${shown.length}. Narrow the filter to see the rest.`));
}

// ─── Devices ─────────────────────────────────────────────────────────────

const deviceView = { type: 'ALL', search: '', data: null, sort: { key: 'packets', dir: -1 } };

async function refreshDevices() {
  deviceView.data = await api('/api/devices');
  renderDevices();
}

function renderDevices() {
  const d = deviceView.data || { devices: [], by_type: {} };
  const types = Object.entries(d.by_type || {}).sort((a, b) => b[1] - a[1]);
  $('device-types').replaceChildren(
    h('button', { type: 'button', class: `chip${deviceView.type === 'ALL' ? ' on' : ''}`, onclick: () => { deviceView.type = 'ALL'; renderDevices(); } },
      'All', h('span', { class: 'n' }, d.total_devices || 0)),
    ...types.map(([t, n]) => h('button', {
      type: 'button', class: `chip${deviceView.type === t ? ' on' : ''}`,
      onclick: () => { deviceView.type = t; renderDevices(); },
    }, t, h('span', { class: 'n' }, n))));
  const q = deviceView.search.toLowerCase();
  const { key, dir } = deviceView.sort;
  const column = DEVICE_COLUMNS.find((c) => c.key === key);
  const shown = (d.devices || []).filter((x) =>
    (deviceView.type === 'ALL' || x.type === deviceView.type) &&
    (!q || [x.ip, x.hostname, x.mac].some((f) => String(f || '').toLowerCase().includes(q))));
  if (column) {
    shown.sort((a, b) => {
      const va = column.sort(a), vb = column.sort(b);
      return (va < vb ? -1 : va > vb ? 1 : 0) * dir;
    });
  }
  const rows = shown.map((x) => h('tr', null,
    h('td', { class: 'mono' }, x.ip), h('td', null, x.hostname || '—'), h('td', { class: 'mono' }, x.mac || '—'),
    h('td', null, x.type), h('td', { class: 'num' }, x.confidence), h('td', { class: 'num' }, fmtNum(x.packets)),
    h('td', { class: 'mono' }, x.last_seen), h('td', { class: 'wrap' }, (x.services || []).join(', '))));
  const heads = DEVICE_COLUMNS.map((c) => h('th', {
    class: `${c.sort ? 'sortable' : ''}${c.key === key ? ' sorted' : ''}${c.num ? ' num' : ''}`,
    'aria-sort': c.key === key ? (dir > 0 ? 'ascending' : 'descending') : null,
    onclick: c.sort ? () => {
      deviceView.sort = { key: c.key, dir: c.key === key ? -dir : (c.num ? -1 : 1) };
      renderDevices();
    } : null,
  }, c.label, c.key === key ? h('span', { class: 'arrow' }, dir > 0 ? ' ▲' : ' ▼') : null));
  $('device-table').replaceWith(Object.assign(
    h('table', null, h('thead', null, h('tr', null, heads)), h('tbody', null,
      rows.length ? rows : [h('tr', null, h('td', { colspan: 8, class: 'empty' },
        'No devices yet. They appear as monitoring sees them.'))])),
    { id: 'device-table' }));
}

// Sorting keys: addresses by number, so 192.168.1.10 comes after .9.
const ipKey = (ip) => String(ip || '').includes(':') ? `z${ip}`
  : String(ip || '').split('.').map((n) => n.padStart(3, '0')).join('.');
const DEVICE_COLUMNS = [
  { key: 'ip', label: 'IP', sort: (x) => ipKey(x.ip) },
  { key: 'hostname', label: 'Hostname', sort: (x) => String(x.hostname || '~').toLowerCase() },
  { key: 'mac', label: 'MAC', sort: (x) => String(x.mac || '~') },
  { key: 'type', label: 'Type', sort: (x) => String(x.type || '') },
  { key: 'confidence', label: 'Confidence', num: true, sort: (x) => parseFloat(x.confidence) || 0 },
  { key: 'packets', label: 'Packets', num: true, sort: (x) => Number(x.packets) || 0 },
  { key: 'last_seen', label: 'Last seen', sort: (x) => String(x.last_seen || '') },
  { key: 'services', label: 'Services' },
];

// ─── Incidents ───────────────────────────────────────────────────────────

async function refreshIncidents() {
  const data = await api('/api/incidents?limit=50');
  const list = $('incident-list');
  list.replaceChildren(...data.incidents.map((i) => typeof i === 'string'
    ? h('div', { class: 'alert' }, i)
    : h('div', { class: `alert sev-${i.severity}` },
      h('div', { class: 'head' },
        h('span', { class: `badge ${i.severity}` }, i.severity),
        h('span', { class: 'title' }, i.title),
        h('span', { class: 'time' }, i.created_str || '')),
      i.narrative ? h('div', { class: 'desc' }, i.narrative) : null,
      h('div', { class: 'meta' }, [`${i.alert_count || 0} alerts`,
        (i.source_ips || []).slice(0, 5).join(', '),
        (i.categories || []).join(', ')].filter(Boolean).join('  ·  ')))));
  if (!data.incidents.length) list.append(h('div', { class: 'empty' }, 'No correlated incidents.'));
}

// ─── Threat data ─────────────────────────────────────────────────────────

const SOURCE_STATES = { ok: 'In use', bundled: 'Bundled', stale: 'Too old', 'needs key': 'Needs key',
  off: 'Off', failed: 'Failed', waiting: 'Waiting' };
const SOURCE_COLOURS = { ok: 'LOW', bundled: 'LOW', stale: 'HIGH', 'needs key': 'MEDIUM',
  off: 'private', failed: 'HIGH', waiting: 'MEDIUM' };

function fmtUpdated(u) {
  if (!u) return '';
  if (typeof u === 'number') return new Date(u * 1000).toLocaleString();
  return String(u);
}

async function refreshSources() {
  const data = await api('/api/sources');
  const rows = data.sources.map((s) => h('tr', null,
    h('td', null, s.description || s.name),
    h('td', null, h('span', { class: `badge ${SOURCE_COLOURS[s.state] || 'private'}` },
      SOURCE_STATES[s.state] || s.state)),
    h('td', { class: 'mono nowrap' }, fmtUpdated(s.updated)),
    h('td', { class: 'num' }, s.entries ? fmtNum(s.entries) : ''),
    h('td', { class: 'wrap' }, s.note || '')));
  $('source-table').replaceWith(Object.assign(
    table(['Source', 'State', 'Updated', 'Entries', 'Note'], rows), { id: 'source-table' }));
  const counts = {};
  for (const s of data.sources) counts[s.state] = (counts[s.state] || 0) + 1;
  $('source-summary').replaceChildren(...Object.keys(SOURCE_STATES).filter((k) => counts[k])
    .map((k) => h('span', { class: 'chip static' }, SOURCE_STATES[k], h('span', { class: 'n' }, counts[k]))));
}

// ─── Scan files ──────────────────────────────────────────────────────────

const scan = { queue: [], skipped: 0, id: null, xhr: null, cancelled: false, report: null, kind: 'ipv4', filter: '' };
// The same folders and file types the scanner leaves out: no point uploading them.
const SKIP_DIRS = new Set(['.git', '.svn', '.hg', 'node_modules', '__pycache__', '.venv', 'venv']);
const MEDIA = /\.(jpe?g|png|gif|bmp|ico|webp|mp3|mp4|m4a|wav|avi|mov|mkv|flac|ogg|woff2?|ttf|otf)$/i;
const BATCH_BYTES = 8 * 1024 * 1024, BATCH_FILES = 2000, SINGLE_FILE = 4 * 1024 * 1024;

function addToQueue(entries) {
  for (const e of entries) {
    const parts = e.path.split('/');
    if (parts.slice(0, -1).some((p) => SKIP_DIRS.has(p)) || MEDIA.test(e.path)) scan.skipped++;
    else scan.queue.push(e);
  }
  renderQueue();
}

function scanError(message) {
  const el = $('scan-error');
  el.textContent = message;
  el.hidden = !message;
}

function renderQueue() {
  const total = scan.queue.reduce((n, e) => n + e.file.size, 0);
  $('queue').hidden = !scan.queue.length;
  $('queue').hidden = !scan.queue.length && !scan.skipped;
  $('queue-summary').textContent = `${fmtNum(scan.queue.length)} file${scan.queue.length === 1 ? '' : 's'}, ${fmtBytes(total)}` +
    (scan.skipped ? ` · ${fmtNum(scan.skipped)} left out (version control, dependencies, images and media)` : '');
  const shown = scan.queue.slice(0, 200).map((e) => h('li', null, h('span', null, e.path), h('span', null, fmtBytes(e.file.size))));
  if (scan.queue.length > 200) shown.push(h('li', null, `… and ${scan.queue.length - 200} more`));
  $('queue-list').replaceChildren(...shown);
}

async function readEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((ok, fail) => entry.file(ok, fail));
    out.push({ file, path: prefix + file.name });
    if (out.length % 500 === 0) $('queue-summary').textContent = `Reading the folder… ${fmtNum(out.length)} files`;
  } else if (entry.isDirectory) {
    if (SKIP_DIRS.has(entry.name)) { scan.skipped++; return; }
    $('queue').hidden = false;
    const reader = entry.createReader();
    for (;;) {
      const batch = await new Promise((ok, fail) => reader.readEntries(ok, fail));
      if (!batch.length) break;
      for (const child of batch) await readEntry(child, `${prefix}${entry.name}/`, out);
    }
  }
}

function setProgress(label, fraction) {
  $('scan-progress').hidden = false;
  $('scan-progress-label').textContent = label;
  $('scan-progress-bar').style.width = `${Math.round(100 * Math.min(1, fraction))}%`;
}

// Small files travel together: [u16 name length][name][u32 size][bytes] per file.
function batches(files) {
  const out = [];
  let current = null;
  for (const e of files) {
    if (e.file.size > SINGLE_FILE) { out.push({ single: e, size: e.file.size, count: 1 }); continue; }
    if (!current || current.size + e.file.size > BATCH_BYTES || current.count >= BATCH_FILES) {
      current = { parts: [], size: 0, count: 0 };
      out.push(current);
    }
    const name = new TextEncoder().encode(e.path).slice(0, 4096);
    const head = new Uint8Array(2 + name.length + 4);
    const view = new DataView(head.buffer);
    view.setUint16(0, name.length);
    head.set(name, 2);
    view.setUint32(2 + name.length, e.file.size);
    current.parts.push(head, e.file);
    current.size += e.file.size;
    current.count++;
  }
  return out;
}

function upload(id, batch, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    scan.xhr = xhr;
    xhr.open('POST', batch.single
      ? `/api/scan/upload?id=${encodeURIComponent(id)}&name=${encodeURIComponent(batch.single.path)}`
      : `/api/scan/upload-batch?id=${encodeURIComponent(id)}`);
    xhr.setRequestHeader('X-NetSentinel-Token', token);
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => {
      if (xhr.status < 300) resolve();
      else reject(new Error((() => { try { return JSON.parse(xhr.responseText).error; } catch (_) { return xhr.statusText; } })()));
    };
    xhr.onerror = () => reject(new Error('upload failed'));
    xhr.onabort = () => reject(new Error('cancelled'));
    xhr.send(batch.single ? batch.single.file : new Blob(batch.parts));
  });
}

async function startScan() {
  if (!scan.queue.length) return;
  const files = scan.queue.slice();
  scan.cancelled = false;
  $('start-scan').disabled = $('clear-queue').disabled = true;
  $('scan-report').replaceChildren();
  scanError('');
  try {
    const session = await api('/api/scan/new', { method: 'POST' });
    scan.id = session.id;
    const total = files.reduce((n, e) => n + e.file.size, 0) || 1;
    let done = 0, sent = 0;
    for (const batch of batches(files)) {
      if (scan.cancelled) throw new Error('cancelled');
      await upload(scan.id, batch, (loaded) =>
        setProgress(`Uploading… ${fmtNum(sent)} of ${fmtNum(files.length)} files sent`,
          (done + Math.min(loaded, batch.size)) / total * 0.5));
      done += batch.size;
      sent += batch.count;
    }
    await api(`/api/scan/start?id=${scan.id}`, { method: 'POST' });
    for (;;) {
      const s = await api(`/api/scan?id=${scan.id}`);
      const p = s.progress;
      if (s.state === 'running') {
        setProgress(p.total ? `Scanning ${p.index + 1} of ${p.total}: ${p.name}` : 'Collecting files…',
          0.5 + 0.5 * (p.total ? p.index / p.total : 0));
      } else if (s.state === 'error') {
        throw new Error(s.error || 'scan failed');
      } else {
        scan.report = s.report;
        break;
      }
      await new Promise((r) => setTimeout(r, 600));
    }
    scan.queue = [];
    renderQueue();
    renderReport();
  } catch (e) {
    if (e.message === 'cancelled') toast('Scan cancelled.');
    else scanError(`The scan stopped: ${e.message}`);
  } finally {
    scan.xhr = null;
    $('scan-progress').hidden = true;
    $('start-scan').disabled = $('clear-queue').disabled = false;
  }
}

async function cancelScan() {
  scan.cancelled = true;
  if (scan.xhr) scan.xhr.abort();
  if (scan.id) await api(`/api/scan/cancel?id=${scan.id}`, { method: 'POST' }).catch(() => {});
}

const KINDS = {
  ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domains', url: 'URLs', email: 'Emails',
  mac: 'MAC addresses', host: 'Host names', unc: 'UNC paths',
};

// ─── Scan ignore list ────────────────────────────────────────────────────

function ignoreButton(finding) {
  if (!overview || !overview.controls) return null;
  return h('button', {
    type: 'button', class: 'ack secondary',
    onclick: async (e) => {
      e.stopPropagation();
      try {
        await api('/api/scan/ignore', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ finding }),
        });
        e.target.replaceWith(h('span', { class: 'acked-tag' }, 'ignored from now on'));
        refreshIgnored();
      } catch (err) {
        toast(err.message);
      }
    },
  }, 'Ignore');
}

async function refreshIgnored() {
  const { ignored } = await api('/api/scan/ignored');
  const panel = $('scan-ignored');
  panel.hidden = !ignored.length;
  panel.replaceChildren(h('h2', null, 'Ignored in scans'),
    h('p', { class: 'hint' }, 'Later scans leave these out. Card numbers and SSNs are ignored only at that file and line.'),
    h('div', { class: 'table-wrap' }, table(['What', 'Where', 'Added', ''], ignored.map((e) => h('tr', null,
      h('td', null, `${e.label || e.kind}: `, h('span', { class: 'mono' }, e.shown || '')),
      h('td', { class: 'mono wrap' }, e.file ? `${e.file}${e.line ? ':' + e.line : ''}` : 'anywhere'),
      h('td', null, e.added ? new Date(e.added * 1000).toLocaleDateString() : ''),
      h('td', null, overview && overview.controls ? h('button', {
        type: 'button', class: 'ack secondary',
        onclick: () => control(`/api/scan/unignore?id=${encodeURIComponent(e.id)}`, refreshIgnored),
      }, 'Remove') : null))))));
}

function csv(rows) {
  const cell = (v) => {
    let s = String(v ?? '');
    if (/^[=+\-@]/.test(s)) s = `'${s}`;   // keep spreadsheets from running it as a formula
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return rows.map((r) => r.map(cell).join(',')).join('\n');
}

function renderReport() {
  const r = scan.report;
  if (!r) return;
  const s = r.summary;
  const exposed = s.credentials + s.secrets;
  const out = h('div', { class: 'report' });

  out.append(h('div', { class: 'cards' },
    card('Files scanned', `${fmtNum(s.scanned)} / ${fmtNum(s.items)}`, `${s.captures} packet captures${s.failed ? ` · ${s.failed} failed` : ''}`),
    Object.assign(card('Exposed secrets', fmtNum(exposed), 'passwords, keys, tokens'), { className: `card ${exposed ? 'bad' : 'good'}` }),
    Object.assign(card('On threat feeds', fmtNum(s.threats), 'known-bad addresses'), { className: `card ${s.threats ? 'bad' : 'good'}` }),
    card('IP addresses', fmtNum(s.ipv4 + s.ipv6), `${r.indicators.ipv4.filter((e) => e.scope === 'public').length} public IPv4`),
    card('Domains', fmtNum(s.domain), `${fmtNum(s.url)} URLs`),
    card('Emails', fmtNum(s.email), `${fmtNum(s.mac)} MAC addresses`),
    Object.assign(card('Known-bad files', fmtNum(s.malware || 0), 'on your hash lists'), { className: `card ${s.malware ? 'bad' : 'good'}` }),
    card('Suspicious scripts', fmtNum(s.findings || 0), `${fmtNum(s.ignored || 0)} ignored`)));

  if ((r.malware || []).length) {
    out.append(h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, table(
      ['Known-bad file', 'SHA-256', 'List'],
      r.malware.map((m) => h('tr', null, h('td', { class: 'wrap mono' }, m.file),
        h('td', { class: 'mono wrap' }, m.sha256), h('td', null, m.feed || '')))))));
  }

  if ((r.findings || []).length) {
    out.append(h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, table(
      ['Suspicious script or macro', 'What it does', 'Where', ''],
      r.findings.slice(0, 500).map((f) => h('tr', null,
        h('td', null, h('span', { class: `badge ${f.severity || 'MEDIUM'}` }, f.severity || 'MEDIUM'), ` ${f.label}`),
        h('td', null, f.value), h('td', { class: 'wrap mono' }, `${f.file}:${f.line}`),
        h('td', null, ignoreButton(f))))))));
  }

  if ((r.suspicious || []).length) {
    out.append(h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, table(
      ['Suspicious (weak feed match)', 'Kind', 'Why', 'Found in'],
      r.suspicious.map((t) => h('tr', null, h('td', { class: 'mono' }, t.value), h('td', null, t.kind),
        h('td', null, t.category || t.description || ''), h('td', { class: 'wrap' }, (t.files || []).join(', '))))))));
  }

  if (r.threats.length) {
    out.append(h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, table(
      ['On threat feeds', 'Kind', 'Feed', 'Category', 'Found in'],
      r.threats.map((t) => h('tr', null, h('td', { class: 'mono' }, t.value), h('td', null, t.kind),
        h('td', null, t.feed || ''), h('td', null, t.category || ''), h('td', { class: 'wrap' }, t.files.join(', '))))))));
  }

  const secretRows = [
    ...r.credentials.map((c) => h('tr', null,
      h('td', null, h('span', { class: 'badge CRITICAL' }, 'CAPTURE'), ` ${c.protocol} ${c.credential_type}`),
      h('td', { class: 'mono' }, c.value), h('td', { class: 'wrap' }, `${c.source} in ${c.captures.join(', ')}`))),
    ...r.secrets.map((x) => h('tr', null,
      h('td', null, h('span', { class: `badge ${x.severity}` }, x.severity), ` ${x.label}`),
      h('td', { class: 'mono' }, x.value),
      h('td', { class: 'wrap mono' }, `${x.file}:${x.line}`, ' ', ignoreButton(x)))),
  ];
  const secretCsv = () => download('netsentinel-secrets.csv', csv([['kind', 'value_masked', 'file', 'line'],
    ...r.credentials.map((c) => [`${c.protocol} ${c.credential_type}`, c.value, c.captures.join('; '), '']),
    ...r.secrets.map((x) => [x.label, x.value, x.file, x.line])]), 'text/csv');
  out.append(h('div', { class: 'panel' + (secretRows.length ? ' flush' : '') },
    secretRows.length
      ? [h('div', { class: 'table-wrap' }, table(['Exposed', 'Value (masked)', 'Where'], secretRows.slice(0, 1000))),
        h('div', { class: 'panel-foot' },
          secretRows.length > 1000 ? `Showing 1,000 of ${fmtNum(secretRows.length)}. ` : '',
          h('button', { type: 'button', class: 'secondary', onclick: secretCsv }, 'Download CSV'))]
      : [h('h2', null, 'Exposed secrets'), h('div', { class: 'empty' }, 'Nothing that looks like a leaked password, key or token.')]));

  const indicatorPanel = h('div', { class: 'panel' });
  out.append(indicatorPanel);
  const renderIndicators = () => {
    const entries = r.indicators[scan.kind] || [];
    const q = scan.filter.toLowerCase();
    const shown = entries.filter((e) => !q || e.value.toLowerCase().includes(q) || e.files.some((f) => f.toLowerCase().includes(q)));
    const search = h('input', { type: 'search', placeholder: 'Filter', value: scan.filter });
    search.addEventListener('input', () => {
      scan.filter = search.value;
      renderIndicators();
      const again = indicatorPanel.querySelector('input[type=search]');
      again.focus();
      again.setSelectionRange(again.value.length, again.value.length);
    });
    indicatorPanel.replaceChildren(...[
      h('div', { class: 'tabbar' },
        Object.entries(KINDS).map(([k, label]) => h('button', {
          type: 'button', class: `chip${scan.kind === k ? ' on' : ''}`,
          onclick: () => { scan.kind = k; renderIndicators(); },
        }, label, h('span', { class: 'n' }, (r.indicators[k] || []).length))),
        h('span', { class: 'spacer' }), search,
        h('button', {
          type: 'button', class: 'secondary',
          onclick: () => download(`netsentinel-${scan.kind}.csv`, csv([['value', 'scope', 'count', 'files'],
            ...entries.map((e) => [e.value, e.scope || '', e.count, e.files.join('; ')])]), 'text/csv'),
        }, 'Download CSV')),
      shown.length
        ? h('div', { class: 'table-wrap' }, table(['Value', 'Scope', 'Seen', 'Found in', ''],
          shown.slice(0, 500).map((e) => h('tr', null,
            h('td', { class: 'mono wrap' }, e.value),
            h('td', null, e.scope ? h('span', { class: `badge ${e.scope}` }, e.scope) : ''),
            h('td', null, fmtNum(e.count)),
            h('td', { class: 'wrap' }, e.files.slice(0, 5).join(', ') + (e.files.length > 5 ? ` and ${e.files.length - 5} more` : '')),
            h('td', null, ignoreButton({ kind: scan.kind, value: e.value }))))))
        : h('div', { class: 'empty' }, entries.length ? 'Nothing matches the filter.' : `No ${KINDS[scan.kind]} found.`),
      shown.length > 500 ? h('div', { class: 'empty' }, `Showing 500 of ${shown.length}. Download the CSV for all of them.`) : null,
    ].filter(Boolean));
  };
  renderIndicators();

  // A 40,000-file scan should not mean a 40,000-row table: failures first, then a sample.
  const files = [...r.files.filter((f) => f.error), ...r.files.filter((f) => !f.error)].slice(0, 500);
  const hidden = r.files.length - files.length + Math.max(0, r.skipped.length - 200);
  out.append(h('div', { class: 'panel flush' }, h('div', { class: 'table-wrap' }, table(['File', 'Type', 'Result'], [
    ...files.map((f) => h('tr', null, h('td', { class: 'wrap mono' }, f.file), h('td', null, f.type),
      h('td', null, f.error ? `Failed: ${f.error}` : f.type === 'capture'
        ? `${fmtNum(f.packets)} packets, ${f.alerts} alerts, ${f.credentials} credentials`
        : `${f.indicators} indicators, ${f.secrets} secrets${f.note ? ` (${f.note})` : ''}`))),
    ...r.skipped.slice(0, 200).map((f) => h('tr', null, h('td', { class: 'wrap mono' }, f.file), h('td', null, 'skipped'), h('td', null, f.reason))),
  ])), hidden ? h('div', { class: 'panel-foot' }, `${fmtNum(hidden)} more files are in the JSON report.`) : null));

  out.append(h('div', { class: 'report-actions' },
    h('button', { type: 'button', class: 'secondary', onclick: () => download('netsentinel-scan.json', JSON.stringify(r, null, 2), 'application/json') },
      'Download full report (JSON)')));
  $('scan-report').replaceChildren(out);
}

function setUpScan() {
  const zone = $('dropzone');
  $('pick-files').addEventListener('click', () => $('file-input').click());
  $('pick-folder').addEventListener('click', () => $('folder-input').click());
  for (const id of ['file-input', 'folder-input']) {
    $(id).addEventListener('change', (e) => {
      addToQueue([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
      e.target.value = '';
    });
  }
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', async (e) => {
    e.preventDefault();
    zone.classList.remove('over');
    const items = [...(e.dataTransfer.items || [])].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
    const out = [];
    if (items.length) for (const entry of items) await readEntry(entry, '', out);
    else for (const f of e.dataTransfer.files) out.push({ file: f, path: f.name });
    addToQueue(out);
  });
  $('clear-queue').addEventListener('click', () => { scan.queue = []; scan.skipped = 0; renderQueue(); });
  $('start-scan').addEventListener('click', startScan);
  $('cancel-scan').addEventListener('click', cancelScan);
}

// ─── Network audit ───────────────────────────────────────────────────────

const auditView = { data: null, picked: null };
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

async function refreshAudit() {
  const d = auditView.data = await api('/api/audit');
  if (auditView.picked === null) {
    const first = d.choices.filter((c) => !c.virtual).slice(0, 1).map((c) => c.network);
    auditView.picked = new Set(d.saved.length ? d.saved : first);
  }
  renderAudit();
}

function renderAudit() {
  const d = auditView.data;
  const running = Boolean(d.job && d.job.state === 'running');
  $('audit-off').hidden = d.enabled;
  $('audit-choices').replaceChildren(...(d.choices.length ? d.choices.map((c) => h('label', { class: 'check' },
    h('input', {
      type: 'checkbox', checked: auditView.picked.has(c.network), disabled: running,
      onchange: (e) => { if (e.target.checked) auditView.picked.add(c.network); else auditView.picked.delete(c.network); },
    }),
    c.network, h('small', null, `${c.interface}${c.virtual ? ' · virtual adapter' : ''}`)))
    : [h('div', { class: 'empty' }, 'This computer has no private network to audit.')]));
  $('audit-run').hidden = !d.controls;
  $('audit-run').disabled = running || !d.enabled;
  $('audit-cancel').hidden = !(d.controls && running);
  if (d.job) {
    const label = { running: d.job.message, done: 'Done', cancelled: 'Cancelled',
      error: `Did not finish: ${d.job.error}` }[d.job.state] || d.job.state;
    $('audit-progress').hidden = false;
    $('audit-progress-label').textContent = `${d.job.networks.join(', ')}${d.job.gentle ? ' (gentle)' : ''}: ${label}`;
    $('audit-progress-bar').style.width = `${Math.round(100 * (d.job.fraction || 0))}%`;
  }
  renderAuditReport(d.report);
}

function renderAuditReport(report) {
  const out = $('audit-report');
  if (!report) { out.replaceChildren(); return; }
  const panels = report.networks.map((n) => {
    const d = n.diff;
    const changes = d && d.new_hosts && !n.first_audit
      ? `Since the last audit: ${d.new_hosts.length} new hosts, ${d.opened.length} ports opened, ${d.closed.length} closed.`
      : 'First audit of this network.';
    const findings = [...n.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
    return h('div', { class: 'panel' },
      h('h2', null, n.network, h('small', null, ` ${n.hosts.length} hosts · ${n.findings.length} findings · found by ${n.discovery.method}${n.complete ? '' : ' · incomplete'}`)),
      h('p', { class: 'hint' }, changes),
      findings.length ? findings.map((f) => h('div', { class: 'finding' },
        h('div', { class: 'head' }, h('span', { class: `badge ${f.severity}` }, f.severity), ' ',
          h('b', null, f.title), h('span', { class: 'time' }, `  ${f.host}${f.port ? ':' + f.port : ''}`)),
        h('div', { class: 'why' }, f.why), h('div', { class: 'fix' }, `Fix: ${f.fix}`)))
        : h('div', { class: 'empty' }, 'Nothing risky found.'),
      h('div', { class: 'table-wrap' }, table(['Host', 'Vendor', 'Open ports', 'Looks like'],
        n.hosts.map((x) => h('tr', null, h('td', null, x.ip + (x.self ? ' (this computer)' : '')),
          h('td', null, x.vendor || x.mac || ''), h('td', null, (x.open_ports || []).join(', ')),
          h('td', null, [x.role, ...(x.tags || [])].filter(Boolean).join(', ')))))),
      (n.notes || []).map((note) => h('p', { class: 'hint' }, note)));
  });
  out.replaceChildren(...panels);
}

function runAudit() {
  const nets = [...auditView.picked];
  if (!nets.length) { toast('Choose a network to audit.'); return; }
  const query = nets.map((n) => `network=${encodeURIComponent(n)}`).join('&') +
    ($('audit-gentle').checked ? '&gentle=1' : '');
  control(`/api/audit/start?${query}`, refreshAudit);
}

// ─── Controls (only while the server is bound to localhost) ─────────────

let busy = false;

async function control(path, after) {
  if (busy) return;
  busy = true;
  try {
    await api(path, { method: 'POST' });
    if (after) await after();
  } catch (e) {
    toast(e.message);
  } finally {
    busy = false;
    await refreshOverview();
  }
}

async function buildBundle() {
  const button = $('build-bundle');
  button.disabled = true;
  button.textContent = 'Building…';
  try {
    const r = await api('/api/review/bundle', { method: 'POST' });
    $('bundle-result').hidden = false;
    $('bundle-result').textContent =
      `Bundle ready: ${r.alerts} alerts in ${r.groups} groups, ${r.digests} traffic digests, ` +
      `${Math.round(r.bytes / 1024)} KB, ${r.masked} values masked. Upload this zip to Claude: ${r.zip}`;
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Build review bundle';
  }
}

function renderControls(o) {
  $('build-bundle').hidden = !(o.controls && o.review && o.review.enabled);
  $('ack-all').hidden = !o.controls;
  const toggle = $('monitor-toggle');
  toggle.hidden = !o.controls;
  if (busy) return;   // keeps "Starting…" up until the request returns
  toggle.disabled = false;
  toggle.textContent = o.monitoring ? 'Stop' : 'Start';
  toggle.className = o.monitoring ? 'secondary' : '';
}

function toggleMonitoring() {
  const stopping = Boolean(overview && overview.monitoring);
  if (stopping && !confirm('Stop monitoring? Nothing is captured or detected until it starts again.')) return;
  const toggle = $('monitor-toggle');
  toggle.disabled = true;
  toggle.textContent = stopping ? 'Stopping…' : 'Starting…';
  control(stopping ? '/api/monitoring/stop' : '/api/monitoring/start');
}

function refreshCurrent() {
  return PAGES[current].refresh();
}

// ─── Pages and polling ───────────────────────────────────────────────────

const PAGES = {
  overview: { refresh: () => Promise.all([refreshOverview(), refreshRecentAlerts()]), every: 2000 },
  alerts: { refresh: refreshAlerts, every: 5000 },
  devices: { refresh: refreshDevices, every: 5000 },
  incidents: { refresh: refreshIncidents, every: 10000 },
  scan: { refresh: refreshIgnored, every: 10000 },
  audit: { refresh: refreshAudit, every: 2000 },
  sources: { refresh: refreshSources, every: 30000 },
};
let current = null, timer = null;

async function tick() {
  clearTimeout(timer);
  const page = PAGES[current];
  try {
    await page.refresh();
    if (current !== 'overview') await refreshOverview();   // keeps the status pill and charts live
  } catch (e) {
    // the status pill shows a lost connection; the next tick retries
  }
  timer = setTimeout(tick, page.every || 2000);
}

function show() {
  const name = location.hash.slice(1);
  current = PAGES[name] ? name : 'overview';
  for (const p of Object.keys(PAGES)) $(`page-${p}`).hidden = p !== current;
  for (const a of document.querySelectorAll('#tabs a')) a.classList.toggle('active', a.dataset.page === current);
  tick();
}

document.addEventListener('DOMContentLoaded', () => {
  charts.pps = new TimeChart($('chart-pps'), { colour: '#58a6ff', format: fmtPps, axis: fmtRate });
  charts.bw = new TimeChart($('chart-bw'), { colour: '#39d2c0', format: fmtBps, axis: fmtBytes, base: 1024 });
  renderRanges();
  window.addEventListener('resize', () => { charts.pps.draw(); charts.bw.draw(); });
  $('alert-search').addEventListener('input', (e) => { alertView.search = e.target.value; renderAlerts(); });
  $('device-search').addEventListener('input', (e) => { deviceView.search = e.target.value; renderDevices(); });
  $('monitor-toggle').addEventListener('click', toggleMonitoring);
  $('ack-all').addEventListener('click', () => control('/api/alerts/ack-all', refreshCurrent));
  $('build-bundle').addEventListener('click', buildBundle);
  $('audit-run').addEventListener('click', runAudit);
  $('audit-cancel').addEventListener('click', () => control('/api/audit/cancel', refreshAudit));
  setUpScan();
  window.addEventListener('hashchange', show);
  show();
});
