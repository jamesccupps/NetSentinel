'use strict';
// NetSentinel dashboard. Everything that came off the network or out of a
// scanned file is put on the page as text (textContent), never as HTML.

const TOKEN = document.querySelector('meta[name="netsentinel-token"]').content;
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

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers);
  if (options.method === 'POST') headers['X-NetSentinel-Token'] = TOKEN;
  const res = await fetch(path, Object.assign({ cache: 'no-store' }, options, { headers }));
  const body = await res.json().catch(() => ({}));
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

class LineChart {
  constructor(canvas, colour) {
    this.canvas = canvas;
    this.colour = colour;
    this.points = [];
    this.max = 150;
  }
  push(v) {
    this.points.push(Number(v) || 0);
    if (this.points.length > this.max) this.points.shift();
    this.draw();
  }
  draw() {
    const c = this.canvas, dpr = window.devicePixelRatio || 1;
    const w = c.clientWidth, ht = c.clientHeight;
    if (!w || !ht) return;
    if (c.width !== Math.round(w * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(ht * dpr); }
    const g = c.getContext('2d');
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, w, ht);
    const top = Math.max(1, ...this.points) * 1.15;
    const pad = 4, x = (i) => (w - 50) * i / (this.max - 1), y = (v) => ht - pad - (ht - 2 * pad) * v / top;
    g.strokeStyle = '#30363d'; g.lineWidth = 1; g.setLineDash([3, 4]);
    for (let i = 1; i <= 3; i++) { const yy = Math.round(ht * i / 4) + .5; g.beginPath(); g.moveTo(0, yy); g.lineTo(w, yy); g.stroke(); }
    g.setLineDash([]);
    if (this.points.length < 2) return;
    const off = this.max - this.points.length;
    g.beginPath();
    this.points.forEach((v, i) => (i ? g.lineTo : g.moveTo).call(g, x(i + off), y(v)));
    g.strokeStyle = this.colour; g.lineWidth = 2; g.stroke();
    g.lineTo(x(this.max - 1), ht); g.lineTo(x(off), ht); g.closePath();
    const grad = g.createLinearGradient(0, 0, 0, ht);
    grad.addColorStop(0, this.colour + '55'); grad.addColorStop(1, this.colour + '00');
    g.fillStyle = grad; g.fill();
    const last = this.points[this.points.length - 1];
    g.fillStyle = this.colour; g.font = '600 13px Segoe UI, system-ui, sans-serif'; g.textAlign = 'right';
    g.fillText(last >= 100 ? Math.round(last).toLocaleString() : last.toFixed(1), w - 4, Math.max(16, y(last) - 6));
  }
}

const charts = {};

// ─── Shared pieces ───────────────────────────────────────────────────────

function card(key, value, sub, colour) {
  return h('div', { class: 'card' },
    h('div', { class: 'k' }, key),
    h('div', { class: 'v', style: colour ? { color: colour } : null }, value),
    sub ? h('div', { class: 's' }, sub) : null);
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

function alertItem(a) {
  const key = a.id || `${a.timestamp}|${a.rule_id}|${a.title}`;
  const evidence = h('pre', { hidden: !expanded.has(key) }, JSON.stringify(a.evidence || {}, null, 2));
  const where = [a.src_ip, a.dst_ip ? `→ ${a.dst_ip}${a.dst_port ? ':' + a.dst_port : ''}` : null]
    .filter(Boolean).join(' ');
  return h('div', {
    class: `alert sev-${a.severity}${a.acknowledged ? ' acked' : ''}`,
    onclick: (e) => {
      if (e.target === evidence) return;
      evidence.hidden = !evidence.hidden;
      if (evidence.hidden) expanded.delete(key); else expanded.add(key);
    },
  },
  h('div', { class: 'head' },
    h('span', { class: `badge ${a.severity}` }, a.severity),
    h('span', { class: 'title' }, a.title),
    h('span', { class: 'time' }, a.time_str || ''),
    ackButton(a)),
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
  $('cards').replaceChildren(
    card('Packets captured', fmtNum(o.capture.packets_captured), `${fmtNum(Math.round(o.capture.packets_per_sec))} per second`),
    card('Bandwidth', `${fmtBytes(o.capture.bytes_per_sec)}/s`, `${fmtBytes(o.capture.bytes_captured)} total`),
    card('Active flows', fmtNum(o.capture.flows_active), `${fmtNum(o.capture.packets_dropped)} packets dropped`),
    card('Alerts', fmtNum(o.alerts.total), `${sev.CRITICAL || 0} critical · ${sev.HIGH || 0} high · ${o.alerts.unacknowledged} open`,
      (sev.CRITICAL || sev.HIGH) ? COLOURS.red : null),
    card('Threat level', o.threat.label, `anomaly score ${o.threat.score.toFixed(2)}`, COLOURS[o.threat.colour]),
    card('Devices', fmtNum(o.devices.total), `${fmtNum(o.devices.active_last_hour)} active in the last hour`));

  if (o.monitoring) {
    charts.pps.push(o.capture.packets_per_sec);
    charts.bw.push(o.capture.bytes_per_sec / 1024);
  }
  bars($('protocols'), o.protocols.map((p) => ({ name: p.name, value: p.count, fraction: p.fraction })),
    (r) => `${(r.fraction * 100).toFixed(1)}%`);
  bars($('talkers'), o.top_talkers.map((t) => ({ name: t.ip, value: t.bytes })), (r) => fmtBytes(r.value));
  const res = o.resources || {};
  const rate = Number(o.capture.sample_rate || 1);
  const facts = [
    ['Monitoring', o.monitoring ? 'Yes' : 'No'],
    ['Uptime', o.monitoring ? fmtDuration(o.uptime_sec) : '—'],
    ['Alerts per minute', fmtNum(o.alerts.per_minute)],
    ['Open incidents', fmtNum(o.incidents_active)],
    ['ML model', o.ml.is_trained ? 'Trained' : 'Learning the baseline'],
    ['Baseline samples', fmtNum(o.ml.baseline_samples)],
    ['CPU', res.available ? `${res.cpu_percent}%${res.low_priority ? ' (low priority)' : ''}` : '—'],
    ['Memory', res.available ? fmtBytes(res.rss_bytes) : '—'],
    ['Threads', res.available ? fmtNum(res.threads) : '—'],
    ['Packets dropped', fmtNum(o.capture.packets_dropped)],
    ['Analysing', rate > 1 ? `1 in ${rate} packets (busy)` : 'Every packet'],
  ];
  $('engine').replaceChildren(...facts.flatMap(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
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

const deviceView = { type: 'ALL', search: '', data: null };

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
  const rows = (d.devices || []).filter((x) =>
    (deviceView.type === 'ALL' || x.type === deviceView.type) &&
    (!q || [x.ip, x.hostname, x.mac].some((f) => String(f || '').toLowerCase().includes(q))))
    .map((x) => h('tr', null,
      h('td', { class: 'mono' }, x.ip), h('td', null, x.hostname), h('td', { class: 'mono' }, x.mac || '—'),
      h('td', null, x.type), h('td', null, x.confidence), h('td', null, fmtNum(x.packets)),
      h('td', { class: 'mono' }, x.last_seen), h('td', { class: 'wrap' }, (x.services || []).join(', '))));
  $('device-table').replaceWith(Object.assign(
    table(['IP', 'Hostname', 'MAC', 'Type', 'Confidence', 'Packets', 'Last seen', 'Services'],
      rows.length ? rows : [h('tr', null, h('td', { colspan: 8, class: 'empty' }, 'No devices yet. They appear as monitoring sees them.'))]),
    { id: 'device-table' }));
}

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
    xhr.setRequestHeader('X-NetSentinel-Token', TOKEN);
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

const KINDS = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domains', url: 'URLs', email: 'Emails', mac: 'MAC addresses' };

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
    card('Emails', fmtNum(s.email), `${fmtNum(s.mac)} MAC addresses`)));

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
      h('td', { class: 'mono' }, x.value), h('td', { class: 'wrap mono' }, `${x.file}:${x.line}`))),
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
        ? h('div', { class: 'table-wrap' }, table(['Value', 'Scope', 'Seen', 'Found in'],
          shown.slice(0, 500).map((e) => h('tr', null,
            h('td', { class: 'mono wrap' }, e.value),
            h('td', null, e.scope ? h('span', { class: `badge ${e.scope}` }, e.scope) : ''),
            h('td', null, fmtNum(e.count)),
            h('td', { class: 'wrap' }, e.files.slice(0, 5).join(', ') + (e.files.length > 5 ? ` and ${e.files.length - 5} more` : ''))))))
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

function renderControls(o) {
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
  scan: { refresh: () => Promise.resolve(), every: 0 },
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
  charts.pps = new LineChart($('chart-pps'), '#58a6ff');
  charts.bw = new LineChart($('chart-bw'), '#39d2c0');
  window.addEventListener('resize', () => { charts.pps.draw(); charts.bw.draw(); });
  $('alert-search').addEventListener('input', (e) => { alertView.search = e.target.value; renderAlerts(); });
  $('device-search').addEventListener('input', (e) => { deviceView.search = e.target.value; renderDevices(); });
  $('monitor-toggle').addEventListener('click', toggleMonitoring);
  $('ack-all').addEventListener('click', () => control('/api/alerts/ack-all', refreshCurrent));
  setUpScan();
  window.addEventListener('hashchange', show);
  show();
});
