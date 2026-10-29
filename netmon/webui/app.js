'use strict';

/* The UI. No framework, no build step, nothing fetched from anywhere — this
   runs on a sensor that may have no route to the internet, and a page that
   silently depends on a CDN is a page that renders blank there.

   Everything from the server is inserted as text, never as HTML. The data
   includes device names, SNI values and rule descriptions, which come from the
   network being watched; treating any of it as markup would let whatever is out
   there script this page. */

const TOKEN = document.body.dataset.token;
const EDITABLE = document.body.dataset.editable === 'true';
// Acknowledge, snooze and maintenance need both --allow-edit and somewhere to
// keep them (--state); the server says whether it has both.
const SILENCES = document.body.dataset.silences === 'true';
const SUMMARISE = document.body.dataset.summarise === 'true';

const SILENCE_LABELS = { ack: 'acknowledged', maintenance: 'maintenance',
                         snooze: 'snoozed' };

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const state = { findings: [], devices: null, rules: [], summary: null };

async function get(path, params) {
  const url = new URL(path, location.origin);
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== '' && v != null) url.searchParams.set(k, v);
  });
  const response = await fetch(url, { headers: { 'Accept': 'application/json' } });
  return response.json();
}

async function post(path, body, timeoutMs) {
  // A timeout so a stuck request does not leave a button pressed for ever.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 30000);
  try {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Netmon-Token': TOKEN },
      body: JSON.stringify(body || {}),
      signal: controller.signal,
    });
    return { status: response.status, data: await response.json() };
  } catch (e) {
    return { status: 0, data: { error: e.name === 'AbortError'
      ? 'no answer in time' : String(e) } };
  } finally {
    clearTimeout(timer);
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;     // text, never innerHTML
  return node;
}

function card(value, label) {
  const node = el('div', 'card');
  node.append(el('div', 'n', String(value)), el('div', 'k', label));
  return node;
}

function badge(text, kind) {
  return el('span', 'badge ' + (kind || text), text);
}

// ─── Tabs ──────────────────────────────────────────────────────────────

$$('nav button').forEach((button) => {
  button.onclick = () => {
    $$('nav button').forEach((b) => b.classList.toggle('active', b === button));
    $$('main section').forEach((s) =>
      s.classList.toggle('active', s.id === button.dataset.tab));
  };
});

// ─── Findings ──────────────────────────────────────────────────────────

function renderFindings() {
  const search = $('#f-search').value.trim().toLowerCase();
  const list = $('#finding-list');
  list.replaceChildren();

  const shown = state.findings.filter((f) => !search
    || (f.device || '').toLowerCase().includes(search)
    || (f.description || '').toLowerCase().includes(search)
    || (f.rule_id || '').toLowerCase().includes(search));

  if (!shown.length) {
    const empty = el('div', 'empty');
    empty.append(el('strong', null, state.findings.length
      ? 'Nothing matches that filter.'
      : 'Nothing found.'));
    empty.append(el('div', null, state.findings.length ? '' :
      'That is a result, not a failure — but check the source covered the ' +
      'VLANs you care about before reading it as an all-clear.'));
    list.append(empty);
    return;
  }

  for (const finding of shown) {
    const silenced = finding.silenced || null;
    const node = el('div', 'finding ' + finding.severity +
                    (silenced ? ' silenced' : ''));
    const top = el('div', 'top');
    top.append(badge(finding.severity), badge(finding.tier),
               el('span', 'rule', finding.rule_id));
    if (finding.count > 1) top.append(el('span', 'note', `×${finding.count}`));
    if (finding.device) top.append(el('span', 'note', finding.device));
    if (silenced) {
      top.append(badge(SILENCE_LABELS[silenced.kind] || silenced.kind,
                       silenced.kind));
      if (silenced.reason) top.append(el('span', 'note', silenced.reason));
    }
    node.append(top);
    node.append(el('div', 'desc', finding.description));

    const evidence = Object.entries(finding.evidence || {})
      .filter(([, v]) => v !== null && v !== '' && v !== undefined);
    if (evidence.length) {
      node.append(el('div', 'ev mono',
        evidence.map(([k, v]) => `${k}=${v}`).join('   ')));
    }
    if (finding.next_check) {
      node.append(el('div', 'next mono', 'next: ' + finding.next_check));
    }
    if (SILENCES) node.append(silenceButtons(finding));
    list.append(node);
  }
}

// ─── Acknowledge, snooze, maintenance ──────────────────────────────────

function silenceButtons(finding) {
  const row = el('div', 'actions');
  const button = (label, title, body) => {
    const node = el('button', 'small', label);
    node.title = title;
    node.onclick = () => addSilence(body, node);
    return node;
  };
  if (finding.silenced) {
    const clear = el('button', 'small', 'Clear ' +
      (SILENCE_LABELS[finding.silenced.kind] || finding.silenced.kind));
    clear.onclick = () => clearSilence(finding.silenced.id, clear);
    row.append(clear);
    return row;
  }
  row.append(
    button('Acknowledge',
      'Stop this one finding pushing for 30 days. It stays in the digest.',
      { kind: 'ack', rule: finding.rule_id, device: finding.device,
        key: finding.key }),
    button('Snooze',
      'Hide this rule on this device completely, for the time chosen above.',
      { kind: 'snooze', rule: finding.rule_id, device: finding.device,
        hours: () => $('#s-hours').value }),
    button('Maintenance',
      'Stop everything about this device pushing until cleared. It all ' +
      'still goes in the digest.',
      { kind: 'maintenance', device: finding.device }));
  return row;
}

function silenceStatus(text, kind) {
  const status = $('#s-status');
  status.className = 'note ' + (kind || '');
  status.textContent = text;
}

async function addSilence(template, button) {
  const body = {};
  for (const [k, v] of Object.entries(template)) {
    body[k] = typeof v === 'function' ? v() : v;
  }
  body.reason = $('#s-reason').value.trim();
  button.disabled = true;
  const { status, data } = await post('/api/silence', body);
  button.disabled = false;
  if (status === 200) {
    silenceStatus(`${SILENCE_LABELS[data.silence.kind] || data.silence.kind}` +
                  ` recorded (${data.silence.id})`, 'ok');
    await Promise.all([loadFindings(), loadSilences()]);
  } else {
    silenceStatus(data.error || 'refused', 'err');
  }
}

async function clearSilence(id, button) {
  if (button) button.disabled = true;
  const { status, data } = await post('/api/silence/clear', { id });
  if (status === 200) {
    silenceStatus(`cleared ${id}`, 'ok');
    await Promise.all([loadFindings(), loadSilences()]);
  } else {
    if (button) button.disabled = false;
    silenceStatus(data.error || 'refused', 'err');
  }
}

async function loadSilences() {
  const wrap = $('#silences-wrap');
  if (!state.summary || !state.summary.silences) {
    wrap.style.display = 'none';
    return;
  }
  const data = await get('/api/silences');
  const entries = data.silences || [];
  wrap.style.display = entries.length ? '' : 'none';
  const list = $('#silence-list');
  list.replaceChildren();
  for (const entry of entries) {
    const node = el('div', 'finding info');
    const top = el('div', 'top');
    top.append(badge(SILENCE_LABELS[entry.kind] || entry.kind, entry.kind),
               el('span', 'mono', entry.id));
    const scope = ['rule', 'device', 'key']
      .filter((k) => entry[k]).map((k) => `${k}=${entry[k]}`).join('  ');
    top.append(el('span', 'note', scope));
    top.append(el('span', 'note', entry.until
      ? 'until ' + new Date(entry.until * 1000).toLocaleString()
      : 'until cleared'));
    node.append(top);
    if (entry.reason) node.append(el('div', 'desc', entry.reason));
    if (SILENCES) {
      const row = el('div', 'actions');
      const clear = el('button', 'small', 'Clear');
      clear.onclick = () => clearSilence(entry.id, clear);
      row.append(clear);
      node.append(row);
    }
    list.append(node);
  }
}

async function loadFindings() {
  const data = await get('/api/findings', {
    min_severity: $('#f-severity').value,
    tier: $('#f-tier').value,
    rule: $('#f-rule').value,
    snoozed: $('#f-snoozed').checked ? '1' : '',
  });
  state.findings = data.findings || [];

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let push = 0;
  for (const finding of state.findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    if (finding.tier === 'push') push += 1;
  }
  const cards = $('#finding-cards');
  cards.replaceChildren(
    card(state.findings.length, 'findings'),
    card(push, 'need attention now'),
    card(counts.critical, 'critical'),
    card(counts.high, 'high'),
    card(counts.medium, 'medium'));
  renderFindings();
}

['#f-severity', '#f-tier', '#f-rule', '#f-snoozed'].forEach((sel) => {
  $(sel).onchange = loadFindings;
});
$('#f-search').oninput = renderFindings;

// ─── Devices ───────────────────────────────────────────────────────────

function renderDevices() {
  if (!state.devices) return;
  const search = $('#d-search').value.trim().toLowerCase();
  const onlyFindings = $('#d-only-findings').checked;
  const body = $('#device-table tbody');
  body.replaceChildren();

  for (const device of state.devices.devices) {
    if (onlyFindings && !device.findings.length) continue;
    const haystack = [device.name, device.mac, device.role, device.zone,
                      ...device.ips].join(' ').toLowerCase();
    if (search && !haystack.includes(search)) continue;

    const row = el('tr');
    const nameCell = el('td');
    nameCell.append(el('span', null, device.name || device.mac));
    if (device.metadata_only) {
      nameCell.append(document.createTextNode(' '));
      nameCell.append(badge('metadata only', 'meta'));
    }
    if (device.mac) nameCell.append(el('div', 'note mono', device.mac));
    row.append(nameCell);
    row.append(el('td', null, device.role));
    row.append(el('td', 'mono', device.ips.join(', ')));
    row.append(el('td', null, device.vlan != null
      ? `${device.vlan} ${device.vlan_name}` : ''));
    row.append(el('td', null, device.zone));

    const findingCell = el('td');
    if (device.findings.length) {
      findingCell.append(badge(device.worst));
      findingCell.append(document.createTextNode(' ' + device.findings.length));
      const detail = el('div', 'note',
        device.findings.map((f) => f.rule_id).join(', '));
      findingCell.append(detail);
    } else {
      findingCell.append(el('span', 'note', '—'));
    }
    row.append(findingCell);
    body.append(row);
  }

  const vlanBody = $('#vlan-table tbody');
  vlanBody.replaceChildren();
  for (const vlan of state.devices.vlans) {
    const row = el('tr');
    row.append(el('td', null, String(vlan.id)), el('td', null, vlan.name),
               el('td', 'mono', vlan.subnet), el('td', null, vlan.zone),
               el('td', 'mono', vlan.gateway));
    const flag = el('td');
    if (vlan.metadata_only) flag.append(badge('no payload stored', 'meta'));
    row.append(flag);
    vlanBody.append(row);
  }

  const unprofiled = state.devices.unprofiled || [];
  $('#unprofiled-wrap').style.display = unprofiled.length ? '' : 'none';
  $('#unprofiled').textContent = unprofiled.join('\n');
}

$('#d-search').oninput = renderDevices;
$('#d-only-findings').onchange = renderDevices;

// ─── Rules ─────────────────────────────────────────────────────────────

function renderRules() {
  const search = $('#r-search').value.trim().toLowerCase();
  const list = $('#rule-list');
  list.replaceChildren();

  for (const rule of state.rules) {
    const haystack = [rule.id, rule.title, rule.grounded_in].join(' ').toLowerCase();
    if (search && !haystack.includes(search)) continue;

    const node = el('div', 'finding ' + rule.severity);
    const top = el('div', 'top');
    top.append(badge(rule.severity), badge(rule.tier),
               el('span', 'rule', rule.id));
    if (rule.type === 'stateful') top.append(el('span', 'note', 'stateful'));
    if (!rule.enabled) top.append(el('span', 'note', 'disabled'));
    node.append(top);
    node.append(el('div', 'desc', rule.title));
    if (rule.grounded_in) {
      node.append(el('div', 'ev', 'grounded in: ' + rule.grounded_in.trim()));
    }
    list.append(node);
  }
}

$('#r-search').oninput = renderRules;

$('#r-edit-toggle').onclick = async () => {
  const editor = $('#rule-editor');
  const showing = editor.style.display !== 'none';
  editor.style.display = showing ? 'none' : '';
  $('#rule-list').style.display = showing ? '' : 'none';
  if (!showing && !$('#rule-source').value) {
    const data = await get('/api/rule', { file: 'core.yaml' });
    $('#rule-source').value = data.source || '';
  }
};

$('#r-save').onclick = async () => {
  const status = $('#r-status');
  status.className = 'note';
  status.textContent = 'checking…';
  const { status: code, data } = await post('/api/rules/save', {
    file: 'core.yaml', source: $('#rule-source').value,
  });
  if (code === 200) {
    status.className = 'note ok';
    status.textContent = `saved — ${data.rules.rules} rules, previous kept as .bak`;
    state.rules = (await get('/api/rules')).rules || [];
    renderRules();
  } else {
    status.className = 'note err';
    status.textContent = `${data.error}${data.detail ? ': ' + data.detail : ''}`;
  }
};

// ─── Capture filter ────────────────────────────────────────────────────

async function buildFilter() {
  const data = await get('/api/filter', {
    vlans: $('#cf-vlans').value,
    untagged: $('#cf-untagged').checked ? 'true' : 'false',
    drop_hosts: $('#cf-drop-hosts').value,
    drop_ports: $('#cf-drop-ports').value,
    protocol: $('#cf-protocol').value,
    ports: $('#cf-ports').value,
  });
  if (data.error) {
    $('#cf-bpf').textContent = data.error;
    $('#cf-bpf').className = 'out err';
    return;
  }
  $('#cf-bpf').className = 'out';
  $('#cf-bpf').textContent = data.bpf || '(empty — captures everything)';
  $('#cf-wireshark').textContent = data.wireshark || '(none)';
  $('#cf-note').textContent = data.note || '';
}

['#cf-vlans', '#cf-drop-hosts', '#cf-drop-ports', '#cf-ports'].forEach((sel) => {
  $(sel).oninput = buildFilter;
});
['#cf-untagged', '#cf-protocol'].forEach((sel) => { $(sel).onchange = buildFilter; });

$('#cf-verify').onclick = async () => {
  const output = $('#cf-result');
  output.style.display = '';
  output.className = 'out';
  output.textContent = 'running…';
  const { data } = await post('/api/filter/verify', {
    bpf: $('#cf-bpf').textContent.startsWith('(') ? '' : $('#cf-bpf').textContent,
    pcap: $('#cf-pcap').value,
  });
  if (data.error) {
    output.className = 'out err';
    output.textContent = data.error;
    return;
  }
  const lines = [
    `${data.matched} of ${data.total} frames kept`,
    '',
    'kept, by VLAN:      ' + (Object.keys(data.by_vlan).length
      ? JSON.stringify(data.by_vlan) : 'none'),
    `kept, untagged:     ${data.untagged_matched}`,
    '',
    'present in capture: ' + JSON.stringify(data.vlans_present),
    `untagged present:   ${data.untagged_present}`,
  ];
  if (data.vlans_dropped.length) {
    lines.push('', 'dropped entirely:   VLAN ' + data.vlans_dropped.join(', '));
  }
  output.textContent = lines.join('\n');
};

// ─── Profile ───────────────────────────────────────────────────────────

$('#p-save').onclick = async () => {
  const status = $('#p-status');
  status.className = 'note';
  status.textContent = 'checking…';
  const { status: code, data } = await post('/api/profile/save', {
    source: $('#profile-source').value,
  });
  if (code === 200) {
    status.className = 'note ok';
    status.textContent = `saved — ${data.summary.devices} devices, ` +
      `${data.summary.vlans} VLANs, previous kept as .bak`;
    await loadAll();
  } else {
    status.className = 'note err';
    status.textContent = `${data.error}${data.detail ? ': ' + data.detail : ''}`;
  }
};

// ─── Model triage ──────────────────────────────────────────────────────
// Two requests, deliberately. Prepare shows exactly what would leave the
// sensor and sends nothing; Send sends that preview, once. Everything the
// model returns is put on the page as text: it was written from findings
// that carry names off the network.

const triage = { previewId: null };

function triageStatus(text, kind) {
  const status = $('#t-status');
  status.className = 'note ' + (kind || '');
  status.textContent = text;
}

function budgetCards(budget) {
  return [
    card(budget.remaining_today, 'tokens left today'),
    card(`${budget.sends_last_hour} / ${budget.hourly_cap}`, 'sent this hour'),
  ];
}

function resetTriage() {
  triage.previewId = null;
  $('#t-send').disabled = true;
  $('#t-discard').disabled = true;
  $('#t-preview').style.display = 'none';
}

$('#t-prepare').onclick = async () => {
  resetTriage();
  $('#t-result').style.display = 'none';
  triageStatus('preparing…');
  const { status, data } = await post('/api/summarise/preview',
                                      { device: $('#t-device').value.trim() });
  if (status !== 200) {
    triageStatus(`${data.error}${data.detail ? ': ' + data.detail : ''}`, 'err');
    return;
  }
  triage.previewId = data.preview_id;
  $('#t-cards').replaceChildren(
    card(data.estimated_input_tokens, 'tokens in (estimated)'),
    card(data.max_output_tokens, 'tokens out, at most'),
    card(data.findings_included, 'findings included'),
    card(data.withheld_from_restricted_segments, 'withheld, restricted'),
    ...budgetCards(data.budget));
  $('#t-note').textContent = `${data.note} Model: ${data.model}. ` +
    `This preview can be sent for ${Math.round(data.expires_in / 60)} minutes.`;
  $('#t-message').textContent = data.message;
  $('#t-system').textContent = data.system;
  $('#t-preview').style.display = '';
  $('#t-send').disabled = false;
  $('#t-discard').disabled = false;
  triageStatus('nothing has been sent', 'ok');
};

$('#t-discard').onclick = () => {
  resetTriage();
  triageStatus('discarded; nothing was sent');
};

$('#t-send').onclick = async () => {
  if (!triage.previewId) return;
  const previewId = triage.previewId;
  resetTriage();
  triageStatus('sending — this can take a minute or two…');
  const { status, data } = await post('/api/summarise/send',
                                      { preview_id: previewId }, 120000);
  if (status !== 200) {
    triageStatus(`${data.error}${data.detail ? ': ' + data.detail : ''}`, 'err');
    return;
  }
  triageStatus(`done — ${data.budget.remaining_today} tokens left today`, 'ok');
  renderTriage(data.result);
};

function renderTriage(result) {
  const body = $('#t-result-body');
  body.replaceChildren();
  body.append(el('p', null, result.assessment || ''));
  for (const item of result.priorities || []) {
    const node = el('div', 'finding ' + (item.likely_benign ? 'info' : 'high'));
    const top = el('div', 'top');
    top.append(el('span', 'rule', item.rule), el('span', 'note', item.device),
               badge(item.confidence + ' confidence', 'info'));
    if (item.likely_benign) top.append(badge('likely benign', 'digest'));
    node.append(top);
    if (item.why_it_matters) node.append(el('div', 'desc', item.why_it_matters));
    if (item.reasoning) node.append(el('div', 'ev', item.reasoning));
    if (item.what_to_check) {
      node.append(el('div', 'next', 'check: ' + item.what_to_check));
    }
    body.append(node);
  }
  const lists = [['Accounted for by the profile', result.expected_by_profile],
                 ['Open questions', result.questions]];
  for (const [title, items] of lists) {
    if (!items || !items.length) continue;
    body.append(el('h3', null, title));
    const pre = el('pre', 'out', items.map((x) => '· ' + x).join('\n'));
    body.append(pre);
  }
  for (const capture of result.capture_filters || []) {
    body.append(el('h3', null, 'Suggested capture — ' + capture.purpose));
    body.append(el('pre', 'out', (capture.bpf || '(everything)') +
      '\nunverified: check it against a sample on the sensor'));
  }
  if (result.dropped_suggestions) {
    body.append(el('p', 'note', `${result.dropped_suggestions} suggestions ` +
      'were dropped for looking like commands rather than descriptions.'));
  }
  const usage = result.usage || {};
  if (usage.input_tokens != null) {
    body.append(el('p', 'note', `${usage.input_tokens} in, ` +
      `${usage.output_tokens} out — ${result.model || ''}`));
  }
  $('#t-result').style.display = '';
}

// ─── Startup ───────────────────────────────────────────────────────────

async function loadAll() {
  state.summary = await get('/api/summary');
  const site = state.summary.site || {};
  $('#site-name').textContent = site.site || '';

  const analysis = state.summary.analysis || {};
  $('#analysed').textContent = analysis.events
    ? `${analysis.events} events analysed`
    : 'no analysis loaded — run with --unifi';

  state.devices = await get('/api/devices');
  renderDevices();

  state.rules = (await get('/api/rules')).rules || [];
  renderRules();
  const select = $('#f-rule');
  const current = select.value;
  select.replaceChildren(el('option', null, 'all'));
  select.firstChild.value = '';
  for (const rule of state.rules) {
    const option = el('option', null, rule.id);
    option.value = rule.id;
    select.append(option);
  }
  select.value = current;

  const profile = await get('/api/profile');
  $('#profile-source').value = profile.source || '';
  const summary = profile.summary || {};
  $('#profile-summary').replaceChildren(
    card(summary.vlans || 0, 'VLANs'),
    card(summary.devices || 0, 'devices'),
    card(summary.roles || 0, 'roles'),
    card(summary.expected_flows || 0, 'expected flows'),
    card((summary.metadata_only_vlans || []).length, 'metadata-only VLANs'));

  if (!EDITABLE) {
    // Every POST but the summariser's is refused read-only, the capture check
    // included — so its button is disabled with the rest rather than left to
    // fail with "editing is off" after it is pressed.
    $$('button.action').forEach((button) => {
      if (button.dataset.permission === 'summarise') return;
      button.disabled = true;
      button.title = 'start with --allow-edit to enable the editors';
    });
    $('#profile-source').readOnly = true;
    $('#rule-source').readOnly = true;
  }
  $('#silence-controls').style.display = SILENCES ? '' : 'none';
  $('#nav-triage').style.display = SUMMARISE ? '' : 'none';

  await Promise.all([loadFindings(), loadSilences()]);
}

$('#reload').onclick = async () => {
  const { data } = await post('/api/reload', {});
  if (data.error) { alert(data.error); return; }
  await loadAll();
};

loadAll().then(buildFilter);
