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

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Netmon-Token': TOKEN },
    body: JSON.stringify(body || {}),
  });
  return { status: response.status, data: await response.json() };
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
    const node = el('div', 'finding ' + finding.severity);
    const top = el('div', 'top');
    top.append(badge(finding.severity), badge(finding.tier),
               el('span', 'rule', finding.rule_id));
    if (finding.count > 1) top.append(el('span', 'note', `×${finding.count}`));
    if (finding.device) top.append(el('span', 'note', finding.device));
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
    list.append(node);
  }
}

async function loadFindings() {
  const data = await get('/api/findings', {
    min_severity: $('#f-severity').value,
    tier: $('#f-tier').value,
    rule: $('#f-rule').value,
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

['#f-severity', '#f-tier', '#f-rule'].forEach((sel) => {
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
    $$('button.action').forEach((button) => {
      if (button.id === 'cf-verify') return;
      button.disabled = true;
      button.title = 'start with --allow-edit to enable the editors';
    });
    $('#profile-source').readOnly = true;
    $('#rule-source').readOnly = true;
  }

  await loadFindings();
}

$('#reload').onclick = async () => {
  const { data } = await post('/api/reload', {});
  if (data.error) { alert(data.error); return; }
  await loadAll();
};

loadAll().then(buildFilter);
