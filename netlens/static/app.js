const $ = id => document.getElementById(id);
let packets = [], selectedId = null, mode = 'beginner', session = null, polling = false;
async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) { let data; try { data = await response.json(); } catch { data = {}; } const detail = Array.isArray(data.detail) ? data.detail.map(item => item.msg || 'Invalid input').join('; ') : data.detail; throw new Error(detail || `Request failed (${response.status})`); }
  return response.json();
}
function notice(message) { $('notice').hidden = !message; $('notice').textContent = message || ''; }
async function interfaces() {
  try {
    const data = await api('/api/interfaces'); const select = $('interfaces'); const previous = select.value;
    select.replaceChildren();
    if (!data.interfaces.length) select.add(new Option('No interfaces found', ''));
    for (const item of data.interfaces) { const option = new Option(item.name + (item.allowed ? '' : ' (not authorized)'), item.name); option.disabled = !item.allowed; select.add(option); }
    if ([...select.options].some(option => option.value === previous && !option.disabled)) select.value = previous;
    else { const allowed = [...select.options].find(option => !option.disabled && option.value); if (allowed) select.value = allowed.value; }
    if (!data.interfaces.some(item => item.allowed)) notice('Capture is disabled until an interface is authorized. Copy an interface name, stop the server, set NETLENS_ALLOWED_INTERFACES to that name, and restart the server. See the README for the exact steps.');
  } catch (error) { notice(error.message); }
}
function cell(row, value, className) { const td = document.createElement('td'); td.textContent = value; if (className) td.className = className; row.append(td); }
function render() {
  const query = $('filter').value.trim().toLowerCase();
  const filtered = packets.filter(p => [p.source, p.destination, p.protocol, p.transport_protocol, String(p.length), String(p.id)].some(value => (value || '').toLowerCase().includes(query)));
  $('packets').replaceChildren(); $('empty').hidden = filtered.length > 0; $('displayed').textContent = filtered.length;
  for (const packet of filtered) { const row = document.createElement('tr'); if (packet.id === selectedId) row.className = 'selected';
    cell(row, packet.id); cell(row, new Date(packet.timestamp).toLocaleTimeString()); cell(row, packet.source || '—'); cell(row, packet.destination || '—'); cell(row, packet.protocol, 'protocol'); cell(row, packet.length + ' B'); cell(row, packet.explanation?.title || 'Network packet');
    row.addEventListener('click', () => { selectedId = packet.id; render(); }); $('packets').append(row);
  }
  renderDetails();
}
function renderDetails() {
  const packet = packets.find(p => p.id === selectedId); const target = $('details'); target.replaceChildren();
  $('selection').textContent = packet ? `PACKET #${packet.id}` : 'NO PACKET SELECTED';
  if (!packet) { const box = document.createElement('div'); box.className = 'detail-empty'; const icon = document.createElement('span'); icon.textContent = '◇'; const text = document.createElement('div'); const title = document.createElement('strong'); title.textContent = 'Select a packet to inspect'; const description = document.createElement('p'); description.textContent = 'Choose a row above to see its available details.'; text.append(title, description); box.append(icon,text); target.append(box); return; }
  const box = document.createElement('div'); box.className = 'detail-content';
  if (mode === 'beginner') {
    const explanation = document.createElement('div'); explanation.className = 'explanation';
    const label = document.createElement('span'); label.className = 'explanation-label'; label.textContent = 'WHAT HAPPENED';
    const title = document.createElement('h3'); title.textContent = packet.explanation?.title || 'Network packet';
    const description = document.createElement('p'); description.textContent = packet.explanation?.description || 'A network packet was observed, but its purpose is unknown.';
    const limit = document.createElement('p'); limit.className = 'explanation-limit'; const limitLabel = document.createElement('strong'); limitLabel.textContent = 'What we can’t tell: '; limit.append(limitLabel, document.createTextNode(packet.explanation?.limitation || 'There is not enough information in this summary to explain the full exchange.'));
    explanation.append(label, title, description, limit); box.append(explanation);
  } else {
    const title = document.createElement('h3'); title.textContent = 'Packet summary'; box.append(title);
    const description = document.createElement('p'); description.textContent = 'Available capture metadata. Detailed headers and raw bytes are not yet available.'; box.append(description);
  }
  const grid = document.createElement('div'); grid.className = 'detail-grid';
  const fields = [['Source', packet.source || 'Unavailable'], ['Destination', packet.destination || 'Unavailable'], ['Protocol', packet.protocol], ['Packet length', `${packet.length} bytes`], ['Captured at', new Date(packet.timestamp).toLocaleString()], ['Session', packet.session_id]];
  if (mode === 'technical') fields.push(['Transport', packet.transport_protocol ?? 'Unavailable'], ['Source port', packet.source_port ?? 'Unavailable'], ['Destination port', packet.destination_port ?? 'Unavailable'], ['Source MAC', packet.source_mac ?? 'Unavailable'], ['Destination MAC', packet.destination_mac ?? 'Unavailable'], ['TTL / hop limit', packet.ttl ?? 'Unavailable'], ['TCP flags', packet.tcp_flags ?? 'Unavailable']);
  for (const [label, value] of fields) { const item = document.createElement('div'); const small = document.createElement('small'); small.textContent = label; const strong = document.createElement('strong'); strong.textContent = value; item.append(small,strong); grid.append(item); }
  box.append(grid); target.append(box);
}
async function update() {
  if (polling) return; polling = true;
  try { const status = await api('/api/capture/status'); $('state').textContent = status.state === 'running' ? 'Capturing' : status.state.charAt(0).toUpperCase() + status.state.slice(1); $('footer-state').textContent = status.state === 'running' ? 'Capture in progress' : 'Capture ' + status.state; $('dot').classList.toggle('live', status.state === 'running'); document.querySelector('.footer-dot').classList.toggle('live', status.state === 'running'); $('start').disabled = ['running','starting','stopping'].includes(status.state); $('stop').disabled = status.state !== 'running'; $('captured').textContent = status.captured; $('dropped').textContent = status.dropped; if (status.error) notice(status.error);
    if (session !== status.session_id) { session = status.session_id; selectedId = null; }
    let data = await api('/api/packets?limit=1'); const offset = Math.max(0, data.total - 500); data = await api(`/api/packets?limit=500&offset=${offset}`); packets = data.items; render();
  } catch (error) { $('state').textContent = 'Disconnected'; notice('Cannot reach the NetLens service. Check that the server is running.'); } finally { polling = false; }
}
$('start').addEventListener('click', async () => { try { if (!$('interfaces').value || $('interfaces').selectedOptions[0]?.disabled) { notice('No authorized interface is selected. Stop the server and run start-netlens.ps1, then choose an interface from the numbered list.'); return; } notice(''); await api('/api/capture/start', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interface:$('interfaces').value})}); await update(); } catch(error) { notice(error.message); } });
$('stop').addEventListener('click', async () => { try { await api('/api/capture/stop',{method:'POST'}); await update(); } catch(error) { notice(error.message); } });
$('refresh').addEventListener('click', interfaces); $('filter').addEventListener('input', render); $('clear').addEventListener('click', () => { $('filter').value = ''; render(); });
for (const name of ['beginner','technical']) $(name).addEventListener('click', () => { mode = name; $('beginner').classList.toggle('active', mode === 'beginner'); $('technical').classList.toggle('active', mode === 'technical'); renderDetails(); });
interfaces(); update(); setInterval(update, 1500);
