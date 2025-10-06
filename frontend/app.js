const tableBody = document.querySelector('#nodes-table tbody');
const refreshButton = document.querySelector('#refresh-button');
const toast = document.getElementById('toast');
const summaryTotal = document.getElementById('summary-total');
const summaryOnline = document.getElementById('summary-online');
const summaryOffline = document.getElementById('summary-offline');
const summaryBusy = document.getElementById('summary-busy');
const summaryUpdated = document.getElementById('summary-updated');

const STATUS_PRIORITY = ['busy', 'offline', 'online'];

async function fetchJson(endpoint) {
  const response = await fetch(endpoint);
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return response.json();
}

function formatEndpoint(node) {
  if (!node.host || !node.port) {
    return '—';
  }
  const protocol = node.protocol || 'http';
  const path = node.path || '/wd/hub';
  return `${protocol}://${node.host}:${node.port}${path}`;
}

function deriveStatus(node) {
  const baseStatus = (node.status || 'offline').toLowerCase();
  if (baseStatus === 'online') {
    const maxSessions = Number(node.max_sessions ?? 1);
    const activeSessions = Number(node.active_sessions ?? 0);
    if (maxSessions > 0 && activeSessions >= maxSessions) {
      return 'busy';
    }
  }
  return baseStatus;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    toast.classList.remove('visible');
  }, 2500);
}

async function copyNodeDetails(node) {
  const payload = {
    id: node.id,
    endpoint: formatEndpoint(node),
    status: deriveStatus(node),
    max_sessions: node.max_sessions,
    active_sessions: node.active_sessions,
    platform: node.platform,
    capabilities: node.capabilities,
  };

  try {
    await navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    showToast(`Copied details for ${node.id}`);
  } catch (error) {
    console.error('Clipboard copy failed', error);
    showToast('Unable to copy node details');
  }
}

function renderRows(nodes) {
  tableBody.innerHTML = '';
  if (nodes.length === 0) {
    tableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No nodes registered yet.</td></tr>';
    return;
  }

  const sortedNodes = [...nodes].sort((a, b) => {
    const statusDiff = STATUS_PRIORITY.indexOf(deriveStatus(a)) - STATUS_PRIORITY.indexOf(deriveStatus(b));
    if (statusDiff !== 0) {
      return statusDiff;
    }
    return (a.id || '').localeCompare(b.id || '');
  });

  for (const node of sortedNodes) {
    const tr = document.createElement('tr');

    const sessionsLabel = `${Number(node.active_sessions ?? 0)} / ${Number(node.max_sessions ?? 1)}`;

    tr.innerHTML = `
      <td>
        <div class="node-name">${node.id || 'Unknown node'}</div>
        <div class="node-meta">${node.platform || ''}</div>
      </td>
      <td>
        <code class="endpoint">${formatEndpoint(node)}</code>
      </td>
      <td>${sessionsLabel}</td>
      <td>
        <span class="badge" data-status="${deriveStatus(node)}">${deriveStatus(node)}</span>
      </td>
      <td>
        <button class="action-button" data-copy="${node.id}">Copy details</button>
      </td>
    `;

    tr.querySelector('button[data-copy]').addEventListener('click', () => copyNodeDetails(node));
    tableBody.appendChild(tr);
  }
}

function updateSummary(nodes) {
  const total = nodes.length;
  const counts = nodes.reduce(
    (acc, node) => {
      const status = deriveStatus(node);
      acc[status] = (acc[status] || 0) + 1;
      return acc;
    },
    { online: 0, offline: 0, busy: 0 }
  );

  summaryTotal.textContent = total;
  summaryOnline.textContent = counts.online;
  summaryOffline.textContent = counts.offline;
  summaryBusy.textContent = counts.busy;
  summaryUpdated.textContent = new Date().toLocaleTimeString();
}

async function loadNodes() {
  tableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Loading nodes...</td></tr>';

  try {
    const nodeMap = await fetchJson('/nodes');
    const nodes = Object.values(nodeMap);
    renderRows(nodes);
    updateSummary(nodes);
  } catch (error) {
    console.error('Failed to load nodes', error);
    tableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Unable to load nodes. Please try again.</td></tr>';
    showToast('Failed to load nodes');
  }
}

refreshButton.addEventListener('click', loadNodes);

loadNodes();
setInterval(loadNodes, 15000);
