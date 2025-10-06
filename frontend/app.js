const tableBody = document.querySelector('#nodes-table tbody');
const refreshButton = document.querySelector('#refresh-button');
const toast = document.getElementById('toast');
const summaryTotal = document.getElementById('summary-total');
const summaryOnline = document.getElementById('summary-online');
const summaryOffline = document.getElementById('summary-offline');
const summaryBusy = document.getElementById('summary-busy');
const summaryUpdated = document.getElementById('summary-updated');
const detailsModal = document.getElementById('details-modal');
const detailsBody = document.getElementById('details-modal-body');
const dismissTargets = detailsModal
  ? Array.from(detailsModal.querySelectorAll('[data-dismiss]'))
  : [];
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

let lastFocusedTrigger = null;

const STATUS_PRIORITY = ['busy', 'offline', 'online'];

async function fetchJson(endpoint) {
  const response = await fetch(`http://10.160.24.110:8080${endpoint}`);
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

function serializeNode(node) {
  const payload = {
    id: node.id,
    endpoint: formatEndpoint(node),
    status: deriveStatus(node),
    max_sessions: node.max_sessions,
    active_sessions: node.active_sessions,
    platform: node.platform,
    capabilities: node.capabilities,
  };

  return JSON.stringify(payload, null, 2);
}

function closeDetailsModal() {
  if (!detailsModal) {
    return;
  }

  detailsModal.classList.remove('visible');
  detailsModal.setAttribute('aria-hidden', 'true');
  if (lastFocusedTrigger && typeof lastFocusedTrigger.focus === 'function') {
    if (!lastFocusedTrigger.isConnected) {
      const fallbackTrigger = document.querySelector('.action-button');
      if (fallbackTrigger) {
        fallbackTrigger.focus();
      }
    } else {
      lastFocusedTrigger.focus();
    }
  }
  lastFocusedTrigger = null;
}

function showNodeDetails(node, triggerButton) {
  if (!detailsModal || !detailsBody) {
    console.warn('Details modal not available');
    return;
  }

  lastFocusedTrigger = triggerButton || null;
  detailsBody.textContent = serializeNode(node);
  detailsModal.classList.add('visible');
  detailsModal.setAttribute('aria-hidden', 'false');

  const closeButton = detailsModal.querySelector('.details-modal__close');
  if (closeButton) {
    closeButton.focus();
  }
}

if (detailsModal) {
  dismissTargets.forEach((target) => {
    target.addEventListener('click', closeDetailsModal);
  });

  detailsModal.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab' || !detailsModal.classList.contains('visible')) {
      return;
    }

    const focusableElements = Array.from(
      detailsModal.querySelectorAll(FOCUSABLE_SELECTOR)
    ).filter((element) => !element.hasAttribute('disabled'));

    if (focusableElements.length === 0) {
      event.preventDefault();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const { activeElement } = document;

    if (event.shiftKey) {
      if (activeElement === firstElement || !detailsModal.contains(activeElement)) {
        event.preventDefault();
        lastElement.focus();
      }
    } else if (activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && detailsModal.classList.contains('visible')) {
      closeDetailsModal();
    }
  });
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
        <button class="action-button" data-show="${node.id}">Show details</button>
      </td>
    `;

    const trigger = tr.querySelector('button[data-show]');
    trigger.addEventListener('click', () => showNodeDetails(node, trigger));
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
