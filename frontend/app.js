const tableBody = document.querySelector('#nodes-table tbody');
const refreshButton = document.querySelector('#refresh-button');
const tableWrapper = document.querySelector('.table-wrapper');
const tableLoadingOverlay = document.getElementById('table-loading-overlay');
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
let isInitialLoad = true;

const REFRESH_INTERVAL = 15000;

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

function setTableLoading(isLoading) {
  if (tableWrapper) {
    tableWrapper.classList.toggle('is-loading', isLoading);
  }
  if (tableLoadingOverlay) {
    tableLoadingOverlay.classList.toggle('visible', isLoading);
    tableLoadingOverlay.setAttribute('aria-hidden', String(!isLoading));
  }
}

function serializeNode(node) {
  const endpoint = formatEndpoint(node);
  const sessionData = node.resources?.session_data ?? {};
  const status = deriveStatus(node);

  const sections = [
    `Node: ${node.id || 'Unknown node'}`,
    `Platform: ${node.platform || 'Unknown platform'}`,
    `Status: ${status}`,
    `Endpoint: ${endpoint}`,
    '',
    'Session data:',
    JSON.stringify(sessionData, null, 2),
  ];

  return sections.join('\n');
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
    tableBody.innerHTML = '<tr><td colspan="4" class="empty-state">No nodes registered yet.</td></tr>';
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

    const status = deriveStatus(node);
    const isDetailsAvailable = status === 'online';

    tr.innerHTML = `
      <td>
        <div class="node-name">${node.id || 'Unknown node'}</div>
        <div class="node-meta">${node.platform || ''}</div>
      </td>
      <td>${sessionsLabel}</td>
      <td>
        <span class="badge" data-status="${status}">${status}</span>
      </td>
      <td>
        <button class="action-button" data-show="${node.id}">Show details</button>
      </td>
    `;

    const trigger = tr.querySelector('button[data-show]');

    if (!isDetailsAvailable) {
      trigger.setAttribute('disabled', 'true');
      trigger.setAttribute('aria-disabled', 'true');
      trigger.title = 'Session details are only available when the node is online.';
    } else {
      trigger.addEventListener('click', () => showNodeDetails(node, trigger));
    }
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

async function loadNodes({ userInitiated = false } = {}) {
  const hasExistingRows = tableBody && tableBody.querySelector('tr') && !tableBody.querySelector('.empty-state');
  const shouldShowOverlay = !isInitialLoad || userInitiated;

  if (!hasExistingRows && isInitialLoad) {
    tableBody.innerHTML = '<tr><td colspan="4" class="empty-state">Loading nodes...</td></tr>';
  } else if (shouldShowOverlay) {
    setTableLoading(true);
  }

  try {
    const nodeMap = await fetchJson('/nodes');
    const nodes = Object.values(nodeMap);
    renderRows(nodes);
    updateSummary(nodes);
  } catch (error) {
    console.error('Failed to load nodes', error);
    if (!hasExistingRows) {
      tableBody.innerHTML =
        '<tr><td colspan="4" class="empty-state">Unable to load nodes. Please try again.</td></tr>';
    }
    showToast('Failed to load nodes');
  } finally {
    if (shouldShowOverlay) {
      setTableLoading(false);
    }
    isInitialLoad = false;
  }
}

refreshButton.addEventListener('click', () => loadNodes({ userInitiated: true }));

loadNodes();
setInterval(() => loadNodes(), REFRESH_INTERVAL);
