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
const filterForm = document.getElementById('filters-form');
const filterSearch = document.getElementById('filter-search');
const filterPlatform = document.getElementById('filter-platform');
const filterPlatformVersion = document.getElementById('filter-platform-version');
const filterStatus = document.getElementById('filter-status');
const addNodeForm = document.getElementById('add-node-form');
const addNodeSubmit = document.getElementById('add-node-submit');
const dismissTargets = detailsModal
  ? Array.from(detailsModal.querySelectorAll('[data-dismiss]'))
  : [];
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

let lastFocusedTrigger = null;
let isInitialLoad = true;
let allNodes = [];

const REFRESH_INTERVAL = 15000;

const STATUS_PRIORITY = ['busy', 'offline', 'online'];
const API_BASE_URL = 'http://10.160.24.110:8080';

function normaliseText(value) {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim().toLowerCase();
}

function getNodeTags(node) {
  const tags = new Set();
  const push = (value) => {
    const normalised = normaliseText(value);
    if (normalised) {
      tags.add(normalised);
    }
  };

  push(node.id);
  push(node.type);
  push(node.platform);
  push(node.platform_version);
  push(node.device_name);
  push(node.udid);

  const resources = node.resources;
  if (resources && typeof resources === 'object') {
    const resourceTags = Array.isArray(resources.tags) ? resources.tags : [];
    resourceTags.forEach(push);

    if (resources.session_data && typeof resources.session_data === 'object') {
      Object.values(resources.session_data).forEach(push);
    }
  }

  return tags;
}

function fetchOptions(method = 'GET', payload) {
  const options = { method, headers: { Accept: 'application/json' } };
  if (payload !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  return options;
}

async function fetchJson(endpoint, options) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
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

function filtersAreActive() {
  const search = normaliseText(filterSearch?.value || '');
  const platform = normaliseText(filterPlatform?.value || '');
  const platformVersion = normaliseText(filterPlatformVersion?.value || '');
  const status = normaliseText(filterStatus?.value || '');
  return Boolean(search || platform || platformVersion || status);
}

function applyFilters(nodes) {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    return [];
  }

  const search = normaliseText(filterSearch?.value || '');
  const platformFilter = normaliseText(filterPlatform?.value || '');
  const platformVersionFilter = normaliseText(filterPlatformVersion?.value || '');
  const statusFilter = normaliseText(filterStatus?.value || '');

  return nodes.filter((node) => {
    const status = deriveStatus(node);

    if (statusFilter && status !== statusFilter) {
      return false;
    }

    if (platformFilter) {
      const tags = getNodeTags(node);
      const matchesPlatform = Array.from(tags).some((tag) => {
        if (tag === platformFilter) {
          return true;
        }
        if (platformFilter === 'android-emulator') {
          return tag.includes('emulator') || tag.includes('simulator');
        }
        return tag.includes(platformFilter);
      });

      if (!matchesPlatform) {
        return false;
      }
    }

    if (platformVersionFilter) {
      const version = normaliseText(node.platform_version || '');
      if (!version.includes(platformVersionFilter)) {
        return false;
      }
    }

    if (search) {
      const fields = [
        node.id,
        node.device_name,
        node.host,
        node.udid,
        node.platform,
        node.platform_version,
      ];
      const matchesSearch = fields.some((field) => normaliseText(field).includes(search));

      if (!matchesSearch) {
        const tags = getNodeTags(node);
        if (!Array.from(tags).some((tag) => tag.includes(search))) {
          return false;
        }
      }
    }

    return true;
  });
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

function handleFiltersChange() {
  const filteredNodes = applyFilters(allNodes);
  renderRows(filteredNodes);
  updateSummary(allNodes, filteredNodes);
}

async function handleDeleteNode(node, button) {
  if (!node || !node.id) {
    return;
  }

  const confirmation = window.confirm(
    `Are you sure you want to delete the node "${node.id}"? This action cannot be undone.`
  );

  if (!confirmation) {
    return;
  }

  if (button) {
    button.disabled = true;
    button.textContent = 'Deleting…';
  }

  try {
    const response = await fetch(`${API_BASE_URL}/unregister/${encodeURIComponent(node.id)}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      const message = errorPayload.detail || 'Failed to delete node';
      throw new Error(message);
    }
    showToast(`Node ${node.id} deleted`);
    await loadNodes({ userInitiated: true });
  } catch (error) {
    console.error('Failed to delete node', error);
    showToast(error.message || 'Failed to delete node');
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = 'Delete';
    }
  }
}

async function handleAddNode(event) {
  event.preventDefault();

  if (!addNodeForm) {
    return;
  }

  const formData = new FormData(addNodeForm);
  const payload = {};

  for (const [key, rawValue] of formData.entries()) {
    if (rawValue == null) {
      continue;
    }
    const value = typeof rawValue === 'string' ? rawValue.trim() : rawValue;
    if (value === '') {
      continue;
    }

    if (key === 'resources') {
      try {
        payload[key] = JSON.parse(value);
      } catch (error) {
        console.warn('Invalid resources JSON', error);
        showToast('Resources must be valid JSON.');
        return;
      }
      continue;
    }

    if (['max_sessions', 'active_sessions', 'port'].includes(key)) {
      const numericValue = Number(value);
      if (!Number.isFinite(numericValue)) {
        showToast(`${key.replace('_', ' ')} must be a valid number.`);
        return;
      }
      payload[key] = numericValue;
      continue;
    }

    payload[key] = value;
  }

  if (addNodeSubmit) {
    addNodeSubmit.disabled = true;
    addNodeSubmit.dataset.originalLabel = addNodeSubmit.textContent;
    addNodeSubmit.textContent = 'Registering…';
  }

  try {
    const response = await fetch(`${API_BASE_URL}/register`, fetchOptions('POST', payload));
    if (!response.ok) {
      const errorPayload = await response.json().catch(() => ({}));
      const message = errorPayload.detail || 'Failed to register node';
      throw new Error(message);
    }
    showToast('Node registered successfully');
    addNodeForm.reset();
    await loadNodes({ userInitiated: true });
  } catch (error) {
    console.error('Failed to register node', error);
    showToast(error.message || 'Failed to register node');
  } finally {
    if (addNodeSubmit) {
      addNodeSubmit.disabled = false;
      addNodeSubmit.textContent = addNodeSubmit.dataset.originalLabel || 'Register node';
      delete addNodeSubmit.dataset.originalLabel;
    }
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
    const emptyMessage = filtersAreActive()
      ? 'No nodes match the selected filters.'
      : 'No nodes registered yet.';
    tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">${emptyMessage}</td></tr>`;
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
      <td class="actions-column__cell">
        <div class="actions-stack">
          <button class="action-button" data-show="${node.id}">Show details</button>
          <button class="danger-button" data-delete="${node.id}">Delete</button>
        </div>
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

    const deleteButton = tr.querySelector('button[data-delete]');
    if (deleteButton) {
      deleteButton.addEventListener('click', () => handleDeleteNode(node, deleteButton));
    }
    tableBody.appendChild(tr);
  }
}

function updateSummary(allNodesList, visibleNodesList = allNodesList) {
  const counts = visibleNodesList.reduce(
    (acc, node) => {
      const status = deriveStatus(node);
      acc[status] = (acc[status] || 0) + 1;
      return acc;
    },
    { online: 0, offline: 0, busy: 0 }
  );

  summaryTotal.textContent = visibleNodesList.length;
  summaryTotal.dataset.total = String(allNodesList.length);
  if (visibleNodesList.length !== allNodesList.length) {
    summaryTotal.setAttribute(
      'title',
      `Showing ${visibleNodesList.length} of ${allNodesList.length} total nodes`
    );
  } else {
    summaryTotal.removeAttribute('title');
  }

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
    allNodes = Object.values(nodeMap);
    const filtered = applyFilters(allNodes);
    renderRows(filtered);
    updateSummary(allNodes, filtered);
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

if (filterForm) {
  filterForm.addEventListener('input', handleFiltersChange);
  filterForm.addEventListener('change', handleFiltersChange);
}

if (addNodeForm) {
  addNodeForm.addEventListener('submit', handleAddNode);
}

refreshButton.addEventListener('click', () => loadNodes({ userInitiated: true }));

loadNodes();
setInterval(() => loadNodes(), REFRESH_INTERVAL);
