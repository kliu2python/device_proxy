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
const adminSection = document.getElementById('admin-section');
const adminLoginForm = document.getElementById('admin-login-form');
const adminUsernameInput = document.getElementById('admin-username');
const adminPasswordInput = document.getElementById('admin-password');
const adminLoginFeedback = document.getElementById('admin-login-feedback');
const adminLoginSubmit = document.getElementById('admin-login-submit');
const adminLoginCard = document.getElementById('admin-login-card');
const adminToolsCard = document.getElementById('admin-tools-card');
const adminLockButton = document.getElementById('admin-lock-button');
const dismissTargets = detailsModal
  ? Array.from(detailsModal.querySelectorAll('[data-dismiss]'))
  : [];
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

let lastFocusedTrigger = null;
let isInitialLoad = true;
let allNodes = [];
let adminToken = '';
let isAdminUnlocked = false;

const REFRESH_INTERVAL = 15000;

const STATUS_PRIORITY = ['busy', 'offline', 'online'];
const API_BASE_URL = 'http://10.160.24.110:8080';
const ADMIN_TOKEN_STORAGE_KEY = 'deviceProxyAdminToken';
const normalisedPathname = window.location.pathname.replace(/\/+$/, '') || '/';
const isAdminRoute = normalisedPathname === '/admin';

if (!isAdminRoute && adminSection) {
  adminSection.hidden = true;
}

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

function getStoredAdminToken() {
  try {
    return window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) || '';
  } catch (error) {
    console.warn('Unable to access localStorage for admin token', error);
    return '';
  }
}

function storeAdminToken(token) {
  try {
    window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
  } catch (error) {
    console.warn('Unable to persist admin token', error);
  }
}

function clearStoredAdminToken() {
  try {
    window.localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
  } catch (error) {
    console.warn('Unable to clear stored admin token', error);
  }
}

function showAdminLoginFeedback(message, state = 'info') {
  if (!adminLoginFeedback) {
    return;
  }
  adminLoginFeedback.textContent = message;
  adminLoginFeedback.dataset.state = state;
}

function refreshAdminDependentUi() {
  if (!tableBody) {
    return;
  }

  const filtered = applyFilters(allNodes);
  renderRows(filtered);
}

function lockAdminTools({ notify = false, message, state = 'info' } = {}) {
  isAdminUnlocked = false;
  const previousToken = adminToken;
  adminToken = '';
  clearStoredAdminToken();

  if (previousToken) {
    fetch(`${API_BASE_URL}/admin/logout`, fetchOptions('POST', { token: previousToken })).catch(
      (error) => {
        console.warn('Failed to revoke admin session', error);
      }
    );
  }

  refreshAdminDependentUi();

  if (!isAdminRoute) {
    if (adminSection) {
      adminSection.hidden = true;
    }
    return;
  }

  if (adminToolsCard) {
    adminToolsCard.hidden = true;
  }
  if (adminLoginCard) {
    adminLoginCard.hidden = false;
  }

  if (adminUsernameInput) {
    adminUsernameInput.value = '';
  }
  if (adminPasswordInput) {
    adminPasswordInput.value = '';
  }

  if (message) {
    showAdminLoginFeedback(message, state);
  } else if (adminLoginFeedback) {
    adminLoginFeedback.textContent = '';
    delete adminLoginFeedback.dataset.state;
  }

  if (notify) {
    showToast('Admin access required to manage nodes.');
  }
}

function unlockAdminTools(token, { notify = true } = {}) {
  isAdminUnlocked = true;
  adminToken = token;
  storeAdminToken(token);

  refreshAdminDependentUi();

  if (!isAdminRoute) {
    return;
  }

  if (adminToolsCard) {
    adminToolsCard.hidden = false;
  }
  if (adminLoginCard) {
    adminLoginCard.hidden = true;
  }

  if (adminSection) {
    adminSection.hidden = false;
  }

  if (adminUsernameInput) {
    adminUsernameInput.value = '';
  }
  if (adminPasswordInput) {
    adminPasswordInput.value = '';
  }

  if (adminLoginFeedback) {
    adminLoginFeedback.textContent = '';
    delete adminLoginFeedback.dataset.state;
  }

  if (notify) {
    showToast('Admin tools unlocked.');
  }
}

function ensureAdminAccess({ focus = true } = {}) {
  if (isAdminUnlocked && adminToken) {
    return true;
  }

  if (!isAdminRoute) {
    if (focus) {
      showToast('Admin tools are available from the /admin page.');
    }
    return false;
  }

  if (focus && adminLoginCard) {
    adminLoginCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (adminUsernameInput) {
      adminUsernameInput.focus();
    } else if (adminPasswordInput) {
      adminPasswordInput.focus();
    }
  }
  if (!focus) {
    return false;
  }
  showToast('Admin access required. Please unlock the admin tools.');
  return false;
}

function fetchOptions(method = 'GET', payload, { requireAdmin = false, adminTokenOverride } = {}) {
  const options = { method, headers: { Accept: 'application/json' } };
  if (payload !== undefined) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }

  if (requireAdmin) {
    const token = adminTokenOverride ?? adminToken;
    if (token) {
      options.headers['X-Admin-Token'] = token;
    }
  }

  return options;
}

async function fetchJson(endpoint, options) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
  if (!response.ok) {
    let message = `Request failed: ${response.status}`;
    let payload = null;
    try {
      payload = await response.json();
      if (payload && typeof payload === 'object' && payload.detail) {
        message = payload.detail;
      }
    } catch (error) {
      // Ignore JSON parsing errors for unsuccessful responses
    }
    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  if (response.status === 204) {
    return null;
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

  if (!ensureAdminAccess()) {
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
    await fetchJson(
      `/unregister/${encodeURIComponent(node.id)}`,
      fetchOptions('DELETE', undefined, { requireAdmin: true })
    );
    showToast(`Node ${node.id} deleted`);
    await loadNodes({ userInitiated: true });
  } catch (error) {
    console.error('Failed to delete node', error);
    if (error.status === 403) {
      lockAdminTools({
        notify: true,
        message: 'Your admin session has expired. Please sign in again.',
        state: 'error',
      });
    } else {
      showToast(error.message || 'Failed to delete node');
    }
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

  if (!ensureAdminAccess()) {
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
    await fetchJson('/register', fetchOptions('POST', payload, { requireAdmin: true }));
    showToast('Node registered successfully');
    addNodeForm.reset();
    await loadNodes({ userInitiated: true });
  } catch (error) {
    console.error('Failed to register node', error);
    if (error.status === 403) {
      lockAdminTools({
        notify: true,
        message: 'Your admin session has expired. Please sign in again.',
        state: 'error',
      });
    } else {
      showToast(error.message || 'Failed to register node');
    }
  } finally {
    if (addNodeSubmit) {
      addNodeSubmit.disabled = false;
      addNodeSubmit.textContent = addNodeSubmit.dataset.originalLabel || 'Register node';
      delete addNodeSubmit.dataset.originalLabel;
    }
  }
}

async function verifyAdminToken(token) {
  try {
    await fetchJson('/admin/ping', fetchOptions('GET', undefined, { requireAdmin: true, adminTokenOverride: token }));
    return true;
  } catch (error) {
    if (error.status === 403) {
      return false;
    }
    throw error;
  }
}

async function initialiseAdminAccess() {
  if (!isAdminRoute) {
    lockAdminTools();
    return;
  }

  const storedToken = getStoredAdminToken();
  if (!storedToken) {
    lockAdminTools();
    return;
  }

  showAdminLoginFeedback('Validating saved admin session…', 'info');

  try {
    const isValid = await verifyAdminToken(storedToken);
    if (isValid) {
      unlockAdminTools(storedToken, { notify: false });
    } else {
      lockAdminTools({ message: 'Saved session is no longer valid. Please sign in again.', state: 'error' });
    }
  } catch (error) {
    console.error('Failed to validate stored admin session', error);
    lockAdminTools({ state: 'error', message: 'Unable to validate admin session. Please try again.' });
  }
}

async function handleAdminLogin(event) {
  event.preventDefault();

  if (!isAdminRoute) {
    showToast('Admin login is only available from /admin.');
    return;
  }

  if (!adminLoginForm || !adminLoginSubmit) {
    return;
  }

  const username = adminUsernameInput?.value.trim() || '';
  if (!username) {
    showAdminLoginFeedback('Please enter the admin username.', 'error');
    adminUsernameInput?.focus();
    return;
  }

  const password = adminPasswordInput?.value || '';
  if (!password) {
    showAdminLoginFeedback('Please enter the admin password.', 'error');
    adminPasswordInput?.focus();
    return;
  }

  adminLoginSubmit.disabled = true;
  adminLoginSubmit.dataset.originalLabel = adminLoginSubmit.textContent;
  adminLoginSubmit.textContent = 'Signing in…';

  try {
    const response = await fetchJson('/admin/login', fetchOptions('POST', { username, password }));
    const token = response?.token;
    if (!token) {
      throw new Error('Admin session token was not returned.');
    }

    unlockAdminTools(token);
    await loadNodes({ userInitiated: true });
  } catch (error) {
    console.error('Failed to sign in as admin', error);
    if (error.status === 403) {
      showAdminLoginFeedback('Invalid username or password. Please try again.', 'error');
    } else {
      showAdminLoginFeedback(error.message || 'Unable to sign in. Please try again.', 'error');
    }
  } finally {
    if (adminLoginSubmit) {
      adminLoginSubmit.disabled = false;
      adminLoginSubmit.textContent = adminLoginSubmit.dataset.originalLabel || 'Sign in';
      delete adminLoginSubmit.dataset.originalLabel;
    }

    if (adminPasswordInput) {
      adminPasswordInput.value = '';
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

    const actions = [
      `<button class="action-button" data-show="${node.id}">Show details</button>`,
    ];

    if (isAdminUnlocked && adminToken) {
      actions.push(`<button class="danger-button" data-delete="${node.id}">Delete</button>`);
    }

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
          ${actions.join('\n          ')}
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

if (adminLoginForm) {
  adminLoginForm.addEventListener('submit', handleAdminLogin);
}

if (adminLockButton) {
  adminLockButton.addEventListener('click', () => {
    lockAdminTools({
      notify: true,
      message: 'Admin access locked. Enter your credentials to continue.',
      state: 'info',
    });
  });
}

refreshButton.addEventListener('click', () => loadNodes({ userInitiated: true }));

initialiseAdminAccess();
loadNodes();
setInterval(() => loadNodes(), REFRESH_INTERVAL);
