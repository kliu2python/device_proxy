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
const detailsActions = document.getElementById('details-modal-actions');
const detailsOpenStfButton = document.getElementById('details-open-stf');
const stfSessionContainer = document.getElementById('stf-session-container');
const stfSessionMessage = document.getElementById('stf-session-message');
const stfSessionFrame = document.getElementById('stf-session-frame');
const stfSessionCloseButton = document.getElementById('stf-session-close');
const filterForm = document.getElementById('filters-form');
const filterSearch = document.getElementById('filter-search');
const filterPlatform = document.getElementById('filter-platform');
const filterPlatformVersion = document.getElementById('filter-platform-version');
const filterStatus = document.getElementById('filter-status');
const filtersToggle = document.getElementById('filters-toggle');
const filtersMenu = document.getElementById('filters-menu');
const filtersReset = document.getElementById('filters-reset');
const filtersDropdown = document.querySelector('.filters-dropdown');
const paginationContainer = document.getElementById('pagination');
const paginationLabel = document.getElementById('pagination-label');
const paginationPrev = document.getElementById('pagination-prev');
const paginationNext = document.getElementById('pagination-next');
const addNodeForm = document.getElementById('add-node-form');
const addNodeSubmit = document.getElementById('add-node-submit');
const cancelEditButton = document.getElementById('cancel-edit-button');
const editModeHint = document.getElementById('edit-mode-hint');
const editModeNodeLabel = document.getElementById('edit-mode-node-label');
const ADD_NODE_SUBMIT_DEFAULT_LABEL = addNodeSubmit
  ? addNodeSubmit.textContent || 'Register node'
  : 'Register node';
const NODE_FORM_FIELD_NAMES = [
  'id',
  'type',
  'udid',
  'host',
  'port',
  'protocol',
  'path',
  'max_sessions',
  'active_sessions',
  'status',
  'platform',
  'platform_version',
  'device_name',
  'resources',
];
const adminToolsTrigger = document.getElementById('admin-tools-trigger');
const adminLoginForm = document.getElementById('admin-login-form');
const adminUsernameInput = document.getElementById('admin-username');
const adminPasswordInput = document.getElementById('admin-password');
const adminLoginFeedback = document.getElementById('admin-login-feedback');
const adminLoginSubmit = document.getElementById('admin-login-submit');
const adminLockButton = document.getElementById('admin-lock-button');
const adminLogoutButton = document.getElementById('admin-logout-button');
const adminModal = document.getElementById('admin-modal');
const adminLoginPanel = document.getElementById('admin-login-panel');
const adminToolsPanel = document.getElementById('admin-tools-panel');
const adminModalTitle = document.getElementById('admin-modal-title');
const detailsDismissTargets = detailsModal
  ? Array.from(detailsModal.querySelectorAll('[data-dismiss]'))
  : [];
const adminModalDismissTargets = adminModal
  ? Array.from(adminModal.querySelectorAll('[data-dismiss]'))
  : [];
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

let lastFocusedTrigger = null;
let lastAdminModalTrigger = null;
let isInitialLoad = true;
let allNodes = [];
let filteredNodes = [];
let currentPage = 1;
let adminToken = '';
let isAdminUnlocked = false;
let isFiltersMenuOpen = false;
let editingNodeId = '';
let detailsModalNode = null;
let activeStfSession = null;

const REFRESH_INTERVAL = 15000;
const PAGE_SIZE = 5;

const STATUS_PRIORITY = ['busy', 'offline', 'online'];
const DEFAULT_API_PORT = 8090;
const STREAM_BASE_URL = 'http://10.160.13.110:8099/stream';

function buildStreamEmbedBaseUrl() {
  if (typeof window !== 'undefined' && window.location && window.location.origin) {
    return `${window.location.origin.replace(/\/$/, '')}/stream/embed`;
  }
  return '/stream/embed';
}

function buildStreamEmbedUrl(node, streamUrl) {
  const resolvedStreamUrl = typeof streamUrl === 'string' && streamUrl.trim()
    ? streamUrl.trim()
    : deriveStreamUrl(node);

  if (!resolvedStreamUrl) {
    return null;
  }

  const params = new URLSearchParams();
  params.set('src', resolvedStreamUrl);

  if (node) {
    const displayName = formatNodeDisplayName(node);
    if (displayName) {
      params.set('label', displayName);
    }

    const udid = node?.udid ? String(node.udid).trim() : '';
    if (udid) {
      params.set('subtitle', `UDID: ${udid}`);
    }
  }

  return `${buildStreamEmbedBaseUrl()}?${params.toString()}`;
}

function deriveApiBaseUrl() {
  const overrides = [];

  if (typeof window !== 'undefined') {
    if (typeof window.API_BASE_URL === 'string') {
      overrides.push(window.API_BASE_URL);
    }

    if (window.appConfig && typeof window.appConfig.apiBaseUrl === 'string') {
      overrides.push(window.appConfig.apiBaseUrl);
    }
  }

  if (document && document.body) {
    const dataAttribute = document.body.getAttribute('data-api-base-url');
    if (typeof dataAttribute === 'string') {
      overrides.push(dataAttribute);
    }
  }

  for (const candidate of overrides) {
    const trimmed = typeof candidate === 'string' ? candidate.trim() : '';
    if (trimmed) {
      return trimmed.replace(/\/+$/, '');
    }
  }

  const protocol =
    typeof window !== 'undefined' && typeof window.location?.protocol === 'string'
      ? window.location.protocol
      : 'http:';
  const isHttpProtocol = protocol.startsWith('http');
  const safeProtocol = isHttpProtocol ? protocol : 'http:';

  let hostname =
    typeof window !== 'undefined' && typeof window.location?.hostname === 'string'
      ? window.location.hostname
      : '';

  if (!hostname) {
    hostname = '127.0.0.1';
  }

  return `${safeProtocol}//${hostname}:${DEFAULT_API_PORT}`;
}

const API_BASE_URL = deriveApiBaseUrl();
const ADMIN_TOKEN_STORAGE_KEY = 'deviceProxyAdminToken';
const normalisedPathname = window.location.pathname.replace(/\/+$/, '') || '/';
const isAdminRoute = normalisedPathname === '/admin';

const STOP_USING_MESSAGE_TYPE = 'device-proxy:stop-using';
const STOP_USING_DELAY_MS = 150;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, Number(ms) || 0)));
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

function getNodeStfConfig(node) {
  if (!node || typeof node !== 'object') {
    return null;
  }

  const resources = node.resources;
  if (!resources || typeof resources !== 'object') {
    return null;
  }

  const stfConfig = resources.stf;
  if (!stfConfig || typeof stfConfig !== 'object') {
    return null;
  }

  return stfConfig;
}

function nodeSupportsStf(node) {
  if (!node || typeof node !== 'object') {
    return false;
  }

  if (typeof node.stf_enabled === 'boolean') {
    return node.stf_enabled;
  }

  const stfConfig = getNodeStfConfig(node);
  if (!stfConfig) {
    return false;
  }

  if (typeof stfConfig.enabled === 'boolean' && !stfConfig.enabled) {
    return false;
  }

  return true;
}

function deriveStreamPlatformSegment(node) {
  if (!node || typeof node !== 'object') {
    return null;
  }

  const tags = Array.from(getNodeTags(node));

  const iosMatch = tags.find((tag) =>
    tag.includes('ios') || tag.includes('iphone') || tag.includes('ipad')
  );
  if (iosMatch) {
    return 'ios';
  }

  const androidMatch = tags.find((tag) => tag.includes('android'));
  if (androidMatch) {
    return 'android';
  }

  const platform = normaliseText(node.platform || '');
  if (platform.includes('ios') || platform.includes('iphone') || platform.includes('ipad')) {
    return 'ios';
  }
  if (platform.includes('android')) {
    return 'android';
  }

  const type = normaliseText(node.type || '');
  if (type.includes('ios') || type.includes('iphone') || type.includes('ipad')) {
    return 'ios';
  }
  if (type.includes('android')) {
    return 'android';
  }

  return null;
}

function deriveStreamUrl(node) {
  if (!node || typeof node !== 'object') {
    return null;
  }

  const udid = typeof node.udid === 'string' ? node.udid.trim() : '';
  if (!udid) {
    return null;
  }

  const platformSegment = deriveStreamPlatformSegment(node);
  if (!platformSegment) {
    return null;
  }

  return `${STREAM_BASE_URL}/${platformSegment}/${encodeURIComponent(udid)}`;
}

function openStreamWindow(node) {
  if (!node || typeof node !== 'object') {
    showToast('Select a node before opening the stream.');
    return;
  }

  const streamUrl = deriveStreamUrl(node);
  if (!streamUrl) {
    showToast('Stream is not available for this device.');
    return;
  }

  if (deriveStatus(node) !== 'online') {
    showToast('Stream is only available when the node is online.');
    return;
  }

  const embedUrl = buildStreamEmbedUrl(node, streamUrl) || streamUrl;
  const popup = window.open(embedUrl, '_blank', 'noopener,noreferrer,width=480,height=900');

  if (popup) {
    if (typeof popup.focus === 'function') {
      popup.focus();
    }
    return;
  }

  showToast('Unable to open stream window. Allow pop-ups and try again.');
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

function getNodeFormField(name) {
  if (!addNodeForm || !addNodeForm.elements) {
    return null;
  }
  return addNodeForm.elements.namedItem(name);
}

function populateNodeFormFields(node) {
  if (!addNodeForm) {
    return;
  }

  NODE_FORM_FIELD_NAMES.forEach((fieldName) => {
    const field = getNodeFormField(fieldName);
    if (!field) {
      return;
    }

    let value = '';

    if (fieldName === 'resources') {
      const resources = node?.resources;
      if (!resources) {
        value = '';
      } else if (typeof resources === 'string') {
        value = resources;
      } else {
        try {
          value = JSON.stringify(resources, null, 2);
        } catch (error) {
          console.warn('Failed to serialise resources for editing', error);
          value = '';
        }
      }
    } else {
      const rawValue = node?.[fieldName];
      if (rawValue == null) {
        value = '';
      } else if (typeof rawValue === 'number') {
        value = String(rawValue);
      } else {
        value = String(rawValue);
      }
    }

    if (fieldName === 'status' && !value) {
      value = 'online';
    }

    if (
      field instanceof HTMLInputElement ||
      field instanceof HTMLSelectElement ||
      field instanceof HTMLTextAreaElement
    ) {
      field.value = value;
    }
  });
}

function clearEditMode({ resetForm = true } = {}) {
  editingNodeId = '';

  if (!addNodeForm) {
    return;
  }

  if (resetForm) {
    addNodeForm.reset();
  }

  addNodeForm.dataset.mode = 'create';
  addNodeForm.removeAttribute('data-node-id');

  const idField = getNodeFormField('id');
  if (idField instanceof HTMLInputElement) {
    idField.removeAttribute('readonly');
    idField.removeAttribute('aria-readonly');
    idField.removeAttribute('title');
  }

  if (addNodeSubmit) {
    addNodeSubmit.textContent = ADD_NODE_SUBMIT_DEFAULT_LABEL;
    delete addNodeSubmit.dataset.originalLabel;
  }

  if (cancelEditButton) {
    cancelEditButton.hidden = true;
  }

  if (editModeHint) {
    editModeHint.hidden = true;
  }

  if (editModeNodeLabel) {
    editModeNodeLabel.textContent = '';
  }
}

function enterEditMode(node, { trigger } = {}) {
  if (!addNodeForm || !node || !node.id) {
    return;
  }

  addNodeForm.reset();
  populateNodeFormFields(node);

  editingNodeId = node.id;
  addNodeForm.dataset.mode = 'edit';
  addNodeForm.dataset.nodeId = node.id;

  const idField = getNodeFormField('id');
  if (idField instanceof HTMLInputElement) {
    idField.value = node.id;
    idField.setAttribute('readonly', 'true');
    idField.setAttribute('aria-readonly', 'true');
    idField.title = 'Node ID cannot be changed while editing.';
  }

  if (addNodeSubmit) {
    addNodeSubmit.textContent = 'Update node';
  }

  if (cancelEditButton) {
    cancelEditButton.hidden = false;
  }

  if (editModeHint && editModeNodeLabel) {
    editModeHint.hidden = false;
    editModeNodeLabel.textContent = node.id;
  }

  openAdminModal('tools', { trigger });
  showToast(`Editing node ${node.id}. Update the details and save when ready.`);
}

function setAdminModalView(view) {
  if (!adminModal) {
    return;
  }

  const resolvedView = view === 'tools' && isAdminUnlocked ? 'tools' : 'login';

  if (adminLoginPanel) {
    adminLoginPanel.hidden = resolvedView !== 'login';
  }
  if (adminToolsPanel) {
    adminToolsPanel.hidden = resolvedView !== 'tools';
  }
  if (adminModalTitle) {
    adminModalTitle.textContent =
      resolvedView === 'tools' ? 'Admin tools' : 'Admin sign in';
  }
}

function focusAdminModal(view) {
  if (!adminModal) {
    return;
  }

  const resolvedView = view === 'tools' && isAdminUnlocked ? 'tools' : 'login';

  if (resolvedView === 'login') {
    if (adminUsernameInput && !adminUsernameInput.disabled) {
      adminUsernameInput.focus();
      return;
    }
    if (adminPasswordInput && !adminPasswordInput.disabled) {
      adminPasswordInput.focus();
      return;
    }
    const loginButton = adminLoginForm?.querySelector('button:not([disabled])');
    loginButton?.focus();
    return;
  }

  const firstField = addNodeForm?.querySelector(
    'input:not([disabled]):not([readonly]), select:not([disabled]), textarea:not([disabled]):not([readonly])'
  );
  if (firstField && !firstField.disabled) {
    firstField.focus();
  }
}

function openAdminModal(view = isAdminUnlocked ? 'tools' : 'login', { trigger } = {}) {
  if (!adminModal) {
    return;
  }

  lastAdminModalTrigger = trigger || null;
  setAdminModalView(view);
  adminModal.classList.add('visible');
  adminModal.setAttribute('aria-hidden', 'false');
  window.requestAnimationFrame(() => focusAdminModal(view));
}

function closeAdminModal({ restoreFocus = true } = {}) {
  if (!adminModal) {
    return;
  }

  adminModal.classList.remove('visible');
  adminModal.setAttribute('aria-hidden', 'true');

  if (restoreFocus && lastAdminModalTrigger && typeof lastAdminModalTrigger.focus === 'function') {
    if (lastAdminModalTrigger.isConnected) {
      lastAdminModalTrigger.focus();
    }
  }
  lastAdminModalTrigger = null;
}

function refreshAdminDependentUi() {
  updateAdminControlsVisibility();

  if (!tableBody) {
    return;
  }

  refreshNodeViews();
}

function updateAdminControlsVisibility() {
  if (!adminLogoutButton) {
    return;
  }

  const shouldShow = isAdminUnlocked && Boolean(adminToken);
  adminLogoutButton.hidden = !shouldShow;
}

function lockAdminTools({
  notify = false,
  message,
  state = 'info',
  revokeSession = true,
  focusLogin = isAdminRoute,
} = {}) {
  isAdminUnlocked = false;
  const previousToken = adminToken;
  adminToken = '';
  clearStoredAdminToken();
  clearEditMode();

  if (previousToken && revokeSession) {
    fetch(`${API_BASE_URL}/admin/logout`, fetchOptions('POST', { token: previousToken })).catch(
      (error) => {
        console.warn('Failed to revoke admin session', error);
      }
    );
  }

  refreshAdminDependentUi();

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

  if (adminModal) {
    setAdminModalView('login');
    if (isAdminRoute && focusLogin) {
      openAdminModal('login');
    } else if (!isAdminRoute) {
      closeAdminModal({ restoreFocus: false });
    }
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

  if (adminModal) {
    const wasModalOpen = adminModal.classList.contains('visible');
    setAdminModalView('tools');
    if (!wasModalOpen) {
      closeAdminModal({ restoreFocus: false });
    } else {
      window.requestAnimationFrame(() => focusAdminModal('tools'));
    }
  }

  if (notify) {
    showToast('Admin tools unlocked. Use “Add node” to manage nodes.');
  }
}

function handleAdminLogout({ focusLogin = isAdminRoute, toast = 'Signed out of admin tools.' } = {}) {
  lockAdminTools({
    notify: false,
    message: 'Admin access locked. Enter your credentials to continue.',
    state: 'info',
    focusLogin,
  });

  if (toast) {
    showToast(toast);
  }
}

function ensureAdminAccess({ focus = true } = {}) {
  if (isAdminUnlocked && adminToken) {
    return true;
  }

  if (focus) {
    if (isAdminRoute) {
      openAdminModal('login');
      showToast('Admin access required. Please sign in to continue.');
    } else {
      showToast('Admin tools require signing in at /admin.');
    }
  }
  return false;
}

function handleEditNode(node, trigger) {
  if (!node || !node.id) {
    showToast('Unable to edit node without an identifier.');
    return;
  }

  if (!ensureAdminAccess()) {
    return;
  }

  enterEditMode(node, { trigger });
}

async function handleOpenInStf(node, trigger) {
  if (!node || !node.id) {
    showToast('Unable to open STF without a node identifier.');
    return;
  }

  if (!nodeSupportsStf(node)) {
    showToast('STF access is not available for this node.');
    return;
  }

  if (activeStfSession && activeStfSession.nodeId === node.id) {
    updateStfSessionUi(activeStfSession);
    showToast('This STF session is already active in this tab.');
    return;
  }

  if (activeStfSession && activeStfSession.nodeId !== node.id) {
    showToast('Close the active STF session before opening another device.');
    return;
  }

  const encodedId = encodeURIComponent(node.id);
  const originalLabel = trigger ? trigger.textContent : '';

  if (trigger) {
    trigger.disabled = true;
    trigger.textContent = 'Opening…';
  }

  let sessionActivated = false;

  try {
    const response = await fetchJson(
      `/nodes/${encodedId}/stf/session`,
      fetchOptions('POST', {})
    );

    let finalUrl = response.launch_url || '';
    const jwt = response.jwt;
    const queryParam = response.jwt_query_param;
    const responseJwt = typeof jwt === 'string' && jwt.trim() ? jwt.trim() : '';

    if (jwt && queryParam && typeof finalUrl === 'string') {
      try {
        const parsedUrl = new URL(finalUrl);
        parsedUrl.searchParams.set(queryParam, jwt);
        finalUrl = parsedUrl.toString();
      } catch (error) {
        const separator = finalUrl.includes('?') ? '&' : '?';
        finalUrl = `${finalUrl}${separator}${encodeURIComponent(queryParam)}=${encodeURIComponent(jwt)}`;
      }
    }

    if (!finalUrl) {
      throw new Error('The STF session did not include a launch URL.');
    }

    const stfConfig = getNodeStfConfig(node);
    const session = {
      nodeId: node.id,
      launchUrl: finalUrl,
      displayName: formatNodeDisplayName(node),
      endpoint: formatEndpoint(node),
      ttlSeconds: response.ttl_seconds,
      expiresAt: response.expires_at || null,
      jwt: responseJwt
        ? responseJwt
        : typeof stfConfig?.jwt === 'string' && stfConfig.jwt.trim()
        ? stfConfig.jwt.trim()
        : typeof stfConfig?.token === 'string' && stfConfig.token.trim()
        ? stfConfig.token.trim()
        : null,
      jwtQueryParam: typeof queryParam === 'string' && queryParam.trim() ? queryParam.trim() : '',
    };

    markNodeBusyLocally(node.id);
    setActiveStfSession(session);
    sessionActivated = true;

    let message = 'STF session ready. The device is displayed below.';
    const statusMessage = buildSessionStatusMessage(session);
    if (statusMessage) {
      message += ` ${statusMessage}`;
    }
    showToast(message.trim());
  } catch (error) {
    const message = error?.message || 'Failed to open device in STF.';
    showToast(message);
  } finally {
    if (!sessionActivated && trigger && trigger.isConnected) {
      trigger.disabled = false;
      trigger.textContent = originalLabel || 'Use';
    }

    let updatedNode = null;
    try {
      await loadNodes();
      updatedNode = allNodes.find((candidate) => candidate && candidate.id === node.id) || null;
    } catch (refreshError) {
      console.warn('Failed to refresh nodes after STF action', refreshError);
    }

    if (
      updatedNode &&
      detailsModal &&
      detailsModal.classList.contains('visible') &&
      detailsModalNode &&
      detailsModalNode.id === node.id
    ) {
      detailsModalNode = updatedNode;
      if (detailsBody) {
        detailsBody.textContent = serializeNode(updatedNode);
      }
      updateDetailsModalActions(updatedNode);
    }
  }
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

function formatNodeDisplayName(node) {
  if (!node || typeof node !== 'object') {
    return 'Unknown device';
  }
  if (node.device_name) {
    return node.device_name;
  }
  return node.id || 'Unknown device';
}

function buildSessionStatusMessage(session) {
  if (!session) {
    return '';
  }

  if (session.expiresAt) {
    try {
      const expiresAt = new Date(session.expiresAt);
      if (!Number.isNaN(expiresAt.valueOf())) {
        return `Reservation expires at ${expiresAt.toLocaleTimeString()}.`;
      }
    } catch (error) {
      // Ignore invalid timestamps
    }
  }

  if (typeof session.ttlSeconds === 'number' && Number.isFinite(session.ttlSeconds)) {
    return `Reservation lasts ${Math.round(session.ttlSeconds)} seconds.`;
  }

  return '';
}

function setStfSessionFrameSource(url) {
  if (!stfSessionFrame) {
    return;
  }

  const targetUrl = typeof url === 'string' ? url.trim() : '';

  if (!targetUrl) {
    clearStfSessionFrameSource();
    return;
  }

  if (stfSessionFrame.dataset.src === targetUrl) {
    return;
  }

  stfSessionFrame.dataset.src = targetUrl;
  stfSessionFrame.src = targetUrl;
}

function clearStfSessionFrameSource() {
  if (!stfSessionFrame) {
    return;
  }

  delete stfSessionFrame.dataset.src;
  try {
    stfSessionFrame.src = 'about:blank';
  } catch (error) {
    stfSessionFrame.removeAttribute('src');
  }
}

function updateStfSessionUi(session) {
  if (!stfSessionContainer) {
    return;
  }

  stfSessionContainer.hidden = false;
  if (session?.nodeId) {
    stfSessionContainer.dataset.nodeId = session.nodeId;
  } else {
    delete stfSessionContainer.dataset.nodeId;
  }

  const launchUrl = typeof session?.launchUrl === 'string' ? session.launchUrl.trim() : '';

  if (document?.body) {
    document.body.classList.add('stf-session-active');
  }

  setStfSessionFrameSource(launchUrl);

  if (stfSessionMessage) {
    const messageParts = [];
    if (session?.displayName) {
      messageParts.push(session.displayName);
    }

    const statusMessage = buildSessionStatusMessage(session);
    if (statusMessage) {
      messageParts.push(statusMessage);
    }

    if (launchUrl) {
      messageParts.push('The STF session is shown below.');
    } else {
      messageParts.push('An STF session is active.');
    }
    messageParts.push('Select "End session" when you are finished to release the device.');

    stfSessionMessage.textContent = messageParts.join(' ');
    stfSessionMessage.hidden = messageParts.length === 0;
  }

  if (stfSessionCloseButton) {
    stfSessionCloseButton.disabled = false;
    window.requestAnimationFrame(() => {
      if (typeof stfSessionCloseButton.focus === 'function') {
        stfSessionCloseButton.focus();
      }
    });
  }
}

function hideStfSessionUi() {
  if (stfSessionContainer) {
    stfSessionContainer.hidden = true;
    delete stfSessionContainer.dataset.nodeId;
  }

  if (stfSessionMessage) {
    stfSessionMessage.textContent = '';
    stfSessionMessage.hidden = true;
  }

  if (document?.body) {
    document.body.classList.remove('stf-session-active');
  }

  clearStfSessionFrameSource();
}

function sendStopUsingPostMessage(session) {
  if (!stfSessionFrame || !stfSessionFrame.contentWindow) {
    return;
  }

  try {
    stfSessionFrame.contentWindow.postMessage(
      {
        type: STOP_USING_MESSAGE_TYPE,
        nodeId: session?.nodeId ?? null,
      },
      '*'
    );
  } catch (error) {
    console.debug('Unable to send STF stop-using message', error);
  }
}

function normaliseStopUsingLabel(text) {
  if (typeof text !== 'string') {
    return '';
  }

  return text.replace(/\s+/g, ' ').trim().toLowerCase();
}

function findStopUsingButton(doc) {
  if (!doc || typeof doc.querySelector !== 'function') {
    return null;
  }

  const selectors = [
    '[ng-click="ctrl.stopUsing()"]',
    '[ng-click$="stopUsing()"]',
    '[data-action="stop-using"]',
    '[data-testid="stop-using"]',
    'button.stop-using',
    'button[data-stop-using]',
  ];

  for (const selector of selectors) {
    try {
      const element = doc.querySelector(selector);
      if (element) {
        return element;
      }
    } catch (error) {
      // Ignore selector errors and keep searching.
    }
  }

  const candidates = Array.from(doc.querySelectorAll('button, a, [role="button"]'));
  for (const candidate of candidates) {
    const label = normaliseStopUsingLabel(candidate?.textContent);
    if (label && (label === 'stop using' || label.startsWith('stop using '))) {
      return candidate;
    }
  }

  return null;
}

function triggerStopUsingInStf(session) {
  sendStopUsingPostMessage(session);

  if (!stfSessionFrame) {
    return false;
  }

  try {
    const frameWindow = stfSessionFrame.contentWindow;
    if (!frameWindow) {
      return false;
    }

    const frameDocument = frameWindow.document;
    const stopButton = findStopUsingButton(frameDocument);
    if (stopButton && typeof stopButton.click === 'function') {
      stopButton.click();
      return true;
    }
  } catch (error) {
    console.debug('Unable to access STF frame to trigger stop', error);
  }

  return false;
}

function setActiveStfSession(session) {
  activeStfSession = session || null;

  if (activeStfSession) {
    updateStfSessionUi(activeStfSession);
  } else {
    hideStfSessionUi();
  }

  refreshNodeViews();

  if (detailsModalNode) {
    const updatedNode = allNodes.find((candidate) => candidate && candidate.id === detailsModalNode.id);
    if (updatedNode) {
      detailsModalNode = updatedNode;
      if (detailsModal && detailsModal.classList.contains('visible') && detailsBody) {
        detailsBody.textContent = serializeNode(updatedNode);
      }
      updateDetailsModalActions(updatedNode);
    } else {
      detailsModalNode = null;
      updateDetailsModalActions(null);
    }
  } else {
    updateDetailsModalActions(null);
  }
}

function markNodeBusyLocally(nodeId) {
  if (!nodeId) {
    return;
  }

  const node = allNodes.find((candidate) => candidate && candidate.id === nodeId);
  if (!node) {
    return;
  }

  const maxSessions = Number(node.max_sessions ?? 1);
  if (Number.isFinite(maxSessions) && maxSessions > 0) {
    node.active_sessions = maxSessions;
  }
  node.status = 'busy';

  if (detailsModalNode && detailsModalNode.id === nodeId) {
    detailsModalNode = node;
    if (detailsModal && detailsModal.classList.contains('visible') && detailsBody) {
      detailsBody.textContent = serializeNode(node);
    }
  }
}

async function releaseStfReservation(nodeId, { keepalive = false } = {}) {
  if (!nodeId) {
    return;
  }

  const encodedId = encodeURIComponent(nodeId);
  const options = fetchOptions('DELETE');
  if (keepalive) {
    options.keepalive = true;
  }

  const response = await fetch(`${API_BASE_URL}/nodes/${encodedId}/stf/session`, options);
  if (!response.ok && response.status !== 404) {
    const error = new Error('Failed to release STF session.');
    error.status = response.status;
    throw error;
  }
}

async function closeActiveStfSession({ silent = false } = {}) {
  if (!activeStfSession) {
    return;
  }

  const session = activeStfSession;
  const stopTriggered = triggerStopUsingInStf(session);

  if (stopTriggered) {
    try {
      await delay(STOP_USING_DELAY_MS);
    } catch (error) {
      console.debug('Stop-using delay interrupted', error);
    }
  }

  setActiveStfSession(null);

  let releaseFailed = false;

  try {
    await releaseStfReservation(session.nodeId);
    if (!silent) {
      showToast('STF session closed. Device released.');
    }
  } catch (error) {
    releaseFailed = true;
    console.error('Failed to release STF session', error);
    if (!silent) {
      const message = error?.message || 'Failed to release STF session. Please try again.';
      showToast(message);
    }
  }

  if (releaseFailed) {
    setActiveStfSession(session);
    return;
  }

  try {
    await loadNodes();
  } catch (refreshError) {
    console.warn('Failed to refresh nodes after closing STF session', refreshError);
  }
}

function sendStfReleaseKeepalive(nodeId) {
  if (!nodeId) {
    return;
  }

  try {
    const encodedId = encodeURIComponent(nodeId);
    const options = fetchOptions('DELETE');
    options.keepalive = true;
    fetch(`${API_BASE_URL}/nodes/${encodedId}/stf/session`, options).catch((error) => {
      console.warn('Failed to send STF release keepalive', error);
    });
  } catch (error) {
    console.warn('Failed to prepare STF release keepalive', error);
  }
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

function setFiltersMenuOpen(open) {
  if (!filtersToggle || !filtersMenu) {
    return;
  }

  isFiltersMenuOpen = Boolean(open);
  filtersToggle.setAttribute('aria-expanded', String(isFiltersMenuOpen));
  filtersMenu.hidden = !isFiltersMenuOpen;
}

function toggleFiltersMenu() {
  setFiltersMenuOpen(!isFiltersMenuOpen);
}

function handleFiltersMenuDocumentClick(event) {
  if (!isFiltersMenuOpen) {
    return;
  }

  if (filtersDropdown?.contains(event.target)) {
    return;
  }

  setFiltersMenuOpen(false);
}

function handleFiltersMenuKeydown(event) {
  if (event.key !== 'Escape' || !isFiltersMenuOpen) {
    return;
  }

  event.preventDefault();
  setFiltersMenuOpen(false);
  filtersToggle?.focus();
}

function resetFilters() {
  if (!filterForm) {
    return;
  }

  filterForm.reset();
  handleFiltersChange();
  setFiltersMenuOpen(false);
}

function filtersAreActive() {
  const search = normaliseText(filterSearch?.value || '');
  const platform = normaliseText(filterPlatform?.value || '');
  const platformVersion = normaliseText(filterPlatformVersion?.value || '');
  const status = normaliseText(filterStatus?.value || '');
  return Boolean(search || platform || platformVersion || status);
}

function updateFiltersToggleState() {
  if (!filtersToggle) {
    return;
  }

  filtersToggle.classList.toggle('button--active', filtersAreActive());
}

function refreshNodeViews({ resetPage = false } = {}) {
  if (resetPage) {
    currentPage = 1;
  }

  filteredNodes = applyFilters(allNodes);
  renderRows(filteredNodes);
  updateSummary(allNodes, filteredNodes);
  updateFiltersToggleState();

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

function updatePaginationControls({ totalItems, totalPages }) {
  if (!paginationContainer) {
    return;
  }

  const resolvedTotalPages = Math.max(1, totalPages || 1);
  const resolvedCurrentPage = Math.min(Math.max(currentPage, 1), resolvedTotalPages);
  const shouldHide = totalItems <= PAGE_SIZE;

  paginationContainer.hidden = shouldHide;

  if (paginationLabel) {
    paginationLabel.textContent = `Page ${resolvedCurrentPage} of ${resolvedTotalPages}`;
  }

  if (paginationPrev) {
    paginationPrev.disabled = shouldHide || resolvedCurrentPage <= 1;
  }

  if (paginationNext) {
    paginationNext.disabled = shouldHide || resolvedCurrentPage >= resolvedTotalPages;
  }
}

function goToPage(page) {
  if (!Array.isArray(filteredNodes) || filteredNodes.length === 0) {
    return;
  }

  const totalPages = Math.max(1, Math.ceil(filteredNodes.length / PAGE_SIZE));
  const targetPage = Math.min(Math.max(page, 1), totalPages);

  if (targetPage === currentPage) {
    return;
  }

  currentPage = targetPage;
  renderRows(filteredNodes);
}

function handleFiltersChange() {
  refreshNodeViews({ resetPage: true });
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
    if (editingNodeId === node.id) {
      clearEditMode();
    }
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
  const isEditing = addNodeForm.dataset.mode === 'edit' && Boolean(editingNodeId);
  const submitInProgressLabel = isEditing ? 'Updating…' : 'Registering…';

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

  if (isEditing) {
    payload.id = editingNodeId;
  }

  if (addNodeSubmit) {
    addNodeSubmit.disabled = true;
    addNodeSubmit.dataset.originalLabel = addNodeSubmit.textContent;
    addNodeSubmit.textContent = submitInProgressLabel;
  }

  try {
    await fetchJson('/register', fetchOptions('POST', payload, { requireAdmin: true }));
    if (isEditing) {
      showToast(`Node ${editingNodeId} updated successfully`);
      clearEditMode();
    } else {
      showToast('Node registered successfully');
      addNodeForm.reset();
    }
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
      if (addNodeSubmit.dataset.originalLabel) {
        addNodeSubmit.textContent = addNodeSubmit.dataset.originalLabel;
        delete addNodeSubmit.dataset.originalLabel;
      } else {
        addNodeSubmit.textContent = ADD_NODE_SUBMIT_DEFAULT_LABEL;
      }
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
  const storedToken = getStoredAdminToken();

  if (!storedToken) {
    lockAdminTools({ revokeSession: false });
    return;
  }

  if (isAdminRoute) {
    showAdminLoginFeedback('Validating saved admin session…', 'info');
  }

  try {
    const isValid = await verifyAdminToken(storedToken);
    if (isValid) {
      unlockAdminTools(storedToken, { notify: false });
    } else {
      lockAdminTools({
        message: 'Saved session is no longer valid. Please sign in again.',
        state: 'error',
      });
    }
  } catch (error) {
    console.error('Failed to validate stored admin session', error);
    lockAdminTools({
      state: 'error',
      message: 'Unable to validate admin session. Please try again.',
    });
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

function updateDetailsModalActions(node) {
  if (!detailsActions) {
    return;
  }

  const hasNode = Boolean(node && typeof node === 'object');
  const status = hasNode ? deriveStatus(node) : null;

  detailsActions.hidden = !hasNode;

  if (!detailsOpenStfButton) {
    return;
  }

  detailsOpenStfButton.textContent = 'Use';

  if (!hasNode) {
    detailsOpenStfButton.disabled = true;
    detailsOpenStfButton.setAttribute('aria-disabled', 'true');
    detailsOpenStfButton.title = 'Select a node to open STF.';
    return;
  }

  const supportsStf = nodeSupportsStf(node);
  if (!supportsStf) {
    detailsOpenStfButton.disabled = true;
    detailsOpenStfButton.setAttribute('aria-disabled', 'true');
    detailsOpenStfButton.title = 'STF access is not configured for this node.';
    return;
  }

  const isSessionActiveForNode = activeStfSession?.nodeId === node.id;
  const isAnotherSessionActive = activeStfSession && !isSessionActiveForNode;

  if (isSessionActiveForNode) {
    detailsOpenStfButton.disabled = true;
    detailsOpenStfButton.setAttribute('aria-disabled', 'true');
    detailsOpenStfButton.textContent = 'Session active';
    detailsOpenStfButton.title = 'This STF session is already active in this tab.';
    return;
  }

  if (isAnotherSessionActive) {
    detailsOpenStfButton.disabled = true;
    detailsOpenStfButton.setAttribute('aria-disabled', 'true');
    detailsOpenStfButton.title = 'Close the active STF session before opening another device.';
    return;
  }

  if (status === 'online') {
    detailsOpenStfButton.disabled = false;
    detailsOpenStfButton.removeAttribute('aria-disabled');
    detailsOpenStfButton.title = 'Open this device in STF within this page.';
  } else {
    detailsOpenStfButton.disabled = true;
    detailsOpenStfButton.setAttribute('aria-disabled', 'true');
    detailsOpenStfButton.title = 'STF access is only available when the node is online.';
  }
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
  detailsModalNode = null;
  updateDetailsModalActions(null);
}

function showNodeDetails(node, triggerButton) {
  if (!detailsModal || !detailsBody) {
    console.warn('Details modal not available');
    return;
  }

  lastFocusedTrigger = triggerButton || null;
  detailsModalNode = node;
  detailsBody.textContent = serializeNode(node);
  updateDetailsModalActions(node);
  detailsModal.classList.add('visible');
  detailsModal.setAttribute('aria-hidden', 'false');

  const closeButton = detailsModal.querySelector('.details-modal__close');
  if (closeButton) {
    closeButton.focus();
  }
}

if (detailsModal) {
  detailsDismissTargets.forEach((target) => {
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

if (detailsOpenStfButton) {
  detailsOpenStfButton.addEventListener('click', () => {
    if (!detailsModalNode) {
      showToast('Select a node before opening STF.');
      return;
    }

    handleOpenInStf(detailsModalNode, detailsOpenStfButton);
  });
}

updateDetailsModalActions(null);

if (adminModal) {
  adminModalDismissTargets.forEach((target) => {
    target.addEventListener('click', () => closeAdminModal());
  });

  adminModal.addEventListener('keydown', (event) => {
    if (event.key !== 'Tab' || !adminModal.classList.contains('visible')) {
      return;
    }

    const focusableElements = Array.from(adminModal.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
      (element) =>
        !element.hasAttribute('disabled') &&
        !element.closest('[hidden]') &&
        (element.offsetParent !== null || element.getClientRects().length > 0)
    );

    if (focusableElements.length === 0) {
      event.preventDefault();
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    const { activeElement } = document;

    if (event.shiftKey) {
      if (activeElement === firstElement || !adminModal.contains(activeElement)) {
        event.preventDefault();
        lastElement.focus();
      }
    } else if (activeElement === lastElement) {
      event.preventDefault();
      firstElement.focus();
    }
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && adminModal.classList.contains('visible')) {
      closeAdminModal();
    }
  });
}

function renderRows(nodes) {
  tableBody.innerHTML = '';

  if (!Array.isArray(nodes) || nodes.length === 0) {
    const emptyMessage = filtersAreActive()
      ? 'No nodes match the selected filters.'
      : 'No nodes registered yet.';
    tableBody.innerHTML = `<tr><td colspan="4" class="empty-state">${emptyMessage}</td></tr>`;
    updatePaginationControls({ totalItems: 0, totalPages: 1 });
    return;
  }

  const sortedNodes = [...nodes].sort((a, b) => {
    const statusDiff = STATUS_PRIORITY.indexOf(deriveStatus(a)) - STATUS_PRIORITY.indexOf(deriveStatus(b));
    if (statusDiff !== 0) {
      return statusDiff;
    }
    return (a.id || '').localeCompare(b.id || '');
  });

  const totalPages = Math.max(1, Math.ceil(sortedNodes.length / PAGE_SIZE));
  if (currentPage > totalPages) {
    currentPage = totalPages;
  } else if (currentPage < 1) {
    currentPage = 1;
  }

  const startIndex = (currentPage - 1) * PAGE_SIZE;
  const endIndex = startIndex + PAGE_SIZE;
  const pageNodes = sortedNodes.slice(startIndex, endIndex);

  for (const node of pageNodes) {
    const tr = document.createElement('tr');

    const sessionsLabel = `${Number(node.active_sessions ?? 0)} / ${Number(node.max_sessions ?? 1)}`;

    const status = deriveStatus(node);
    const isDetailsAvailable = status === 'online';

    const actions = [
      `<button class="action-button" data-show="${node.id}">Show details</button>`,
      `<button class="action-button" data-open-stream="${node.id}">View stream</button>`,
      `<button class="action-button" data-open-stf="${node.id}">Use</button>`,
    ];

    if (isAdminUnlocked && adminToken) {
      actions.push(`<button class="action-button" data-edit="${node.id}">Edit</button>`);
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

    const openStreamButton = tr.querySelector('button[data-open-stream]');
    if (openStreamButton) {
      openStreamButton.textContent = 'View stream';

      const streamUrl = deriveStreamUrl(node);
      if (!streamUrl) {
        openStreamButton.disabled = true;
        openStreamButton.setAttribute('aria-disabled', 'true');
        openStreamButton.title = 'Stream is not available for this node.';
      } else if (status !== 'online') {
        openStreamButton.disabled = true;
        openStreamButton.setAttribute('aria-disabled', 'true');
        openStreamButton.title = 'Streams are only available when the node is online.';
      } else {
        openStreamButton.disabled = false;
        openStreamButton.removeAttribute('aria-disabled');
        openStreamButton.title = 'View the live stream in a popup window.';
        openStreamButton.addEventListener('click', () => openStreamWindow(node));
      }
    }

    const openStfButton = tr.querySelector('button[data-open-stf]');
    if (openStfButton) {
      const supportsStf = nodeSupportsStf(node);
      const isSessionActiveForNode = activeStfSession?.nodeId === node.id;
      const isAnotherSessionActive = activeStfSession && !isSessionActiveForNode;

      openStfButton.textContent = isSessionActiveForNode ? 'Session active' : 'Use';

      if (!supportsStf) {
        openStfButton.disabled = true;
        openStfButton.setAttribute('aria-disabled', 'true');
        openStfButton.title = 'STF access is not configured for this node.';
      } else if (isSessionActiveForNode) {
        openStfButton.disabled = true;
        openStfButton.setAttribute('aria-disabled', 'true');
        openStfButton.title = 'This STF session is already active in this tab.';
      } else if (isAnotherSessionActive) {
        openStfButton.disabled = true;
        openStfButton.setAttribute('aria-disabled', 'true');
        openStfButton.title = 'Close the active STF session before opening another device.';
      } else if (status !== 'online') {
        openStfButton.disabled = true;
        openStfButton.setAttribute('aria-disabled', 'true');
        openStfButton.title = 'STF access is only available when the node is online.';
      } else {
        openStfButton.disabled = false;
        openStfButton.removeAttribute('aria-disabled');
        openStfButton.title = 'Open this device in STF within this page.';
        openStfButton.addEventListener('click', () => handleOpenInStf(node, openStfButton));
      }
    }

    const editButton = tr.querySelector('button[data-edit]');
    if (editButton) {
      editButton.addEventListener('click', () => handleEditNode(node, editButton));
    }

    const deleteButton = tr.querySelector('button[data-delete]');
    if (deleteButton) {
      deleteButton.addEventListener('click', () => handleDeleteNode(node, deleteButton));
    }
    tableBody.appendChild(tr);
  }

  updatePaginationControls({ totalItems: sortedNodes.length, totalPages });
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
    if (editingNodeId) {
      const nodeStillExists = allNodes.some((node) => node.id === editingNodeId);
      if (!nodeStillExists) {
        clearEditMode();
        showToast('The node you were editing is no longer available.');
      }
    }
    refreshNodeViews({ resetPage: isInitialLoad });

    if (activeStfSession) {
      const activeNode = allNodes.find((candidate) => candidate && candidate.id === activeStfSession.nodeId);
      const nodeStatus = activeNode ? deriveStatus(activeNode) : null;
      if (!activeNode || nodeStatus !== 'busy') {
        const endedMessage = !activeNode
          ? 'Active STF session ended because the node is no longer available.'
          : 'Active STF session ended because the device is available again.';
        setActiveStfSession(null);
        showToast(endedMessage);
      }
    }


    if (detailsModalNode) {
      const updatedDetailsNode = allNodes.find(
        (candidate) => candidate && candidate.id === detailsModalNode.id
      );

      if (updatedDetailsNode) {
        detailsModalNode = updatedDetailsNode;
        if (detailsModal && detailsModal.classList.contains('visible')) {
          detailsBody.textContent = serializeNode(updatedDetailsNode);
          updateDetailsModalActions(updatedDetailsNode);
        }
      } else if (detailsModal && detailsModal.classList.contains('visible')) {
        closeDetailsModal();
        showToast('The node you were viewing is no longer available.');
      } else {
        detailsModalNode = null;
        updateDetailsModalActions(null);
      }
    }
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

if (filtersToggle && filtersMenu) {
  filtersToggle.addEventListener('click', toggleFiltersMenu);
  document.addEventListener('click', handleFiltersMenuDocumentClick);
  document.addEventListener('keydown', handleFiltersMenuKeydown);
  setFiltersMenuOpen(false);
  updateFiltersToggleState();
}

if (filtersReset) {
  filtersReset.addEventListener('click', resetFilters);
}

if (cancelEditButton) {
  cancelEditButton.addEventListener('click', () => {
    const wasEditing = Boolean(editingNodeId);
    clearEditMode();
    if (wasEditing) {
      showToast('Edit cancelled. Ready to register a new node.');
    }
  });
}

if (addNodeForm) {
  clearEditMode();
  addNodeForm.addEventListener('submit', handleAddNode);
}

if (adminLoginForm) {
  adminLoginForm.addEventListener('submit', handleAdminLogin);
}

if (adminLockButton) {
  adminLockButton.addEventListener('click', () => {
    handleAdminLogout({ focusLogin: true, toast: 'Admin access required to manage nodes.' });
  });
}

if (adminLogoutButton) {
  adminLogoutButton.addEventListener('click', () => {
    handleAdminLogout({ focusLogin: false, toast: 'Signed out of admin tools.' });
  });
}

if (paginationPrev) {
  paginationPrev.addEventListener('click', () => {
    goToPage(currentPage - 1);
  });
}

if (paginationNext) {
  paginationNext.addEventListener('click', () => {
    goToPage(currentPage + 1);
  });
}

if (stfSessionCloseButton) {
  stfSessionCloseButton.addEventListener('click', () => {
    stfSessionCloseButton.disabled = true;
    closeActiveStfSession();
  });
}

if (adminToolsTrigger) {
  adminToolsTrigger.addEventListener('click', () => {
    if (isAdminUnlocked && adminToken) {
      openAdminModal('tools', { trigger: adminToolsTrigger });
      return;
    }

    if (isAdminRoute) {
      openAdminModal('login', { trigger: adminToolsTrigger });
      if (!adminLoginFeedback?.textContent) {
        showAdminLoginFeedback('Sign in with your admin credentials to continue.', 'info');
      }
      return;
    }

    showToast('Admin tools require signing in at /admin.');
  });
}

refreshButton.addEventListener('click', () => loadNodes({ userInitiated: true }));

initialiseAdminAccess();
loadNodes();
setInterval(() => loadNodes(), REFRESH_INTERVAL);

window.addEventListener('beforeunload', () => {
  if (activeStfSession?.nodeId) {
    sendStfReleaseKeepalive(activeStfSession.nodeId);
  }
});
