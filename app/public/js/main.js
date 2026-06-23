import { state } from './state.js';
import { showToast, escapeHtml, getCookie, parseJwt } from './utils.js';
import { secureFetch, initSession } from './api.js';

window.showToast = showToast; // expose for any html onclick if any

// --- Tab Navigation ---
const tabs = [
    { navId: 'nav-proxies', panelId: 'panel-proxies', title: 'Proxy Routes' },
    { navId: 'nav-servers', panelId: 'panel-servers', title: 'Caddy Servers' },
    { navId: 'nav-users', panelId: 'panel-users', title: 'User Accounts' },
    { navId: 'nav-providers', panelId: 'panel-providers', title: 'SSO Providers' },
    { navId: 'nav-sso', panelId: 'panel-sso', title: 'Settings' },
    { navId: 'nav-logs', panelId: 'panel-logs', title: 'Live Logs' }
];

tabs.forEach(tab => {
    document.getElementById(tab.navId).addEventListener('click', () => {
        tabs.forEach(t => {
            document.getElementById(t.navId).classList.remove('active');
            document.getElementById(t.panelId).classList.add('hidden');
        });
        document.getElementById(tab.navId).classList.add('active');
        document.getElementById(tab.panelId).classList.remove('hidden');
        document.getElementById('page-title').textContent = tab.title;
        
        // Refresh specific tab data
        if (tab.navId === 'nav-sso') {
            loadSettings();
        } else if (tab.navId === 'nav-users') {
            loadUsersData();
        } else if (tab.navId === 'nav-providers') {
            loadProvidersData();
        } else if (tab.navId === 'nav-logs') {
            loadLogsData();
        } else {
            loadDashboardData();
        }
    });
});

// --- Modal Handling ---
function setupModal(modalId, openBtnId, closeBtnId, cancelBtnId) {
    const modal = document.getElementById(modalId);
    const openBtn = document.getElementById(openBtnId);
    const closeBtn = document.getElementById(closeBtnId);
    const cancelBtn = document.getElementById(cancelBtnId);

    if (openBtn) {
        openBtn.addEventListener('click', () => {
            modal.classList.add('open');
        });
    }
    
    const closeModal = () => modal.classList.remove('open');
    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
}

setupModal('proxy-modal', null, 'close-proxy-modal', 'cancel-proxy-modal');
setupModal('server-modal', null, 'close-server-modal', 'cancel-server-modal');
setupModal('user-modal', null, 'close-user-modal', 'cancel-user-modal');
setupModal('provider-modal', null, 'close-provider-modal', 'cancel-provider-modal');
setupModal('mfa-modal', null, 'close-mfa-modal', 'cancel-mfa-modal');

// --- Render Functions (Secure Vanilla DOM Builders) ---
function renderProxyList() {
    const container = document.getElementById('proxy-list-container');
    container.replaceChildren(); // Safe clearing
    
    if (state.proxies.length === 0) {
        const placeholder = document.createElement('div');
        placeholder.className = 'glass';
        placeholder.style.padding = '2rem';
        placeholder.style.textAlign = 'center';
        placeholder.style.color = 'var(--text-secondary)';
        placeholder.textContent = 'No proxy routes configured. Click "+ Add Proxy Route" to create one.';
        container.appendChild(placeholder);
        return;
    }

    state.proxies.forEach(proxy => {
        const instance = state.instances.find(i => i.id === proxy.instanceId);
        const serverName = instance ? instance.name : 'Unknown Server';

        const card = document.createElement('div');
        card.className = 'proxy-card glass';

        // Host Column
        const hostCol = document.createElement('div');
        hostCol.className = 'proxy-host';
        const globeIcon = document.createElement('span');
        globeIcon.textContent = '🌐 ';
        hostCol.appendChild(globeIcon);
        const hostNameText = document.createTextNode(proxy.host);
        hostCol.appendChild(hostNameText);

        // Target / Upstream Column
        const targetCol = document.createElement('div');
        targetCol.className = 'proxy-target';
        targetCol.textContent = `➡ ${proxy.target} (${serverName})`;

        // SSO / Auth Mode Badge
        const ssoCol = document.createElement('div');
        const statusBadge = document.createElement('span');
        if (proxy.enabled !== false) {
            statusBadge.className = 'badge';
            statusBadge.style.background = 'rgba(16, 185, 129, 0.2)';
            statusBadge.style.color = '#34d399';
            statusBadge.textContent = 'ACTIVE';
        } else {
            statusBadge.className = 'badge badge-danger';
            statusBadge.style.background = 'rgba(239, 68, 68, 0.2)';
            statusBadge.style.color = '#f87171';
            statusBadge.textContent = 'DISABLED';
        }
        statusBadge.style.marginRight = '0.5rem';
        ssoCol.appendChild(statusBadge);

        const badge = document.createElement('span');
        const authMode = proxy.authMode || (proxy.ssoEnabled ? 'sso' : 'none');
        if (authMode === 'sso') {
            badge.className = 'badge badge-sso';
            const matchedProvider = state.oidcProviders.find(p => p.id === proxy.ssoProviderId);
            badge.textContent = matchedProvider ? `SSO: ${matchedProvider.name}` : 'SSO';
        } else if (authMode === 'basic') {
            badge.className = 'badge';
            badge.style.background = 'rgba(245, 158, 11, 0.2)';
            badge.style.color = '#fbbf24';
            badge.textContent = 'Basic Auth';
        } else {
            badge.className = 'badge badge-no-sso';
            badge.textContent = 'Public';
        }
        ssoCol.appendChild(badge);

        // Actions
        const actionsCol = document.createElement('div');
        actionsCol.className = 'proxy-actions';
        
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-secondary';
        editBtn.style.padding = '0.4rem 0.8rem';
        editBtn.style.fontSize = '0.85rem';
        editBtn.style.marginRight = '0.5rem';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => openEditProxyModal(proxy));

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger';
        deleteBtn.style.padding = '0.4rem 0.8rem';
        deleteBtn.style.fontSize = '0.85rem';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteProxyRoute(proxy.id));

        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn btn-secondary';
        toggleBtn.style.padding = '0.4rem 0.8rem';
        toggleBtn.style.fontSize = '0.85rem';
        toggleBtn.style.marginRight = '0.5rem';
        toggleBtn.textContent = proxy.enabled !== false ? 'Disable' : 'Enable';
        toggleBtn.addEventListener('click', () => toggleProxyRoute(proxy.id));
        actionsCol.appendChild(toggleBtn);
        actionsCol.appendChild(editBtn);
        actionsCol.appendChild(deleteBtn);

        card.appendChild(hostCol);
        card.appendChild(targetCol);
        card.appendChild(ssoCol);
        card.appendChild(actionsCol);

        container.appendChild(card);
    });
}

function renderServerList() {
    const container = document.getElementById('server-list-container');
    container.replaceChildren(); // Safe clearing

    state.instances.forEach(instance => {
        const item = document.createElement('div');
        item.className = 'list-item glass';

        const info = document.createElement('div');
        info.className = 'item-info';

        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = instance.name;
        if (instance.isLocal) {
            const localLabel = document.createElement('span');
            localLabel.style.fontSize = '0.7rem';
            localLabel.style.background = 'rgba(255,255,255,0.1)';
            localLabel.style.padding = '0.15rem 0.4rem';
            localLabel.style.borderRadius = '4px';
            localLabel.style.marginLeft = '0.5rem';
            localLabel.textContent = 'LOCAL';
            title.appendChild(localLabel);
        }

        const subtitle = document.createElement('div');
        subtitle.className = 'item-subtitle';
        subtitle.textContent = instance.url;

        info.appendChild(title);
        info.appendChild(subtitle);

        const statusContainer = document.createElement('div');
        statusContainer.style.display = 'flex';
        statusContainer.style.alignItems = 'center';
        statusContainer.style.gap = '1.5rem';

        // Latency and Status Badge
        const stat = state.serverStatus[instance.id];
        const statusBadge = document.createElement('span');
        
        if (stat) {
            if (stat.online) {
                statusBadge.className = 'badge badge-online';
                statusBadge.textContent = `Online (${stat.latency}ms)`;
            } else if (stat.error === 'Instance is disabled') {
                statusBadge.className = 'badge badge-offline';
                statusBadge.style.background = 'rgba(239, 68, 68, 0.2)';
                statusBadge.style.color = '#f87171';
                statusBadge.textContent = 'Disabled';
            } else {
                statusBadge.className = 'badge badge-offline';
                statusBadge.textContent = 'Offline';
            }
        } else {
            statusBadge.className = 'badge badge-no-sso';
            statusBadge.textContent = 'Checking...';
        }
        statusContainer.appendChild(statusBadge);

        // Edit button
        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-secondary';
        editBtn.style.padding = '0.4rem 0.8rem';
        editBtn.style.fontSize = '0.85rem';
        editBtn.style.marginRight = '0.5rem';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => openEditServerModal(instance));
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn btn-secondary';
        toggleBtn.style.padding = '0.4rem 0.8rem';
        toggleBtn.style.fontSize = '0.85rem';
        toggleBtn.style.marginRight = '0.5rem';
        toggleBtn.textContent = instance.enabled !== false ? 'Disable' : 'Enable';
        toggleBtn.addEventListener('click', () => toggleServer(instance.id));
        statusContainer.appendChild(toggleBtn);
        statusContainer.appendChild(editBtn);

        // View Config button
        const viewConfigBtn = document.createElement('button');
        viewConfigBtn.className = 'btn btn-secondary';
        viewConfigBtn.style.padding = '0.4rem 0.8rem';
        viewConfigBtn.style.fontSize = '0.85rem';
        viewConfigBtn.style.marginRight = '0.5rem';
        viewConfigBtn.textContent = 'View Config';
        viewConfigBtn.addEventListener('click', () => viewRawConfig(instance));
        statusContainer.appendChild(viewConfigBtn);

        // Delete button for remote instances
        if (!instance.isLocal) {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger';
            deleteBtn.style.padding = '0.4rem 0.8rem';
            deleteBtn.style.fontSize = '0.85rem';
            deleteBtn.textContent = 'Remove';
            deleteBtn.addEventListener('click', () => removeCaddyServer(instance.id));
            statusContainer.appendChild(deleteBtn);
        }

        item.appendChild(info);
        item.appendChild(statusContainer);
        container.appendChild(item);
    });
}

function updateWidgets() {
    document.getElementById('widget-proxy-count').textContent = state.proxies.length;
    document.getElementById('widget-server-count').textContent = state.instances.length;
    
    const oidcStatus = document.getElementById('widget-sso-status');
    oidcStatus.replaceChildren(); // Clear
    
    const hasEnabledProvider = state.oidcProviders && state.oidcProviders.some(p => p.enabled);
    if (hasEnabledProvider) {
        oidcStatus.className = 'widget-value';
        oidcStatus.style.color = 'var(--success)';
        oidcStatus.textContent = 'ENABLED';
    } else {
        oidcStatus.className = 'widget-value';
        oidcStatus.style.color = 'var(--text-muted)';
        oidcStatus.textContent = 'DISABLED';
    }
}

function renderServerSelectOptions() {
    const proxySelect = document.getElementById('proxy-server-select');
    const logsSelect = document.getElementById('logs-server-select');
    
    proxySelect.replaceChildren(); // Clear
    if (logsSelect) logsSelect.replaceChildren();

    state.instances.forEach(inst => {
        const opt = document.createElement('option');
        opt.value = inst.id;
        opt.textContent = inst.name;
        proxySelect.appendChild(opt);
        
        if (logsSelect) {
            const logsOpt = document.createElement('option');
            logsOpt.value = inst.id;
            logsOpt.textContent = inst.name;
            logsSelect.appendChild(logsOpt);
        }
    });
}

// --- Data Fetching Operations ---
async function loadDashboardData() {
    try {
        const [instancesRes, proxiesRes, providersRes] = await Promise.all([
            secureFetch('/api/instances'),
            secureFetch('/api/proxies'),
            secureFetch('/api/oidc-providers')
        ]);
        
        if (instancesRes) state.instances = await instancesRes.json();
        if (proxiesRes) state.proxies = await proxiesRes.json();
        if (providersRes) state.oidcProviders = await providersRes.json();
        
        renderProxyList();
        renderServerList();
        renderServerSelectOptions();
        updateWidgets();
        
        // Fetch server connection details asynchronously
        fetchServerStatus();
    } catch (err) {
        console.error('Error loading dashboard data:', err);
    }
}

async function fetchServerStatus() {
    try {
        const res = await secureFetch('/api/status');
        if (!res) return;
        const statusData = await res.json();
        
        statusData.forEach(stat => {
            state.serverStatus[stat.id] = stat;
        });
        
        renderServerList();
    } catch (err) {
        console.error('Error checking server status:', err);
    }
}

// --- Live Logs Fetching ---
async function loadLogsData() {
    const viewer = document.getElementById('logs-viewer');
    const lines = document.getElementById('logs-lines-select').value;
    const instanceId = document.getElementById('logs-server-select')?.value || '';
    
    viewer.textContent = 'Loading logs...';
    
    try {
        const res = await secureFetch(`/api/logs?lines=${lines}&instanceId=${instanceId}`);
        if (res && res.ok) {
            const data = await res.json();
            if (data.length === 0) {
                viewer.textContent = 'No logs available yet. Make sure Caddy has processed at least one request.';
                return;
            }
            // Format log lines beautifully
            const formatted = data.map(log => {
                if (log.raw) return log.raw;
                const timestamp = new Date(log.ts * 1000).toLocaleString() || log.ts;
                const level = log.level ? `[${log.level.toUpperCase()}]` : '';
                const msg = log.msg || '';
                let details = '';
                if (log.request) {
                    const req = log.request;
                    details = `| ${req.remote_ip} | ${req.method} ${req.host}${req.uri}`;
                }
                if (log.error) {
                    details += ` | ERROR: ${log.error}`;
                }
                return `${timestamp} ${level} ${msg} ${details}`;
            });
            viewer.textContent = formatted.join('\n');
            // Scroll to bottom
            viewer.scrollTop = viewer.scrollHeight;
        } else if (res) {
            const err = await res.json();
            viewer.textContent = `Error: ${err.error}`;
        }
    } catch (err) {
        viewer.textContent = 'Failed to fetch logs. Check console for details.';
        console.error(err);
    }
}

if (document.getElementById('refresh-logs-btn')) {
    document.getElementById('refresh-logs-btn').addEventListener('click', loadLogsData);
}
if (document.getElementById('logs-lines-select')) {
    document.getElementById('logs-lines-select').addEventListener('change', loadLogsData);
}
if (document.getElementById('logs-server-select')) {
    document.getElementById('logs-server-select').addEventListener('change', loadLogsData);
}

// SSO Config is now fully handled in SSO Providers tab.

// --- Advanced Routing Logic ---
function renderAdvancedRoutes(routes = []) {
    const container = document.getElementById('proxy-advanced-routes-container');
    if (!container) return;
    container.replaceChildren();
    routes.forEach(route => addAdvancedRouteRow(route.path, route.target));
}

function addAdvancedRouteRow(path = '', target = '') {
    const container = document.getElementById('proxy-advanced-routes-container');
    if (!container) return;
    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.gap = '0.5rem';
    row.style.alignItems = 'center';
    row.className = 'advanced-route-row';
    
    const pathInput = document.createElement('input');
    pathInput.type = 'text';
    pathInput.className = 'adv-path';
    pathInput.placeholder = 'Path (e.g. /app/*)';
    pathInput.value = path;
    pathInput.style.flex = '1';
    
    const targetInput = document.createElement('input');
    targetInput.type = 'text';
    targetInput.className = 'adv-target';
    targetInput.placeholder = 'Target (e.g. http://ip:6001)';
    targetInput.value = target;
    targetInput.style.flex = '2';
    
    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.className = 'btn btn-danger';
    rmBtn.textContent = 'X';
    rmBtn.style.padding = '0.3rem 0.6rem';
    rmBtn.addEventListener('click', () => row.remove());
    
    row.appendChild(pathInput);
    row.appendChild(targetInput);
    row.appendChild(rmBtn);
    container.appendChild(row);
}

if (document.getElementById('add-path-route-btn')) {
    document.getElementById('add-path-route-btn').addEventListener('click', () => addAdvancedRouteRow());
}

// --- Proxy Route Management Actions ---
function openEditProxyModal(proxy) {
    document.getElementById('proxy-modal-title').textContent = 'Edit Proxy Route';
    document.getElementById('proxy-id').value = proxy.id;
    document.getElementById('proxy-server-select').value = proxy.instanceId;
    document.getElementById('proxy-host').value = proxy.host;
    document.getElementById('proxy-enabled').checked = proxy.enabled !== false;
    
    let authMode = proxy.authMode;
    if (!authMode) {
        authMode = proxy.ssoEnabled ? 'sso' : 'none';
    }
    document.getElementById('proxy-auth-mode').value = authMode;
    
    populateProxySSOProviders();
    document.getElementById('proxy-sso-provider').value = proxy.ssoProviderId || '';

    const credTextarea = document.getElementById('proxy-basic-credentials');
    if (proxy.basicAuthCredentials && Array.isArray(proxy.basicAuthCredentials)) {
        credTextarea.value = proxy.basicAuthCredentials.map(c => `${c.username}:`).join('\n');
    } else {
        credTextarea.value = '';
    }

    toggleProxyAuthFields();

    const configMode = proxy.configMode || 'form';
    document.getElementById('proxy-config-type').value = configMode;
    
    if (configMode === 'json') {
        document.getElementById('proxy-form-builder-fields').classList.add('hidden');
        document.getElementById('proxy-raw-json-fields').classList.remove('hidden');
        document.getElementById('proxy-json-text').value = typeof proxy.rawCaddyConfig === 'string' 
            ? proxy.rawCaddyConfig 
            : JSON.stringify(proxy.rawCaddyConfig || [], null, 2);
    } else {
        document.getElementById('proxy-form-builder-fields').classList.remove('hidden');
        document.getElementById('proxy-raw-json-fields').classList.add('hidden');
        document.getElementById('proxy-target').value = proxy.target || '';
        if (document.getElementById('proxy-tls-insecure')) {
            document.getElementById('proxy-tls-insecure').checked = proxy.tlsInsecure === true;
        }
        renderAdvancedRoutes(proxy.advancedRoutes || []);
    }
    
    document.getElementById('proxy-modal').classList.add('open');
}

// Close proxy modal and reset form
function resetProxyModal() {
    document.getElementById('proxy-modal').classList.remove('open');
    document.getElementById('proxy-form').reset();
    document.getElementById('proxy-id').value = '';
    document.getElementById('proxy-modal-title').textContent = 'Add Proxy Route';
    
    document.getElementById('proxy-config-type').value = 'form';
    document.getElementById('proxy-form-builder-fields').classList.remove('hidden');
    document.getElementById('proxy-raw-json-fields').classList.add('hidden');
    document.getElementById('proxy-sso-group').classList.add('hidden');
    document.getElementById('proxy-basic-group').classList.add('hidden');
    document.getElementById('proxy-json-text').value = '';
    document.getElementById('proxy-enabled').checked = true;
    if (document.getElementById('proxy-tls-insecure')) {
        document.getElementById('proxy-tls-insecure').checked = false;
    }
    renderAdvancedRoutes([]);
}

document.getElementById('proxy-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const id = document.getElementById('proxy-id').value;
    const configType = document.getElementById('proxy-config-type').value;
    
    const instanceId = document.getElementById('proxy-server-select').value;
    const host = document.getElementById('proxy-host').value.trim();
    const enabled = document.getElementById('proxy-enabled').checked;
    
    const authMode = document.getElementById('proxy-auth-mode').value;
    const ssoProviderId = authMode === 'sso' ? document.getElementById('proxy-sso-provider').value : null;
    const ssoEnabled = authMode === 'sso';
    
    const credLines = document.getElementById('proxy-basic-credentials').value.split('\n');
    const basicAuthCredentials = [];
    credLines.forEach(line => {
        const parts = line.split(':');
        const username = parts[0]?.trim();
        const password = parts.slice(1).join(':')?.trim();
        if (username) {
            basicAuthCredentials.push({ username, password });
        }
    });

    let payload = {
        instanceId,
        host,
        enabled,
        authMode,
        ssoProviderId,
        ssoEnabled,
        basicAuthCredentials,
        configMode: configType
    };
    
    if (configType === 'json') {
        try {
            const rawJson = document.getElementById('proxy-json-text').value.trim() || '[]';
            JSON.parse(rawJson); // Validate JSON format
            payload.rawCaddyConfig = rawJson;
        } catch (err) {
            alert('Invalid JSON syntax: ' + err.message);
            return;
        }
    } else {
        payload.target = document.getElementById('proxy-target').value.trim();
        payload.tlsInsecure = document.getElementById('proxy-tls-insecure') ? document.getElementById('proxy-tls-insecure').checked : false;
        
        const advancedRoutes = [];
        document.querySelectorAll('.advanced-route-row').forEach(row => {
            const path = row.querySelector('.adv-path').value.trim();
            const target = row.querySelector('.adv-target').value.trim();
            if (path && target) {
                advancedRoutes.push({ path, target });
            }
        });
        payload.advancedRoutes = advancedRoutes;
    }
    
    const method = id ? 'PUT' : 'POST';
    const url = id ? `/api/proxies/${id}` : '/api/proxies';

    try {
        const res = await secureFetch(url, {
            method,
            body: payload
        });
        
        if (res && res.ok) {
            const data = await res.json();
            if (data.syncError) {
                alert(`Proxy saved locally, but Caddy sync failed: ${data.syncError}`);
            }
            resetProxyModal();
            loadDashboardData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        // alert(Server request failed);
    }
});

async function deleteProxyRoute(id) {
    if (!confirm('Are you sure you want to delete this proxy route?')) return;
    
    try {
        const res = await secureFetch(`/api/proxies/${id}`, {
            method: 'DELETE'
        });
        
        if (res && res.ok) {
            const data = await res.json();
            if (data.syncError) {
                alert(`Proxy deleted locally, but Caddy sync failed: ${data.syncError}`);
            }
            loadDashboardData();
        }
    } catch (err) {
        console.error(err);
    }
}

// --- Remote Server Management Actions ---
function resetServerModal() {
    document.getElementById('server-modal').classList.remove('open');
    document.getElementById('server-form').reset();
    document.getElementById('server-id').value = '';
    document.getElementById('server-modal-title').textContent = 'Add Remote Caddy Server';
    document.getElementById('save-server-btn').textContent = 'Add Server';
    document.getElementById('server-enabled').checked = true;
}

function openEditServerModal(instance) {
    document.getElementById('server-modal-title').textContent = 'Edit Caddy Server';
    document.getElementById('server-id').value = instance.id;
    document.getElementById('server-name').value = instance.name;
    document.getElementById('server-url').value = instance.url;
    document.getElementById('server-enabled').checked = instance.enabled !== false;
    document.getElementById('save-server-btn').textContent = 'Save Changes';
    document.getElementById('server-modal').classList.add('open');
}

document.getElementById('add-server-btn').addEventListener('click', () => {
    resetServerModal();
    document.getElementById('server-modal').classList.add('open');
});

document.getElementById('server-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const id = document.getElementById('server-id').value;
    const name = document.getElementById('server-name').value.trim();
    const url = document.getElementById('server-url').value.trim();
    const enabled = document.getElementById('server-enabled').checked;

    const method = id ? 'PUT' : 'POST';
    const endpoint = id ? `/api/instances/${id}` : '/api/instances';

    try {
        const res = await secureFetch(endpoint, {
            method,
            body: { name, url, enabled }
        });
        
        if (res && res.ok) {
            resetServerModal();
            loadDashboardData();
        } else if (res) {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        alert('Request failed');
    }
});

async function removeCaddyServer(id) {
    if (!confirm('Are you sure you want to remove this Caddy instance? All associated proxy rules will be deleted.')) return;
    
    try {
        const res = await secureFetch(`/api/instances/${id}`, {
            method: 'DELETE'
        });
        
        if (res && res.ok) {
            loadDashboardData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        console.error(err);
    }
}

// Legacy SSO settings form handler removed.

// --- Admin Credentials Form Submit ---
document.getElementById('admin-credentials-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('admin-username').value.trim();
    const password = document.getElementById('admin-password').value;

    const payload = { username };
    if (password) payload.password = password;

    try {
        const res = await secureFetch('/api/admin-credentials', {
            method: 'POST',
            body: payload
        });
        
        if (res && res.ok) {
            alert('Admin credentials saved successfully!');
            displayUserSession();
            loadAdminCredentials();
        } else {
            const err = await res.json();
            alert(`Error saving credentials: ${err.error}`);
        }
    } catch (err) {
        alert('Failed to save admin credentials');
    }
});

// --- Settings Load Helper ---
async function loadSettings() {
    await Promise.all([
        loadAdminCredentials(),
        loadDashboardAuthConfig(),
        renderDashboard2FASettings()
    ]);
}

async function loadAdminCredentials() {
    try {
        const res = await secureFetch('/api/admin-credentials');
        if (!res) return;
        const data = await res.json();
        document.getElementById('admin-username').value = data.username || '';
        document.getElementById('admin-password').value = '';
    } catch (err) {
        console.error('Error fetching admin credentials:', err);
    }
}

// --- Dashboard Authentication Form Submit & Load ---
async function loadDashboardAuthConfig() {
    try {
        const [res, providersRes] = await Promise.all([
            secureFetch('/api/dashboard-auth-config'),
            secureFetch('/api/oidc-providers')
        ]);
        
        if (!res || !providersRes) return;
        
        const config = await res.json();
        const providers = await providersRes.json();
        
        const container = document.getElementById('dash-allowed-providers-list');
        container.replaceChildren();
        
        const enabledProviders = providers.filter(p => p.enabled);
        if (enabledProviders.length === 0) {
            const noProviders = document.createElement('div');
            noProviders.textContent = 'No SSO providers configured. Add providers in the SSO Providers tab first.';
            noProviders.style.color = 'var(--text-muted)';
            noProviders.style.fontSize = '0.9rem';
            container.appendChild(noProviders);
        } else {
            enabledProviders.forEach(prov => {
                const label = document.createElement('label');
                label.style.display = 'flex';
                label.style.alignItems = 'center';
                label.style.gap = '0.5rem';
                label.style.cursor = 'pointer';
                label.style.userSelect = 'none';

                const chk = document.createElement('input');
                chk.type = 'checkbox';
                chk.value = prov.id;
                chk.className = 'dash-prov-chk';
                chk.style.width = 'auto';
                chk.style.margin = '0';
                
                if (config.allowedProviderIds && config.allowedProviderIds.includes(prov.id)) {
                    chk.checked = true;
                }

                label.appendChild(chk);
                label.appendChild(document.createTextNode(prov.name));
                container.appendChild(label);
            });
        }
        
        document.getElementById('dash-sso-only').checked = config.ssoOnly || false;
    } catch (err) {
        console.error('Error fetching dashboard auth configuration:', err);
    }
}

document.getElementById('dashboard-auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const ssoOnly = document.getElementById('dash-sso-only').checked;
    const checkedBoxes = document.querySelectorAll('.dash-prov-chk:checked');
    const allowedProviderIds = Array.from(checkedBoxes).map(cb => cb.value);
    
    try {
        const res = await secureFetch('/api/dashboard-auth-config', {
            method: 'POST',
            body: { ssoOnly, allowedProviderIds }
        });
        
        if (res && res.ok) {
            alert('Dashboard authentication settings saved successfully!');
            await loadDashboardAuthConfig();
        } else {
            const err = await res.json();
            alert(`Error saving auth settings: ${err.error}`);
        }
    } catch (err) {
        alert('Failed to save dashboard auth settings');
    }
});

// --- Dashboard Personal 2FA Actions & Rendering ---
async function renderDashboard2FASettings() {
    await displayUserSession();
    
    const section = document.getElementById('dash-2fa-section');
    if (!state.user || state.user.ssoEnabled) {
        section.style.display = 'none';
        return;
    }
    
    section.style.display = 'block';
    const statusText = document.getElementById('dash-2fa-status-text');
    const statusContainer = document.getElementById('dash-2fa-status-container');
    const btn = document.getElementById('dash-2fa-btn');
    
    if (state.user.twoFactorEnabled) {
        statusContainer.style.borderLeftColor = 'var(--success)';
        statusText.style.color = 'var(--success)';
        statusText.textContent = 'Two-Factor Authentication (2FA) is active. Your account is protected with an extra layer of security.';
        btn.textContent = 'Disable 2FA';
        btn.className = 'btn btn-danger';
    } else {
        statusContainer.style.borderLeftColor = 'var(--text-muted)';
        statusText.style.color = 'var(--text-muted)';
        statusText.textContent = 'Two-Factor Authentication (2FA) is inactive. We recommend enabling 2FA to secure your credentials login.';
        btn.textContent = 'Setup 2FA';
        btn.className = 'btn btn-secondary';
    }
}

document.getElementById('dash-2fa-btn').addEventListener('click', async () => {
    if (!state.user) return;
    if (state.user.twoFactorEnabled) {
        await disableTwoFactor(state.user);
    } else {
        await setupTwoFactor(state.user);
    }
    await renderDashboard2FASettings();
});

// --- Sync Config Manually ---
document.getElementById('sync-all-btn').addEventListener('click', async () => {
    const btn = document.getElementById('sync-all-btn');
    btn.disabled = true;
    btn.textContent = 'Syncing...';
    
    let successCount = 0;
    let failCount = 0;

    for (const inst of state.instances) {
        try {
            const res = await secureFetch(`/api/sync/${inst.id}`, {
                method: 'POST'
            });
            if (res && res.ok) {
                successCount++;
            } else {
                failCount++;
            }
        } catch (err) {
            failCount++;
        }
    }
    
    alert(`Sync operation complete.\nSuccessfully synced: ${successCount} servers\nFailed: ${failCount} servers`);
    
    btn.disabled = false;
    btn.replaceChildren();
    const icon = document.createElement('span');
    icon.className = 'icon';
    icon.style.marginRight = '0.5rem';
    icon.textContent = '🔄';
    btn.appendChild(icon);
    btn.appendChild(document.createTextNode(' Sync Config'));
    
    fetchServerStatus();
});

// --- Session Handling (Log In / Log Out) ---
async function displayUserSession() {
    try {
        const res = await secureFetch('/api/me');
        if (res && res.ok) {
            const session = await res.json();
            if (session && session.username) {
                document.getElementById('display-user').textContent = `Logged in as ${session.username}`;
                state.user = session;
            }
        }
    } catch (err) {
        console.error('Error fetching user session:', err);
    }
}

document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
        const res = await secureFetch('/auth/logout', {
            method: 'POST'
        });
        if (res && res.ok) {
            window.location.href = '/login';
        }
    } catch (err) {
        console.error(err);
    }
});

// --- View Raw Config Modal ---
async function viewRawConfig(instance) {
    const modal = document.getElementById('config-modal');
    const viewer = document.getElementById('raw-config-viewer');
    const title = document.getElementById('config-modal-title');
    
    title.textContent = `Active JSON Config - ${instance.name}`;
    viewer.textContent = 'Loading...';
    modal.classList.add('open');
    
    try {
        const res = await secureFetch(`/api/raw-config/${instance.id}`);
        if (res && res.ok) {
            const config = await res.json();
            viewer.textContent = JSON.stringify(config, null, 2);
        } else {
            const err = await res.json();
            viewer.textContent = `Error: ${err.error || 'Failed to load configuration'}`;
        }
    } catch (err) {
        viewer.textContent = `Failed to connect to server: ${err.message}`;
    }
}

// Config Modal Close Listeners
const configModal = document.getElementById('config-modal');
const closeConfigModalBtn1 = document.getElementById('close-config-modal');
const closeConfigModalBtn2 = document.getElementById('close-config-modal-btn');
const closeConfigModal = () => configModal.classList.remove('open');
if (closeConfigModalBtn1) closeConfigModalBtn1.addEventListener('click', closeConfigModal);
if (closeConfigModalBtn2) closeConfigModalBtn2.addEventListener('click', closeConfigModal);

// --- Proxy Auth Mode Handlers ---
function toggleProxyAuthFields() {
    const authMode = document.getElementById('proxy-auth-mode').value;
    const ssoGroup = document.getElementById('proxy-sso-group');
    const basicGroup = document.getElementById('proxy-basic-group');

    if (authMode === 'sso') {
        ssoGroup.classList.remove('hidden');
        basicGroup.classList.add('hidden');
    } else if (authMode === 'basic') {
        ssoGroup.classList.add('hidden');
        basicGroup.classList.remove('hidden');
    } else {
        ssoGroup.classList.add('hidden');
        basicGroup.classList.add('hidden');
    }
}

document.getElementById('proxy-auth-mode').addEventListener('change', toggleProxyAuthFields);

function populateProxySSOProviders() {
    const select = document.getElementById('proxy-sso-provider');
    select.replaceChildren();

    const defaultOpt = document.createElement('option');
    defaultOpt.value = '';
    defaultOpt.textContent = 'Select SSO Provider...';
    select.appendChild(defaultOpt);

    state.oidcProviders.forEach(p => {
        if (p.enabled) {
            const opt = document.createElement('option');
            opt.value = p.id;
            opt.textContent = p.name;
            select.appendChild(opt);
        }
    });
}

document.getElementById('add-proxy-btn').addEventListener('click', () => {
    resetProxyModal();
    populateProxySSOProviders();
    document.getElementById('proxy-modal').classList.add('open');
});

// Mode Toggling in Proxy Modal
document.getElementById('proxy-config-type').addEventListener('change', () => {
    const type = document.getElementById('proxy-config-type').value;
    if (type === 'json') {
        document.getElementById('proxy-form-builder-fields').classList.add('hidden');
        document.getElementById('proxy-raw-json-fields').classList.remove('hidden');
        
        if (!document.getElementById('proxy-json-text').value.trim()) {
            const target = document.getElementById('proxy-target').value.trim() || 'http://127.0.0.1:80';
            const tlsInsecure = document.getElementById('proxy-tls-insecure') ? document.getElementById('proxy-tls-insecure').checked : false;
            
            const cleanDialTarget = (t) => {
              let cleaned = t.replace(/^https?:\/\//, '');
              if (!cleaned.includes(':')) {
                cleaned += t.startsWith('https') ? ':443' : ':80';
              }
              return cleaned;
            };

            const createReverseProxyHandler = (targetUrl) => {
              const handler = {
                handler: "reverse_proxy",
                upstreams: [{ dial: cleanDialTarget(targetUrl) }],
                flush_interval: -1,
                stream_close_delay: "10m",
                headers: {
                  request: {
                    set: {
                      "X-Forwarded-Host": ["{http.request.host}"],
                      "X-Forwarded-Port": ["{http.request.port}"],
                      "X-Forwarded-Proto": ["{http.request.scheme}"],
                      "X-Real-Ip": ["{http.request.remote.host}"]
                    }
                  }
                }
              };

              if (tlsInsecure && targetUrl.startsWith('https://')) {
                handler.transport = {
                  protocol: "http",
                  tls: { insecure_skip_verify: true }
                };
              }
              return handler;
            };

            const generatedRoutes = [];

            // Advanced Routes
            document.querySelectorAll('.advanced-route-row').forEach(row => {
                const advPath = row.querySelector('.adv-path').value.trim();
                const advTarget = row.querySelector('.adv-target').value.trim();
                if (advPath && advTarget) {
                    generatedRoutes.push({
                        match: [{ path: [advPath] }],
                        handle: [createReverseProxyHandler(advTarget)]
                    });
                }
            });

            // Main Target
            if (target) {
                generatedRoutes.push({
                    handle: [createReverseProxyHandler(target)]
                });
            }

            document.getElementById('proxy-json-text').value = JSON.stringify(generatedRoutes, null, 2);
        }
    } else {
        document.getElementById('proxy-form-builder-fields').classList.remove('hidden');
        document.getElementById('proxy-raw-json-fields').classList.add('hidden');
    }
});

// JSON file upload handler inside modal
document.getElementById('proxy-json-file').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (evt) => {
        try {
            const parsed = JSON.parse(evt.target.result);
            document.getElementById('proxy-json-text').value = JSON.stringify(parsed, null, 2);
        } catch (err) {
            alert('Invalid JSON file format.');
        }
    };
    reader.readAsText(file);
});

// Bulk Import JSON button handler
document.getElementById('import-proxies-btn').addEventListener('click', () => {
    document.getElementById('import-proxies-file').click();
});

document.getElementById('import-proxies-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (evt) => {
        try {
            const proxies = JSON.parse(evt.target.result);
            const proxyArray = Array.isArray(proxies) ? proxies : [proxies];
            
            let imported = 0;
            let failed = 0;
            
            for (const p of proxyArray) {
                if (!p.instanceId || !p.host || !p.target) {
                    failed++;
                    continue;
                }
                
                const res = await secureFetch('/api/proxies', {
                    method: 'POST',
                    body: p
                });
                if (res && res.ok) {
                    imported++;
                } else {
                    failed++;
                }
            }
            
            alert(`Import complete.\nSuccessfully imported: ${imported} routes\nFailed: ${failed} routes`);
            loadDashboardData();
        } catch (err) {
            alert('Failed to parse JSON file.');
        }
    };
    reader.readAsText(file);
    e.target.value = ''; // Reset value to allow uploading same file
});

// Bulk Export JSON button handler
document.getElementById('export-proxies-btn').addEventListener('click', () => {
    if (state.proxies.length === 0) {
        alert('No proxy routes to export.');
        return;
    }
    const exported = state.proxies.map(p => {
        const clean = {
            instanceId: p.instanceId,
            host: p.host,
            target: p.target,
            authMode: p.authMode || (p.ssoEnabled ? 'sso' : 'none'),
            ssoProviderId: p.ssoProviderId || null
        };
        if (p.basicAuthCredentials) {
            clean.basicAuthCredentials = p.basicAuthCredentials.map(c => ({
                username: c.username,
                password: ''
            }));
        }
        return clean;
    });
    
    const blob = new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'caddy-proxies-export.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});


// --- User Accounts Management ---
async function loadUsersData() {
    try {
        const [res, providersRes] = await Promise.all([
            secureFetch('/api/users'),
            secureFetch('/api/oidc-providers')
        ]);
        
        if (res) state.users = await res.json();
        if (providersRes) state.oidcProviders = await providersRes.json();
        
        if (res) {
            renderUserList();
        }
    } catch (err) {
        console.error('Error loading users:', err);
    }
}

function renderUserList() {
    const container = document.getElementById('user-list-container');
    container.replaceChildren();

    if (!state.users || state.users.length === 0) {
        const placeholder = document.createElement('div');
        placeholder.className = 'glass';
        placeholder.style.padding = '2rem';
        placeholder.style.textAlign = 'center';
        placeholder.style.color = 'var(--text-secondary)';
        placeholder.textContent = 'No user accounts configured. Click "+ Add User" to create one.';
        container.appendChild(placeholder);
        return;
    }

    state.users.forEach(user => {
        const item = document.createElement('div');
        item.className = 'list-item glass';

        const info = document.createElement('div');
        info.className = 'item-info';

        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = user.username;

        const roleBadge = document.createElement('span');
        roleBadge.style.fontSize = '0.7rem';
        roleBadge.style.marginLeft = '0.5rem';
        roleBadge.style.padding = '0.15rem 0.4rem';
        roleBadge.style.borderRadius = '4px';
        if (user.role === 'admin') {
            roleBadge.style.background = 'rgba(239, 68, 68, 0.2)';
            roleBadge.style.color = '#f87171';
            roleBadge.textContent = 'ADMIN';
        } else {
            roleBadge.style.background = 'rgba(59, 130, 246, 0.2)';
            roleBadge.style.color = '#60a5fa';
            roleBadge.textContent = 'VIEWER';
        }
        title.appendChild(roleBadge);
        
        const enabledBadge = document.createElement('span');
        enabledBadge.style.fontSize = '0.7rem';
        enabledBadge.style.marginLeft = '0.5rem';
        enabledBadge.style.padding = '0.15rem 0.4rem';
        enabledBadge.style.borderRadius = '4px';
        if (user.enabled !== false) {
            enabledBadge.style.background = 'rgba(16, 185, 129, 0.2)';
            enabledBadge.style.color = '#34d399';
            enabledBadge.textContent = 'ACTIVE';
        } else {
            enabledBadge.style.background = 'rgba(239, 68, 68, 0.2)';
            enabledBadge.style.color = '#f87171';
            enabledBadge.textContent = 'DISABLED';
        }
        title.appendChild(enabledBadge);

        if (user.ssoEnabled) {
            const ssoBadge = document.createElement('span');
            ssoBadge.style.fontSize = '0.7rem';
            ssoBadge.style.marginLeft = '0.5rem';
            ssoBadge.style.padding = '0.15rem 0.4rem';
            ssoBadge.style.borderRadius = '4px';
            ssoBadge.style.background = 'rgba(168, 85, 247, 0.2)';
            ssoBadge.style.color = '#c084fc';
            const matchedProvider = state.oidcProviders.find(p => p.id === user.ssoProviderId);
            ssoBadge.textContent = matchedProvider ? `SSO: ${matchedProvider.name}` : 'SSO Only';
            title.appendChild(ssoBadge);
        }

        const mfaBadge = document.createElement('span');
        mfaBadge.style.fontSize = '0.7rem';
        mfaBadge.style.marginLeft = '0.5rem';
        mfaBadge.style.padding = '0.15rem 0.4rem';
        mfaBadge.style.borderRadius = '4px';
        if (user.twoFactorEnabled) {
            mfaBadge.style.background = 'rgba(16, 185, 129, 0.2)';
            mfaBadge.style.color = '#34d399';
            mfaBadge.textContent = '2FA ACTIVE';
        } else {
            mfaBadge.style.background = 'rgba(255, 255, 255, 0.1)';
            mfaBadge.style.color = 'var(--text-muted)';
            mfaBadge.textContent = '2FA DISABLED';
        }
        title.appendChild(mfaBadge);

        info.appendChild(title);

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.alignItems = 'center';
        actions.style.gap = '0.5rem';

        const mfaBtn = document.createElement('button');
        mfaBtn.className = 'btn btn-secondary';
        mfaBtn.style.padding = '0.4rem 0.8rem';
        mfaBtn.style.fontSize = '0.85rem';
        if (user.twoFactorEnabled) {
            mfaBtn.textContent = 'Disable 2FA';
            mfaBtn.addEventListener('click', () => disableTwoFactor(user));
        } else {
            mfaBtn.textContent = 'Enable 2FA';
            mfaBtn.addEventListener('click', () => forceEnableTwoFactor(user));
        }
        actions.appendChild(mfaBtn);

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-secondary';
        editBtn.style.padding = '0.4rem 0.8rem';
        editBtn.style.fontSize = '0.85rem';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => openEditUserModal(user));
        if (user.id !== 'admin') {
            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'btn btn-secondary';
            toggleBtn.style.padding = '0.4rem 0.8rem';
            toggleBtn.style.fontSize = '0.85rem';
            toggleBtn.textContent = user.enabled !== false ? 'Disable' : 'Enable';
            toggleBtn.addEventListener('click', () => toggleUser(user.id));
            actions.appendChild(toggleBtn);
        }
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'btn btn-secondary';
        toggleBtn.style.padding = '0.4rem 0.8rem';
        toggleBtn.style.fontSize = '0.85rem';
        toggleBtn.textContent = provider.enabled ? 'Disable' : 'Enable';
        toggleBtn.addEventListener('click', () => toggleProvider(provider.id));
        actions.appendChild(toggleBtn);
        actions.appendChild(editBtn);

        if (user.id !== 'admin') {
            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'btn btn-danger';
            deleteBtn.style.padding = '0.4rem 0.8rem';
            deleteBtn.style.fontSize = '0.85rem';
            deleteBtn.textContent = 'Delete';
            deleteBtn.addEventListener('click', () => deleteUser(user.id));
            actions.appendChild(deleteBtn);
        }

        item.appendChild(info);
        item.appendChild(actions);
        container.appendChild(item);
    });
}

function toggleUserSSOFields() {
    const ssoEnabled = document.getElementById('user-sso-enabled').checked;
    const passwordGroup = document.getElementById('user-password-group');
    const ssoProviderGroup = document.getElementById('user-sso-provider-group');
    const passwordInput = document.getElementById('user-password');

    if (ssoEnabled) {
        passwordGroup.classList.add('hidden');
        ssoProviderGroup.classList.remove('hidden');
        passwordInput.required = false;
    } else {
        passwordGroup.classList.remove('hidden');
        ssoProviderGroup.classList.add('hidden');
        const isAdding = !document.getElementById('user-id').value;
        passwordInput.required = isAdding;
    }
}

document.getElementById('user-sso-enabled').addEventListener('change', toggleUserSSOFields);

function populateUserSSOProviders() {
    const select = document.getElementById('user-sso-provider');
    select.replaceChildren();
    
    const defaultOpt = document.createElement('option');
    defaultOpt.value = '';
    defaultOpt.textContent = 'Any enabled Provider';
    select.appendChild(defaultOpt);

    state.oidcProviders.forEach(p => {
        if (p.enabled) {
            const opt = document.createElement('option');
            opt.value = p.id;
            opt.textContent = p.name;
            select.appendChild(opt);
        }
    });
}

function openEditUserModal(user) {
    document.getElementById('user-modal-title').textContent = 'Edit User';
    document.getElementById('user-id').value = user.id;
    document.getElementById('user-username').value = user.username;
    document.getElementById('user-username').readOnly = (user.id === 'admin');
    document.getElementById('user-password').value = '';
    document.getElementById('user-password').placeholder = user.id ? '•••••••••••• (Leave empty to keep current)' : 'Password';
    document.getElementById('user-role').value = user.role;
    document.getElementById('user-enabled').checked = user.enabled !== false;
    document.getElementById('user-sso-enabled').checked = user.ssoEnabled;
    
    populateUserSSOProviders();
    document.getElementById('user-sso-provider').value = user.ssoProviderId || '';
    toggleUserSSOFields();
    
    document.getElementById('user-modal').classList.add('open');
}

document.getElementById('add-user-btn').addEventListener('click', () => {
    document.getElementById('user-modal-title').textContent = 'Add User';
    document.getElementById('user-id').value = '';
    document.getElementById('user-username').value = '';
    document.getElementById('user-username').readOnly = false;
    document.getElementById('user-password').value = '';
    document.getElementById('user-password').placeholder = 'Password';
    document.getElementById('user-role').value = 'viewer';
    document.getElementById('user-enabled').checked = true;
    document.getElementById('user-sso-enabled').checked = false;
    
    populateUserSSOProviders();
    document.getElementById('user-sso-provider').value = '';
    toggleUserSSOFields();
    document.getElementById('user-modal').classList.add('open');
});

document.getElementById('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('user-id').value;
    const username = document.getElementById('user-username').value.trim();
    const password = document.getElementById('user-password').value;
    const role = document.getElementById('user-role').value;
    const enabled = document.getElementById('user-enabled').checked;
    const ssoEnabled = document.getElementById('user-sso-enabled').checked;
    const ssoProviderId = ssoEnabled ? document.getElementById('user-sso-provider').value : null;

    const payload = { username, role, ssoEnabled, ssoProviderId, enabled };
    if (password) payload.password = password;

    const method = id ? 'PUT' : 'POST';
    const url = id ? `/api/users/${id}` : '/api/users';

    try {
        const res = await secureFetch(url, {
            method,
            body: payload
        });
        if (res && res.ok) {
            document.getElementById('user-modal').classList.remove('open');
            document.getElementById('user-form').reset();
            loadUsersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        // alert(Server request failed);
    }
});

async function deleteUser(id) {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
        const res = await secureFetch(`/api/users/${id}`, {
            method: 'DELETE'
        });
        if (res && res.ok) {
            loadUsersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        console.error(err);
    }
}


// --- 2FA Enrollment Management ---
let currentSetupUserId = null;

async function setupTwoFactor(user) {
    currentSetupUserId = user.id;
    try {
        const res = await secureFetch(`/api/users/${user.id}/2fa/setup`, {
            method: 'POST'
        });
        if (res && res.ok) {
            const data = await res.json();
            document.getElementById('mfa-secret-key').textContent = data.secret;
            const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(data.otpauthUrl)}`;
            document.getElementById('mfa-qr-img').src = qrUrl;
            document.getElementById('mfa-verify-code').value = '';
            document.getElementById('mfa-modal').classList.add('open');
        } else {
            const err = await res.json();
            alert(`Error: ${err.error || 'Failed to initiate 2FA setup'}`);
        }
    } catch (err) {
        console.error(err);
        alert('Failed to initiate 2FA setup.');
    }
}

async function disableTwoFactor(user) {
    if (!confirm(`Are you sure you want to disable Two-Factor Authentication for ${user.username}?`)) return;
    try {
        const res = await secureFetch(`/api/users/${user.id}/2fa/disable`, {
            method: 'POST'
        });
        if (res && res.ok) {
            alert('2FA has been disabled.');
            if (state.user && user.id === state.user.id) {
                await renderDashboard2FASettings();
            }
            loadUsersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error || 'Failed to disable 2FA'}`);
        }
    } catch (err) {
        console.error(err);
        alert('Failed to disable 2FA.');
    }
}

async function forceEnableTwoFactor(user) {
    if (!confirm(`Are you sure you want to force-enable 2FA for ${user.username}? The user will need the secret key to log in.`)) return;
    try {
        const res = await secureFetch(`/api/users/${user.id}/2fa/force-enable`, {
            method: 'POST'
        });
        if (res && res.ok) {
            const data = await res.json();
            alert(`2FA has been enabled for ${user.username}!\n\nIMPORTANT: Share this secret key with the user so they can configure their authenticator app:\n${data.secret}`);
            loadUsersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error || 'Failed to force-enable 2FA'}`);
        }
    } catch (err) {
        console.error(err);
        alert('Failed to force-enable 2FA.');
    }
}

document.getElementById('mfa-verify-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('mfa-verify-code').value.trim();
    if (!code || !currentSetupUserId) return;

    try {
        const res = await secureFetch(`/api/users/${currentSetupUserId}/2fa/enable`, {
            method: 'POST',
            body: { code }
        });
        if (res && res.ok) {
            alert('Two-Factor Authentication enabled successfully!');
            document.getElementById('mfa-modal').classList.remove('open');
            if (state.user && currentSetupUserId === state.user.id) {
                await renderDashboard2FASettings();
            }
            loadUsersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error || 'Failed to verify code'}`);
        }
    } catch (err) {
        console.error(err);
        alert('Verification request failed.');
    }
});


// --- SSO Providers Management ---
async function loadProvidersData() {
    try {
        const res = await secureFetch('/api/oidc-providers');
        if (res) {
            state.oidcProviders = await res.json();
            renderProviderList();
        }
    } catch (err) {
        console.error('Error loading providers:', err);
    }
}

function renderProviderList() {
    const container = document.getElementById('provider-list-container');
    container.replaceChildren();

    if (!state.oidcProviders || state.oidcProviders.length === 0) {
        const placeholder = document.createElement('div');
        placeholder.className = 'glass';
        placeholder.style.padding = '2rem';
        placeholder.style.textAlign = 'center';
        placeholder.style.color = 'var(--text-secondary)';
        placeholder.textContent = 'No SSO Providers configured. Click "+ Add SSO Provider" to create one.';
        container.appendChild(placeholder);
        return;
    }

    state.oidcProviders.forEach(provider => {
        const item = document.createElement('div');
        item.className = 'list-item glass';

        const info = document.createElement('div');
        info.className = 'item-info';

        const title = document.createElement('div');
        title.className = 'item-title';
        title.textContent = provider.name;

        const statusBadge = document.createElement('span');
        statusBadge.style.fontSize = '0.7rem';
        statusBadge.style.marginLeft = '0.5rem';
        statusBadge.style.padding = '0.15rem 0.4rem';
        statusBadge.style.borderRadius = '4px';
        if (provider.enabled) {
            statusBadge.style.background = 'rgba(16, 185, 129, 0.2)';
            statusBadge.style.color = '#34d399';
            statusBadge.textContent = 'ACTIVE';
        } else {
            statusBadge.style.background = 'rgba(239, 68, 68, 0.2)';
            statusBadge.style.color = '#f87171';
            statusBadge.textContent = 'DISABLED';
        }
        title.appendChild(statusBadge);

        const subtitle = document.createElement('div');
        subtitle.className = 'item-subtitle';
        subtitle.textContent = `Issuer: ${provider.issuer} | Client ID: ${provider.clientId}`;

        info.appendChild(title);
        info.appendChild(subtitle);

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.gap = '0.5rem';

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-secondary';
        editBtn.style.padding = '0.4rem 0.8rem';
        editBtn.style.fontSize = '0.85rem';
        editBtn.textContent = 'Edit';
        editBtn.addEventListener('click', () => openEditProviderModal(provider));
        actions.appendChild(editBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'btn btn-danger';
        deleteBtn.style.padding = '0.4rem 0.8rem';
        deleteBtn.style.fontSize = '0.85rem';
        deleteBtn.textContent = 'Delete';
        deleteBtn.addEventListener('click', () => deleteProvider(provider.id));
        actions.appendChild(deleteBtn);

        item.appendChild(info);
        item.appendChild(actions);
        container.appendChild(item);
    });
}

function openEditProviderModal(provider) {
    document.getElementById('provider-modal-title').textContent = 'Edit SSO Provider';
    document.getElementById('provider-id').value = provider.id;
    document.getElementById('provider-name').value = provider.name;
    document.getElementById('provider-issuer').value = provider.issuer;
    document.getElementById('provider-client-id').value = provider.clientId;
    document.getElementById('provider-client-secret').value = '';
    document.getElementById('provider-client-secret').placeholder = '•••••••••••• (Leave empty to keep current)';
    document.getElementById('provider-redirect-uri').value = provider.redirectUri;
    document.getElementById('provider-enabled').checked = provider.enabled;
    document.getElementById('provider-modal').classList.add('open');
}

document.getElementById('add-provider-btn').addEventListener('click', () => {
    document.getElementById('provider-modal-title').textContent = 'Add SSO Provider';
    document.getElementById('provider-id').value = '';
    document.getElementById('provider-name').value = '';
    document.getElementById('provider-issuer').value = '';
    document.getElementById('provider-client-id').value = '';
    document.getElementById('provider-client-secret').value = '';
    document.getElementById('provider-client-secret').placeholder = 'Client Secret';
    document.getElementById('provider-redirect-uri').value = window.location.origin + '/auth/callback';
    document.getElementById('provider-enabled').checked = true;
    document.getElementById('provider-modal').classList.add('open');
});

document.getElementById('provider-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('provider-id').value;
    const name = document.getElementById('provider-name').value.trim();
    const issuer = document.getElementById('provider-issuer').value.trim();
    const clientId = document.getElementById('provider-client-id').value.trim();
    const clientSecret = document.getElementById('provider-client-secret').value.trim();
    const redirectUri = document.getElementById('provider-redirect-uri').value.trim();
    const enabled = document.getElementById('provider-enabled').checked;

    const payload = { name, issuer, clientId, redirectUri, enabled };
    if (clientSecret) payload.clientSecret = clientSecret;

    const method = id ? 'PUT' : 'POST';
    const url = id ? `/api/oidc-providers/${id}` : '/api/oidc-providers';

    try {
        const res = await secureFetch(url, {
            method,
            body: payload
        });
        if (res && res.ok) {
            document.getElementById('provider-modal').classList.remove('open');
            document.getElementById('provider-form').reset();
            loadProvidersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        // alert(Server request failed);
    }
});

async function deleteProvider(id) {
    if (!confirm('Are you sure you want to delete this SSO provider?')) return;
    try {
        const res = await secureFetch(`/api/oidc-providers/${id}`, {
            method: 'DELETE'
        });
        if (res && res.ok) {
            loadProvidersData();
        } else {
            const err = await res.json();
            alert(`Error: ${err.error}`);
        }
    } catch (err) {
        console.error(err);
    }
}


// --- Page Load Handler ---
window.addEventListener('load', async () => {
    await initSession();
    displayUserSession();
    loadDashboardData();
});


// --- Quick Action Toggle Functions ---
async function toggleProxyRoute(id) {
    try {
        const res = await secureFetch(`/api/proxies/${id}/toggle`, { method: 'PUT' });
        if (res && res.ok) loadDashboardData();
    } catch (err) { console.error(err); }
}

async function toggleServer(id) {
    try {
        const res = await secureFetch(`/api/instances/${id}/toggle`, { method: 'PUT' });
        if (res && res.ok) loadDashboardData();
    } catch (err) { console.error(err); }
}

async function toggleUser(id) {
    try {
        const res = await secureFetch(`/api/users/${id}/toggle`, { method: 'PUT' });
        if (res && res.ok) loadUsersData();
    } catch (err) { console.error(err); }
}

async function toggleProvider(id) {
    try {
        const res = await secureFetch(`/api/oidc-providers/${id}/toggle`, { method: 'PUT' });
        if (res && res.ok) loadProvidersData();
    } catch (err) { console.error(err); }
}
