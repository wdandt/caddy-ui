// State Management
let state = {
    user: null,
    instances: [],
    proxies: [],
    oidcConfig: {},
    serverStatus: {},
    csrfToken: ''
};

// --- CSRF and Secure Fetch API ---
async function initSession() {
    try {
        const res = await fetch('/api/csrf');
        if (!res.ok) throw new Error('Failed to fetch CSRF token');
        const data = await res.json();
        state.csrfToken = data.csrfToken;
    } catch (err) {
        console.error('CSRF initiation error:', err);
    }
}

async function secureFetch(url, options = {}) {
    if (!options.headers) {
        options.headers = {};
    }
    
    // Add CSRF token for state-changing requests
    if (options.method && !['GET', 'HEAD', 'OPTIONS'].includes(options.method.toUpperCase())) {
        options.headers['X-CSRF-Token'] = state.csrfToken;
    }
    
    if (options.body && typeof options.body === 'object') {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(options.body);
    }

    const response = await fetch(url, options);
    
    if (response.status === 401) {
        // Session expired, redirect to login
        window.location.href = '/login.html';
        return null;
    }
    
    return response;
}

// --- DOM Helpers ---
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

// --- Tab Navigation ---
const tabs = [
    { navId: 'nav-proxies', panelId: 'panel-proxies', title: 'Proxy Routes' },
    { navId: 'nav-servers', panelId: 'panel-servers', title: 'Caddy Servers' },
    { navId: 'nav-sso', panelId: 'panel-sso', title: 'Settings' }
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

setupModal('proxy-modal', 'add-proxy-btn', 'close-proxy-modal', 'cancel-proxy-modal');
setupModal('server-modal', 'add-server-btn', 'close-server-modal', 'cancel-server-modal');

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

        // SSO Badge
        const ssoCol = document.createElement('div');
        const badge = document.createElement('span');
        if (proxy.ssoEnabled) {
            badge.className = 'badge badge-sso';
            badge.textContent = 'SSO';
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
        subtitle.textContent = `${instance.url} (SSO Gateway: ${instance.ssoUpstreamDial})`;

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
            } else {
                statusBadge.className = 'badge badge-offline';
                statusBadge.textContent = 'Offline';
            }
        } else {
            statusBadge.className = 'badge badge-no-sso';
            statusBadge.textContent = 'Checking...';
        }
        statusContainer.appendChild(statusBadge);

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
    
    if (state.oidcConfig.enabled) {
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
    const select = document.getElementById('proxy-server-select');
    select.replaceChildren(); // Clear

    state.instances.forEach(inst => {
        const opt = document.createElement('option');
        opt.value = inst.id;
        opt.textContent = inst.name;
        select.appendChild(opt);
    });
}

// --- Data Fetching Operations ---
async function loadDashboardData() {
    try {
        const instancesRes = await secureFetch('/api/instances');
        if (instancesRes) state.instances = await instancesRes.json();
        
        const proxiesRes = await secureFetch('/api/proxies');
        if (proxiesRes) state.proxies = await proxiesRes.json();
        
        const oidcRes = await secureFetch('/api/oidc');
        if (oidcRes) state.oidcConfig = await oidcRes.json();
        
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

async function loadSSOConfig() {
    try {
        const res = await secureFetch('/api/oidc');
        if (!res) return;
        const data = await res.json();
        state.oidcConfig = data;
        
        document.getElementById('sso-enabled-toggle').checked = data.enabled;
        document.getElementById('sso-issuer').value = data.issuer || '';
        document.getElementById('sso-client-id').value = data.clientId || '';
        document.getElementById('sso-client-secret').value = ''; // Don't fill password field
        document.getElementById('sso-redirect-uri').value = data.redirectUri || '';
        
        updateWidgets();
    } catch (err) {
        console.error('Error fetching SSO config:', err);
    }
}

// --- Proxy Route Management Actions ---
function openEditProxyModal(proxy) {
    document.getElementById('proxy-modal-title').textContent = 'Edit Proxy Route';
    document.getElementById('proxy-id').value = proxy.id;
    document.getElementById('proxy-server-select').value = proxy.instanceId;
    document.getElementById('proxy-host').value = proxy.host;
    document.getElementById('proxy-target').value = proxy.target;
    document.getElementById('proxy-sso-enabled').checked = proxy.ssoEnabled;
    
    document.getElementById('proxy-modal').classList.add('open');
}

// Close proxy modal and reset form
function resetProxyModal() {
    document.getElementById('proxy-modal').classList.remove('open');
    document.getElementById('proxy-form').reset();
    document.getElementById('proxy-id').value = '';
    document.getElementById('proxy-modal-title').textContent = 'Add Proxy Route';
}

document.getElementById('proxy-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const id = document.getElementById('proxy-id').value;
    const instanceId = document.getElementById('proxy-server-select').value;
    const host = document.getElementById('proxy-host').value.trim();
    const target = document.getElementById('proxy-target').value.trim();
    const ssoEnabled = document.getElementById('proxy-sso-enabled').checked;

    const payload = { instanceId, host, target, ssoEnabled };
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
        alert('Server request failed.');
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
document.getElementById('server-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = document.getElementById('server-name').value.trim();
    const url = document.getElementById('server-url').value.trim();
    const ssoUpstreamDial = document.getElementById('server-dial').value.trim();

    try {
        const res = await secureFetch('/api/instances', {
            method: 'POST',
            body: { name, url, ssoUpstreamDial }
        });
        
        if (res && res.ok) {
            document.getElementById('server-modal').classList.remove('open');
            document.getElementById('server-form').reset();
            loadDashboardData();
        } else {
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

// --- SSO Settings Form Submit ---
document.getElementById('sso-config-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const enabled = document.getElementById('sso-enabled-toggle').checked;
    const issuer = document.getElementById('sso-issuer').value.trim();
    const clientId = document.getElementById('sso-client-id').value.trim();
    const clientSecret = document.getElementById('sso-client-secret').value.trim();
    const redirectUri = document.getElementById('sso-redirect-uri').value.trim();

    const payload = { enabled, issuer, clientId, redirectUri };
    if (clientSecret) payload.clientSecret = clientSecret;

    try {
        const res = await secureFetch('/api/oidc', {
            method: 'POST',
            body: payload
        });
        
        if (res && res.ok) {
            alert('SSO configuration saved successfully!');
            loadSSOConfig();
        } else {
            const err = await res.json();
            alert(`Error saving config: ${err.error}`);
        }
    } catch (err) {
        alert('Failed to save configuration');
    }
});

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
    await loadSSOConfig();
    await loadAdminCredentials();
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
function displayUserSession() {
    const token = getCookie('caddyui-session') || getCookie('__Host-caddyui-session');
    if (token) {
        const session = parseJwt(token);
        if (session && session.username) {
            document.getElementById('display-user').textContent = `Logged in as ${session.username}`;
            state.user = session;
        }
    }
}

document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
        const res = await secureFetch('/auth/logout', {
            method: 'POST'
        });
        if (res && res.ok) {
            window.location.href = '/login.html';
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

// --- Page Load Handler ---
window.addEventListener('load', async () => {
    await initSession();
    displayUserSession();
    loadDashboardData();
});
