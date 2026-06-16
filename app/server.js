const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security configuration
app.disable('x-powered-by');
app.use(express.json());
app.use(cookieParser());

// Database file setup
const DB_PATH = path.join(__dirname, 'data', 'db.json');

// Ensure database directory exists
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

// Initialize database with defaults
function readDb() {
  const defaultAdminUser = process.env.ADMIN_USER || 'admin';
  const defaultAdminPass = process.env.ADMIN_PASS || 'caddyui_admin_secure_pass_123';
  const defaultAdminPassHash = bcrypt.hashSync(defaultAdminPass, 10);

  const defaultOidcIssuer = process.env.OIDC_ISSUER || '';
  const defaultOidcClientId = process.env.OIDC_CLIENT_ID || '';
  const defaultOidcClientSecret = process.env.OIDC_CLIENT_SECRET || '';
  const defaultOidcRedirectUri = process.env.OIDC_REDIRECT_URI || '';
  const defaultOidcEnabled = !!(defaultOidcIssuer && defaultOidcClientId);

  if (!fs.existsSync(DB_PATH)) {
    const defaultDb = {
      instances: [
        {
          id: 'local',
          name: 'Local Caddy',
          url: 'http://caddyui-caddy:2019',
          ssoUpstreamDial: 'caddy-ui:3000', // How local Caddy reaches Caddy UI
          isLocal: true
        }
      ],
      proxies: [],
      oidcConfig: {
        issuer: defaultOidcIssuer,
        clientId: defaultOidcClientId,
        clientSecret: defaultOidcClientSecret,
        redirectUri: defaultOidcRedirectUri,
        enabled: defaultOidcEnabled
      },
      adminCredentials: {
        username: defaultAdminUser,
        passwordHash: defaultAdminPassHash
      }
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDb, null, 2), 'utf-8');
    return defaultDb;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    // Ensure adminCredentials exists
    let modified = false;
    if (!db.adminCredentials) {
      db.adminCredentials = {
        username: defaultAdminUser,
        passwordHash: defaultAdminPassHash
      };
      modified = true;
    }
    // Ensure oidcConfig exists
    if (!db.oidcConfig) {
      db.oidcConfig = {
        issuer: defaultOidcIssuer,
        clientId: defaultOidcClientId,
        clientSecret: defaultOidcClientSecret,
        redirectUri: defaultOidcRedirectUri,
        enabled: defaultOidcEnabled
      };
      modified = true;
    }
    if (modified) {
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
    }
    return db;
  } catch (err) {
    console.error('Error reading DB, resetting to default:', err);
    return {
      instances: [
        {
          id: 'local',
          name: 'Local Caddy',
          url: 'http://caddyui-caddy:2019',
          ssoUpstreamDial: 'caddy-ui:3000',
          isLocal: true
        }
      ],
      proxies: [],
      oidcConfig: {
        issuer: defaultOidcIssuer,
        clientId: defaultOidcClientId,
        clientSecret: defaultOidcClientSecret,
        redirectUri: defaultOidcRedirectUri,
        enabled: defaultOidcEnabled
      },
      adminCredentials: {
        username: defaultAdminUser,
        passwordHash: defaultAdminPassHash
      }
    };
  }
}

function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

// Generate or fetch JWT Secret
function getJwtSecret() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }
  const secretFile = path.join(__dirname, 'data', 'jwt_secret.txt');
  if (fs.existsSync(secretFile)) {
    return fs.readFileSync(secretFile, 'utf-8').trim();
  }
  console.warn("WARNING: JWT_SECRET environment variable not set. Generating an ephemeral secret key. Horizontal scaling will not share sessions!");
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(secretFile, secret, 'utf-8');
  return secret;
}

const JWT_SECRET = getJwtSecret();

// Get cookie name based on security context
function getSessionCookieName(req) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  return isHttps ? '__Host-caddyui-session' : 'caddyui-session';
}

// Authentication Middlewares
function authenticateToken(req, res, next) {
  const cookieName = getSessionCookieName(req);
  const token = req.cookies[cookieName];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      res.clearCookie(cookieName);
      return res.status(403).json({ error: 'Session expired or invalid' });
    }
    req.user = user;
    next();
  });
}

// CSRF Protection Middleware (Double Submit Cookie)
function csrfProtection(req, res, next) {
  // Safe methods do not require CSRF protection
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const csrfCookie = req.cookies['caddyui-csrf'];
  const csrfHeader = req.headers['x-csrf-token'];

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return res.status(403).json({ error: 'Invalid or missing CSRF token' });
  }
  next();
}

// Helper to sanitize dial targets for Caddy
function cleanDialTarget(target) {
  let clean = target.replace(/^(https?:\/\/)/, '');
  // Strip trailing slash or path if any
  clean = clean.split('/')[0];
  if (!clean.includes(':')) {
    if (target.startsWith('https://')) {
      clean += ':443';
    } else {
      clean += ':80';
    }
  }
  return clean;
}

// Re-generate Caddy JSON configuration and push it via Admin API
async function syncCaddyConfig(instance, proxies) {
  const targetUrl = instance.url;
  
  // 1. Fetch current Caddy config
  let caddyConfig = {};
  try {
    const response = await axios.get(`${targetUrl}/config/`, { timeout: 3000 });
    caddyConfig = response.data || {};
  } catch (err) {
    console.log(`Could not fetch config from ${instance.name}, creating new structure:`, err.message);
    caddyConfig = {};
  }

  // Ensure standard Caddy structure exists
  if (!caddyConfig.apps) caddyConfig.apps = {};
  if (!caddyConfig.apps.http) caddyConfig.apps.http = {};
  if (!caddyConfig.apps.http.servers) caddyConfig.apps.http.servers = {};
  
  // Set default listener if not exists
  if (!caddyConfig.apps.http.servers.srv0) {
    caddyConfig.apps.http.servers.srv0 = {
      listen: [":80", ":443"],
      routes: []
    };
  }

  // Filter proxies belonging to this instance
  const instanceProxies = proxies.filter(p => p.instanceId === instance.id);

  // Generate routes
  const routes = instanceProxies.map(proxy => {
    const innerRoutes = [];

    // Route 1: SSO / Forward Auth (if enabled)
    if (proxy.ssoEnabled) {
      innerRoutes.push({
        handle: [
          {
            handler: "reverse_proxy",
            rewrite: {
              method: "GET",
              uri: "/forward-auth"
            },
            headers: {
              request: {
                set: {
                  "X-Forwarded-Method": ["{http.request.method}"],
                  "X-Forwarded-Uri": ["{http.request.uri}"],
                  "X-Forwarded-Host": ["{http.request.host}"]
                }
              }
            },
            handle_response: [
              {
                match: {
                  status_code: [2]
                },
                routes: [
                  {
                    handle: [
                      {
                        handler: "vars"
                      }
                    ]
                  }
                ]
              }
            ],
            upstreams: [
              {
                dial: cleanDialTarget(instance.ssoUpstreamDial || 'caddy-ui:3000')
              }
            ]
          }
        ]
      });
    }

    // Route 2: Actual Reverse Proxy to target
    innerRoutes.push({
      handle: [
        {
          handler: "reverse_proxy",
          upstreams: [
            {
              dial: cleanDialTarget(proxy.target)
            }
          ]
        }
      ]
    });

    return {
      match: [
        {
          host: [proxy.host]
        }
      ],
      handle: [
        {
          handler: "subroute",
          routes: innerRoutes
        }
      ],
      terminal: true
    };
  });

  // Assign routes
  caddyConfig.apps.http.servers.srv0.routes = routes;

  // 2. Post configuration back to Caddy
  console.log(`Pushing synced configuration to ${instance.name} (${targetUrl})...`);
  await axios.post(`${targetUrl}/load`, caddyConfig, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 5000
  });
}

// --- API ROUTES ---

// Helper to generate CSRF token
app.get('/api/csrf', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie('caddyui-csrf', token, {
    httpOnly: false, // Read by frontend JS
    secure: isHttps,
    sameSite: 'lax'
  });
  res.json({ csrfToken: token });
});

// Get connection status of Caddy Instances
app.get('/api/status', authenticateToken, async (req, res) => {
  const db = readDb();
  const statusList = [];

  for (const instance of db.instances) {
    try {
      const start = Date.now();
      await axios.get(`${instance.url}/config/`, { timeout: 2000 });
      const latency = Date.now() - start;
      statusList.push({ id: instance.id, online: true, latency });
    } catch (err) {
      statusList.push({ id: instance.id, online: false, error: err.message });
    }
  }

  res.json(statusList);
});

// Get raw Caddy active JSON configuration
app.get('/api/raw-config/:instanceId', authenticateToken, async (req, res) => {
  const db = readDb();
  const instance = db.instances.find(i => i.id === req.params.instanceId);
  if (!instance) {
    return res.status(404).json({ error: 'Instance not found' });
  }

  try {
    const response = await axios.get(`${instance.url}/config/`, { timeout: 3000 });
    res.json(response.data || {});
  } catch (err) {
    res.status(500).json({ error: `Failed to fetch raw config: ${err.message}` });
  }
});

// Instances API
app.get('/api/instances', authenticateToken, (req, res) => {
  const db = readDb();
  // Strip sensitive info if any
  res.json(db.instances);
});

app.post('/api/instances', authenticateToken, csrfProtection, (req, res) => {
  const { name, url, ssoUpstreamDial } = req.body;
  if (!name || !url) {
    return res.status(400).json({ error: 'Name and URL are required' });
  }

  const db = readDb();
  const newInstance = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(name),
    url: String(url),
    ssoUpstreamDial: ssoUpstreamDial ? String(ssoUpstreamDial) : 'caddy-ui:3000',
    isLocal: false
  };

  db.instances.push(newInstance);
  writeDb(db);
  res.status(201).json(newInstance);
});

app.delete('/api/instances/:id', authenticateToken, csrfProtection, (req, res) => {
  const db = readDb();
  const instance = db.instances.find(i => i.id === req.params.id);
  
  if (!instance) {
    return res.status(404).json({ error: 'Instance not found' });
  }
  if (instance.isLocal) {
    return res.status(400).json({ error: 'Cannot delete local Caddy instance' });
  }

  db.instances = db.instances.filter(i => i.id !== req.params.id);
  // Also clean up proxies belonging to deleted instance
  db.proxies = db.proxies.filter(p => p.instanceId !== req.params.id);
  writeDb(db);
  res.json({ message: 'Instance deleted successfully' });
});

// Proxies API
app.get('/api/proxies', authenticateToken, (req, res) => {
  const db = readDb();
  res.json(db.proxies);
});

app.post('/api/proxies', authenticateToken, csrfProtection, async (req, res) => {
  const { instanceId, host, target, ssoEnabled } = req.body;
  if (!instanceId || !host || !target) {
    return res.status(400).json({ error: 'Instance ID, Host, and Target are required' });
  }

  const db = readDb();
  const instance = db.instances.find(i => i.id === instanceId);
  if (!instance) {
    return res.status(404).json({ error: 'Caddy instance not found' });
  }

  const newProxy = {
    id: crypto.randomBytes(8).toString('hex'),
    instanceId: String(instanceId),
    host: String(host).trim().toLowerCase(),
    target: String(target).trim(),
    ssoEnabled: Boolean(ssoEnabled)
  };

  db.proxies.push(newProxy);
  writeDb(db);

  // Auto-sync config to Caddy
  try {
    await syncCaddyConfig(instance, db.proxies);
    res.status(201).json({ proxy: newProxy, synced: true });
  } catch (err) {
    res.status(201).json({ proxy: newProxy, synced: false, syncError: err.message });
  }
});

app.put('/api/proxies/:id', authenticateToken, csrfProtection, async (req, res) => {
  const { host, target, ssoEnabled } = req.body;
  const db = readDb();
  const proxyIndex = db.proxies.findIndex(p => p.id === req.params.id);

  if (proxyIndex === -1) {
    return res.status(404).json({ error: 'Proxy route not found' });
  }

  const updatedProxy = {
    ...db.proxies[proxyIndex],
    host: host ? String(host).trim().toLowerCase() : db.proxies[proxyIndex].host,
    target: target ? String(target).trim() : db.proxies[proxyIndex].target,
    ssoEnabled: ssoEnabled !== undefined ? Boolean(ssoEnabled) : db.proxies[proxyIndex].ssoEnabled
  };

  db.proxies[proxyIndex] = updatedProxy;
  writeDb(db);

  const instance = db.instances.find(i => i.id === updatedProxy.instanceId);
  if (instance) {
    try {
      await syncCaddyConfig(instance, db.proxies);
      res.json({ proxy: updatedProxy, synced: true });
    } catch (err) {
      res.json({ proxy: updatedProxy, synced: false, syncError: err.message });
    }
  } else {
    res.json({ proxy: updatedProxy, synced: false, syncError: 'Instance not found' });
  }
});

app.delete('/api/proxies/:id', authenticateToken, csrfProtection, async (req, res) => {
  const db = readDb();
  const proxy = db.proxies.find(p => p.id === req.params.id);

  if (!proxy) {
    return res.status(404).json({ error: 'Proxy route not found' });
  }

  db.proxies = db.proxies.filter(p => p.id !== req.params.id);
  writeDb(db);

  const instance = db.instances.find(i => i.id === proxy.instanceId);
  if (instance) {
    try {
      await syncCaddyConfig(instance, db.proxies);
      res.json({ message: 'Proxy deleted and configuration synced', synced: true });
    } catch (err) {
      res.json({ message: 'Proxy deleted but sync failed', synced: false, syncError: err.message });
    }
  } else {
    res.json({ message: 'Proxy deleted', synced: false });
  }
});

// Sync configuration endpoint
app.post('/api/sync/:instanceId', authenticateToken, csrfProtection, async (req, res) => {
  const db = readDb();
  const instance = db.instances.find(i => i.id === req.params.instanceId);
  if (!instance) {
    return res.status(404).json({ error: 'Instance not found' });
  }

  try {
    await syncCaddyConfig(instance, db.proxies);
    res.json({ message: 'Configuration successfully synced to Caddy' });
  } catch (err) {
    res.status(500).json({ error: `Sync failed: ${err.message}` });
  }
});

// Configure SSO settings
app.get('/api/oidc', authenticateToken, (req, res) => {
  const db = readDb();
  res.json({
    issuer: db.oidcConfig.issuer,
    clientId: db.oidcConfig.clientId,
    enabled: db.oidcConfig.enabled,
    redirectUri: db.oidcConfig.redirectUri
  });
});

app.post('/api/oidc', authenticateToken, csrfProtection, (req, res) => {
  const { issuer, clientId, clientSecret, redirectUri, enabled } = req.body;
  const db = readDb();

  db.oidcConfig = {
    issuer: issuer ? String(issuer) : db.oidcConfig.issuer,
    clientId: clientId ? String(clientId) : db.oidcConfig.clientId,
    clientSecret: clientSecret ? String(clientSecret) : db.oidcConfig.clientSecret,
    redirectUri: redirectUri ? String(redirectUri) : db.oidcConfig.redirectUri,
    enabled: enabled !== undefined ? Boolean(enabled) : db.oidcConfig.enabled
  };

  writeDb(db);
  res.json({ message: 'SSO configuration updated successfully' });
});

// Get admin credentials (username only for security)
app.get('/api/admin-credentials', authenticateToken, (req, res) => {
  const db = readDb();
  res.json({
    username: db.adminCredentials.username
  });
});

// Update admin credentials
app.post('/api/admin-credentials', authenticateToken, csrfProtection, (req, res) => {
  const { username, password } = req.body;
  
  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ error: 'Username must be at least 3 characters long.' });
  }

  if (password) {
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }
  }

  const db = readDb();
  db.adminCredentials.username = username.trim();
  if (password) {
    db.adminCredentials.passwordHash = bcrypt.hashSync(password, 10);
  }

  writeDb(db);
  res.json({ message: 'Admin credentials updated successfully' });
});

// --- AUTHENTICATION FLOWS ---

// Fallback password login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const db = readDb();
  const credentials = db.adminCredentials;

  if (username === credentials.username && bcrypt.compareSync(password, credentials.passwordHash)) {
    const userSession = { username, role: 'admin' };
    const token = jwt.sign(userSession, JWT_SECRET, { expiresIn: '8h' });

    const cookieName = getSessionCookieName(req);
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';

    res.cookie(cookieName, token, {
      httpOnly: true,
      secure: isHttps,
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    return res.json({ success: true, redirect: '/' });
  }

  res.status(401).json({ error: 'Invalid username or password' });
});

// Get public auth configuration (OIDC enabled status)
app.get('/auth/config', (req, res) => {
  const db = readDb();
  res.json({
    ssoEnabled: db.oidcConfig && db.oidcConfig.enabled
  });
});

// Redirect to OIDC provider
app.get('/auth/sso', async (req, res) => {
  const db = readDb();
  if (!db.oidcConfig.enabled || !db.oidcConfig.issuer || !db.oidcConfig.clientId) {
    return res.redirect('/login.html?error=SSO+not+configured');
  }

  const redirectUrl = req.query.redirect || '/';
  const state = crypto.randomBytes(16).toString('hex') + '|' + Buffer.from(redirectUrl).toString('base64');

  try {
    // Fetch OIDC configuration
    const discoveryUrl = `${db.oidcConfig.issuer}/.well-known/openid-configuration`;
    const discovery = await axios.get(discoveryUrl);
    const authEndpoint = discovery.data.authorization_endpoint;

    const queryParams = new URLSearchParams({
      response_type: 'code',
      client_id: db.oidcConfig.clientId,
      redirect_uri: db.oidcConfig.redirectUri,
      scope: 'openid email profile',
      state: state
    });

    res.redirect(`${authEndpoint}?${queryParams.toString()}`);
  } catch (err) {
    console.error('SSO discovery failed:', err);
    res.redirect('/login.html?error=SSO+discovery+failed');
  }
});

// OIDC callback
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const db = readDb();

  if (!code) {
    return res.redirect('/login.html?error=SSO+code+missing');
  }

  try {
    // Fetch OIDC configuration
    const discoveryUrl = `${db.oidcConfig.issuer}/.well-known/openid-configuration`;
    const discovery = await axios.get(discoveryUrl);
    const tokenEndpoint = discovery.data.token_endpoint;
    const userinfoEndpoint = discovery.data.userinfo_endpoint;

    // Exchange code for token
    const tokenResponse = await axios.post(tokenEndpoint, new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: db.oidcConfig.redirectUri,
      client_id: db.oidcConfig.clientId,
      client_secret: db.oidcConfig.clientSecret
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    const accessToken = tokenResponse.data.access_token;
    
    // Fetch user info using access token
    const userinfo = await axios.get(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const email = userinfo.data.email || userinfo.data.sub;
    const userSession = { username: email, role: 'admin', oidc: true };

    const token = jwt.sign(userSession, JWT_SECRET, { expiresIn: '8h' });
    const cookieName = getSessionCookieName(req);
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';

    res.cookie(cookieName, token, {
      httpOnly: true,
      secure: isHttps,
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000 // 8 hours
    });

    // Parse redirect URI from state
    let targetRedirect = '/';
    if (state) {
      const parts = state.split('|');
      if (parts[1]) {
        targetRedirect = Buffer.from(parts[1], 'base64').toString('utf-8');
      }
    }

    res.redirect(targetRedirect);
  } catch (err) {
    console.error('SSO Authentication failed:', err);
    res.redirect('/login.html?error=SSO+authentication+failed');
  }
});

// Logout
app.post('/auth/logout', (req, res) => {
  const cookieName = getSessionCookieName(req);
  res.clearCookie(cookieName);
  res.clearCookie('caddyui-csrf');
  res.json({ success: true });
});

// --- FORWARD AUTH GATEKEEPER ---
app.get('/forward-auth', (req, res) => {
  const cookieName = getSessionCookieName(req);
  const token = req.cookies[cookieName];

  // Original request metadata forwarded by Caddy
  const originalHost = req.headers['x-forwarded-host'] || req.headers['host'];
  const originalUri = req.headers['x-forwarded-uri'] || '/';
  const originalMethod = req.headers['x-forwarded-method'] || 'GET';

  if (!token) {
    return handleUnauthorized(req, res, originalHost, originalUri, originalMethod);
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return handleUnauthorized(req, res, originalHost, originalUri, originalMethod);
    }
    // Authenticated successfully! Return 200 OK to tell Caddy to pass request through
    res.setHeader('X-Auth-User', user.username);
    res.status(200).send('OK');
  });
});

function handleUnauthorized(req, res, host, uri, method) {
  // If it's a browser request (HTML view), redirect to SSO/login page
  const accept = req.headers['accept'] || '';
  if (accept.includes('text/html') && method === 'GET') {
    const originalUrl = `http${req.secure || req.headers['x-forwarded-proto'] === 'https' ? 's' : ''}://${host}${uri}`;
    const db = readDb();
    
    // Redirect to OIDC SSO auth if enabled, otherwise fallback login page
    if (db.oidcConfig.enabled) {
      return res.redirect(`/auth/sso?redirect=${encodeURIComponent(originalUrl)}`);
    } else {
      // Find the Caddy UI public URL (we assume we can redirect to this service's login page)
      // Since Caddy UI is accessible at host/login.html if matched, or we redirect to Caddy UI's port/domain
      return res.redirect(`/login.html?redirect=${encodeURIComponent(originalUrl)}`);
    }
  }

  // API/Ajax requests fail with 401
  res.status(401).send('Unauthorized');
}

// Serve Frontend Files
app.use(express.static(path.join(__dirname, 'public')));

// Fallback to serve index.html for dashboard routing
app.get('*', (req, res, next) => {
  // Exclude API and Auth routes
  if (req.path.startsWith('/api') || req.path.startsWith('/auth') || req.path === '/forward-auth') {
    return next();
  }
  
  // Verify token before serving index.html
  const cookieName = getSessionCookieName(req);
  const token = req.cookies[cookieName];
  if (!token) {
    return res.redirect('/login.html');
  }

  jwt.verify(token, JWT_SECRET, (err) => {
    if (err) {
      res.clearCookie(cookieName);
      return res.redirect('/login.html');
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error' });
});

// Start Server
app.listen(PORT, () => {
  console.log(`Caddy UI is running on port ${PORT}`);
});
