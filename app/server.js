import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { sign, verify } from 'hono/jwt';
import { serveStatic } from 'hono/bun';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const app = new Hono();

// Global middleware to handle HTTPS detection behind proxies/tunnels (like Cloudflare Tunnel)
app.use('*', async (c, next) => {
  const originalHeader = c.req.header;
  c.req.header = function (name) {
    if (name && name.toLowerCase() === 'x-forwarded-proto') {
      const xfp = originalHeader.call(c.req, name);
      const portalUrl = process.env.SSO_PORTAL_URL || '';
      return xfp === 'https' || portalUrl.startsWith('https://') ? 'https' : 'http';
    }
    return originalHeader.call(c.req, name);
  };
  await next();
});

const PORT = parseInt(process.env.PORT || '3000', 10);

// Database file setup
const DB_PATH = path.join(__dirname, 'data', 'db.json');

// Ensure database directory exists
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

let dbInMemory = null;

// Initialize database with defaults and perform migrations
async function initDb() {
  const defaultAdminUser = process.env.ADMIN_USER || 'admin';
  const defaultAdminPass = process.env.ADMIN_PASS || 'caddyui_admin_secure_pass_123';
  const defaultAdminPassHash = await Bun.password.hash(defaultAdminPass, { algorithm: 'bcrypt', cost: 10 });

  const defaultOidcIssuer = process.env.OIDC_ISSUER || '';
  const defaultOidcClientId = process.env.OIDC_CLIENT_ID || '';
  const defaultOidcClientSecret = process.env.OIDC_CLIENT_SECRET || '';
  const defaultOidcRedirectUri = process.env.OIDC_REDIRECT_URI || '';
  const defaultOidcEnabled = !!(defaultOidcIssuer && defaultOidcClientId);

  const defaultDbStructure = {
    instances: [
      {
        id: 'local',
        name: 'Local Caddy',
        url: 'http://127.0.0.1:2019',
        isLocal: true
      }
    ],
    proxies: [],
    users: [
      {
        id: 'admin',
        username: defaultAdminUser,
        passwordHash: defaultAdminPassHash,
        role: 'admin',
        ssoEnabled: false,
        ssoProviderId: null,
        twoFactorEnabled: false,
        twoFactorSecret: null
      }
    ],
    oidcProviders: [],
    dashboardAuthConfig: {
      ssoOnly: false,
      allowedProviderIds: []
    }
  };

  if (defaultOidcEnabled) {
    defaultDbStructure.oidcProviders.push({
      id: 'default',
      name: 'Default OIDC',
      issuer: defaultOidcIssuer,
      clientId: defaultOidcClientId,
      clientSecret: defaultOidcClientSecret,
      redirectUri: defaultOidcRedirectUri,
      enabled: true
    });
  }

  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDbStructure, null, 2), 'utf-8');
    dbInMemory = defaultDbStructure;
    return;
  }

  try {
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    let modified = false;

    // Migrate old structure
    if (db.adminCredentials) {
      if (!db.users) db.users = [];
      const hasAdmin = db.users.some(u => u.username === db.adminCredentials.username);
      if (!hasAdmin) {
        db.users.push({
          id: 'admin',
          username: db.adminCredentials.username,
          passwordHash: db.adminCredentials.passwordHash,
          role: 'admin',
          ssoEnabled: false,
          ssoProviderId: null,
          twoFactorEnabled: false,
          twoFactorSecret: null
        });
      }
      delete db.adminCredentials;
      modified = true;
    }

    if (db.oidcConfig) {
      if (!db.oidcProviders) db.oidcProviders = [];
      if (db.oidcConfig.issuer && db.oidcConfig.clientId) {
        const hasDefault = db.oidcProviders.some(p => p.id === 'default');
        if (!hasDefault) {
          db.oidcProviders.push({
            id: 'default',
            name: 'Default OIDC',
            issuer: db.oidcConfig.issuer,
            clientId: db.oidcConfig.clientId,
            clientSecret: db.oidcConfig.clientSecret,
            redirectUri: db.oidcConfig.redirectUri,
            enabled: db.oidcConfig.enabled
          });
        }
      }
      delete db.oidcConfig;
      modified = true;
    }

    // Ensure lists exist
    if (!db.users) {
      db.users = defaultDbStructure.users;
      modified = true;
    }
    if (!db.oidcProviders) {
      db.oidcProviders = defaultDbStructure.oidcProviders;
      modified = true;
    }
    if (!db.instances) {
      db.instances = defaultDbStructure.instances;
      modified = true;
    }
    if (!db.proxies) {
      db.proxies = defaultDbStructure.proxies;
      modified = true;
    }
    if (!db.dashboardAuthConfig) {
      db.dashboardAuthConfig = {
        ssoOnly: false,
        allowedProviderIds: []
      };
      modified = true;
    } else if (db.dashboardAuthConfig.defaultProviderId !== undefined) {
      db.dashboardAuthConfig.allowedProviderIds = db.dashboardAuthConfig.defaultProviderId
        ? [db.dashboardAuthConfig.defaultProviderId]
        : [];
      delete db.dashboardAuthConfig.defaultProviderId;
      modified = true;
    }

    if (modified) {
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
    }
    dbInMemory = db;
  } catch (err) {
    console.error('Error migrating DB:', err);
  }
}

function readDb() {
  if (!dbInMemory) {
    dbInMemory = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  }
  // Dynamically align the local instance URL with CADDY_ADMIN env var
  const localInstance = dbInMemory.instances.find(i => i.isLocal);
  if (localInstance) {
    const defaultCaddyAdmin = process.env.CADDY_ADMIN || '127.0.0.1:2019';
    localInstance.url = `http://${defaultCaddyAdmin}`;
  }
  return dbInMemory;
}

function writeDb(data) {
  dbInMemory = data;
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

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '';

function checkHttps(c) {
  const xfp = c.req.header('x-forwarded-proto');
  const portalUrl = process.env.SSO_PORTAL_URL || '';
  return xfp === 'https' || portalUrl.startsWith('https://');
}

// Get cookie name based on security context
function getSessionCookieName(c) {
  if (checkHttps(c)) {
    return COOKIE_DOMAIN ? '__Secure-caddyui-session' : '__Host-caddyui-session';
  }
  return 'caddyui-session';
}

function setSessionCookie(c, cookieName, token, _isHttps) {
  const isHttps = checkHttps(c);
  const cookieOpts = {
    path: '/',
    httpOnly: true,
    secure: isHttps,
    sameSite: 'Lax',
    maxAge: 8 * 60 * 60
  };
  if (COOKIE_DOMAIN) {
    cookieOpts.domain = COOKIE_DOMAIN;
  }
  setCookie(c, cookieName, token, cookieOpts);
}

function removeSessionCookie(c, cookieName, _isHttps) {
  const isHttps = checkHttps(c);
  const cookieOpts = { path: '/', secure: isHttps };
  if (COOKIE_DOMAIN) {
    cookieOpts.domain = COOKIE_DOMAIN;
  }
  deleteCookie(c, cookieName, cookieOpts);
}

// --- Native TOTP (2FA) Helper Functions (RFC 6238) ---
function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let cleanStr = base32.replace(/=+$/, '').toUpperCase();
  let bits = '';
  for (let i = 0; i < cleanStr.length; i++) {
    const val = alphabet.indexOf(cleanStr[i]);
    if (val === -1) throw new Error('Invalid base32 character');
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotp(secret, timeOffset = 0) {
  const key = base32Decode(secret);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + timeOffset;

  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(counter, 4);

  const hmac = crypto.createHmac('sha1', key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const codeBin = ((hmac[offset] & 0x7f) << 24) |
                  ((hmac[offset + 1] & 0xff) << 16) |
                  ((hmac[offset + 2] & 0xff) << 8) |
                  (hmac[offset + 3] & 0xff);

  const code = codeBin % 1000000;
  return String(code).padStart(6, '0');
}

function verifyTotp(secret, code, windowSize = 1) {
  if (!secret || !code) return false;
  for (let i = -windowSize; i <= windowSize; i++) {
    if (generateTotp(secret, i) === code) {
      return true;
    }
  }
  return false;
}

function generateTotpSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  const bytes = crypto.randomBytes(10);
  for (let i = 0; i < bytes.length; i++) {
    secret += alphabet[bytes[i] % 32];
  }
  return secret;
}

// Authentication Middlewares
const authenticateToken = async (c, next) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);

  if (!token) {
    return c.json({ error: 'Authentication required' }, 401);
  }

  try {
    const decoded = await verify(token, JWT_SECRET, 'HS256');
    c.set('user', decoded);
    await next();
  } catch (err) {
        const cookieName = getSessionCookieName(c);
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    removeSessionCookie(c, cookieName, isHttps);
    return c.json({ error: 'Session expired or invalid' }, 401);
  }
};

// CSRF Protection Middleware (Double Submit Cookie)
const csrfProtection = async (c, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(c.req.method)) {
    return await next();
  }

  const csrfCookie = getCookie(c, 'caddyui-csrf');
  const csrfHeader = c.req.header('x-csrf-token');

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return c.json({ error: 'Invalid or missing CSRF token' }, 403);
  }
  await next();
};

// Helper to sanitize dial targets for Caddy
function cleanDialTarget(target) {
  let clean = target.replace(/^(https?:\/\/)/, '');
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
  
  let caddyConfig = {};
  try {
    const response = await fetch(`${targetUrl}/config/`, { signal: AbortSignal.timeout(3000) });
    if (response.ok) {
      caddyConfig = await response.json();
    }
  } catch (err) {
    console.log(`Could not fetch config from ${instance.name}, creating new structure:`, err.message);
  }

  if (!caddyConfig.apps) caddyConfig.apps = {};
  if (!caddyConfig.apps.http) caddyConfig.apps.http = {};
  if (!caddyConfig.apps.http.servers) caddyConfig.apps.http.servers = {};
  
  if (!caddyConfig.apps.http.servers.srv0) {
    caddyConfig.apps.http.servers.srv0 = {
      listen: [":80", ":443"],
      routes: []
    };
  }

  const instanceProxies = proxies.filter(p => p.instanceId === instance.id);

  const routes = instanceProxies.map(proxy => {
    const innerRoutes = [];
    const isSso = proxy.authMode === 'sso' || (proxy.authMode === undefined && proxy.ssoEnabled);
    const isBasic = proxy.authMode === 'basic';

    if (isSso) {
      innerRoutes.push({
        handle: [
          {
            handler: "authentication",
            providers: {
              jwt: {
                sign_key: Buffer.from(JWT_SECRET).toString('base64'),
                sign_alg: "HS256",
                from_cookies: ["__Secure-caddyui-session", "__Host-caddyui-session", "caddyui-session"]
              }
            }
          }
        ]
      });
    }

    if (isBasic && proxy.basicAuthCredentials && proxy.basicAuthCredentials.length > 0) {
      innerRoutes.push({
        handle: [
          {
            handler: "basic_auth",
            accounts: proxy.basicAuthCredentials.map(cred => ({
              username: cred.username,
              password: cred.passwordHash
            }))
          }
        ]
      });
    }

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

  caddyConfig.apps.http.servers.srv0.routes = routes;

  const portalUrl = process.env.SSO_PORTAL_URL ? process.env.SSO_PORTAL_URL.replace(/\/$/, '') : '';
  const redirectScheme = portalUrl.startsWith('https://') ? 'https' : '{http.request.scheme}';
  caddyConfig.apps.http.servers.srv0.handle_errors = [
    {
      match: [
        {
          method: ["GET"],
          header: {
            "Accept": ["*text/html*"]
          },
          expression: "{err.status_code} == 401"
        }
      ],
      handle: [
        {
          handler: "static_response",
          status_code: 302,
          headers: {
            "Location": [`${portalUrl}/login?redirect=${redirectScheme}://{http.request.host}{http.request.uri}`]
          }
        }
      ]
    }
  ];

  console.log(`Pushing synced configuration to ${instance.name} (${targetUrl})...`);
  const response = await fetch(`${targetUrl}/load`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(caddyConfig),
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) {
    throw new Error(`Caddy load returned status ${response.status}`);
  }
}

// --- API ROUTES ---

app.get('/api/csrf', (c) => {
  const token = crypto.randomBytes(32).toString('hex');
  const isHttps = checkHttps(c);
  setCookie(c, 'caddyui-csrf', token, {
    path: '/',
    httpOnly: false,
    secure: isHttps,
    sameSite: 'Lax'
  });
  return c.json({ csrfToken: token });
});

app.get('/api/me', authenticateToken, (c) => {
  const sessionUser = c.get('user');
  const db = readDb();
  const user = db.users.find(u => u.username.toLowerCase() === sessionUser.username.toLowerCase());
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  return c.json({
    id: user.id,
    username: user.username,
    role: user.role,
    ssoEnabled: user.ssoEnabled,
    twoFactorEnabled: user.twoFactorEnabled
  });
});

app.get('/api/oidc-providers', authenticateToken, (c) => {
  const db = readDb();
  const sanitized = db.oidcProviders.map(p => ({
    id: p.id,
    name: p.name,
    issuer: p.issuer,
    clientId: p.clientId,
    redirectUri: p.redirectUri,
    enabled: p.enabled
  }));
  return c.json(sanitized);
});

app.post('/api/oidc-providers', authenticateToken, csrfProtection, async (c) => {
  const { name, issuer, clientId, clientSecret, redirectUri, enabled } = await c.req.json();
  if (!name || !issuer || !clientId || !redirectUri) {
    return c.json({ error: 'Name, Issuer, Client ID, and Redirect URI are required' }, 400);
  }
  const db = readDb();
  const newProvider = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(name).trim(),
    issuer: String(issuer).trim(),
    clientId: String(clientId).trim(),
    clientSecret: clientSecret ? String(clientSecret).trim() : '',
    redirectUri: String(redirectUri).trim(),
    enabled: enabled !== undefined ? Boolean(enabled) : true
  };
  db.oidcProviders.push(newProvider);
  writeDb(db);
  return c.json(newProvider, 201);
});

app.put('/api/oidc-providers/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { name, issuer, clientId, clientSecret, redirectUri, enabled } = await c.req.json();
  const db = readDb();
  const idx = db.oidcProviders.findIndex(p => p.id === id);
  if (idx === -1) {
    return c.json({ error: 'SSO Provider not found' }, 404);
  }
  const current = db.oidcProviders[idx];
  db.oidcProviders[idx] = {
    ...current,
    name: name ? String(name).trim() : current.name,
    issuer: issuer ? String(issuer).trim() : current.issuer,
    clientId: clientId ? String(clientId).trim() : current.clientId,
    clientSecret: clientSecret !== undefined ? String(clientSecret).trim() : current.clientSecret,
    redirectUri: redirectUri ? String(redirectUri).trim() : current.redirectUri,
    enabled: enabled !== undefined ? Boolean(enabled) : current.enabled
  };
  writeDb(db);
  return c.json(db.oidcProviders[idx]);
});

app.delete('/api/oidc-providers/:id', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  db.oidcProviders = db.oidcProviders.filter(p => p.id !== id);
  writeDb(db);
  return c.json({ message: 'SSO Provider deleted' });
});

app.get('/api/users', authenticateToken, (c) => {
  const db = readDb();
  const sanitized = db.users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    ssoEnabled: u.ssoEnabled,
    ssoProviderId: u.ssoProviderId,
    twoFactorEnabled: u.twoFactorEnabled
  }));
  return c.json(sanitized);
});

app.post('/api/users', authenticateToken, csrfProtection, async (c) => {
  const { username, password, role, ssoEnabled, ssoProviderId } = await c.req.json();
  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return c.json({ error: 'Username is required and must be at least 3 characters.' }, 400);
  }
  const db = readDb();
  const exists = db.users.some(u => u.username.toLowerCase() === username.trim().toLowerCase());
  if (exists) {
    return c.json({ error: 'Username already exists' }, 400);
  }
  
  let passwordHash = '';
  if (password) {
    passwordHash = await Bun.password.hash(password, { algorithm: 'bcrypt', cost: 10 });
  } else if (!ssoEnabled) {
    return c.json({ error: 'Password is required when SSO is disabled.' }, 400);
  }

  const newUser = {
    id: crypto.randomBytes(8).toString('hex'),
    username: String(username).trim(),
    passwordHash,
    role: role === 'admin' ? 'admin' : 'viewer',
    ssoEnabled: Boolean(ssoEnabled),
    ssoProviderId: ssoProviderId ? String(ssoProviderId) : null,
    twoFactorEnabled: false,
    twoFactorSecret: null
  };
  db.users.push(newUser);
  writeDb(db);
  return c.json({
    id: newUser.id,
    username: newUser.username,
    role: newUser.role,
    ssoEnabled: newUser.ssoEnabled,
    ssoProviderId: newUser.ssoProviderId,
    twoFactorEnabled: newUser.twoFactorEnabled
  }, 201);
});

app.put('/api/users/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { username, password, role, ssoEnabled, ssoProviderId } = await c.req.json();
  const db = readDb();
  const idx = db.users.findIndex(u => u.id === id);
  if (idx === -1) {
    return c.json({ error: 'User not found' }, 404);
  }

  const current = db.users[idx];
  const currentUser = c.get('user');
  if (current.id === 'admin' && currentUser.username !== current.username) {
    return c.json({ error: 'Only the default admin can modify their account.' }, 403);
  }

  if (username && username.trim().toLowerCase() !== current.username.toLowerCase()) {
    const exists = db.users.some(u => u.username.toLowerCase() === username.trim().toLowerCase());
    if (exists) {
      return c.json({ error: 'Username already in use' }, 400);
    }
    current.username = String(username).trim();
  }

  if (password) {
    current.passwordHash = await Bun.password.hash(password, { algorithm: 'bcrypt', cost: 10 });
  }

  if (role) {
    current.role = role === 'admin' ? 'admin' : 'viewer';
  }

  if (ssoEnabled !== undefined) {
    current.ssoEnabled = Boolean(ssoEnabled);
  }

  if (ssoProviderId !== undefined) {
    current.ssoProviderId = ssoProviderId ? String(ssoProviderId) : null;
  }

  writeDb(db);
  return c.json({
    id: current.id,
    username: current.username,
    role: current.role,
    ssoEnabled: current.ssoEnabled,
    ssoProviderId: current.ssoProviderId,
    twoFactorEnabled: current.twoFactorEnabled
  });
});

app.delete('/api/users/:id', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const user = db.users.find(u => u.id === id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  if (user.id === 'admin') {
    return c.json({ error: 'Cannot delete the default admin account.' }, 400);
  }
  db.users = db.users.filter(u => u.id !== id);
  writeDb(db);
  return c.json({ message: 'User deleted successfully' });
});

app.post('/api/users/:id/2fa/force-enable', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const user = db.users.find(u => u.id === id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  const secret = generateTotpSecret();
  user.twoFactorEnabled = true;
  user.twoFactorSecret = secret;
  delete user.twoFactorTempSecret;
  writeDb(db);
  return c.json({ success: true, secret });
});

app.post('/api/users/:id/2fa/setup', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const user = db.users.find(u => u.id === id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  const secret = generateTotpSecret();
  user.twoFactorTempSecret = secret;
  writeDb(db);

  const otpauthUrl = `otpauth://totp/CaddyUI:${encodeURIComponent(user.username)}?secret=${secret}&issuer=CaddyUI`;
  return c.json({ secret, otpauthUrl });
});

app.post('/api/users/:id/2fa/enable', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { code } = await c.req.json();
  if (!code) {
    return c.json({ error: 'Verification code is required' }, 400);
  }
  const db = readDb();
  const user = db.users.find(u => u.id === id);
  if (!user || !user.twoFactorTempSecret) {
    return c.json({ error: '2FA setup was not initiated.' }, 400);
  }

  const verified = verifyTotp(user.twoFactorTempSecret, code);
  if (!verified) {
    return c.json({ error: 'Invalid verification code.' }, 400);
  }

  user.twoFactorEnabled = true;
  user.twoFactorSecret = user.twoFactorTempSecret;
  delete user.twoFactorTempSecret;
  writeDb(db);
  return c.json({ success: true, message: '2FA enabled successfully!' });
});

app.post('/api/users/:id/2fa/disable', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const user = db.users.find(u => u.id === id);
  if (!user) {
    return c.json({ error: 'User not found' }, 404);
  }
  user.twoFactorEnabled = false;
  user.twoFactorSecret = null;
  delete user.twoFactorTempSecret;
  writeDb(db);
  return c.json({ success: true, message: '2FA disabled successfully!' });
});

app.get('/api/status', authenticateToken, async (c) => {
  const db = readDb();

  const statusPromises = db.instances.map(async (instance) => {
    try {
      const start = Date.now();
      await fetch(`${instance.url}/config/`, { signal: AbortSignal.timeout(2000) });
      const latency = Date.now() - start;
      return { id: instance.id, online: true, latency };
    } catch (err) {
      return { id: instance.id, online: false, error: err.message };
    }
  });

  const statusList = await Promise.all(statusPromises);
  return c.json(statusList);
});

app.get('/api/raw-config/:instanceId', authenticateToken, async (c) => {
  const instanceId = c.req.param('instanceId');
  const db = readDb();
  const instance = db.instances.find(i => i.id === instanceId);
  if (!instance) {
    return c.json({ error: 'Instance not found' }, 404);
  }

  try {
    const response = await fetch(`${instance.url}/config/`, { signal: AbortSignal.timeout(3000) });
    if (response.ok) {
      return c.json(await response.json());
    } else {
      return c.json({ error: `Failed to fetch raw config: ${response.statusText}` }, 500);
    }
  } catch (err) {
    return c.json({ error: `Failed to fetch raw config: ${err.message}` }, 500);
  }
});

app.get('/api/instances', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.instances);
});

app.post('/api/instances', authenticateToken, csrfProtection, async (c) => {
  const { name, url } = await c.req.json();
  if (!name || !url) {
    return c.json({ error: 'Name and URL are required' }, 400);
  }

  const db = readDb();
  const newInstance = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(name),
    url: String(url),
    isLocal: false
  };

  db.instances.push(newInstance);
  writeDb(db);
  return c.json(newInstance, 201);
});

app.delete('/api/instances/:id', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const instance = db.instances.find(i => i.id === id);
  
  if (!instance) {
    return c.json({ error: 'Instance not found' }, 404);
  }
  if (instance.isLocal) {
    return c.json({ error: 'Cannot delete local Caddy instance' }, 400);
  }

  db.instances = db.instances.filter(i => i.id !== id);
  db.proxies = db.proxies.filter(p => p.instanceId !== id);
  writeDb(db);
  return c.json({ message: 'Instance deleted successfully' });
});

app.get('/api/proxies', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.proxies);
});

app.post('/api/proxies', authenticateToken, csrfProtection, async (c) => {
  const { instanceId, host, target, ssoEnabled, authMode, ssoProviderId, basicAuthCredentials } = await c.req.json();
  if (!instanceId || !host || !target) {
    return c.json({ error: 'Instance ID, Host, and Target are required' }, 400);
  }

  const db = readDb();
  const instance = db.instances.find(i => i.id === instanceId);
  if (!instance) {
    return c.json({ error: 'Caddy instance not found' }, 404);
  }

  let credentials = [];
  if (basicAuthCredentials && Array.isArray(basicAuthCredentials)) {
    credentials = await Promise.all(basicAuthCredentials.map(async cred => ({
      username: String(cred.username).trim(),
      passwordHash: cred.password ? await Bun.password.hash(cred.password, { algorithm: 'bcrypt', cost: 10 }) : ''
    })));
  }

  const newProxy = {
    id: crypto.randomBytes(8).toString('hex'),
    instanceId: String(instanceId),
    host: String(host).trim().toLowerCase(),
    target: String(target).trim(),
    ssoEnabled: Boolean(ssoEnabled),
    authMode: authMode || 'none',
    ssoProviderId: ssoProviderId || null,
    basicAuthCredentials: credentials
  };

  db.proxies.push(newProxy);
  writeDb(db);

  try {
    await syncCaddyConfig(instance, db.proxies);
    return c.json({ proxy: newProxy, synced: true }, 201);
  } catch (err) {
    return c.json({ proxy: newProxy, synced: false, syncError: err.message }, 201);
  }
});

app.put('/api/proxies/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { host, target, ssoEnabled, authMode, ssoProviderId, basicAuthCredentials } = await c.req.json();
  const db = readDb();
  const proxyIndex = db.proxies.findIndex(p => p.id === id);

  if (proxyIndex === -1) {
    return c.json({ error: 'Proxy route not found' }, 404);
  }

  const currentProxy = db.proxies[proxyIndex];

  let credentials = currentProxy.basicAuthCredentials || [];
  if (basicAuthCredentials && Array.isArray(basicAuthCredentials)) {
    credentials = await Promise.all(basicAuthCredentials.map(async cred => {
      const existing = (currentProxy.basicAuthCredentials || []).find(c => c.username === cred.username);
      return {
        username: String(cred.username).trim(),
        passwordHash: cred.password ? await Bun.password.hash(cred.password, { algorithm: 'bcrypt', cost: 10 }) : (existing ? existing.passwordHash : '')
      };
    }));
  }

  const updatedProxy = {
    ...currentProxy,
    host: host ? String(host).trim().toLowerCase() : currentProxy.host,
    target: target ? String(target).trim() : currentProxy.target,
    ssoEnabled: ssoEnabled !== undefined ? Boolean(ssoEnabled) : currentProxy.ssoEnabled,
    authMode: authMode !== undefined ? authMode : currentProxy.authMode,
    ssoProviderId: ssoProviderId !== undefined ? ssoProviderId : currentProxy.ssoProviderId,
    basicAuthCredentials: credentials
  };

  db.proxies[proxyIndex] = updatedProxy;
  writeDb(db);

  const instance = db.instances.find(i => i.id === updatedProxy.instanceId);
  if (instance) {
    try {
      await syncCaddyConfig(instance, db.proxies);
      return c.json({ proxy: updatedProxy, synced: true });
    } catch (err) {
      return c.json({ proxy: updatedProxy, synced: false, syncError: err.message });
    }
  } else {
    return c.json({ proxy: updatedProxy, synced: false, syncError: 'Instance not found' });
  }
});

app.delete('/api/proxies/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const proxy = db.proxies.find(p => p.id === id);

  if (!proxy) {
    return c.json({ error: 'Proxy route not found' }, 404);
  }

  db.proxies = db.proxies.filter(p => p.id !== id);
  writeDb(db);

  const instance = db.instances.find(i => i.id === proxy.instanceId);
  if (instance) {
    try {
      await syncCaddyConfig(instance, db.proxies);
      return c.json({ message: 'Proxy route deleted and synced', synced: true });
    } catch (err) {
      return c.json({ message: 'Proxy route deleted locally, sync failed', synced: false, syncError: err.message });
    }
  }
  return c.json({ message: 'Proxy route deleted locally', synced: false });
});

app.post('/api/sync/:instanceId', authenticateToken, csrfProtection, async (c) => {
  const instanceId = c.req.param('instanceId');
  const db = readDb();
  const instance = db.instances.find(i => i.id === instanceId);
  if (!instance) {
    return c.json({ error: 'Instance not found' }, 404);
  }

  try {
    await syncCaddyConfig(instance, db.proxies);
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: err.message }, 500);
  }
});

app.get('/api/oidc', authenticateToken, (c) => {
  const db = readDb();
  const defaultProvider = db.oidcProviders.find(p => p.id === 'default');
  return c.json({
    enabled: defaultProvider ? defaultProvider.enabled : false,
    issuer: defaultProvider ? defaultProvider.issuer : '',
    clientId: defaultProvider ? defaultProvider.clientId : '',
    redirectUri: defaultProvider ? defaultProvider.redirectUri : ''
  });
});

app.post('/api/oidc', authenticateToken, csrfProtection, async (c) => {
  const { enabled, issuer, clientId, clientSecret, redirectUri } = await c.req.json();
  const db = readDb();
  let idx = db.oidcProviders.findIndex(p => p.id === 'default');
  if (idx === -1) {
    const defaultProvider = {
      id: 'default',
      name: 'Default OIDC',
      issuer: issuer || '',
      clientId: clientId || '',
      clientSecret: clientSecret || '',
      redirectUri: redirectUri || '',
      enabled: Boolean(enabled)
    };
    db.oidcProviders.push(defaultProvider);
  } else {
    const current = db.oidcProviders[idx];
    db.oidcProviders[idx] = {
      ...current,
      issuer: issuer !== undefined ? String(issuer).trim() : current.issuer,
      clientId: clientId !== undefined ? String(clientId).trim() : current.clientId,
      clientSecret: clientSecret !== undefined ? String(clientSecret).trim() : current.clientSecret,
      redirectUri: redirectUri !== undefined ? String(redirectUri).trim() : current.redirectUri,
      enabled: enabled !== undefined ? Boolean(enabled) : current.enabled
    };
  }
  writeDb(db);
  return c.json({ success: true });
});

app.get('/api/admin-credentials', authenticateToken, (c) => {
  const db = readDb();
  const admin = db.users.find(u => u.id === 'admin');
  return c.json({ username: admin ? admin.username : 'admin' });
});

app.post('/api/admin-credentials', authenticateToken, csrfProtection, async (c) => {
  const { username, password } = await c.req.json();
  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return c.json({ error: 'Username must be at least 3 characters.' }, 400);
  }

  const db = readDb();
  const adminIdx = db.users.findIndex(u => u.id === 'admin');
  if (adminIdx === -1) {
    return c.json({ error: 'Admin user not found' }, 404);
  }

  db.users[adminIdx].username = String(username).trim();
  if (password) {
    db.users[adminIdx].passwordHash = await Bun.password.hash(password, { algorithm: 'bcrypt', cost: 10 });
  }
  writeDb(db);
  return c.json({ success: true });
});

app.get('/api/dashboard-auth-config', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.dashboardAuthConfig || { ssoOnly: false, allowedProviderIds: [] });
});

app.post('/api/dashboard-auth-config', authenticateToken, csrfProtection, async (c) => {
  const { ssoOnly, allowedProviderIds } = await c.req.json();
  const db = readDb();
  db.dashboardAuthConfig = {
    ssoOnly: Boolean(ssoOnly),
    allowedProviderIds: Array.isArray(allowedProviderIds) ? allowedProviderIds : []
  };
  writeDb(db);
  return c.json({ success: true });
});

app.post('/auth/login', async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password) {
    return c.json({ error: 'Username and password are required' }, 400);
  }

  const db = readDb();
  const dashConfig = db.dashboardAuthConfig || { ssoOnly: false, allowedProviderIds: [] };
  if (dashConfig.ssoOnly && username.toLowerCase() !== 'admin') {
    return c.json({ error: 'This dashboard is configured for SSO login only.' }, 403);
  }

  const user = db.users.find(u => u.username.toLowerCase() === username.trim().toLowerCase());

  if (!user) {
    return c.json({ error: 'Invalid username or password' }, 401);
  }

  if (user.ssoEnabled && !user.passwordHash) {
    return c.json({ error: 'This account is configured to sign in with SSO only.' }, 401);
  }

  const matched = await Bun.password.verify(password, user.passwordHash);
  if (!matched) {
    return c.json({ error: 'Invalid username or password' }, 401);
  }

  if (user.twoFactorEnabled) {
    const pendingPayload = { userId: user.id, username: user.username, pending2fa: true, exp: Math.floor(Date.now() / 1000) + 10 * 60 };
    const pendingToken = await sign(pendingPayload, JWT_SECRET, 'HS256');

    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    setCookie(c, 'caddyui-pending2fa', pendingToken, {
      path: '/',
      httpOnly: true,
      secure: isHttps,
      sameSite: 'Lax',
      maxAge: 10 * 60
    });

    return c.json({ success: true, pending2fa: true, redirect: '/login-2fa' });
  }

  const userSession = { username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60 };
  const token = await sign(userSession, JWT_SECRET, 'HS256');

  const cookieName = getSessionCookieName(c);
  const isHttps = c.req.header('x-forwarded-proto') === 'https';

  setSessionCookie(c, cookieName, token, isHttps);

  return c.json({ success: true, redirect: '/' });
});

app.post('/auth/verify-2fa', async (c) => {
  const { code } = await c.req.json();
  if (!code) {
    return c.json({ error: 'Code is required' }, 400);
  }

  const pendingToken = getCookie(c, 'caddyui-pending2fa');
  if (!pendingToken) {
    return c.json({ error: 'No pending 2FA authentication found' }, 401);
  }

  try {
    const decoded = await verify(pendingToken, JWT_SECRET, 'HS256');
    if (!decoded.pending2fa) {
      deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
      return c.json({ error: 'Invalid or expired 2FA session' }, 401);
    }

    const db = readDb();
    const user = db.users.find(u => u.id === decoded.userId);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
      return c.json({ error: '2FA is not enabled for this user' }, 400);
    }

    const verified = verifyTotp(user.twoFactorSecret, code);
    if (!verified) {
      return c.json({ error: 'Invalid verification code' }, 400);
    }

    const userSession = { username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60 };
    const token = await sign(userSession, JWT_SECRET, 'HS256');

    const cookieName = getSessionCookieName(c);
    const isHttps = c.req.header('x-forwarded-proto') === 'https';

    deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
    setSessionCookie(c, cookieName, token, isHttps);

    return c.json({ success: true, redirect: '/' });
  } catch (err) {
    deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: c.req.header('x-forwarded-proto') === 'https' });
    return c.json({ error: 'Invalid or expired 2FA session' }, 401);
  }
});

app.get('/auth/config', (c) => {
  const db = readDb();
  const enabledProviders = db.oidcProviders.filter(p => p.enabled);
  const dashConfig = db.dashboardAuthConfig || { ssoOnly: false, allowedProviderIds: [] };
  const allowedIds = dashConfig.allowedProviderIds || [];
  
  // Filter OIDC providers allowed for dashboard login.
  // If allowedIds is empty, we default to showing all enabled providers.
  const allowedProviders = allowedIds.length > 0
    ? enabledProviders.filter(p => allowedIds.includes(p.id))
    : enabledProviders;

  return c.json({
    ssoEnabled: allowedProviders.length > 0,
    providers: allowedProviders.map(p => ({ id: p.id, name: p.name })),
    ssoOnly: dashConfig.ssoOnly,
    allowedProviderIds: allowedIds
  });
});

app.get('/auth/sso', async (c) => {
  const providerId = c.req.query('providerId');
  const redirectParam = c.req.query('redirect') || '/';

  const db = readDb();
  let provider = null;
  if (providerId) {
    provider = db.oidcProviders.find(p => p.id === providerId && p.enabled);
  } else {
    provider = db.oidcProviders.find(p => p.enabled);
  }

  if (!provider) {
    return c.redirect(`/login?error=No+enabled+SSO+provider+found`);
  }

  try {
    const discoveryUrl = `${provider.issuer}/.well-known/openid-configuration`;
    const discRes = await fetch(discoveryUrl);
    if (!discRes.ok) throw new Error(`OIDC configuration discovery failed`);
    const discovery = await discRes.json();
    const authEndpoint = discovery.authorization_endpoint;

    const nonce = crypto.randomBytes(16).toString('hex');
    const state = `${provider.id}|${nonce}|${Buffer.from(redirectParam).toString('base64')}`;

    const params = new URLSearchParams({
      response_type: 'code',
      scope: 'openid email profile',
      client_id: provider.clientId,
      redirect_uri: provider.redirectUri,
      state
    });

    return c.redirect(`${authEndpoint}?${params.toString()}`);
  } catch (err) {
    console.error('SSO initialization failed:', err);
    return c.redirect(`/login?error=Failed+to+initialize+SSO+authentication`);
  }
});

app.get('/auth/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');

  if (!code || !state) {
    return c.redirect('/login?error=Invalid+OAuth+callback+parameters');
  }

  const parts = state.split('|');
  const providerId = parts[0];
  const db = readDb();
  const provider = db.oidcProviders.find(p => p.id === providerId);
  if (!provider) {
    return c.redirect('/login?error=OIDC+provider+not+found');
  }

  try {
    const discoveryUrl = `${provider.issuer}/.well-known/openid-configuration`;
    const discRes = await fetch(discoveryUrl);
    const discovery = await discRes.json();
    const tokenEndpoint = discovery.token_endpoint;
    const userinfoEndpoint = discovery.userinfo_endpoint;

    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: provider.redirectUri,
        client_id: provider.clientId,
        client_secret: provider.clientSecret
      })
    });

    if (!tokenResponse.ok) {
      throw new Error(`Token exchange failed: ${tokenResponse.statusText}`);
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    const userinfoResponse = await fetch(userinfoEndpoint, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    const userinfo = await userinfoResponse.json();

    const email = userinfo.email || userinfo.sub;
    const user = db.users.find(u => u.username.toLowerCase() === email.toLowerCase());
    if (!user) {
      return c.redirect(`/login?error=User+${encodeURIComponent(email)}+not+registered+in+system`);
    }

    if (user.ssoEnabled && user.ssoProviderId && user.ssoProviderId !== provider.id) {
      return c.redirect('/login?error=SSO+provider+mismatch+for+this+user');
    }

    let targetRedirect = '/';
    if (parts[2]) {
      targetRedirect = Buffer.from(parts[2], 'base64').toString('utf-8');
    }

    if (user.twoFactorEnabled) {
      const pendingPayload = { userId: user.id, username: user.username, pending2fa: true, exp: Math.floor(Date.now() / 1000) + 10 * 60 };
      const pendingToken = await sign(pendingPayload, JWT_SECRET, 'HS256');
      
      const isHttps = c.req.header('x-forwarded-proto') === 'https';
      setCookie(c, 'caddyui-pending2fa', pendingToken, {
        path: '/',
        httpOnly: true,
        secure: isHttps,
        sameSite: 'Lax',
        maxAge: 10 * 60
      });

      return c.redirect(`/login-2fa?redirect=${encodeURIComponent(targetRedirect)}`);
    }

    const userSession = { username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60 };
    const token = await sign(userSession, JWT_SECRET, 'HS256');
    const cookieName = getSessionCookieName(c);
    const isHttps = c.req.header('x-forwarded-proto') === 'https';

    setSessionCookie(c, cookieName, token, isHttps);

    return c.redirect(targetRedirect);
  } catch (err) {
    console.error('SSO Authentication failed:', err);
    return c.redirect(`/login?error=${encodeURIComponent(err.message)}`);
  }
});

app.post('/auth/logout', (c) => {
  const cookieName = getSessionCookieName(c);
  const isHttps = c.req.header('x-forwarded-proto') === 'https';
  removeSessionCookie(c, cookieName, isHttps);
  return c.json({ success: true });
});

app.get('/forward-auth', async (c) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);

  const originalHost = c.req.header('x-forwarded-host');
  const originalUri = c.req.header('x-forwarded-uri') || '/';
  const originalMethod = c.req.header('x-forwarded-method') || 'GET';

  const db = readDb();
  const matchedProxy = db.proxies.find(p => p.host === originalHost);

  if (!token) {
    return handleUnauthorized(c, originalHost, originalUri, originalMethod, matchedProxy);
  }

  try {
    const user = await verify(token, JWT_SECRET, 'HS256');
    c.header('X-Auth-User', user.username);
    return c.text('OK');
  } catch (err) {
    return handleUnauthorized(c, originalHost, originalUri, originalMethod, matchedProxy);
  }
});

async function handleUnauthorized(c, host, uri, method, proxy) {
  const accept = c.req.header('accept') || '';
  if (accept.includes('text/html') && method === 'GET') {
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    const originalUrl = `http${isHttps ? 's' : ''}://${host}${uri}`;
    const db = readDb();
    
    let provider = null;
    if (proxy && proxy.ssoProviderId) {
      provider = db.oidcProviders.find(p => p.id === proxy.ssoProviderId && p.enabled);
    }
    if (!provider) {
      provider = db.oidcProviders.find(p => p.enabled);
    }

    const portalUrl = process.env.SSO_PORTAL_URL ? process.env.SSO_PORTAL_URL.replace(/\/$/, '') : '';

    if (provider) {
      return c.redirect(`${portalUrl}/auth/sso?providerId=${provider.id}&redirect=${encodeURIComponent(originalUrl)}`);
    } else {
      return c.redirect(`${portalUrl}/login?redirect=${encodeURIComponent(originalUrl)}`);
    }
  }

  return c.text('Unauthorized', 401);
}

// Route to serve login page
app.get('/login', async (c) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);
  if (token) {
    try {
      await verify(token, JWT_SECRET, 'HS256');
      return c.redirect('/');
    } catch (err) {
      const isHttps = c.req.header('x-forwarded-proto') === 'https';
      removeSessionCookie(c, cookieName, isHttps);
    }
  }
  return c.html(fs.readFileSync(path.join(__dirname, 'public', 'login.html'), 'utf-8'));
});

// Redirect old login.html URL to clean /login URL
app.get('/login.html', (c) => {
  const query = c.req.url.split('?')[1];
  return c.redirect(`/login${query ? '?' + query : ''}`, 301);
});

// Route to serve 2FA page
app.get('/login-2fa', (c) => {
  const pendingToken = getCookie(c, 'caddyui-pending2fa');
  if (!pendingToken) {
    return c.redirect('/login');
  }
  return c.html(fs.readFileSync(path.join(__dirname, 'public', 'login-2fa.html'), 'utf-8'));
});

// Protect root dashboard paths
app.get('/', async (c) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);
  if (!token) {
    return c.redirect('/login');
  }
  try {
    await verify(token, JWT_SECRET, 'HS256');
    return c.html(fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8'));
  } catch (err) {
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    removeSessionCookie(c, cookieName, isHttps);
    return c.redirect('/login');
  }
});

app.get('/index.html', (c) => {
  const query = c.req.url.split('?')[1];
  return c.redirect(`/${query ? '?' + query : ''}`, 301);
});

// Redirect old login-2fa.html URL to clean /login-2fa URL
app.get('/login-2fa.html', (c) => {
  const query = c.req.url.split('?')[1];
  return c.redirect(`/login-2fa${query ? '?' + query : ''}`, 301);
});

// Serve static assets
app.use('/*', serveStatic({ root: './public' }));

// Fallback to serve index.html for dashboard routing
app.get('*', async (c, next) => {
  const p = c.req.path;
  if (p.startsWith('/api') || p.startsWith('/auth') || p === '/forward-auth' || p === '/login' || p === '/login-2fa') {
    return await next();
  }

  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);
  if (!token) {
    return c.redirect('/login');
  }

  try {
    await verify(token, JWT_SECRET, 'HS256');
    return c.html(fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8'));
  } catch (err) {
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    removeSessionCookie(c, cookieName, isHttps);
    return c.redirect('/login');
  }
});

// Start Bun server
(async () => {
  await initDb();
})();

export default {
  port: PORT,
  fetch: app.fetch
};
