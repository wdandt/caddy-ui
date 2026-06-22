import { Hono } from 'hono';
import crypto from 'crypto';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';
import { checkHttps } from '../utils/session.js';
import { setCookie } from 'hono/cookie';
import { syncCaddyConfig } from '../services/caddy.js';

const systemRoutes = new Hono();

systemRoutes.get('/csrf', (c) => {
  const token = crypto.randomBytes(32).toString('hex');
  const isHttps = checkHttps(c);
  setCookie(c, 'caddyui-csrf', token, {
    path: '/',
    httpOnly: false, // Must be readable by client JS
    secure: isHttps,
    sameSite: 'Lax',
    maxAge: 8 * 60 * 60
  });
  return c.json({ token });
});

systemRoutes.get('/me', authenticateToken, (c) => {
  const user = c.get('user');
  return c.json({
    username: user.username,
    role: user.role
  });
});

systemRoutes.get('/admin-credentials', authenticateToken, (c) => {
  const db = readDb();
  const admin = db.users.find(u => u.id === 'admin');
  return c.json({ username: admin ? admin.username : 'admin' });
});

systemRoutes.post('/admin-credentials', authenticateToken, csrfProtection, async (c) => {
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

systemRoutes.get('/dashboard-auth-config', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.dashboardAuthConfig || { ssoOnly: false, allowedProviderIds: [] });
});

systemRoutes.post('/dashboard-auth-config', authenticateToken, csrfProtection, async (c) => {
  const { ssoOnly, allowedProviderIds } = await c.req.json();
  const db = readDb();
  db.dashboardAuthConfig = {
    ssoOnly: Boolean(ssoOnly),
    allowedProviderIds: Array.isArray(allowedProviderIds) ? allowedProviderIds : []
  };
  writeDb(db);
  return c.json({ success: true });
});

systemRoutes.get('/status', authenticateToken, async (c) => {
  const db = readDb();

  const statusPromises = db.instances.map(async (instance) => {
    if (instance.enabled === false) {
      return { id: instance.id, online: false, error: 'Instance is disabled' };
    }
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

systemRoutes.get('/raw-config/:instanceId', authenticateToken, async (c) => {
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

systemRoutes.post('/sync/:instanceId', authenticateToken, csrfProtection, async (c) => {
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

export default systemRoutes;
