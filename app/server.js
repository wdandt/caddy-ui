import { Hono } from 'hono';
import { serveStatic } from 'hono/bun';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getCookie } from 'hono/cookie';
import { verify } from 'hono/jwt';

import { initDb } from './db.js';
import { JWT_SECRET } from './utils/crypto.js';
import { getSessionCookieName, removeSessionCookie } from './utils/session.js';

import authRoutes from './routes/auth.routes.js';
import systemRoutes from './routes/system.routes.js';
import userRoutes from './routes/api.users.js';
import instanceRoutes from './routes/api.instances.js';
import proxyRoutes from './routes/api.proxies.js';
import oidcRoutes from './routes/api.oidc.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// Mount Routes
app.route('/', authRoutes);
app.route('/api', systemRoutes);
app.route('/api/users', userRoutes);
app.route('/api/instances', instanceRoutes);
app.route('/api/proxies', proxyRoutes);
app.route('/api/oidc-providers', oidcRoutes);
app.route('/api/oidc', oidcRoutes);

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
