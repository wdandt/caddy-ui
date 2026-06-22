import { Hono } from 'hono';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { sign, verify } from 'hono/jwt';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { readDb } from '../db.js';
import { verifyTotp, JWT_SECRET } from '../utils/crypto.js';
import { getSessionCookieName, setSessionCookie, removeSessionCookie } from '../utils/session.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const authRoutes = new Hono();

authRoutes.post('/auth/login', async (c) => {
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

  if (!user || user.enabled === false) {
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

authRoutes.post('/auth/verify-2fa', async (c) => {
  const { code } = await c.req.json();
  if (!code) {
    return c.json({ error: 'Code is required' }, 400);
  }

  const pendingToken = getCookie(c, 'caddyui-pending2fa');
  if (!pendingToken) {
    return c.json({ error: 'No pending 2FA authentication found' }, 401);
  }

  const isHttps = c.req.header('x-forwarded-proto') === 'https';

  try {
    const decoded = await verify(pendingToken, JWT_SECRET, 'HS256');
    if (!decoded.pending2fa) {
      deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
      return c.json({ error: 'Invalid or expired 2FA session' }, 401);
    }

    const db = readDb();
    const user = db.users.find(u => u.id === decoded.userId);
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret || user.enabled === false) {
      deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
      return c.json({ error: '2FA is not enabled or user disabled' }, 400);
    }

    const verified = verifyTotp(user.twoFactorSecret, code);
    if (!verified) {
      return c.json({ error: 'Invalid verification code' }, 400);
    }

    const userSession = { username: user.username, role: user.role, exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60 };
    const token = await sign(userSession, JWT_SECRET, 'HS256');

    const cookieName = getSessionCookieName(c);

    deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
    setSessionCookie(c, cookieName, token, isHttps);

    return c.json({ success: true, redirect: '/' });
  } catch (err) {
    deleteCookie(c, 'caddyui-pending2fa', { path: '/', secure: isHttps });
    return c.json({ error: 'Invalid or expired 2FA session' }, 401);
  }
});

authRoutes.get('/auth/config', (c) => {
  const db = readDb();
  const enabledProviders = db.oidcProviders.filter(p => p.enabled);
  const dashConfig = db.dashboardAuthConfig || { ssoOnly: false, allowedProviderIds: [] };
  const allowedIds = dashConfig.allowedProviderIds || [];
  
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

authRoutes.get('/auth/sso', async (c) => {
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

authRoutes.get('/auth/callback', async (c) => {
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
    if (!user || user.enabled === false) {
      return c.redirect(`/login?error=User+${encodeURIComponent(email)}+not+registered+or+disabled`);
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

authRoutes.post('/auth/logout', (c) => {
  const cookieName = getSessionCookieName(c);
  const isHttps = c.req.header('x-forwarded-proto') === 'https';
  removeSessionCookie(c, cookieName, isHttps);
  return c.json({ success: true });
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

authRoutes.get('/forward-auth', async (c) => {
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

authRoutes.get('/login', async (c) => {
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
  return c.html(fs.readFileSync(path.join(__dirname, '..', 'public', 'login.html'), 'utf-8'));
});

authRoutes.get('/login.html', (c) => {
  const query = c.req.url.split('?')[1];
  return c.redirect(`/login${query ? '?' + query : ''}`, 301);
});

authRoutes.get('/login-2fa', (c) => {
  const pendingToken = getCookie(c, 'caddyui-pending2fa');
  if (!pendingToken) {
    return c.redirect('/login');
  }
  return c.html(fs.readFileSync(path.join(__dirname, '..', 'public', 'login-2fa.html'), 'utf-8'));
});

// Protect root dashboard paths
authRoutes.get('/', async (c) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);
  if (!token) {
    return c.redirect('/login');
  }
  try {
    await verify(token, JWT_SECRET, 'HS256');
    return c.html(fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8'));
  } catch (err) {
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    removeSessionCookie(c, cookieName, isHttps);
    return c.redirect('/login');
  }
});

authRoutes.get('/index.html', (c) => c.redirect('/', 301));

export default authRoutes;
