import { getCookie } from 'hono/cookie';
import { verify } from 'hono/jwt';
import { readDb } from '../db.js';
import { JWT_SECRET } from '../utils/crypto.js';
import { getSessionCookieName, removeSessionCookie } from '../utils/session.js';

export const authenticateToken = async (c, next) => {
  const cookieName = getSessionCookieName(c);
  const token = getCookie(c, cookieName);

  if (!token) {
    return c.json({ error: 'Authentication required' }, 401);
  }

  try {
    const decoded = await verify(token, JWT_SECRET, 'HS256');
    const db = readDb();
    const user = db.users.find(u => u.username.toLowerCase() === decoded.username.toLowerCase());
    if (user && user.enabled === false) {
      const isHttps = c.req.header('x-forwarded-proto') === 'https';
      removeSessionCookie(c, getSessionCookieName(c), isHttps);
      return c.json({ error: 'User account is disabled' }, 403);
    }
    c.set('user', decoded);
    await next();
  } catch (err) {
    const isHttps = c.req.header('x-forwarded-proto') === 'https';
    removeSessionCookie(c, cookieName, isHttps);
    return c.json({ error: 'Session expired or invalid' }, 401);
  }
};

export const csrfProtection = async (c, next) => {
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
