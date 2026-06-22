import { setCookie, getCookie, deleteCookie } from 'hono/cookie';

const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || '';

export function checkHttps(c) {
  const xfp = c.req.header('x-forwarded-proto');
  const portalUrl = process.env.SSO_PORTAL_URL || '';
  return xfp === 'https' || portalUrl.startsWith('https://');
}

// Get cookie name based on security context
export function getSessionCookieName(c) {
  if (checkHttps(c)) {
    return COOKIE_DOMAIN ? '__Secure-caddyui-session' : '__Host-caddyui-session';
  }
  return 'caddyui-session';
}

export function setSessionCookie(c, cookieName, token, _isHttps) {
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

export function removeSessionCookie(c, cookieName, _isHttps) {
  const isHttps = checkHttps(c);
  const cookieOpts = { path: '/', secure: isHttps };
  if (COOKIE_DOMAIN) {
    cookieOpts.domain = COOKIE_DOMAIN;
  }
  deleteCookie(c, cookieName, cookieOpts);
}
