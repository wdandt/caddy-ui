import { Hono } from 'hono';
import crypto from 'crypto';
import http from 'http';
import https from 'https';
import dns from 'dns/promises';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';
import { syncCaddyConfig } from '../services/caddy.js';

const proxyRoutes = new Hono();

proxyRoutes.get('/', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.proxies);
});

proxyRoutes.post('/test', authenticateToken, csrfProtection, async (c) => {
  const { target, host, tlsInsecure } = await c.req.json();
  if (!target) {
    return c.json({ success: false, error: 'Target is required' }, 400);
  }

  const results = {
    dns: { status: 'skipped', details: 'No domain provided', error: '' },
    upstream: { status: 'skipped', details: '', error: '' },
    public: { status: 'skipped', details: 'No domain provided', error: '' }
  };

  // --- Step 1: DNS Check ---
  if (host) {
    try {
      const records = await dns.lookup(host);
      results.dns = { status: 'success', details: `Resolved to ${records.address}`, error: '' };
    } catch (err) {
      results.dns = { status: 'error', error: err.code || err.message, details: 'DNS lookup failed' };
    }
  }

  // --- Step 2: Upstream Check ---
  let targetUrl = String(target).trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'http://' + targetUrl;
  }

  try {
    const u = new URL(targetUrl);
    const isHttps = u.protocol === 'https:';
    
    const options = {
      method: 'GET',
      timeout: 5000,
      headers: {
        'User-Agent': 'Caddy-UI-Test-Proxy/1.0'
      }
    };

    if (host) {
      const cleanHost = String(host).trim().toLowerCase();
      options.headers['Host'] = cleanHost;
      options.headers['X-Forwarded-Host'] = cleanHost;
      options.headers['X-Forwarded-Proto'] = 'https';
      options.headers['X-Real-Ip'] = '127.0.0.1';
    }

    if (isHttps) {
      if (tlsInsecure) {
        options.rejectUnauthorized = false;
      }
      
      const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(u.hostname) || u.hostname.startsWith('[');
      if (isIp && host) {
        options.servername = String(host).trim().toLowerCase();
      }
    }

    const reqLib = isHttps ? https : http;
    
    results.upstream = await new Promise((resolve) => {
      const startTime = Date.now();
      const req = reqLib.request(u, options, (res) => {
        const timeTaken = Date.now() - startTime;
        let snippet = '';
        res.on('data', chunk => { if (snippet.length < 500) snippet += chunk; });
        res.on('end', () => {
          let detailsStr = `HTTP ${res.statusCode} (${timeTaken}ms)`;
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            detailsStr += ` -> Redirect to ${res.headers.location}`;
          }
          resolve({
            status: 'success',
            details: detailsStr,
            error: '',
            snippet: snippet.substring(0, 500)
          });
        });
      });
      req.on('error', (e) => resolve({ status: 'error', error: e.code || e.message, details: 'Connection failed' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 'error', error: 'ETIMEDOUT', details: '>5000ms' }); });
      req.end();
    });
  } catch (err) {
    results.upstream = { status: 'error', error: err.message, details: 'Invalid target URL' };
  }

  // --- Step 3: Public Domain Check ---
  if (host) {
    try {
      const pubU = new URL(`https://${host}`);
      results.public = await new Promise((resolve) => {
        const startTime = Date.now();
        const req = https.request(pubU, { method: 'GET', timeout: 5000 }, (res) => {
          const timeTaken = Date.now() - startTime;
          let detailsStr = `HTTP ${res.statusCode} (${timeTaken}ms)`;
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            detailsStr += ` -> Redirect to ${res.headers.location}`;
          }
          
          if (res.statusCode >= 200 && res.statusCode < 400) {
            resolve({ status: 'success', details: detailsStr, error: '' });
          } else {
            resolve({ status: 'error', error: `HTTP ${res.statusCode}`, details: `Public endpoint returned error (${timeTaken}ms)` });
          }
        });
        req.on('error', (e) => resolve({ status: 'error', error: e.code || e.message, details: 'Connection failed' }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 'error', error: 'ETIMEDOUT', details: '>5000ms' }); });
        req.end();
      });
    } catch (err) {
      results.public = { status: 'error', error: err.message, details: 'Invalid host' };
    }
  }

  return c.json({ success: true, results });
});

proxyRoutes.post('/', authenticateToken, csrfProtection, async (c) => {
  const { instanceId, host, target, ssoEnabled, authMode, ssoProviderId, basicAuthCredentials, enabled, tlsInsecure, advancedRoutes, configMode, rawCaddyConfig } = await c.req.json();
  if (!instanceId || !host) {
    return c.json({ error: 'Instance ID and Host are required' }, 400);
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
    basicAuthCredentials: credentials,
    enabled: enabled !== undefined ? Boolean(enabled) : true,
    tlsInsecure: Boolean(tlsInsecure),
    advancedRoutes: Array.isArray(advancedRoutes) ? advancedRoutes : [],
    configMode: configMode || 'form',
    rawCaddyConfig: rawCaddyConfig || null
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

proxyRoutes.put('/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { instanceId, host, target, ssoEnabled, authMode, ssoProviderId, basicAuthCredentials, enabled, tlsInsecure, advancedRoutes, configMode, rawCaddyConfig } = await c.req.json();
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
    basicAuthCredentials: credentials,
    enabled: enabled !== undefined ? Boolean(enabled) : currentProxy.enabled,
    tlsInsecure: tlsInsecure !== undefined ? Boolean(tlsInsecure) : currentProxy.tlsInsecure,
    advancedRoutes: advancedRoutes !== undefined ? (Array.isArray(advancedRoutes) ? advancedRoutes : []) : (currentProxy.advancedRoutes || []),
    instanceId: instanceId ? String(instanceId) : currentProxy.instanceId,
    configMode: configMode || currentProxy.configMode || 'form',
    rawCaddyConfig: rawCaddyConfig !== undefined ? rawCaddyConfig : currentProxy.rawCaddyConfig
  };

  db.proxies[proxyIndex] = updatedProxy;
  writeDb(db);

  const oldInstanceId = currentProxy.instanceId;
  const newInstanceId = updatedProxy.instanceId;

  const newInstance = db.instances.find(i => i.id === newInstanceId);
  const oldInstance = db.instances.find(i => i.id === oldInstanceId);

  if (newInstance) {
    try {
      await syncCaddyConfig(newInstance, db.proxies);
      
      // If the instance changed, we must also sync the old instance to remove the route from it
      if (oldInstanceId !== newInstanceId && oldInstance) {
        await syncCaddyConfig(oldInstance, db.proxies);
      }
      
      return c.json({ proxy: updatedProxy, synced: true });
    } catch (err) {
      return c.json({ proxy: updatedProxy, synced: false, syncError: err.message });
    }
  } else {
    return c.json({ proxy: updatedProxy, synced: false, syncError: 'Target instance not found' });
  }
});

proxyRoutes.delete('/:id', authenticateToken, csrfProtection, async (c) => {
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

proxyRoutes.put('/:id/toggle', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const idx = db.proxies.findIndex(item => item.id === id);
  if (idx === -1) return c.json({ error: 'Item not found' }, 404);
  
  db.proxies[idx].enabled = !db.proxies[idx].enabled;
  writeDb(db);
  
  const proxy = db.proxies[idx];
  const instance = db.instances.find(i => i.id === proxy.instanceId);
  if (instance) {
    try {
      await syncCaddyConfig(instance, db.proxies);
    } catch(err) {
      return c.json({ item: proxy, synced: false, syncError: err.message });
    }
  }
  return c.json({ item: proxy, synced: true });
});

export default proxyRoutes;
