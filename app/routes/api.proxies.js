import { Hono } from 'hono';
import crypto from 'crypto';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';
import { syncCaddyConfig } from '../services/caddy.js';

const proxyRoutes = new Hono();

proxyRoutes.get('/', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.proxies);
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
