import { Hono } from 'hono';
import crypto from 'crypto';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';
import { syncCaddyConfig } from '../services/caddy.js';

const instanceRoutes = new Hono();

instanceRoutes.get('/', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.instances);
});

instanceRoutes.post('/', authenticateToken, csrfProtection, async (c) => {
  const { name, url, enabled } = await c.req.json();
  const trimmedName = name ? String(name).trim() : '';
  const trimmedUrl = url ? String(url).trim() : '';

  if (!trimmedName || !trimmedUrl) {
    return c.json({ error: 'Name and URL are required' }, 400);
  }

  // TODO(security): Validate Caddy Admin URL scheme
  if (!trimmedUrl.startsWith('http://') && !trimmedUrl.startsWith('https://')) {
    return c.json({ error: 'URL must start with http:// or https://' }, 400);
  }

  const db = readDb();
  const newInstance = {
    id: crypto.randomBytes(8).toString('hex'),
    name: trimmedName,
    url: trimmedUrl,
    isLocal: false,
    enabled: enabled !== undefined ? Boolean(enabled) : true
  };

  db.instances.push(newInstance);
  writeDb(db);
  return c.json(newInstance, 201);
});

instanceRoutes.put('/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { name, url, enabled } = await c.req.json();
  const trimmedName = name ? String(name).trim() : '';
  const trimmedUrl = url ? String(url).trim() : '';

  if (!trimmedName || !trimmedUrl) {
    return c.json({ error: 'Name and URL are required' }, 400);
  }

  // TODO(security): Validate Caddy Admin URL scheme
  if (!trimmedUrl.startsWith('http://') && !trimmedUrl.startsWith('https://')) {
    return c.json({ error: 'URL must start with http:// or https://' }, 400);
  }

  const db = readDb();
  const idx = db.instances.findIndex(i => i.id === id);
  if (idx === -1) {
    return c.json({ error: 'Instance not found' }, 404);
  }

  const current = db.instances[idx];
  db.instances[idx] = {
    ...current,
    name: trimmedName,
    url: trimmedUrl,
    enabled: enabled !== undefined ? Boolean(enabled) : current.enabled
  };

  writeDb(db);
  return c.json(db.instances[idx]);
});

instanceRoutes.delete('/:id', authenticateToken, csrfProtection, (c) => {
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

instanceRoutes.put('/:id/toggle', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const idx = db.instances.findIndex(item => item.id === id);
  if (idx === -1) return c.json({ error: 'Item not found' }, 404);
  
  db.instances[idx].enabled = !db.instances[idx].enabled;
  writeDb(db);
  
  const instance = db.instances[idx];
  if (instance.enabled !== false) {
    try {
      await syncCaddyConfig(instance, db.proxies);
    } catch(err) {
      return c.json({ item: instance, synced: false, syncError: err.message });
    }
  }
  return c.json({ item: instance, synced: true });
});

export default instanceRoutes;
