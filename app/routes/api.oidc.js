import { Hono } from 'hono';
import crypto from 'crypto';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';

const oidcRoutes = new Hono();

oidcRoutes.get('/', authenticateToken, (c) => {
  const db = readDb();
  return c.json(db.oidcProviders || []);
});

oidcRoutes.post('/', authenticateToken, csrfProtection, async (c) => {
  const { name, issuer, clientId, clientSecret, redirectUri, enabled } = await c.req.json();
  const db = readDb();
  
  const newProvider = {
    id: crypto.randomBytes(8).toString('hex'),
    name: name ? String(name).trim() : 'New OIDC Provider',
    issuer: issuer || '',
    clientId: clientId || '',
    clientSecret: clientSecret || '',
    redirectUri: redirectUri || '',
    enabled: enabled !== undefined ? Boolean(enabled) : true
  };
  
  if (!db.oidcProviders) db.oidcProviders = [];
  db.oidcProviders.push(newProvider);
  writeDb(db);
  return c.json(newProvider, 201);
});

oidcRoutes.put('/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { name, issuer, clientId, clientSecret, redirectUri, enabled } = await c.req.json();
  const db = readDb();
  
  if (!db.oidcProviders) db.oidcProviders = [];
  const idx = db.oidcProviders.findIndex(p => p.id === id);
  
  if (idx === -1) {
    // If updating 'default' which might not exist but was requested:
    if (id === 'default') {
      const defaultProvider = {
        id: 'default',
        name: name ? String(name).trim() : 'Default OIDC',
        issuer: issuer || '',
        clientId: clientId || '',
        clientSecret: clientSecret || '',
        redirectUri: redirectUri || '',
        enabled: Boolean(enabled)
      };
      db.oidcProviders.push(defaultProvider);
      writeDb(db);
      return c.json(defaultProvider);
    }
    return c.json({ error: 'SSO Provider not found' }, 404);
  }
  
  const current = db.oidcProviders[idx];
  db.oidcProviders[idx] = {
    ...current,
    name: name !== undefined ? String(name).trim() : current.name,
    issuer: issuer !== undefined ? String(issuer).trim() : current.issuer,
    clientId: clientId !== undefined ? String(clientId).trim() : current.clientId,
    clientSecret: clientSecret !== undefined ? String(clientSecret).trim() : current.clientSecret,
    redirectUri: redirectUri !== undefined ? String(redirectUri).trim() : current.redirectUri,
    enabled: enabled !== undefined ? Boolean(enabled) : current.enabled
  };
  writeDb(db);
  return c.json(db.oidcProviders[idx]);
});

oidcRoutes.delete('/:id', authenticateToken, csrfProtection, (c) => {
  const id = c.req.param('id');
  const db = readDb();
  if (!db.oidcProviders) return c.json({ message: 'SSO Provider deleted' });
  db.oidcProviders = db.oidcProviders.filter(p => p.id !== id);
  writeDb(db);
  return c.json({ message: 'SSO Provider deleted' });
});

oidcRoutes.put('/:id/toggle', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const db = readDb();
  if (!db.oidcProviders) return c.json({ error: 'Item not found' }, 404);
  const idx = db.oidcProviders.findIndex(item => item.id === id);
  if (idx === -1) return c.json({ error: 'Item not found' }, 404);
  
  db.oidcProviders[idx].enabled = !db.oidcProviders[idx].enabled;
  writeDb(db);
  return c.json({ item: db.oidcProviders[idx], synced: true });
});

export default oidcRoutes;
