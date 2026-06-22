import { Hono } from 'hono';
import crypto from 'crypto';
import { readDb, writeDb } from '../db.js';
import { authenticateToken, csrfProtection } from '../middlewares/auth.js';
import { verifyTotp, generateTotpSecret } from '../utils/crypto.js';

const userRoutes = new Hono();

userRoutes.get('/', authenticateToken, (c) => {
  const db = readDb();
  const sanitized = db.users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    ssoEnabled: u.ssoEnabled,
    ssoProviderId: u.ssoProviderId,
    twoFactorEnabled: u.twoFactorEnabled,
    enabled: u.enabled !== false
  }));
  return c.json(sanitized);
});

userRoutes.post('/', authenticateToken, csrfProtection, async (c) => {
  const { username, password, role, ssoEnabled, ssoProviderId, enabled } = await c.req.json();
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
    twoFactorSecret: null,
    enabled: enabled !== undefined ? Boolean(enabled) : true
  };
  db.users.push(newUser);
  writeDb(db);
  return c.json({
    id: newUser.id,
    username: newUser.username,
    role: newUser.role,
    ssoEnabled: newUser.ssoEnabled,
    ssoProviderId: newUser.ssoProviderId,
    twoFactorEnabled: newUser.twoFactorEnabled,
    enabled: newUser.enabled
  }, 201);
});

userRoutes.put('/:id', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const { username, password, role, ssoEnabled, ssoProviderId, enabled } = await c.req.json();
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
  if (enabled !== undefined) {
    current.enabled = Boolean(enabled);
  }

  writeDb(db);
  return c.json({
    id: current.id,
    username: current.username,
    role: current.role,
    ssoEnabled: current.ssoEnabled,
    ssoProviderId: current.ssoProviderId,
    twoFactorEnabled: current.twoFactorEnabled,
    enabled: current.enabled
  });
});

userRoutes.delete('/:id', authenticateToken, csrfProtection, (c) => {
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

userRoutes.post('/:id/2fa/force-enable', authenticateToken, csrfProtection, (c) => {
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

userRoutes.post('/:id/2fa/setup', authenticateToken, csrfProtection, (c) => {
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

userRoutes.post('/:id/2fa/enable', authenticateToken, csrfProtection, async (c) => {
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

userRoutes.post('/:id/2fa/disable', authenticateToken, csrfProtection, (c) => {
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

userRoutes.put('/:id/toggle', authenticateToken, csrfProtection, async (c) => {
  const id = c.req.param('id');
  const db = readDb();
  const idx = db.users.findIndex(item => item.id === id);
  if (idx === -1) return c.json({ error: 'Item not found' }, 404);
  
  if (id === 'admin') {
    return c.json({ error: 'Cannot disable the default admin account.' }, 400);
  }
  
  db.users[idx].enabled = !db.users[idx].enabled;
  writeDb(db);
  return c.json({ item: db.users[idx], synced: true });
});

export default userRoutes;
