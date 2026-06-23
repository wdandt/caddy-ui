import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_PATH = path.join(__dirname, 'data', 'db.json');

if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

let dbInMemory = null;

export async function initDb() {
  const defaultAdminUser = process.env.ADMIN_USER || 'admin';
  const defaultAdminPass = process.env.ADMIN_PASS || 'caddyui_admin_secure_pass_123';
  const defaultAdminPassHash = await Bun.password.hash(defaultAdminPass, { algorithm: 'bcrypt', cost: 10 });

  const defaultOidcIssuer = process.env.OIDC_ISSUER || '';
  const defaultOidcClientId = process.env.OIDC_CLIENT_ID || '';
  const defaultOidcClientSecret = process.env.OIDC_CLIENT_SECRET || '';
  const defaultOidcRedirectUri = process.env.OIDC_REDIRECT_URI || '';
  const defaultOidcEnabled = !!(defaultOidcIssuer && defaultOidcClientId);

  const defaultDbStructure = {
    instances: [
      {
        id: 'local',
        name: 'Local Caddy',
        url: 'http://127.0.0.1:2019',
        isLocal: true,
        enabled: true
      }
    ],
    proxies: [],
    users: [
      {
        id: 'admin',
        username: defaultAdminUser,
        passwordHash: defaultAdminPassHash,
        role: 'admin',
        ssoEnabled: false,
        ssoProviderId: null,
        twoFactorEnabled: false,
        twoFactorSecret: null,
        enabled: true
      }
    ],
    oidcProviders: [],
    dashboardAuthConfig: {
      ssoOnly: false,
      allowedProviderIds: []
    },
    globalSettings: {
      trustedProxies: "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fc00::/7"
    }
  };

  if (defaultOidcEnabled) {
    defaultDbStructure.oidcProviders.push({
      id: 'default',
      name: 'Default OIDC',
      issuer: defaultOidcIssuer,
      clientId: defaultOidcClientId,
      clientSecret: defaultOidcClientSecret,
      redirectUri: defaultOidcRedirectUri,
      enabled: true
    });
  }

  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(defaultDbStructure, null, 2), 'utf-8');
    dbInMemory = defaultDbStructure;
    return;
  }

  try {
    const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    let modified = false;

    if (db.adminCredentials) {
      if (!db.users) db.users = [];
      const hasAdmin = db.users.some(u => u.username === db.adminCredentials.username);
      if (!hasAdmin) {
        db.users.push({
          id: 'admin',
          username: db.adminCredentials.username,
          passwordHash: db.adminCredentials.passwordHash,
          role: 'admin',
          ssoEnabled: false,
          ssoProviderId: null,
          twoFactorEnabled: false,
          twoFactorSecret: null,
          enabled: true
        });
      }
      delete db.adminCredentials;
      modified = true;
    }

    if (db.oidcConfig) {
      if (!db.oidcProviders) db.oidcProviders = [];
      if (db.oidcConfig.issuer && db.oidcConfig.clientId) {
        const hasDefault = db.oidcProviders.some(p => p.id === 'default');
        if (!hasDefault) {
          db.oidcProviders.push({
            id: 'default',
            name: 'Default OIDC',
            issuer: db.oidcConfig.issuer,
            clientId: db.oidcConfig.clientId,
            clientSecret: db.oidcConfig.clientSecret,
            redirectUri: db.oidcConfig.redirectUri,
            enabled: db.oidcConfig.enabled
          });
        }
      }
      delete db.oidcConfig;
      modified = true;
    }

    if (!db.users) {
      db.users = defaultDbStructure.users;
      modified = true;
    } else {
      db.users.forEach(u => { if (u.enabled === undefined) { u.enabled = true; modified = true; } });
    }
    if (!db.oidcProviders) {
      db.oidcProviders = defaultDbStructure.oidcProviders;
      modified = true;
    }
    if (!db.instances) {
      db.instances = defaultDbStructure.instances;
      modified = true;
    } else {
      db.instances.forEach(i => { if (i.enabled === undefined) { i.enabled = true; modified = true; } });
    }
    if (!db.proxies) {
      db.proxies = defaultDbStructure.proxies;
      modified = true;
    } else {
      db.proxies.forEach(p => { if (p.enabled === undefined) { p.enabled = true; modified = true; } });
    }
    if (!db.dashboardAuthConfig) {
      db.dashboardAuthConfig = {
        ssoOnly: false,
        allowedProviderIds: []
      };
      modified = true;
    } else if (db.dashboardAuthConfig.defaultProviderId !== undefined) {
      db.dashboardAuthConfig.allowedProviderIds = db.dashboardAuthConfig.defaultProviderId
        ? [db.dashboardAuthConfig.defaultProviderId]
        : [];
      delete db.dashboardAuthConfig.defaultProviderId;
      modified = true;
    }

    if (!db.globalSettings) {
      db.globalSettings = defaultDbStructure.globalSettings;
      modified = true;
    }

    if (modified) {
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf-8');
    }
    dbInMemory = db;
  } catch (err) {
    console.error('Error migrating DB:', err);
  }
}

export function readDb() {
  if (!dbInMemory) {
    dbInMemory = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  }
  const localInstance = dbInMemory.instances.find(i => i.isLocal);
  if (localInstance) {
    const defaultCaddyAdmin = process.env.CADDY_ADMIN || '127.0.0.1:2019';
    localInstance.url = `http://${defaultCaddyAdmin}`;
  }
  return dbInMemory;
}

export function writeDb(data) {
  dbInMemory = data;
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}
