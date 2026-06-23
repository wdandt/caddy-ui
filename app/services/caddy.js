import { JWT_SECRET } from '../utils/crypto.js';

export function cleanDialTarget(target) {
  let clean = target.replace(/^(https?:\/\/)/, '');
  clean = clean.split('/')[0];
  if (!clean.includes(':')) {
    if (target.startsWith('https://')) {
      clean += ':443';
    } else {
      clean += ':80';
    }
  }
  return clean;
}

export async function syncCaddyConfig(instance, proxies) {
  if (instance.enabled === false) {
    console.log(`Instance ${instance.name} is disabled. Skipping config sync.`);
    return;
  }
  const targetUrl = instance.url;
  
  let caddyConfig = {};
  try {
    const response = await fetch(`${targetUrl}/config/`, { signal: AbortSignal.timeout(3000) });
    if (response.ok) {
      caddyConfig = await response.json();
    }
  } catch (err) {
    console.log(`Could not fetch config from ${instance.name}, creating new structure:`, err.message);
  }

  if (!caddyConfig.apps) caddyConfig.apps = {};
  if (!caddyConfig.apps.http) caddyConfig.apps.http = {};
  if (!caddyConfig.apps.http.servers) caddyConfig.apps.http.servers = {};
  
  if (!caddyConfig.apps.http.servers.srv0) {
    caddyConfig.apps.http.servers.srv0 = {
      listen: [":80", ":443"],
      routes: []
    };
  }

  // Enable access logging
  caddyConfig.apps.http.servers.srv0.logs = {
    default_logger_name: "log0"
  };

  if (!caddyConfig.logging) caddyConfig.logging = {};
  if (!caddyConfig.logging.logs) caddyConfig.logging.logs = {};
  caddyConfig.logging.logs.log0 = {
    writer: {
      output: "file",
      filename: "/logs/access.log",
      roll_size_mb: 10,
      roll_keep: 5,
      roll_keep_days: 7
    },
    encoder: {
      format: "json"
    },
    level: "INFO"
  };


  const instanceProxies = proxies.filter(p => p.instanceId === instance.id && p.enabled !== false);

  const routes = instanceProxies.map(proxy => {
    const innerRoutes = [];
    const isSso = proxy.authMode === 'sso' || (proxy.authMode === undefined && proxy.ssoEnabled);
    const isBasic = proxy.authMode === 'basic';

    if (isSso) {
      innerRoutes.push({
        handle: [
          {
            handler: "authentication",
            providers: {
              jwt: {
                sign_key: Buffer.from(JWT_SECRET).toString('base64'),
                sign_alg: "HS256",
                from_cookies: ["__Secure-caddyui-session", "__Host-caddyui-session", "caddyui-session"]
              }
            }
          }
        ]
      });
    }

    if (isBasic && proxy.basicAuthCredentials && proxy.basicAuthCredentials.length > 0) {
      innerRoutes.push({
        handle: [
          {
            handler: "basic_auth",
            accounts: proxy.basicAuthCredentials.map(cred => ({
              username: cred.username,
              password: cred.passwordHash
            }))
          }
        ]
      });
    }

    const createReverseProxyHandler = (targetUrl) => {
      const handler = {
        handler: "reverse_proxy",
        upstreams: [{ dial: cleanDialTarget(targetUrl) }],
        flush_interval: -1,
        stream_close_delay: "10m",
        headers: {
          request: {
            set: {
              "X-Forwarded-Host": ["{http.request.host}"],
              "X-Forwarded-Port": ["{http.request.port}"],
              "X-Real-Ip": ["{http.request.remote.host}"]
            }
          }
        }
      };

      if (proxy.tlsInsecure && targetUrl.startsWith('https://')) {
        handler.transport = {
          protocol: "http",
          tls: { insecure_skip_verify: true }
        };
      }
      return handler;
    };

    if (proxy.advancedRoutes && proxy.advancedRoutes.length > 0) {
      proxy.advancedRoutes.forEach(adv => {
        innerRoutes.push({
          match: [{ path: [adv.path] }],
          handle: [createReverseProxyHandler(adv.target)]
        });
      });
    }

    innerRoutes.push({
      handle: [createReverseProxyHandler(proxy.target)]
    });

    return {
      match: [
        {
          host: [proxy.host]
        }
      ],
      handle: [
        {
          handler: "subroute",
          routes: innerRoutes
        }
      ],
      terminal: true
    };
  });

  const logRoute = {
    match: [
      {
        path: ["/_caddyui/logs/access.log"],
        header: {
          "Authorization": [`Bearer ${JWT_SECRET}`]
        }
      }
    ],
    handle: [
      {
        handler: "rewrite",
        uri: "/access.log"
      },
      {
        handler: "file_server",
        root: "/logs"
      }
    ]
  };
  
  routes.unshift(logRoute);

  caddyConfig.apps.http.servers.srv0.routes = routes;

  const portalUrl = process.env.SSO_PORTAL_URL ? process.env.SSO_PORTAL_URL.replace(/\/$/, '') : '';
  const redirectScheme = portalUrl.startsWith('https://') ? 'https' : '{http.request.scheme}';
  caddyConfig.apps.http.servers.srv0.errors = {
    routes: [
      {
        match: [
          {
            method: ["GET"],
            header: {
              "Accept": ["*text/html*"]
            },
            expression: "{err.status_code} == 401"
          }
        ],
        handle: [
          {
            handler: "static_response",
            status_code: 302,
            headers: {
              "Location": [`${portalUrl}/login?redirect=${redirectScheme}://{http.request.host}{http.request.uri}`]
            }
          }
        ]
      }
    ]
  };

  console.log(`Pushing synced configuration to ${instance.name} (${targetUrl})...`);
  const response = await fetch(`${targetUrl}/load`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(caddyConfig),
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) {
    throw new Error(`Caddy load returned status ${response.status}`);
  }
}
