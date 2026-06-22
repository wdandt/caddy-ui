# Caddy UI & SSO Forward Auth Proxy

A lightweight, modern Web UI Dashboard and Single Sign-On (SSO) Forward Auth Proxy for Caddy Server. Easily manage multiple Caddy server instances, dynamic reverse proxy routes, and secure them with OIDC (OpenID Connect) authentication.

---

## 🌟 Key Features

*   **🖥️ Multi-Instance Caddy Management**: Connect, monitor, and synchronize configurations with local and remote Caddy servers via the Caddy Admin API.
*   **🔗 Dynamic Proxy Routing**: Create, edit, and delete reverse proxy routes in real-time. Configuration changes are synced instantly to Caddy servers.
*   **🔐 SSO & Forward Auth (OIDC)**: Integrate with popular Identity Providers (Google, GitHub, Keycloak, Authentik, Okta) using OpenID Connect.
*   **⚙️ UI Configurable Credentials**: Change the admin username and password directly from the Settings tab, stored securely using `bcryptjs` hashing.
*   **🛡️ Route Protection**: Toggle SSO protection on any proxy route to restrict access to authenticated users via Caddy's `forward_auth` middleware.
*   **✨ Modern Glassmorphic Dashboard**: A premium, responsive interface featuring live status indicators, server latency checks, and visual route overviews.
*   **🔒 Security Hardened**: Built with CSRF protection (double submit cookie), secure HTTP-Only session cookies (`__Host-` prefixed for production), and server-side route guards on dashboard access (`/` and `/index.html`) to prevent visual UI leakage/flashing for unauthenticated users.

---

## 📁 Repository Structure

```text
├── app/
│   ├── public/              # SPA Frontend files (HTML, CSS, JS)
│   │   ├── index.html       # Main dashboard page
│   │   ├── login.html       # Login page
│   │   ├── style.css        # Glassmorphic UI theme styles
│   │   └── js/              # Modular Frontend logic
│   │       ├── api.js       # Secure fetch and session API
│   │       ├── main.js      # App assembly and rendering logic
│   │       ├── state.js     # Global state management
│   │       └── utils.js     # UI helpers and toast notifications
│   ├── data/                # Persistent database directory
│   │   ├── db.json          # Lightweight JSON database
│   │   └── jwt_secret.txt   # Ephemeral token encryption key (auto-generated)
│   ├── Dockerfile           # Production Dockerfile for Bun/Node App
│   ├── package.json         # Dependencies & scripts
│   ├── server.js            # Hono API server & Forward Auth Gatekeeper
│   ├── db.js                # Database interaction logic
│   ├── middlewares/         # Route middlewares (e.g. auth, CSRF)
│   ├── routes/              # Modular API endpoints
│   ├── services/            # Background services (Caddy sync)
│   └── utils/               # Backend helper functions (Crypto, session)
├── Dockerfile.caddy         # Custom Caddy image builder with Cloudflare DNS
├── docker-compose.yml       # Orchestration stack for Caddy, Dashboard & Cloudflare Tunnel
├── .env.example             # Template environment variables file
├── .env                     # Local environment settings (ignored by git)
├── .gitignore               # Ignored files for version control
└── .dockerignore            # Minimized Docker context rules
```

---

## 🚀 Getting Started

### 📋 Prerequisites

*   [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)

### 🔧 Configuration

Before launching, copy the `.env.example` template to `.env` and configure your environment variables:

```bash
cp .env.example .env
```

Review and update the variables in `.env`:

```ini
# Fallback Admin Credentials (used to initialize the database)
ADMIN_USER=admin
ADMIN_PASS=caddyui_admin_secure_pass_123

# JWT Secret Key (for session encryption)
# Leave empty to auto-generate a secure random one on startup
JWT_SECRET=

# Cloudflare Integration (Optional)
CLOUDFLARE_API_TOKEN=your_cloudflare_api_token_here
CLOUDFLARE_TUNNEL_TOKEN=your_cloudflared_tunnel_token_here
```

> [!NOTE]
> Admin Credentials (`ADMIN_USER` and `ADMIN_PASS`) are used to initialize the database on the very first run. Once the database is initialized, you can modify the admin credentials directly on the **Settings** page in the UI, and the `.env` settings will no longer override the database values.

### 🏃 Running the Stack

To build and run the services in the background:

```bash
docker compose up -d --build
```

Access the dashboard by navigating to `http://localhost:3000` (or your configured domain).

### 🔄 Updating & Redeploying on Production

When pulling new updates, applying security patches, or modifying files:

1. **Redeploy/Rebuild the Dashboard Service Only** (Zero-downtime for Caddy):
   ```bash
   docker compose up -d --build caddy-ui
   ```
   This rebuilds the dashboard Docker image and restarts the container without affecting Caddy's operations.

2. **Full Stack Redeployment**:
   If there are changes to `docker-compose.yml` or the custom Caddy Dockerfile:
   ```bash
   docker compose down
   docker compose up -d --build
   ```

---

## 🔒 SSO & Forward Auth Setup

### 1. Identity Provider Registration
Register a new OIDC/OAuth2 application with your provider (e.g. Authentik, Google, Keycloak) with the following callback:
*   **Redirect URI**: `https://<your-caddy-ui-domain>/auth/callback`

### 2. Configure OIDC in Caddy UI
Go to **Settings** in the Caddy UI dashboard and configure:
*   **OIDC Issuer URL** (e.g. `https://accounts.google.com`)
*   **Client ID**
*   **Client Secret**
*   **Redirect URI**
*   Toggle **Enable SSO Authentication** and click **Save SSO Config**.

### 3. How Forward Auth Works
When you toggle **Protect with SSO Login** on a proxy route:
1. Caddy UI configures Caddy's `reverse_proxy` to call the `/forward-auth` endpoint on the Caddy UI service.
2. When a client visits the proxy route, Caddy checks with Caddy UI:
   - **Authenticated**: Caddy UI returns `200 OK` and Caddy forwards the request to the upstream target.
   - **Unauthenticated**: Caddy UI redirects the client's browser to the OIDC provider (or dashboard login) to authenticate.

---

## 📝 License

This project is open-source and available under the [MIT License](LICENSE).
