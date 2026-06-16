# Caddy UI & SSO Forward Auth Proxy

A lightweight, modern Web UI Dashboard and Single Sign-On (SSO) Forward Auth Proxy for Caddy Server. Easily manage multiple Caddy server instances, dynamic reverse proxy routes, and secure them with OIDC (OpenID Connect) authentication.

---

## 🌟 Key Features

*   **🖥️ Multi-Instance Caddy Management**: Connect, monitor, and synchronize configurations with local and remote Caddy servers via the Caddy Admin API.
*   **🔗 Dynamic Proxy Routing**: Create, edit, and delete reverse proxy routes in real-time. Configuration changes are synced instantly to Caddy servers.
*   **🔐 SSO & Forward Auth (OIDC)**: Integrate with popular Identity Providers (Google, GitHub, Keycloak, Authentik, Okta) using OpenID Connect.
*   **🛡️ Route Protection**: Toggle SSO protection on any proxy route to restrict access to authenticated users via Caddy's `forward_auth` middleware.
*   **✨ Modern Glassmorphic Dashboard**: A premium, responsive interface featuring live status indicators, server latency checks, and visual route overviews.
*   **🔒 Security Hardened**: Built with CSRF protection (double submit cookie) and secure HTTP-Only session cookies (`__Host-` prefixed for production).

---

## 📁 Repository Structure

```text
├── app/
│   ├── public/              # SPA Frontend files (HTML, CSS, JS)
│   │   ├── index.html       # Main dashboard page
│   │   ├── login.html       # Login page
│   │   ├── style.css        # Glassmorphic UI theme styles
│   │   └── app.js           # Frontend logic & API handlers
│   ├── data/                # Persistent database directory
│   │   ├── db.json          # SQLite-free lightweight JSON database
│   │   └── jwt_secret.txt   # Ephemeral token encryption key (auto-generated)
│   ├── Dockerfile           # Production Dockerfile for Node.js App
│   ├── package.json         # Node.js dependencies & scripts
│   └── server.js            # Express API server & Forward Auth Gatekeeper
├── Dockerfile.caddy         # Custom Caddy image builder with Cloudflare DNS
├── docker-compose.yml       # Orchestration stack for Caddy, Dashboard & Cloudflare Tunnel
├── .gitignore               # Ignored files for version control
└── .dockerignore            # Minimized Docker context rules
```

---

## 🚀 Getting Started

### 📋 Prerequisites

*   [Docker](https://docs.docker.com/get-docker/) & [Docker Compose](https://docs.docker.com/compose/install/)

### 🔧 Configuration

Before launching, review and configure the environment variables in `docker-compose.yml`:

```yaml
# docker-compose.yml
services:
  caddy-ui:
    environment:
      - PORT=3000
      - NODE_ENV=production
      - ADMIN_USER=admin                         # Fallback admin username
      - ADMIN_PASS=caddyui_admin_secure_pass_123 # Fallback admin password
      - JWT_SECRET=                              # Leave blank to auto-generate
```

*   **Cloudflare Integration (Optional)**: If you use Cloudflare Tunnels or DNS validation for Caddy certificates, define:
    *   `CLOUDFLARE_API_TOKEN`
    *   `CLOUDFLARE_TUNNEL_TOKEN`

### 🏃 Running the Stack

To build and run the services in the background:

```bash
docker compose up -d --build
```

Access the dashboard by navigating to `http://localhost:3000` (or your configured domain).

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
