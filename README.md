# SSO Server

Single Sign-On (SSO) service with OAuth/OIDC support, admin management, and a web admin UI.

## Features
- OAuth 2.0 + OIDC endpoints
- Admin setup and user management
- Role/permission model
- Scope management
- Web admin UI (Astro + React)

## Requirements
- Go 1.25.6+
- Node.js 20+ (for frontend dev)
- PostgreSQL 18+ (or SQLite for local testing)
- Docker (optional)

## Quick Start (Docker)
1) Build and run:

```bash
docker-compose up -d --build
```

2) API health check:

```bash
curl http://localhost:8080/health
```

## Configuration

### Environment Variables
Copy `env.example` to `.env`:

```bash
cp env.example .env
```

**Disabling Features:**
- **Email**: Leave `EMAIL_SMTP_HOST` blank (email will be logged instead)
- **OAuth Providers**: Leave `GOOGLE_CLIENT_ID`, `DISCORD_CLIENT_ID` blank

See [env.example](env.example) for all available configuration options.

### 2) Start database

```bash
docker-compose up -d db
```

### 3) Run backend

```bash
go run main.go
```

### 4) Run frontend (optional)
See [web/README.md](web/README.md) for the web UI dev server.

## Admin Setup

Initialize the admin account on first run:

```bash
curl -X POST http://localhost:8080/auth/admin/init \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "username": "admin",
    "password": "SecurePassword123!"
  }'
```

**Response (success):**
```json
{
  "success": true,
  "message": "Admin account initialized successfully",
  "admin_user": {
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "email": "admin@example.com",
    "username": "admin"
  },
  "admin_role": {
    "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "admin"
  }
}
```

**Automatically created:**
- ✅ Admin role with full system access
- ✅ Admin user (email pre-verified)
- ✅ 5 default permissions (oauth:register, users:manage, roles:manage, scopes:manage, permissions:manage)
- ✅ All permissions assigned to admin role

Once initialized, access the admin UI at: `http://localhost:8080/panel/clients`

## API Endpoints
- Health: `GET /health`
- Admin Init: `POST /auth/admin/init`
- OIDC Discovery: `GET /.well-known/openid-configuration`
- Swagger UI: `GET /swagger/index.html`
