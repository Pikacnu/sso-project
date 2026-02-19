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

## Useful Docs
- [docs/QUICK_START.md](docs/QUICK_START.md)
- [docs/QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md)
- [docs/TEST_SUITE.md](docs/TEST_SUITE.md)

## API Endpoints
- Health: `GET /health`
- OIDC Discovery: `GET /.well-known/openid-configuration`
- Swagger UI: `GET /swagger/index.html`
