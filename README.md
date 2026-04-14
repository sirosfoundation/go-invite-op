# go-invite-op

[![CI](https://github.com/sirosfoundation/go-invite-op/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-invite-op/actions/workflows/ci.yml)
[![Security](https://github.com/sirosfoundation/go-invite-op/actions/workflows/security.yml/badge.svg)](https://github.com/sirosfoundation/go-invite-op/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-invite-op)](https://goreportcard.com/report/github.com/sirosfoundation/go-invite-op)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

Invite code service with OpenID Provider interface for SIROS ID.

## Features

- Tenant-scoped invite code management
- Email address and email domain matching
- Cryptographically generated invite codes
- OpenID Provider compatible with wallet-frontend OIDC gate
- Dynamic client registration
- JWT-protected management API
- Admin token protected admin API
- Periodic cleanup of expired/consumed invites
- Memory and MongoDB storage backends

## Quick Start

```bash
make build
./bin/server --config configs/config.yaml
```

## API

### Management API (JWT-protected)

- `POST /api/v1/invites` - Create an invite
- `GET /api/v1/invites` - List invites
- `GET /api/v1/invites/:id` - Get invite
- `PUT /api/v1/invites/:id` - Update invite
- `DELETE /api/v1/invites/:id` - Delete invite

### Admin API (admin token)

Same routes under `/admin/invites` on port 8081.

### OpenID Provider

- `GET /:tenant/.well-known/openid-configuration` - Discovery
- `GET /:tenant/.well-known/jwks.json` - JSON Web Key Set
- `POST /:tenant/register` - Dynamic client registration
- `GET /:tenant/authorize` - Authorization endpoint
- `POST /:tenant/token` - Token endpoint

### Observability (admin port)

- `GET /admin/status` - Liveness probe
- `GET /admin/readyz` - Kubernetes readiness probe
- `GET /metrics` - Prometheus metrics

## Configuration

See `configs/config.yaml` for all options. Environment variables with `INVITE_` prefix override YAML values. See `configs/config.production.yaml` for a production-hardened example.

## Docker

```bash
# Development with MongoDB
docker compose up

# Build image only
make docker-build
```

The image uses a distroless base with a non-root user (UID 65532).

## Development

```bash
make tools      # Install golangci-lint, goimports, govulncheck
make test       # Run tests
make lint       # Run linter
make fmt        # Format code
```

## License

[BSD 2-Clause](LICENSE)
