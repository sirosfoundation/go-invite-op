# go-invite-op

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
- `POST /:tenant/register` - Dynamic client registration
- `GET /:tenant/authorize` - Authorization endpoint
- `POST /:tenant/token` - Token endpoint

## Configuration

See `configs/config.yaml` for all options. Environment variables with `INVITE_` prefix override YAML values.
