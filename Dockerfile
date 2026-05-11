# Node build stage
FROM node:22-alpine AS node-builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY web/src/ web/src/

RUN pnpm build

# Go build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

ARG VERSION=dev
ARG COMMIT=unknown

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=node-builder /app/web/dist /app/web/dist

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o server cmd/server/main.go

# Runtime stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /app/server /app/server
COPY --from=builder /app/configs /app/configs

USER 65532:65532

EXPOSE 8080 8081

ENTRYPOINT ["/app/server"]
