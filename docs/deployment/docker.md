---
description: Building and running Surge with Docker, image tags, and production considerations.
---

# Docker

Surge ships a multi-stage Docker image via GitHub Container Registry. This page covers building, running, and configuring the container.

## Available images

Surge is published to GitHub Container Registry at `ghcr.io/panitdev/surge`. Tags follow the release version:

```bash
# Pull a specific version
docker pull ghcr.io/panitdev/surge:0.1.0

# Pull latest stable
docker pull ghcr.io/panitdev/surge:latest
```

## Multi-stage build

The image uses a two-stage build to keep the runtime image small:

```
rust:1-bookworm (builder)  →  debian:bookworm-slim (runtime)
```

**Stage 1 — Builder:**
- Based on `rust:1-bookworm`
- Installs `libpq-dev` (needed by `diesel` to link against Postgres)
- Builds `surge-server` in release mode with `--locked`
- Uses BuildKit cache mounts for Cargo registry, git index, and target directory

**Stage 2 — Runtime:**
- Based on `debian:bookworm-slim`
- Installs only `ca-certificates` and `libpq5` (the runtime library, not the dev headers)
- Creates a non-root `surge` user and group (`--system`, no home directory)
- Copies the compiled binary from the builder stage

The result is a small runtime image with no build toolchain or source code.

## Running the container

```bash
# Pull and run
docker run \
  -e DATABASE_URL="postgres://user:pass@db:5432/surge" \
  -e SURGE_PEPPER="$(openssl rand -base64 48)" \
  -p 3000:3000 \
  ghcr.io/panitdev/surge:latest
```

The container's entrypoint is `surge-server` and the default command is `serve`, so the above is equivalent to:

```bash
docker run ... ghcr.io/panitdev/surge:latest serve
```

### Required environment variables

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | Yes | Postgres connection string |
| `SURGE_PEPPER` | Yes | Must not be `dev-pepper-change-me` in production |
| `SURGE_BIND` | No | Default: `0.0.0.0:3000` (set in Dockerfile) |
| `SURGE_HYDRA_ADMIN_URL` | No | Ory Hydra admin API base URL; setting this enables the Hydra login/consent bridge |
| `SURGE_HYDRA_BRIDGE_ORIGIN` | No (but required if `SURGE_HYDRA_ADMIN_URL` is set) | This server's own public origin for the bridge's `return_to` callback |
| `SURGE_HYDRA_ADMIN_TIMEOUT_SECS` | No | Timeout in seconds for Hydra admin API requests (default: 10) |

All other configuration variables are optional and fall back to defaults. See [Configuration Reference](/integration/configuration) for the full list.

### Overriding the command

You can run CLI subcommands directly:

```bash
# Identity management
docker run \
  -e DATABASE_URL="..." \
  ghcr.io/panitdev/surge:latest identity create --username alice --display-name "Alice"

# Service token management
docker run \
  -e DATABASE_URL="..." \
  ghcr.io/panitdev/surge:latest svc create --name my-app --grant introspect
```

## Non-root user

The container runs as the `surge` system user (UID/GID assigned at build time). No process in the container runs as root. The home directory is set to `/nonexistent` — there's no writable home directory.

```dockerfile
RUN groupadd --system surge \
    && useradd --system --gid surge --no-create-home --home-dir /nonexistent surge

USER surge
```

If you need to mount volumes for logs or data, ensure they're writable by the `surge` user:

```bash
docker run \
  -v /var/log/surge:/var/log/surge \
  --user "$(id -u):$(id -g)" \
  ... ghcr.io/panitdev/surge:latest
```

## Exposed port

The container exposes port 3000 (the default `SURGE_BIND`). No other ports are exposed.

```dockerfile
EXPOSE 3000
```

If you change `SURGE_BIND` to a different port, use `docker run -p <host>:<container>` to map accordingly.

## Container health checks

The `GET /health` endpoint returns `204 No Content` once the server is accepting connections (it does not check the database). Configure a Docker `HEALTHCHECK` in your compose file or at runtime:

```yaml
# docker-compose.yml
services:
  surge:
    image: ghcr.io/panitdev/surge:latest
    environment:
      DATABASE_URL: "postgres://..."
      SURGE_PEPPER: "..."
    ports:
      - "3000:3000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

Or at runtime:

```bash
docker run \
  --health-cmd "curl -f http://localhost:3000/health" \
  --health-interval 30s \
  --health-timeout 5s \
  --health-retries 3 \
  ... ghcr.io/panitdev/surge:latest
```

## Kubernetes example

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: surge
spec:
  replicas: 2
  selector:
    matchLabels:
      app: surge
  template:
    metadata:
      labels:
        app: surge
    spec:
      containers:
        - name: surge
          image: ghcr.io/panitdev/surge:0.1.0
          ports:
            - containerPort: 3000
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: surge-secrets
                  key: database-url
            - name: SURGE_PEPPER
              valueFrom:
                secretKeyRef:
                  name: surge-secrets
                  key: pepper
          livenessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 3000
            initialDelaySeconds: 5
            periodSeconds: 10
---
apiVersion: v1
kind: Secret
metadata:
  name: surge-secrets
type: Opaque
stringData:
  database-url: "postgres://surge:password@postgres:5432/surge"
  pepper: "base64-encoded-pepper-value"
```

## Build your own

The Dockerfile is at the repository root. Build with BuildKit caching for fast incremental rebuilds:

```bash
# Clone and build
git clone https://github.com/panitdev/surge.git
cd surge

DOCKER_BUILDKIT=1 docker build \
  --tag my-registry/surge:custom \
  .
```

BuildKit cache mounts speed up repeated builds by caching:
- `/usr/local/cargo/registry` — downloaded crate sources
- `/usr/local/cargo/git` — git-sourced dependencies
- `/usr/src/surge/target` — compilation artifacts

The first build downloads and compiles everything. Subsequent builds where only your source changed reuse compiled dependencies.

Customize the image by adding your own layers after the `FROM debian:bookworm-slim` stage — add monitoring agents, configure logging, or embed your auth UI static assets.
