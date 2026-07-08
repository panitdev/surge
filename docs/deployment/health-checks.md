---
description: Health check endpoint, startup coherence validation, and monitoring Surge in production.
---

# Health Checks

Surge provides a health check endpoint and performs startup validation to catch configuration errors early.

## `GET /health` endpoint

Surge exposes a health check at `GET /health`. It always returns `204 No Content` once the server has finished startup and is accepting connections.

```bash
curl -i http://localhost:3000/health
```

```
HTTP/1.1 204 No Content
```

This is a liveness signal, not a dependency check: it does not query the database or verify any downstream state. If the server process is up and the router is mounted, `/health` returns `204`. There is no failure response from this endpoint — if the database or another dependency is unreachable, the process fails to start in the first place (see below), so it never reaches a state where it could serve `/health` at all.

## Startup coherence checks

Before the server starts accepting connections, Surge validates a small set of configuration invariants during router assembly.

### `return_origins` coverage

Every service that participates in browser login redirects must register its return origin:

```bash
surge-server svc create --name my-app --grant introspect --origin https://app.example.com
```

If no services have registered return origins, Surge logs a warning:

```
WARN: no redirect-mode consumer return_origins are registered; \
      every GET /login redirect will fail return_to validation until one is
```

This is a **warning**, not a fatal error — the server starts but redirect-based login won't work until a return origin is registered.

### CORS origin inclusion

If `SURGE_SESSION_CORS_ORIGINS` is set but doesn't include `SURGE_AUTH_UI_ORIGIN`, the server refuses to start:

```
ERROR: SURGE_SESSION_CORS_ORIGINS is set but does not include auth_ui_origin \
       (https://auth.example.com); the auth UI would be excluded from the \
       credentialed session-management zone it needs
```

This is a **fatal error** — the CORS allowlist would lock the auth UI out of its own session endpoints, so the server aborts.

### Served inline acknowledgment

When `SURGE_ALLOW_SERVED_INLINE=1`, Surge logs a detailed warning to confirm the operator understands the tradeoff:

```
WARN: SURGE_ALLOW_SERVED_INLINE=1: served+inline is acknowledged. \
      Credential entry is proxied through the consuming service's origin — \
      central sees that service's IP, not the browser's. Thread a trusted \
      X-Forwarded-For into the rate limiter, or accept coarsened per-client \
      limiting. Password transit through the service origin is incremental \
      risk, not categorical: every service already holds surge_service_token \
      and can mint or introspect sessions.
```

This is an **informational warning** — the server starts but ensures the decision is deliberate.

## Container orchestration

### Docker HEALTHCHECK

```dockerfile
# In Dockerfile (or docker-compose.yml)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1
```

Or in Docker Compose:

```yaml
services:
  surge:
    image: ghcr.io/panitdev/surge:latest
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

The `start_period` gives Surge time to run migrations and startup checks before Docker starts counting health check failures.

### Kubernetes liveness probe

The liveness probe checks if the container is still alive and responsive:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 15
  periodSeconds: 30
  timeoutSeconds: 5
  failureThreshold: 3
```

If the liveness probe fails, Kubernetes restarts the container.

### Kubernetes readiness probe

The readiness probe checks if the container is ready to accept traffic:

```yaml
readinessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 2
```

If the readiness probe fails, Kubernetes removes the pod from service endpoints — no traffic is routed to it until it passes again. Use a shorter `initialDelaySeconds` and `periodSeconds` than the liveness probe so that temporary blips don't cause unnecessary restarts.

### Scaling considerations

When running multiple Surge instances:

```yaml
# HPA for CPU-based scaling
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: surge-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: surge
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

All instances share the same Postgres database — there's no leader election or coordination needed. Rate limit counters and session state are in Postgres, so any instance can handle any request.

## Logging and observability

Surge uses `tracing` for structured logging. Configure via the `RUST_LOG` environment variable:

```bash
# Default: info level
export RUST_LOG=info

# Debug Surge internals
export RUST_LOG=surge=debug,surge_engine=debug,surge_server=debug

# Trace everything (verbose, not for production)
export RUST_LOG=trace
```

The logging subscriber is configured at startup:

```rust
tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::from_default_env())
    .init();
```

Every HTTP request gets a tracing span via `TraceLayer`, which includes:
- Request method and path
- Response status code
- Request duration
- Client IP

Production log output (JSON-formatted for log aggregation):

```json
{
  "timestamp": "2025-01-15T10:30:00.123Z",
  "level": "INFO",
  "target": "surge_server::api",
  "fields": {
    "message": "surge-server listening",
    "addr": "0.0.0.0:3000"
  }
}
```

For JSON-formatted logs, use `tracing-subscriber` with the `json` feature:

```toml
[dependencies]
tracing-subscriber = { version = "0.3", features = ["json"] }
```

## Audit log monitoring

The `surge.audit_log` table records every state-changing operation. Monitor it for operational insight and security incidents:

```sql
-- Recent authentication attempts
SELECT timestamp, actor, action AS event, details
FROM surge.audit_log
WHERE action IN ('authenticate', 'register', 'register_and_authenticate')
ORDER BY timestamp DESC
LIMIT 20;

-- Service token usage patterns
SELECT
  details ->> 'service_id' AS service,
  COUNT(*) AS operations,
  MAX(timestamp) AS last_seen
FROM surge.audit_log
WHERE actor ->> 'type' = 'service'
GROUP BY details ->> 'service_id'
ORDER BY operations DESC;

-- Rate limit hits in the last hour
SELECT timestamp, actor, details
FROM surge.audit_log
WHERE action = 'authenticate'
  AND details ->> 'result' = 'rate_limited'
  AND timestamp > NOW() - INTERVAL '1 hour'
ORDER BY timestamp DESC;
```

Set up alerts on:
- Sustained rate limit hits (potential brute-force attack)
- Unusual service token activity (token compromise)
- Spike in failed authentication attempts
- Service token creation or revocation events

Audit events include the actor (identity ID, service ID, or operator name), action type, timestamp, and structured details. Use these to build dashboards and alerting rules in your observability stack.
