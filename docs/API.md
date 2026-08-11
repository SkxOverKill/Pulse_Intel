# Pulse Intelligence API

The public API is read-only and intended for analyst scripts, SOAR playbooks, internal tools,
and integrations that need trusted CTI data without scraping the UI.

## Authentication

Create an API key from `/settings`, then send it as a bearer token:

```bash
curl -H "Authorization: Bearer $PULSE_API_KEY" \
  "https://your-pulse-host.example/api/v1/indicators?pageSize=100"
```

Keys may be scoped. A key with no scopes has full API access.

| Scope | Endpoints |
|---|---|
| `indicators:read` | `/api/v1/indicators`, `/api/v1/indicators/:id` |
| `actors:read` | `/api/v1/actors`, `/api/v1/actors/:id` |

## Rate Limits

`/api/v1/*` routes are rate limited per API key. Defaults are 120 requests per 60-second
window.

Configure with:

```env
PUBLIC_API_RATE_LIMIT_PER_WINDOW="120"
PUBLIC_API_RATE_LIMIT_WINDOW_SECONDS="60"
```

Responses include:

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | Requests allowed in the current window |
| `X-RateLimit-Remaining` | Requests left in the current window |
| `X-RateLimit-Reset` | Unix timestamp when the current window resets |
| `Retry-After` | Seconds to wait after a `429` response |

## Indicators

```http
GET /api/v1/indicators
```

Query parameters:

| Parameter | Description |
|---|---|
| `page` | Positive integer, default `1` |
| `pageSize` | Positive integer, default `100`, max `500` |
| `q` | Case-insensitive substring match against normalized value |
| `type` | `IPV4`, `IPV6`, `DOMAIN`, `URL`, `MD5`, `SHA1`, `SHA256`, `EMAIL`, `CVE`, `BTC_ADDRESS`, `REGISTRY_KEY`, `MUTEX`, `FILENAME`, `USER_AGENT`, or `ASN` |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `tag` | Exact tag match |
| `format` | `json`, `csv`, `stix`, `misp`, or `snort` |

Whitelisted and expired indicators are never returned.

Example:

```bash
curl -H "Authorization: Bearer $PULSE_API_KEY" \
  "https://your-pulse-host.example/api/v1/indicators?type=DOMAIN&severity=HIGH"
```

## Actors

```http
GET /api/v1/actors
GET /api/v1/actors/:id
```

Query parameters for the list endpoint:

| Parameter | Description |
|---|---|
| `page` | Positive integer, default `1` |
| `pageSize` | Positive integer, default `50`, max `200` |
| `active` | `true` or `false` |

Example:

```bash
curl -H "Authorization: Bearer $PULSE_API_KEY" \
  "https://your-pulse-host.example/api/v1/actors?active=true"
```

## Health

```http
GET /api/health
GET /api/health?deep=1
```

The basic health endpoint reports process status. Deep health checks PostgreSQL and Redis and
returns `503` when a dependency is degraded.
