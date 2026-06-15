# SNR — API Reference

Base URL: `http://127.0.0.1:3001`

All endpoints return JSON unless noted. Auth endpoints issue JWTs; all other endpoints require a valid `Authorization: Bearer <token>` header.

---

## Health & Readiness (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check — returns `{ status, uptime, version, llm }` |
| GET | `/api/ready` | Readiness probe — verifies DB read/write |

---

## Authentication (`/api/auth`)

| Method | Endpoint | Body | Response | Auth | Notes |
|--------|----------|------|----------|------|-------|
| POST | `/api/auth/login` | `{ email, password }` | `{ token, refreshToken, user, teams }` | No | 5 req/15min |
| POST | `/api/auth/refresh` | `{ refreshToken }` | `{ token, refreshToken }` | No | 5 req/15min |
| GET | `/api/auth/me` | — | `{ user, teams }` | Yes | Current user profile |
| PATCH | `/api/auth/me/password` | `{ currentPassword, newPassword }` | `{ ok, message }` | Yes | 5 req/1hr |
| POST | `/api/auth/logout` | — | `{ ok }` | Yes | Revokes current token |

---

## Users (`/api/users`) — Admin Only

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/users` | — | `[ user, ... ]` |
| POST | `/api/users` | `{ email, password, displayName, role? }` | `{ id, email, ... }` |
| GET | `/api/users/:id` | — | user object |
| PATCH | `/api/users/:id` | `{ displayName?, role?, disabled? }` | `{ ok }` |
| PATCH | `/api/users/:id/password` | `{ newPassword }` | `{ ok }` |
| DELETE | `/api/users/:id` | — | `{ ok }` (soft-disable) |

---

## Teams (`/api/teams`)

| Method | Endpoint | Body | Response | Auth |
|--------|----------|------|----------|------|
| GET | `/api/teams` | — | `[ team, ... ]` | Yes |
| POST | `/api/teams` | `{ name, description? }` | `{ id, name, ... }` | Admin |
| GET | `/api/teams/:id` | — | team + members | Yes |
| PATCH | `/api/teams/:id` | `{ name?, description? }` | `{ ok }` | Admin/Lead |
| DELETE | `/api/teams/:id` | — | `{ ok }` | Admin |
| POST | `/api/teams/:id/members` | `{ userId, role? }` | `{ ok }` | Admin/Lead |
| PATCH | `/api/teams/:id/members/:userId` | `{ role }` | `{ ok }` | Admin/Lead |
| DELETE | `/api/teams/:id/members/:userId` | — | `{ ok }` | Admin/Lead |
| GET | `/api/teams/:id/settings` | — | merged settings | Yes |
| PATCH | `/api/teams/:id/settings` | `{ key: value }` | `{ ok }` | Admin/Lead |

---

## Sessions (`/api/sessions`) — Requires Team Membership

| Method | Endpoint | Body | Response | Notes |
|--------|----------|------|----------|-------|
| GET | `/api/sessions` | Query: `limit?=20, offset?=0` | `{ sessions, total, limit, offset }` | Paginated |
| POST | `/api/sessions` | `{ name?, incident_id?, audience? }` | `{ id }` | Create before analysis |
| GET | `/api/sessions/:id` | — | `{ session, result, analystOverrides, inputs, note }` | Full detail |
| PATCH | `/api/sessions/:id/name` | `{ name }` | `{ ok }` | Rename |
| PATCH | `/api/sessions/:id/note` | `{ content }` | `{ ok }` | Save analyst note |
| PATCH | `/api/sessions/:id/overrides` | `{ overrides, expectedVersion? }` | `{ ok }` | Optimistic locking |
| DELETE | `/api/sessions/:id` | — | `{ ok }` | Creator/Lead/Admin |
| GET | `/api/sessions/audit/log` | — | `{ rows }` | Last 100 entries |

---

## Analysis (`/api/analyze`) — Requires Team Membership

### Run Analysis (SSE)

```
POST /api/analyze
Content-Type: multipart/form-data
```

Fields: `session_id`, `siem_input?`, `text_input?`, `logFile?` (upload), `audience`, `redacted_strings?`

Returns an SSE event stream:
- `event: status` — progress updates
- `event: chunk` — streaming partial JSON
- `event: complete` — final `AnalysisResult` JSON
- `event: error` — error message

### Exports

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| POST | `/api/analyze/export/stix` | `{ session_id, tlp }` | STIX 2.1 JSON |
| POST | `/api/analyze/export/navigator` | `{ session_id }` | ATT&CK Navigator layer JSON |
| POST | `/api/analyze/export/eml` | `{ session_id, audience, tlp, attach_stix?, attach_navigator?, attach_iocs?, attach_detection_rules?, diagram_jpg_b64?, email_content_overrides? }` | .eml file |
| POST | `/api/analyze/export/zip` | `{ session_id, audience, tlp, attach_iocs?, diagram_jpg_b64?, email_content_overrides? }` | .zip archive |
| POST | `/api/analyze/export/report` | `{ session_id, audience, tlp, email_content_overrides? }` | Markdown report |
| POST | `/api/analyze/export/detection-rules` | `{ session_id, tlp? }` | Detection rules (.txt) |
| POST | `/api/analyze/report-preview` | `{ session_id, audience?, tlp?, email_content_overrides? }` | Preview markdown (inline) |
| GET | `/api/analyze/email-preview` | Query: `tlp?, audience?` | HTML email preview |

---

## Settings (`/api/settings`) — Requires Team Membership

| Method | Endpoint | Body | Response |
|--------|----------|------|----------|
| GET | `/api/settings` | — | `{ settings }` (sensitive keys masked) |
| PATCH | `/api/settings` | `{ key: value, ... }` | `{ ok }` |
| POST | `/api/settings/logo` | Multipart: `logo` (≤500KB image) | `{ ok, dataUri }` |
| DELETE | `/api/settings/logo` | — | `{ ok }` |

---

## Analytics (`/api/analytics`) — Requires Team Membership

| Method | Endpoint | Query | Response |
|--------|----------|-------|----------|
| GET | `/api/analytics` | `days?=30, all?=true` | `{ sessionsOverTime, severityDistribution, audienceBreakdown, exportActivity, iocDistribution, techniqueMap }` |

---

## Rate Limits

| Scope | Limit |
|-------|-------|
| Login | 5 req / 15 min |
| Token refresh | 5 req / 15 min |
| Password change | 5 req / 1 hr |
| All other API | 100 req / 15 min |

## Error Format

All errors return `{ error: string }` with appropriate HTTP status codes.

## Authentication Flow

1. `POST /api/auth/login` → receive `token` + `refreshToken`
2. Include `Authorization: Bearer <token>` on all subsequent requests
3. Include `X-Team-Id: <teamId>` for team-scoped endpoints
4. When token expires, `POST /api/auth/refresh` with the refresh token
5. `POST /api/auth/logout` to revoke the current token
