# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in SNR, please report it responsibly:

1. **Do not** open a public issue
2. Email your findings to the repository maintainer
3. Include a description of the vulnerability, steps to reproduce, and potential impact
4. Allow reasonable time for a fix before public disclosure

## Security Architecture

### Authentication & Authorization

- **JWT-based authentication** with HS256 algorithm enforcement
- **Role-based access control (RBAC)**: admin, analyst, viewer
- **Team-scoped data isolation**: sessions, settings, and analytics are scoped per team
- **Account lockout**: 5 failed login attempts triggers a 15-minute lockout
- **Timing-safe login**: bcrypt comparison always runs (even for non-existent users) to prevent user enumeration
- **Password complexity**: minimum 10 characters with uppercase, lowercase, number, and special character required
- **Common password rejection**: dictionary-based check blocks known weak passwords

### API Security

- **Helmet.js** security headers (CSP, HSTS, X-Frame-Options, etc.)
- **Rate limiting**: global API rate limit, stricter limits on auth and password endpoints
- **CORS**: configurable allowed origins; locked down in production
- **Input validation**: file uploads validated by both extension and MIME type
- **No dynamic SQL**: all queries use parameterized statements
- **Optimistic locking**: concurrent edit detection on analysis overrides

### Data Protection

- **Sensitive settings masked**: API keys, secrets, and tokens are never returned to the frontend
- **Audit logging**: all significant actions (login, analysis, exports, admin actions) are logged
- **Input redaction**: client-side redaction with server-side verification pass
- **No telemetry**: no external calls beyond the configured LLM provider

### LLM Security

- **Prompt injection defense**: user-supplied data wrapped in XML boundary tags (`<user_provided_data>`)
- **System prompt hardening**: explicit instructions to never follow embedded commands or leak configuration
- **Structured output only**: LLM responses constrained to JSON tool schemas

### Deployment Recommendations

1. Always set `NODE_ENV=production` in production
2. Set a strong `JWT_SECRET` (64+ random bytes)
3. Configure `ALLOWED_ORIGINS` for CORS
4. Use HTTPS (reverse proxy with TLS termination)
5. Change the default admin password immediately after first login
6. Rotate API keys periodically
7. Back up the SQLite database regularly
8. Run behind a reverse proxy (nginx, Caddy) that handles TLS
9. Restrict network access to the server port (3001)

## Dependencies

Security-relevant dependencies:
- `bcryptjs` — password hashing (12 rounds)
- `jsonwebtoken` — JWT token management
- `helmet` — HTTP security headers
- `express-rate-limit` — request throttling
- `multer` — file upload handling with size and type restrictions
