# ANTIVIRUS AL AI Cloud API

Cloudflare Worker API with D1 reputation metadata. Android remains local-first; raw files are never accepted or uploaded.

Endpoints: GET `/v1/health`; POST `/v1/url/check`; POST `/v1/hash/reputation`; GET `/v1/threat-feed/latest`; POST `/v1/admin/feed` (Bearer `ADMIN_API_KEY`).

## Security controls

- HTTPS is required by the Android client; the Worker does not fetch user-supplied URLs.
- Request bodies are bounded; SQL uses bound parameters.
- Raw files are never accepted or uploaded.
- Non-health `/v1/*` endpoints fail closed when D1 is unavailable.
- Protected API requests require a Worker secret named `RATE_SALT` containing at least 32 bytes. A keyed HMAC-SHA-256 of the Cloudflare-provided client IP is stored for rate limiting; a plain unkeyed IP hash is not used.
- D1 errors, missing/short rate-limit secrets, or missing client address cause HTTP 503 rather than allowing a request without rate limiting.
- Admin feed publishing requires a separate `ADMIN_API_KEY` Worker secret. It is never included in the Android app.

## Worker secrets

Configure secrets through Wrangler's secret manager; do not put their values in `wrangler.toml`, source files, GitHub issues, logs, or the APK.

- `RATE_SALT`: high-entropy random secret with at least 32 bytes. Use a generated secret and keep a protected backup. Do not reuse `ADMIN_API_KEY` as the rate-limit key.
- `ADMIN_API_KEY`: separate administrative bearer credential.

For example, from a trusted local terminal connected to the correct Cloudflare account, configure each secret with `wrangler secret put RATE_SALT` and `wrangler secret put ADMIN_API_KEY`. The CLI prompts for the values; never paste them into chat.

Rotating `RATE_SALT` changes the rate-limit identifiers and resets the effective per-IP bucket history. Coordinate rotation deliberately. Old rows are not reversible and are removed by periodic D1 cleanup.

## Validation

Run the dependency-free Worker tests with `npm test` from this directory. GitHub Actions also runs `.github/workflows/cloud-api-ci.yml` on changes to this folder. The tests cover missing D1, missing/short secrets, HMAC output, fail-closed D1 errors, missing client IP and per-minute rate limiting.

## Deployment status

This repository change does not deploy the Worker, create the D1 database, set secrets, populate reputation data, or prove that a live service exists. Configure and test those operational resources in the account owner’s Cloudflare environment before enabling the cloud feature in a release.
