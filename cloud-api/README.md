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
- Admin feed publishing requires a separate `ADMIN_API_KEY` Worker secret and a pinned `FEED_KEY_ID` / `FEED_PUBLIC_KEY_B64` verification pair.
- The Worker rejects invalid signatures, untrusted key IDs, expired/future-dated feeds, excessive feed lifetimes, oversized payloads and version rollback before storing a feed. The Android app still performs its own complete format, indicator, signature, expiry and rollback validation; server-side signature verification does not replace client validation.

## Worker secrets

Configure secrets through Wrangler's secret manager; do not put their values in `wrangler.toml`, source files, GitHub issues, logs, or the APK.

- `RATE_SALT`: high-entropy random secret with at least 32 bytes. Use a generated secret and keep a protected backup. Do not reuse `ADMIN_API_KEY` as the rate-limit key.
- `PLUS_ENTITLEMENT_HMAC_SECRET`: independent high-entropy secret of at least 32 bytes used to sign short-lived PLUS cloud-access tokens. Never reuse `RATE_SALT`, `ADMIN_API_KEY`, or the Google service-account key.
- `ADMIN_API_KEY`: separate administrative bearer credential for the feed-publish endpoint.
- `FEED_KEY_ID`: exact key identifier pinned in the signed feed header.
- `FEED_PUBLIC_KEY_B64`: Base64-encoded X.509 SubjectPublicKeyInfo for the matching ECDSA P-256 public key. The Worker verifies the feed signature over the exact UTF-8 payload before storing it. The private signing key must remain outside Cloudflare, GitHub, this repository, and the Android app.

For example, from a trusted local terminal connected to the correct Cloudflare account, configure secrets with `wrangler secret put RATE_SALT`, `wrangler secret put PLUS_ENTITLEMENT_HMAC_SECRET`, and `wrangler secret put ADMIN_API_KEY`. The CLI prompts for values; never paste secrets into chat.

Rotating `RATE_SALT` changes the rate-limit identifiers and resets the effective per-IP bucket history. Coordinate rotation deliberately. Old rows are not reversible and are removed by periodic D1 cleanup.

## Validation

Run the dependency-free Worker tests with `npm test` from this directory. GitHub Actions also runs `.github/workflows/cloud-api-ci.yml` on changes to this folder. The tests cover missing D1, missing/short secrets, HMAC output, fail-closed D1 errors, missing client IP and per-minute rate limiting.

## Deployment status

This repository change does not deploy the Worker, create the D1 database, set secrets, populate reputation data, or prove that a live service exists. Configure and test those operational resources in the account owner’s Cloudflare environment before enabling the cloud feature in a release.

## Google Play subscription verification (trial-first regional model)

The Android app uses one Google Play subscription product, "alai_plus", with two base plans: "monthly" and "annual". Google Play supplies the localized price and only returns offers for which the current Play account is eligible. A free-trial phase is detected from the purchase resource returned by Google; the app does not invent a duration, regional currency, or eligibility decision.

### Cloudflare configuration

The non-secret package/product/base-plan values are declared in wrangler.toml. Set the service-account JSON only as a Cloudflare Worker secret:

```sh
wrangler secret put PLAY_SERVICE_ACCOUNT_JSON
```

Use a dedicated Google Play service account with the minimum Android Publisher access required to read and acknowledge subscriptions. Link the service account to the correct Play Console developer account and grant its subscription/order permissions. Do not commit its JSON key, send it in chat, or place it in the APK.

Apply the D1 migration before enabling the endpoint:

```sh
wrangler d1 migrations apply antivirus-al-ai-threat-intel --remote
```

The endpoint POST /v1/billing/subscription/verify accepts only a Google Play purchase token and the configured product ID. It verifies the token with purchases.subscriptionsv2.get, checks the package, product, configured base plan, state and expiry, acknowledges a verified unacknowledged purchase, and returns a minimal entitlement result plus a Worker-signed HMAC bearer token scoped to hash reputation. That token expires within five minutes or at the verified subscription expiry, whichever comes first. POST /v1/hash/reputation requires this token and rejects missing, forged, expired, wrong-product, wrong-plan or wrong-state tokens before querying D1. It stores only a SHA-256 digest of the Google purchase token; the raw purchase token is never persisted or logged. The routes fail closed when service-account credentials, D1, rate limiting, the signing secret or Google verification are unavailable.

Entitlement rules: ACTIVE and IN_GRACE_PERIOD subscriptions are entitled; CANCELED subscriptions remain entitled only until their verified expiry; PENDING, ON_HOLD, PAUSED and EXPIRED subscriptions are not entitled. A purchase must be verified by Google before access is granted. Client-side UI state is not proof of purchase.

### Play Console product configuration

Create subscription product ID "alai_plus" with auto-renewing base plans "monthly" and "annual". Configure the trial offer phases and eligible countries/regions for each base plan in Play Console. Price and currency are supplied by Google Play for the buyer's account country; do not hardcode currency or show a trial duration unless an eligible offer is returned. Keep unavailable markets disabled until merchant, tax, payout, policy and support readiness are confirmed.

The repository changes do not create Play Console products, grant service-account permissions, deploy the Worker, apply the D1 migration, set secrets, or initiate real charges. Until these operational steps are complete, the store must remain clearly marked as unavailable and must not imply that an active trial or payment can be started.

### Testing

npm test includes mocked Google OAuth/Publisher API responses for trial and non-trial entitlement, canceled/expired/pending/on-hold states, product mismatch, acknowledgement and missing-configuration fail-closed behavior. No real purchase token or Google service-account credential is used by tests.


## Checkout readiness gate

Before the app enables a purchase button, `GET /v1/billing/status` authenticates the configured Android Publisher service account and reads the subscription product. It reports only the configured monthly/annual base plans whose Google Play state is ACTIVE. If the product is missing, the service account is absent/invalid, or Google does not confirm active base plans, the app keeps checkout disabled. The user's regional offer and free-trial eligibility are still determined independently by the Play Billing product-details query for the current Play account.

The readiness endpoint is diagnostic only; it does not create a product, activate a base plan, enable a country, or prove that a real checkout has completed.
