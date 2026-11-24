# Cafe Bazaar Subscription Commerce — ANTIVIRUS AL AI v1.0

- First distribution: Cafe Bazaar (Android).
- Billing SDK: official Poolakey 2.3.0.
- Package: com.antivirusalai.
- Free tier: local file/APK scanning, evidence-based reports and local quarantine.
- PLUS: optional cloud SHA-256 reputation; each lookup still requires separate user consent.
- Monthly SKU: alai_plus_monthly. Annual SKU: alai_plus_annual.
- Trial duration, eligibility, localized price and renewal terms are configured in Pishkhan, never hardcoded in the APK.

## Purchase verification

Poolakey connects to the installed Cafe Bazaar app and fetches subscription SKU details. The app checks trial eligibility and launches Bazaar's native subscription flow. It sends only the selected SKU and purchase token to the first-party HTTPS Worker. The Worker refreshes its OAuth access token using Cafe Bazaar Developer API credentials held only as Worker secrets, then validates the exact package, SKU and purchase token with Developer API v2. Access is granted only while validUntilTimestampMsec is in the future. A canceled auto-renewal remains entitled only until verified expiry. Expired, refunded, mismatched and unverifiable purchases fail closed. D1 stores only SHA-256 of the purchase token and minimal entitlement metadata; the raw token is never persisted. The Worker issues a signed PLUS cloud token with a maximum five-minute lifetime. Restore queries the current Bazaar account and verifies tokens again.

Poolakey uses server-side verification (SecurityCheck.Disable) intentionally. Developer API credentials are never embedded in the APK.

## Pishkhan setup

Create the exact package and SKUs. Configure monthly/annual billing interval, price, auto-renewal and trial eligibility/duration. Create a Developer API client and complete OAuth authorization to obtain a refresh token. Test purchase, restore, cancellation and expiry on a real device with Cafe Bazaar installed.

## Cloudflare Worker secrets

Set through trusted Cloudflare dashboard/CLI. Never place values in Git, source code, APK, logs or chat.

- BAZAAR_CLIENT_ID
- BAZAAR_CLIENT_SECRET
- BAZAAR_REFRESH_TOKEN
- BAZAAR_PACKAGE_NAME (exactly com.antivirusalai)
- BAZAAR_MONTHLY_PRODUCT_ID (exactly alai_plus_monthly)
- BAZAAR_ANNUAL_PRODUCT_ID (exactly alai_plus_annual)
- PLUS_ENTITLEMENT_HMAC_SECRET (independent random secret, at least 32 bytes)
- RATE_SALT remains independent.

Apply cloud-api/migrations/0003_bazaar_billing.sql and deploy the Worker. Checkout stays disabled until the Worker can obtain a Bazaar access token and the app can query actual SKU details.

## Test matrix

Test Bazaar installed/signed-in/updated; missing/disconnected Bazaar; both SKU details; missing SKU; eligible/ineligible trial accounts; monthly/annual purchase; cancellation; refunded/mismatched product; restore after restart/reinstall; canceled-but-not-expired; expired; invalid token; OAuth, Developer API and D1 outage; duplicate restore; short-lived token expiry; cloud outage with offline scanning.

## Release gates

- [ ] Pishkhan products and trial terms configured.
- [ ] Developer API OAuth client and refresh token configured.
- [ ] Worker secrets and D1 migration installed.
- [ ] Worker deployed and readiness endpoint verified.
- [ ] Purchase/restore tested on physical device with Bazaar installed.
- [ ] Android tests, lint and API 33/35 emulator smoke tests pass.
- [ ] Publisher creates and backs up permanent signing keystore.
- [ ] Release APK signed with permanent key; certificate fingerprint recorded.
- [ ] Privacy policy, support contact, screenshots and accurate descriptions prepared.
- [ ] Cafe Bazaar review completed.

No production payment, Pishkhan product, OAuth credential, Cloudflare secret, D1 resource, deployment or signing key is configured by these source changes.
