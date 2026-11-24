# Roadmap

## Phase 0 — Buildable Android foundation
- [x] Bilingual Android dashboard and scan centre.
- [x] Automatic quick/deep shared-storage scan paths with progress and access-limit reporting.
- [x] Streaming SHA-256 and bounded per-file scan.
- [x] APK package metadata inspection without loading or executing packages.
- [x] Evidence-based permission heuristics; no “safe” guarantee.
- [x] AES-GCM quarantine vault APIs with integrity-checked restore and explicit source-removal attempt.
- [x] CI unit tests, lint, debug APK assembly, and emulator instrumentation coverage (current launch test still being stabilized).

## Phase 1 — Hash reputation and static detection
- [x] Strict ALAI v1 feed format and ECDSA P-256 signature verification.
- [x] Pinned release public key; private key remains external to source and APK.
- [x] Expiry, clock-skew, size, entry-count, duplicate/sort, and rollback checks.
- [x] Runtime feed lookup is integrated into per-file SHA-256 scan verdicts.
- [x] WorkManager schedules network-constrained feed refresh (best effort, not real-time).
- [x] EICAR safe test marker and stream-boundary regression tests.
- [x] Publisher workflow and hash-only MalwareBazaar recent-detections adapter prepared.
- [ ] Configure provider API credential, the matching signing-key secret, and confirm commercial-use entitlement/terms.
- [ ] Run and verify the first successful feed publication; measure feed age, size, and family coverage.
- [ ] Expand APK static analysis with bounded DEX string signals and false-positive calibration.
- [ ] Add a larger lawful benign-app corpus and benchmark set before making accuracy claims.

## Phase 2 — Production threat intelligence and analysis
- [ ] Add a backend reputation proxy, key rotation, provider-health monitoring, rate limiting, and emergency revocation.
- [ ] Evaluate additional licensed sources and curated YARA/signature engines; preserve source attribution and licensing.
- [ ] Add behavior analysis only through supported, policy-compliant Android facilities and a reviewed design.
- [ ] Do not upload file content by default; any hash lookup or telemetry must be transparent and opt-in.

## Phase 3 — Remediation and monitoring
- [x] Verify encrypted quarantine copy and source hash before requesting removal.
- [x] Expose vault list/restore/delete APIs and accurate source-removal result.
- [ ] Build quarantine-management UI, restore destination flow, and recovery tests on multiple document providers.
- [ ] Add Android uninstall handoff with explicit user confirmation; no silent uninstall.
- [ ] Design any continuous monitoring only through supported Android APIs, with battery, privacy, Android platform and Cafe Bazaar review.

## Phase 4 — Independent validation and release readiness
- [ ] Measure precision, recall, false-positive rate, false-negative rate, unknown coverage, scan latency, and battery cost on a lawful benchmark.
- [ ] Complete an external security review and independent AV detection evaluation (AV-TEST or equivalent).
- [ ] Resolve all critical/high findings and publish a reproducible report.
- [ ] Complete Cafe Bazaar permission disclosures/review and Android special-access rationale for MANAGE_EXTERNAL_STORAGE and QUERY_ALL_PACKAGES.
- [ ] Complete privacy, retention, accessibility, localization, billing, release-signing, and supply-chain reviews.


## Commercial MVP — Cafe Bazaar regional trial-first billing (draft PR)

- [x] Replace the Android Google Play Billing client with official Cafe Bazaar Poolakey 2.3.0.
- [x] Query actual Bazaar subscription SKU details, localized prices and account trial eligibility; do not hardcode price, currency or trial duration.
- [x] Implement first-party Worker OAuth and Cafe Bazaar Developer API v2 purchase-token verification.
- [x] Keep checkout closed until the Worker can authenticate to Bazaar and the app retrieves the real SKUs from Bazaar.
- [x] Verify package, exact SKU, purchase token and expiry server-side; store only the SHA-256 purchase-token digest.
- [x] Add restore by querying current Bazaar-account subscriptions and re-verifying them server-side.
- [x] Keep basic offline scanning and reports free; gate optional cloud-hash reputation behind a short-lived signed entitlement and separate consent.
- [ ] Create monthly and annual SKUs in Pishkhan: alai_plus_monthly and alai_plus_annual; configure trial and renewal terms there.
- [ ] Configure Cafe Bazaar Developer API OAuth client ID, client secret and refresh token as Worker secrets.
- [ ] Configure independent RATE_SALT and PLUS_ENTITLEMENT_HMAC_SECRET Worker secrets.
- [ ] Apply D1 migration 0003_bazaar_billing.sql and deploy the Worker.
- [ ] Run real-device tests for eligible/ineligible trial accounts, monthly/annual purchase, cancellation, expiry, restore, invalid tokens and service outage.
- [ ] Complete regional business, tax, payout, consumer-protection, privacy and support readiness before opening each market.

Google Play Billing is not used by the current Cafe Bazaar release candidate.
