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
- [ ] Design any continuous monitoring only through supported Android APIs, with battery, privacy, and Play policy review.

## Phase 4 — Independent validation and release readiness
- [ ] Measure precision, recall, false-positive rate, false-negative rate, unknown coverage, scan latency, and battery cost on a lawful benchmark.
- [ ] Complete an external security review and independent AV detection evaluation (AV-TEST or equivalent).
- [ ] Resolve all critical/high findings and publish a reproducible report.
- [ ] Complete Play Console permission declarations for MANAGE_EXTERNAL_STORAGE and QUERY_ALL_PACKAGES.
- [ ] Complete privacy, retention, accessibility, localization, billing, release-signing, and supply-chain reviews.


## Commercial MVP — regional trial-first billing (development PR)

- [x] Add Google Play Billing 9.1.0 client and dynamically query region/account-eligible subscription offers.
- [x] Read localized price/currency and all price phases from Google Play; do not hardcode regional prices or trial length.
- [x] Implement backend Google Play Publisher OAuth and subscription-token verification.
- [x] Keep checkout closed until the backend confirms the Play product and active base plans.
- [x] Verify subscription state and expiry server-side; acknowledge verified new purchases and persist only a purchase-token SHA-256 digest.
- [x] Add restore and Google Play subscription-management entry points.
- [x] Keep the basic offline scanner and reports free; gate optional cloud-hash reputation behind verified entitlement and separate consent.
- [ ] Create and activate the `alai_plus` product and `monthly` / `annual` base plans in Play Console with trial offers and selected regional availability.
- [ ] Configure the dedicated Android Publisher service account and Cloudflare Worker secret.
- [ ] Apply D1 migration `0002_play_billing.sql` and deploy the Worker.
- [ ] Run internal-track end-to-end tests for new trial, paid conversion, cancellation, grace period, expiry, restore and duplicate purchase.
- [ ] Complete region-specific business, tax, payout, consumer-protection, privacy and support readiness before opening each market.
