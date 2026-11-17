# ANTIVIRUS AL AI — Global Product Readiness Plan

Status date: 2026-11-18
Target: a trustworthy, privacy-first Android security product with a separately operated cloud service and public product website.

## 1. Current verified baseline

The current repository is an Android MVP, not yet a production antivirus suite. It currently provides:
- User-selected file scanning through Android's Storage Access Framework.
- Streaming SHA-256 hashing with a 200 MiB per-file limit.
- Static APK metadata and permission/component heuristics.
- Evidence-based results that distinguish suspicious, unknown, and no-known-indicator outcomes.
- AES-GCM encrypted copies in app-private quarantine; the original file is not silently removed.
- A strict ECDSA P-256 signed-feed parser/store with expiry, size, duplicate/order, and rollback checks, plus synthetic unit tests.

Not yet production-enabled:
- No production malware feed, production publisher key, feed update UI, or scan-engine integration.
- No cloud reputation service or live backend integration.
- No continuous/on-access protection, VPN firewall, phishing protection, or broad device scan.
- No production billing/subscriptions or operational customer-support service.
- Release signing secrets/keystores have not been provisioned.

A clean result must never be described as proof that a file is safe. Android platform and Play policy limits must be respected; do not promise access to other apps' private caches or arbitrary RAM/task killing.

## 2. Product principles
1. Local-first: scan files on-device. Do not upload file contents by default.
2. Hybrid cloud: cloud services provide signed threat intelligence, hash reputation, update metadata, account/licensing, and opt-in diagnostics; core safety functions retain an offline fallback.
3. Safe cleanup: only app-owned cache/temp files can be cleaned automatically. Shared or personal files require clear item-level review and Android system confirmation where required.
4. Explainable detection: every alert carries evidence, confidence, timestamp, source, and a false-positive reporting path.
5. Least privilege: request permissions only when a user activates the corresponding feature; no hidden Accessibility, VPN, notification, or broad file access.
6. Secure supply chain: separate signing identities for Bazaar and Google Play, separate from threat-feed signing keys; secrets never enter Git.
7. Honest claims: no '100% protection', 'detects all viruses', or benchmark claims without independent, reproducible test results.

## 3. Delivery phases and acceptance gates

### P0 — Stabilize the Android foundation
- [ ] Audit Gradle configuration, manifest permissions, exported components, backup rules, network security, and dependency versions.
- [ ] Add CI gates for unit tests, lint, dependency/license inventory, secret scanning, and release artifact verification.
- [ ] Add crash-safe error handling, scan cancellation, temporary-file cleanup, and bounded memory/performance tests.
- [ ] Define independent Bazaar and Google Play release variants/credentials while preserving applicationId com.antivirusalai.
- [ ] Create and securely back up each store's release key; never generate or store private keys in repository files.
- Acceptance: clean CI, reproducible artifact metadata, verified signing certificate fingerprints, upgrade tests for each store.

### P1 — Make detection useful and measurable
- [ ] Connect the existing signed-feed store to the scan engine using an injected production keyring.
- [ ] Add secure feed download over HTTPS, ETag/Last-Modified support, bounded retries, freshness state, and offline fallback.
- [ ] Add feed publisher tooling with canonical serialization, signing, provenance, review, key rotation, and rollback protection.
- [ ] Improve APK static inspection and package risk evidence without executing samples.
- [ ] Add a safe, lawful, synthetic test corpus and measure false positives/false negatives before public claims.
- Acceptance: tamper, expiry, unknown-key, rollback, key-rotation, offline, and interrupted-update tests pass.

### P2 — Hybrid cloud platform
- [ ] Define versioned API contracts and threat model before implementation.
- [ ] Use Cloudflare Worker + D1 (or equivalent managed services) for API, threat-feed metadata, abuse controls, and minimal operational records.
- [ ] Keep publisher and service credentials in backend secrets; never embed privileged API keys in the APK.
- [ ] Default to hash-only reputation queries with explicit opt-in and clear retention/deletion policy.
- [ ] Add rate limits, request validation, audit events, health checks, backups, migrations, and incident response.
- Acceptance: documented API, privacy review, automated security tests, rate-limit tests, backup/restore drill.

### P3 — Safe device tools
- [ ] Storage analysis using supported Android APIs and user-visible categories.
- [ ] Safe cleanup restricted to app-owned cache/temp data.
- [ ] Large/duplicate candidate discovery with user review; never silently delete personal files.
- [ ] Battery/resource information only from supported public APIs; no fake RAM booster or task-killer claims.
- [ ] System-mediated uninstall/removal and MediaStore deletion flows with confirmation.
- Acceptance: no destructive action without user confirmation; permission-denial and Android-version tests.

### P4 — User protection and trust
- [ ] Phishing/link checks with reputation sources, safe URL parsing, and transparent limitations.
- [ ] Optional network protection only after Android VPNService and Google Play policy review.
- [ ] Notification/monitoring features only where technically supported and explicitly enabled.
- [ ] Privacy dashboard, data export/deletion requests, false-positive reporting, and support workflow.
- Acceptance: permission audit, privacy review, battery impact tests, accessibility/localization tests.

### P5 — Public website and international release
- [ ] Acquire and verify the product domain; enable DNSSEC where supported, HTTPS, HSTS, and protected registrar/Cloudflare access.
- [ ] Publish product landing page, truthful feature matrix, downloads/store links, privacy policy, terms, support/contact, security disclosure, and changelog.
- [ ] Provide English and Persian at minimum; make all claims consistent with shipped features.
- [ ] Set up support mailbox, status page, incident contact, and domain-based email authentication (SPF, DKIM, DMARC).
- [ ] Prepare store listings, screenshots, content rating, data-safety disclosures, and region-specific legal review.
- Acceptance: website security checks, working support/contact, policy consistency, store review readiness.

### P6 — Independent validation and scale
- [ ] Independent mobile security review and penetration test.
- [ ] Independent malware-detection evaluation (e.g., AV-TEST or equivalent) before comparative claims.
- [ ] SBOM, signed build provenance, dependency vulnerability response, and coordinated disclosure process.
- [ ] Load, availability, disaster-recovery, and cloud-cost tests.
- Acceptance: published scope/methodology, resolved critical/high findings, operational runbooks.

## 4. Separate release signing

The app keeps the same package ID, com.antivirusalai, but has distinct store signing identities:
- Bazaar: dedicated permanent Bazaar release key.
- Google Play: dedicated Google Play upload/release arrangement. Prefer Play App Signing with the owner's chosen upload key and a documented recovery/rotation process.

Each key is independent of the other store and independent of the ECDSA threat-feed signing key. Back up keystores and credentials offline in at least two secure locations. Never send passwords or private key material in chat or commit them to GitHub. A different signing identity generally prevents in-place updates across stores; users should remain on the same store channel.

## 5. Immediate next inputs

The product domain name must be supplied after it is purchased/registered. Before connecting DNS, confirm the registrar and Cloudflare zone ownership. Do not invent a domain or create public records against a guessed name.

The owner must create the permanent signing keys locally (or in a trusted secure environment) and add the encoded keystore plus passwords as separate GitHub Actions secrets. Do not ask the owner to paste secret values into chat.

## 6. Release truth

Until the relevant acceptance gates pass, describe the product as an evolving security scanner/MVP. Do not advertise real-time antivirus, full-device malware removal, cloud intelligence, or independent certification as available capabilities until they are implemented, tested, and operational.
