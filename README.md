# ANTIVIRUS AL AI

## Support

For support requests, bug reports, and product feedback, contact **Zojajiali4@gmail.com**. The Android Settings → Support screen opens the device's email app when available.

Privacy-first Android security scanner. Cafe Bazaar release candidate: **0.4.0 (versionCode 4)**. The app includes a bilingual Persian/English dashboard, automatic quick/deep shared-storage scanning, a bounded local scan pipeline, an authenticated threat-feed client, and an encrypted quarantine vault.

## Implemented security layers

- Bounded device scanning: quick scan up to 350 files/1 GiB; deep and user-selected folder scans up to 100,000 files/25 GiB; 200 MiB per file. These are traversal limits, not detection-coverage guarantees. Results disclose skipped files and incomplete coverage.
- EICAR harmless antivirus test-string detection for scanner regression checks. EICAR is not live malware and is never described as malware.
- A native C++ Aho-Corasick multi-pattern matcher is wired into the bounded file-read pass through JNI. It accepts reviewed patterns from a signed, expiring offline content-rule bundle; until a production bundle is published, only the harmless built-in self-test rule is active.
- Bounded ZIP/APK structure analysis, DEX header validation, selected static API-reference checks, and ELF header/symbol inspection. No archive entry or native library is extracted for execution.
- Multi-signal heuristics combine manifest capabilities, DEX API references, native symbol references, and archive anomalies. Static references are leads for review, not proof of execution or malware.
- ECDSA P-256 signed-feed verification with a pinned public key, strict format, expiry, monotonic version checks, and atomic private-storage replacement.
- Hash-reputation and content-signature verdicts are separate evidence sources. Optional cloud hash reputation requires explicit confirmation and sends the SHA-256 digest plus a short-lived, server-signed PLUS access token; it does not upload the file or override the local verdict. ML feature extraction is implemented, but model inference is NOT_CONFIGURED until a licensed labelled dataset and independent validation exist.
- Offline URL structure inspection is available from Security Tools. URLs are not opened, resolved, followed or sent to a server; this heuristic is not a complete phishing detector.
- WorkManager refresh scheduling for both signed hash intelligence and the optional signed content-rule bundle. Network/battery constraints and Android Doze may delay work; this is not continuous device monitoring.
- AES-GCM private quarantine vault with verified-copy creation, listing, restore, and removal APIs. Source-removal action is restricted to malware/PUA/suspicious verdicts, requires explicit user confirmation and a verified copy, and can still be refused by Android or the document provider. A full quarantine-management screen remains outstanding.
- File contents, filenames and paths are not uploaded by the local scanning path. A separate optional cloud reputation action sends the SHA-256 digest and a short-lived entitlement token after explicit confirmation; ordinary connection metadata such as IP may be processed for rate limiting. The app downloads public signed hash-intelligence and content-rule metadata bundles.

## Live threat-feed activation

The Android client and publisher workflow are prepared, but a live database is **not active until the repository owner configures** these GitHub Actions secrets:

- `MALWAREBAZAAR_AUTH_KEY` — required MalwareBazaar API credential.
- `THREATFOX_AUTH_KEY` — optional ThreatFox API credential; when configured, the publisher includes SHA-256 metadata for malware samples linked to recent ThreatFox IOCs.
- `ALAI_FEED_SIGNING_KEY_PEM` — matching ECDSA P-256 private key; never commit it or place it in the app.
- `ALAI_ABUSECH_COMMERCIAL_USE_APPROVED` — set to `true` only after the owner has confirmed that the selected provider plan and terms allow this commercial use.

The publisher queries hash/family metadata only; it does not download malware samples. MalwareBazaar documents that its community API is free under fair-use principles, while company or for-profit use may require the enhanced commercial API. The approval flag is only an owner attestation; it is not provider approval or legal advice. Do not activate the workflow until the applicable plan/terms have been confirmed.

The private signing key corresponding to the app-pinned public key is a separate secret. If it is lost or compromised, a reviewed app update and key-rotation procedure are required.

## Threat-intelligence source roles

The publisher can combine four metadata sources into the signed v2 feed:

- MalwareBazaar: recent family-labelled SHA-256 file hashes.
- ThreatFox: typed SHA-256, URL, domain, IPv4, and IPv4:port IOCs, plus linked sample hashes when present.
- URLhaus: active/online malware-distribution URLs when its credential and separate commercial-use approval are configured.
- Feodo Tracker: online botnet command-and-control IPv4 indicators.

Entries retain source provenance, confidence, first-seen and expiry timestamps. Duplicate indicators are merged; the feed is capped at 20,000 entries / 4 MiB and marks truncated coverage. No malware sample bytes are downloaded.

Android uses SHA-256 entries for local file reputation. It parses network IOCs separately, but browser, DNS, VPN, socket, and traffic-blocking protection are not yet connected. Network IOCs are therefore not advertised as active network protection. Commercial-use permission must be confirmed for each enabled provider before a commercial feed is published.

## Scanning coverage and current detection limits

- Quick device scan: up to 350 files / 1 GiB.
- Deep device scan and user-selected folder scan: up to 100,000 files / 25 GiB.
- Maximum individual file size: 200 MiB.
- Android-protected private app locations remain inaccessible and excluded.
- The local hash database currently contains only a benign development fixture, not production malware hashes. The C++ matcher currently has only a harmless self-test rule until a signed production content-rule bundle is published. APK/DEX/ELF/ZIP structural checks and bounded nested-archive inspection are implemented, but are not a substitute for an independently validated malware signature corpus.
- At this integration revision, no production-signed feed or populated production threat-intelligence dataset has been verified as published and installed. Until the owner completes the gated publishing workflow and a device verifies and installs the bundle, threat intelligence must be shown as unavailable or incomplete; an empty dataset is never a clean verdict.

See [Scanning coverage and known limitations](docs/SCANNING_COVERAGE.md) for the exact boundaries and release gates. These limits do not make the app a full or independently validated antivirus product.

## Important Android and detection boundaries

A clean result means only that no currently loaded feed hash or configured static signal matched. It is **not** a guarantee that a file is safe. Hash matching misses unknown, modified, packed, or polymorphic files. The app does not inspect other apps' private data or live process memory, is not a replacement for Android's built-in platform security protections, and does not currently provide real-time protection for every app or network connection.

The manifest requests `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES` for shared-storage and installed-app security scans. Installed-app inventory is denied by default and is read only after separate, revocable in-app consent; without consent, both device scans and the real-time package-install monitor skip installed-app inventory. Shared-storage access is checked independently using the Android special setting on Android 11+ or the legacy storage permission on earlier versions. These sensitive permissions still require review against Android and the target marketplace's current policies; in-app consent does not replace marketplace approval. Android continues to restrict other apps' private storage and protected directories such as `Android/data` and `Android/obb`.

Quarantine can remove an accessible source file only when Android/the provider permits deletion. It cannot silently uninstall installed packages, remove system apps, or guarantee physical secure erasure on flash storage.

## Validation status

Automated unit tests cover the signed-feed parser, signature tampering/replay/expiry rejection, EICAR stream matching, selected static heuristics, offline URL parsing, cloud-client validation, and release invariants for launcher resources and core product wiring. Emulator instrumentation covers launch/artwork and AES-GCM quarantine integrity, restore, and deletion. API 33 and 35 are hard CI gates; API 36 remains advisory while the hosted emulator has intermittent Package Manager/ADB failures. No independent AV-TEST/AV-Comparatives-style malware detection report has been completed; no detection-rate or false-positive-rate claim is made.

See `docs/DETECTION_VALIDATION.md`, `docs/THREAT_INTEL_OPERATIONS.md`, and `docs/ANDROID_LIMITATIONS.md`.

## Build

The Bazaar candidate package version is `0.4.0` (`versionCode=4`). The app uses Poolakey 2.3.0 for Bazaar subscription SKU lookup, trial eligibility, checkout and restore; final subscription entitlement is independently verified by the Cafe Bazaar Developer API through the first-party Worker. Prices and trial duration are supplied by Bazaar, not hardcoded. GitHub Actions publishes a debug APK and an unsigned AAB preflight only; neither is a production release. Checkout remains fail-closed until the owner creates the Pishkhan products, configures Bazaar Developer API and Worker secrets, applies the D1 migration and deploys the Worker. See `docs/CAFEBAZAAR_RELEASE_READINESS.md`.


## Reviewed Android content-rule seed

This implementation branch now includes a reviewed, grouped Android indicator rule adapted from WithSecure Labs' `WITHSECURELABS_Fallspy` rule in the `WithSecureLabs/iocs` repository (pinned commit `1a8384468dd292c6d2c5114c32e42dc0da1f5ae1`, BSD 2-Clause). The source rule requires **4 of 10** string indicators. ANTIVIRUS AL AI preserves that grouping, classifies the adaptation as **SUSPICIOUS** rather than confirmed malware, and records source and licence metadata. The current matcher does not implement YARA's `fullword` modifier, so the adaptation is deliberately conservative and is not equivalent to running the original YARA rule.

The CSV and publisher workflow are included in this branch. They do not activate signatures by themselves: publishing still requires the matching `ALAI_FEED_SIGNING_KEY_PEM` GitHub Secret and the two owner attestation secrets `ALAI_CONTENT_RULES_REVIEWED=true` and `ALAI_CONTENT_RULES_COMMERCIAL_USE_APPROVED=true`. The publishing workflow runs only from `main` and writes the signed bundle to `security-feed/content-rules/latest.alrules`. Until that signed bundle has been published and fetched by a device, only the built-in harmless self-test marker remains active.
