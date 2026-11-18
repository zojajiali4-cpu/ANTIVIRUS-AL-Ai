# Android security boundaries

## Requested capabilities and user consent

The manifest requests `MANAGE_EXTERNAL_STORAGE` for broad shared-storage scanning and `QUERY_ALL_PACKAGES` for installed-app APK inventory. These permissions are sensitive. The app must clearly disclose their purpose, request user authorization through Android, and pass Google Play declaration/review where applicable. A permission being technically requestable does not mean Play has approved its use.

## What the current app can inspect

- Readable shared-storage files Android exposes after the user grants the relevant access, within explicit scan limits: quick device scan 350 files/1 GiB; deep device scan and user-selected folder scan 100,000 files/25 GiB; 200 MiB per file. Directory traversal is additionally bounded by depth and directory-visit limits. Reaching any cap or encountering skipped/unreadable items must be reported as incomplete coverage, never as a complete clean scan.
- APK archives that are readable from shared storage or exposed through package metadata.
- Package metadata exposed by Android's PackageManager: declared permissions, components, target SDK, and signing-certificate information where available.
- SHA-256 hashes calculated locally, then checked against the currently installed authenticated feed.
- A harmless EICAR test string used only for scanner regression checks.
- Offline URL-structure heuristics through the Security Tools screen. The URL is parsed locally; the app does not resolve DNS, follow redirects, open the page or fetch online reputation.

## What it cannot claim

- It cannot inspect other applications' private data directories or their live process memory.
- It cannot guarantee detection of unknown, modified, obfuscated, packed, runtime-loaded, or polymorphic malware.
- It does not continuously monitor every app, file write, or network connection.
- A hash match is a reputation signal; a no-match is not proof of safety.
- It does not replace Google Play Protect or a professionally validated commercial antivirus engine.
- Scheduled WorkManager refreshes are deferrable and may be delayed by connectivity, battery constraints, or Doze. They update threat intelligence; they do not provide real-time protection.

## Remediation and quarantine

The AES-GCM vault creates and verifies an encrypted app-private copy before attempting source deletion. The UI requires explicit user confirmation. Android or the document provider can reject deletion; the app reports whether the source was actually removed. Listing, restore, and delete APIs are present. Emulator tests cover the encrypted vault's core file-URI flow; provider-specific restore tests and a complete quarantine-management UI remain outstanding. The UI only offers source-removal quarantine for malware/PUA/suspicious verdicts, never for unknown, unsupported, clean-labelled or harmless test-marker results.

This does not silently uninstall applications. An ordinary app cannot remove system apps or bypass Android's package manager confirmation. Deleting a file from flash storage also cannot guarantee physical secure overwrite because of wear levelling and filesystem behavior.

## Network and privacy

The app downloads a public, publisher-signed hash feed over HTTPS. The local scanning path does not send file contents, filenames or paths to the publisher. A separate, optional cloud hash-reputation action is shown only after the user explicitly confirms it for a selected scan result; that request contains only the SHA-256 digest. The online result is displayed separately and never overwrites the local verdict. An absent record or unavailable service is UNKNOWN, not clean. The service may process ordinary connection metadata, such as the client IP, for rate limiting. The Cloud Worker code is present in this repository, but production deployment, D1 configuration, threat-data ingestion and live service health have not been verified.

Offline URL inspection is local-only and does not contact a server. It is a structural heuristic, not a phishing verdict or live domain-reputation check. It does not follow URL shorteners or inspect page content.

The publisher workflow queries hash/family metadata from its authorized source and signs the exact feed bytes outside the APK. Provider credentials and the ECDSA private signing key must be stored as GitHub Actions secrets, never in source code or client resources.
