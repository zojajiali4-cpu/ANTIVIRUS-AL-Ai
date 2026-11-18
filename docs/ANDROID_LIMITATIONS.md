# Android security boundaries

## Requested capabilities and user consent

The manifest requests `MANAGE_EXTERNAL_STORAGE` for broad shared-storage scanning and `QUERY_ALL_PACKAGES` for installed-app APK inventory. These are separate capabilities with separate user-facing gates:

- Android 11+ shared-storage scanning checks `Environment.isExternalStorageManager()` before traversing storage. Earlier Android versions check the runtime `READ_EXTERNAL_STORAGE` permission.
- Installed-app inventory is denied by default in the app. Before reading the broad package inventory or monitoring newly installed packages, ANTIVIRUS AL AI displays a separate in-app disclosure and requires affirmative consent. The setting can be revoked later; the scan engine and protection service re-check the saved consent before using package inventory.
- Declining installed-app consent does not block a shared-storage scan when its separate storage access has been granted. If neither access path is approved, the app must not present an automatic device scan as meaningfully completed.

Both permissions remain sensitive. Their availability in Android does not mean Google Play has approved their use. The developer must submit the relevant declarations, justify why the permissions are core to the antivirus purpose, and complete Play review.

## What the current app can inspect

- Readable shared-storage files Android exposes after the user grants the relevant access, within explicit scan limits: quick scan 350 files/1 GiB; deep scan 10,000 files/5 GiB; 200 MiB per file.
- APK archives that are readable from shared storage or exposed through package metadata.
- Package metadata exposed by Android's PackageManager only after separate, revocable in-app consent: declared permissions, components, target SDK, and signing-certificate information where available.
- SHA-256 hashes calculated locally, then checked against the currently installed authenticated feed.
- A harmless EICAR test string used only for scanner regression checks.

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

The app downloads a public, publisher-signed hash feed over HTTPS. The scanning path does not send file contents or file hashes to the publisher. The publisher workflow queries hash/family metadata from its licensed source and signs the exact feed bytes outside the APK. Provider credentials and the ECDSA private signing key must be stored as GitHub Actions secrets, never in source code or client resources.
