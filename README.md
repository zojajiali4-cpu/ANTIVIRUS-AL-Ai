# ANTIVIRUS AL AI

Privacy-first Android security scanner. Current Android milestone: **0.2.0 (versionCode 2)**. The app includes a bilingual Persian/English security dashboard, a scan centre, security tools, a plan catalogue, local file analysis and an optional user-triggered cloud reputation workflow.

## Current Android scope

- User-selected file scanning through Android's Storage Access Framework.
- Streaming SHA-256 calculation with a configurable maximum file size.
- APK metadata inspection using Android's package parser (no APK execution).
- Permission and component heuristics reported as evidence, never as proof of malware.
- Evidence-based verdicts that distinguish known matches, suspicious files, unknown coverage and unsupported formats.
- Private app-storage quarantine copy with hash verification. The original file is not silently deleted.
- URL structure and curated URL reputation checks only after the user submits a URL.
- Optional hash reputation lookup only after a separate confirmation. The app sends the SHA-256 digest, not file bytes, filename or path. Normal network request metadata may be processed by the service for abuse prevention.
- A strict signed-feed verification and storage core is implemented, but production threat-feed publication and activation are separate release gates.

## Important security boundary

A no-match result means only that the configured local or remote dataset did not return a known indicator. It is **not** a guarantee that the file is safe. Permission patterns, APK metadata, URL structure and reputation records are evidence for review, not definitive proof of maliciousness.

The current local indicator database contains only a benign project test fixture; it is not a production malware-signature database. The online hash API is useful only when a reviewed reputation dataset has been provisioned. An empty database, unavailable service, stale feed or failed request must never be presented as a clean result.

The signed-feed core verifies ECDSA P-256 signatures, expiry and monotonic versions. No production signing key or live signed threat-feed publication is included in this repository. Feed-signing private keys must never be stored in Git or the Android application.

## Privacy and network behavior

- Local file scanning does not upload file contents, filename or path.
- No online hash check runs automatically. The user must explicitly approve sending the selected file's SHA-256 digest.
- URL checks run only after the user submits the URL.
- The API may process normal connection metadata, including the client IP, for rate limiting and service security.
- Users can skip all cloud lookups and continue with local analysis.

## Build

The Android package version is `0.2.0` (`versionCode=2`). GitHub Actions publishes a clearly named debug artifact with exact build identity. Debug APKs are for testing only and are not production-signed release packages.

Open the repository in Android Studio or run the CI workflow. The project uses Kotlin, Jetpack Compose and Android SDK 36. The CI workflow runs unit tests, Android lint and a debug APK build.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md), [docs/ANDROID_LIMITATIONS.md](docs/ANDROID_LIMITATIONS.md) and the signed-feed design in [docs/THREAT_FEED_FORMAT.md](docs/THREAT_FEED_FORMAT.md).

## Responsible testing

Use benign test files, synthetic indicator data and the included unit tests. Do not download or execute live malware. The repository does not contain malware samples.
