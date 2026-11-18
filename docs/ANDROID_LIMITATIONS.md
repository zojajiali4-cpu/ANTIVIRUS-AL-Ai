# Android security boundaries

The app uses Android's `INTERNET` permission only for explicitly requested URL/hash reputation checks and signed threat-feed updates. It does not request broad package inventory, Accessibility Service, VPN service or root access in this MVP.

## What it can inspect locally

- Files the user explicitly selects through Android's document picker.
- APK package metadata exposed by Android's package parser.
- SHA-256 hashes calculated locally from selected files.
- Static indicators available in the local scanner and any verified, configured threat data.

## Optional online checks

- URL checks are sent only after the user submits a URL for analysis.
- Hash reputation checks are sent only after a separate user confirmation.
- A hash request contains only the SHA-256 digest. File contents, filename and path are not uploaded.
- The network service may process ordinary request metadata, such as the client IP, for rate limiting and abuse prevention.
- An absent record, unavailable database, stale feed or failed request is UNKNOWN. It must not produce a clean verdict.
- Online reputation is displayed separately from the local scan verdict; it is not silently promoted to a malware verdict.

## What it cannot claim

- It cannot inspect private data or live memory belonging to other applications.
- It cannot guarantee detection of unknown, obfuscated, packed or runtime-loaded malware.
- It does not continuously monitor every app or every network connection.
- It does not uninstall another application silently.
- It does not declare an APK safe merely because a few metadata checks return no warning.
- It does not replace Google Play Protect or a professionally validated antivirus engine.

## Remediation

The encrypted quarantine function stores a verified copy inside the app's private directory. The source remains where the user selected it; the app does not delete it automatically. Any future source-removal workflow must remain separate, explicit, user-confirmed and subject to Android's provider permissions and system UI.

## Future package visibility

A security app may have a legitimate use for `QUERY_ALL_PACKAGES`, but Google Play requires declaration and review. The current app intentionally avoids requesting it until a documented product need and policy review exist.
