# Signed threat-feed operations

## Current runtime behavior

The Android scanner can now consult a locally stored, cryptographically verified threat feed during file scans. A user can request an update from **Settings → Update threat database**. The app downloads only the feed document over HTTPS; it never uploads selected files or their hashes.

The feed is deliberately **disabled until configured**. Empty endpoint or public-key configuration returns a clear "not configured" state. An absent, expired, invalid, or unverifiable feed is never interpreted as a clean result.

## Release configuration

Configure these GitHub Actions repository secrets before publishing a build that should receive the feed:

- `ALAI_THREAT_FEED_URL`: the HTTPS URL of the current feed document. Redirects are rejected.
- `ALAI_THREAT_FEED_PUBLIC_KEY_B64`: Base64-encoded X.509 SubjectPublicKeyInfo for an ECDSA P-256 public key.
- `ALAI_THREAT_FEED_KEY_ID`: the exact key identifier embedded in the feed.

The matching private signing key must remain in a restricted publisher environment or offline signing machine. **Never add it to Android, Git, build artifacts, or ordinary CI variables.** The app contains only the public key.

The feed format is defined by `SignedThreatFeedParser.FORMAT_HEADER` in `SignedThreatFeed.kt`. It is canonical UTF-8 with LF line endings; its ECDSA/SHA-256 signature covers every byte through the final indicator newline, excluding the final `signature=` line. Entries must be sorted by lowercase SHA-256 and use one of `MALWARE`, `PUA`, or `SUSPICIOUS`.

## Security controls

- HTTPS only; redirects disabled; bounded connect/read timeouts.
- Maximum feed size 2 MiB and maximum 20,000 indicators.
- ECDSA P-256 / SHA-256 signature verification against a pinned public key.
- Feed expiry, issue-time, lifetime, strict structure, and monotonic version checks.
- Atomic private app-storage installation and rollback floor.
- Hash-only local matching; no file content or hash is sent to the server.

## Still required before production

1. Generate and back up the feed-signing key in a controlled offline process.
2. Build a publisher that validates, sorts, signs, and publishes the feed.
3. Host the feed at a stable HTTPS endpoint and configure the three repository secrets.
4. Add key rotation and emergency revocation procedures; test signed updates on supported Android versions.
5. Evaluate feed quality and false-positive handling before advertising malware-detection coverage.

A successful Android build with blank secrets proves only that the disabled-by-default integration compiles. It does not mean the live threat feed is active.
