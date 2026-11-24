# Cafe Bazaar Release Readiness — ANTIVIRUS AL AI

The first release target is Cafe Bazaar. Google Play Billing and Play Console are not the payment or publication path for this build.

## Android baseline

- Application ID: com.antivirusalai.
- Candidate version: 0.4.0, versionCode 4.
- Minimum SDK: API 26; target SDK: API 36.
- Billing SDK: official Cafe Bazaar Poolakey 2.3.0.
- Subscription SKUs: alai_plus_monthly and alai_plus_annual.
- Bazaar submission requires a release APK signed with the publisher's permanent key. Debug APKs are testing artifacts only.

## Before submission

### App correctness and security
- [ ] Unit tests, lint, APK build, and API 33/35 emulator smoke tests pass on the exact release commit.
- [ ] Verify permission-denial behavior, low storage, large files, Doze, network loss and damaged quarantine entries.
- [ ] Publish a reviewed signed production threat feed before making detection coverage claims.
- [ ] Keep ML detection, live phishing detection, VPN/network protection and full real-time protection claims disabled unless implemented and independently validated.
- [ ] Confirm all visible descriptions match implemented behavior.

### Permissions and Android behavior
- [ ] Review MANAGE_EXTERNAL_STORAGE, QUERY_ALL_PACKAGES, foreground-service and notification declarations against Android requirements and Cafe Bazaar review rules.
- [ ] Provide a clear user-initiated rationale before broad file access or installed-app inventory.
- [ ] Ensure limited mode remains useful when permission is denied.
- [ ] Ensure monitoring is user-enabled, visible, stoppable and never restarted after user disables it.
- [ ] Test supported Android versions, with special attention to storage and background execution.

### Cafe Bazaar billing
- [ ] Create exact monthly/annual SKUs in Pishkhan.
- [ ] Configure trial duration, recurring billing, prices, renewal and refund terms.
- [ ] Complete Developer API OAuth authorization and store refresh token only in Worker secrets.
- [ ] Apply D1 migration 0003_bazaar_billing.sql.
- [ ] Deploy Worker and verify Bazaar API access before enabling checkout.
- [ ] Test purchase, cancellation, expiry, restore, invalid token and server outage on a real device.

### Privacy and listing
- [ ] Publish a public privacy policy at an accessible HTTPS URL and include it inside the app.
- [ ] Prepare Persian title, short/full description, screenshots, icon, category, age/content rating and support contact.
- [ ] Disclose optional SHA-256 upload and ordinary connection metadata.
- [ ] Never describe a hash no-match as proof of safety.
- [ ] Do not claim full malware removal, private-data scanning, live network protection, behavioral sandboxing or configured ML detection.

### Release artifact
- [ ] Create and securely back up publisher's permanent signing keystore.
- [ ] Never commit keystore/passwords or send them in chat.
- [ ] Build release APK with permanent key; verify package, version, target SDK, manifest, archive and signer fingerprint.
- [ ] Use the same key for every update.
- [ ] Install and test signed APK on a physical device before submission.

Broad file access and package visibility need review; an antivirus label alone does not guarantee approval. A green debug build is not public-release readiness.
