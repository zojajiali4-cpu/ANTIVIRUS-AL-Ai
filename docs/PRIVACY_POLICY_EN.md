# ANTIVIRUS AL AI Privacy Policy

**Last updated: 24 November 2026**

This policy applies to the Android app ANTIVIRUS AL AI, package com.antivirusalai, prepared for distribution through Cafe Bazaar.

## 1. Contact
Support and privacy requests: Zojajiali4@gmail.com

## 2. Data processed on the device
- Files and folders the user selects for scanning.
- Accessible shared-storage files if the user grants Android's special access.
- Readable APK metadata and installed-app inventory only after separate, revocable consent.
- Scan results, reports, settings and quarantined items.

These data are processed or stored in the app's private storage for local security functions. The app cannot access other apps' private data; Android restrictions such as Android/data and Android/obb remain in force.

## 3. Data that may be sent to our server
Cloud transmission depends on the feature the user chooses:

- **Cloud URL check:** If the user chooses online analysis, the submitted URL is sent over HTTPS for structural analysis and curated reputation lookup. The server does not open, fetch or connect to the destination URL.
- **PLUS hash reputation:** After separate consent, only the file's SHA-256 digest and a short-lived subscription proof token are sent. File contents, filename and local path are not sent. A no-match is not proof that a file is safe.
- **Subscription verification:** The product ID and Cafe Bazaar purchase token are sent to our first-party server so the purchase can be checked with Cafe Bazaar Developer API. The app does not receive payment-card or payment-password details; payment is handled by Cafe Bazaar.
- **Connection metadata:** The cloud service may process IP address and ordinary request metadata for security and abuse/rate limiting. A keyed derived identifier is stored for rate limiting instead of the raw IP address.

## 4. Data not uploaded
The local scanning and hash-reputation paths do not upload file contents, filenames or local paths. Installed-app inventory is not sent to the cloud service or an advertising network. This does not prevent the user from intentionally submitting a URL for cloud analysis or including information in a support request.

## 5. Payments and subscriptions
Cafe Bazaar processes subscription purchases and renewals. The app sends the purchase token and product ID for server-side verification. The server stores only the SHA-256 digest of the purchase token and minimal metadata needed to identify the product, plan, status and expiry; the raw purchase token is not stored in the database. Manage or cancel the subscription through the user's Cafe Bazaar account.

## 6. Retention and deletion
- Local reports, settings and quarantine items remain in the app's private storage until the user deletes them or clears app data.
- Subscription verification metadata is retained while needed for entitlement verification, fraud prevention, support or legal obligations.
- Rate-limit data is used to prevent abuse and is not intended for advertising or marketing profiles.
- To request review or deletion of server-side data, email the support address above with the subject “ANTIVIRUS AL AI Privacy Request”. Payment records under Cafe Bazaar's control must be handled through Cafe Bazaar support.

## 7. Security
The app communicates with its first-party API over HTTPS. Purchases are verified server-side using Cafe Bazaar Developer API. PLUS access tokens are signed and short-lived. These controls reduce risk but do not guarantee absolute security or immunity from compromise.

## 8. Permissions and user choice
All files access and installed-app inventory permissions are requested only for relevant features after an explanation and user action. Users can revoke permissions in Android settings. Revocation limits broad scans or inventory features; user-selected file scanning remains available within granted access.

Cloud features are optional. Users can continue using local scanning without cloud hash or URL checks.

## 9. Children and policy changes
The app is intended for general use and does not intentionally collect children's personal information. If data practices materially change, this policy will be updated with a revised date.

