# Regional Trial Commerce — ANTIVIRUS AL AI v1.0

## Product policy

- Launch approach: regional, Android first.
- Revenue model: trial-first subscription, with monthly and annual auto-renewing plans.
- Product identifier: `alai_plus`.
- Base plan identifiers: `monthly` and `annual`.
- Free tier: selected-file and supported APK scanning, local evidence-based reports, and private quarantine remain available without a subscription.
- PLUS: optional cloud SHA-256 reputation and expanded online intelligence. Each hash lookup remains a separate, explicit user-consent action; subscription entitlement does not silently authorize data transmission.

The current development integration deliberately does not include PRO FAMILY or lifetime plans. Those require separate product, device-sharing, entitlement and support designs and must not be exposed as purchasable until implemented.

## Regional price and trial rules

The app must not bundle a region list, currency, product price, discount, or trial duration. Google Play Console controls base-plan availability, regional pricing, and offer eligibility. The Android app obtains localized offer details from Google Play and displays the returned pricing phases in sequence. A free-trial label appears only when Google Play returns an eligible free-trial phase for that Play account. Google Play presents the legally binding payment and renewal terms before confirmation.

The regional launch matrix is configured in Play Console only after the account owner verifies merchant eligibility, settlement/payout support, local tax/VAT treatment, consumer cancellation/refund obligations, privacy requirements, store language/support coverage, and any restrictions on subscription marketing. Do not advertise an unavailable country as supported.

## Purchase and entitlement flow

1. The app queries `alai_plus` and the current Play account's eligible monthly/annual offers.
2. The server readiness endpoint verifies the Android Publisher service account and confirms that the intended base plans exist and are ACTIVE. Until this succeeds, purchase buttons remain disabled.
3. The app opens the native Google Play purchase sheet with a fresh offer token.
4. The app sends the resulting purchase token to the first-party HTTPS Worker. It sends no file, scan sample, filename, filesystem path, or device app inventory.
5. The Worker uses the Android Publisher API to validate the token, exact package, product, supported base plan, subscription state and expiry. It acknowledges a verified new purchase. The raw purchase token is not stored; only its SHA-256 digest and minimal entitlement metadata are persisted in D1.
6. The app grants PLUS only after the server response confirms an allowed state and unexpired entitlement. Pending, on-hold, paused, expired, unrecognized, mismatched or unverifiable purchases do not unlock features.
7. Restore re-queries subscriptions owned by the current Play account and verifies them again with the server. Cancellation and renewal are managed in Google Play; a canceled but unexpired subscription retains access until its verified expiry.

## Required Play Console setup

Create subscription `alai_plus` with auto-renewing base plans `monthly` and `annual`. Configure localized listings, prices and regional availability. Configure free-trial offer phases and eligibility per base plan; duration is a Play Console decision, not a code constant. Ensure the store listing and app accurately disclose trial conversion, recurring price, first payment date, renewal cadence, cancellation path, refund policy and applicable terms before a customer confirms.

The first launch should use a closed/internal testing track and licensed test accounts. Test a fresh eligible account, an ineligible account, a returning subscriber, a canceled-but-not-expired purchase, payment pending, grace period, on-hold, expired, duplicate purchase, restore after reinstall, offline/server outage and product-not-configured states.

## Required Cloudflare setup

- Set `PLAY_SERVICE_ACCOUNT_JSON` as a Worker secret only. Use a dedicated service account linked to the correct Play Console account with minimum required Android Publisher permissions. Never commit, log, paste into chat, or package the private key.
- Apply `cloud-api/migrations/0002_play_billing.sql` to the configured D1 database.
- Deploy the Worker only after reviewed tests and account-owner approval.
- Verify `/v1/billing/status` returns the intended active plans before enabling a real Play product/offer for testers.
- Keep a rollback procedure for disabling checkout without disabling free offline scanning.

These account and production operations are intentionally not performed by this code change. No secret, D1 resource, Play Console product, regional price or production deployment has been created or changed by the repository commit.

## Implementation and release status

The development branch contains the Android Billing 9.1.0 client, localized eligible-offer display, price-phase rendering, secure purchase verification, acknowledgement, restore and a backend readiness gate. The Worker route and D1 migration are source changes only. End-to-end Play testing and production activation remain release gates. A green CI build alone does not prove that the Play Console product, merchant account, Worker credentials, D1 schema or real customer checkout are operational.
