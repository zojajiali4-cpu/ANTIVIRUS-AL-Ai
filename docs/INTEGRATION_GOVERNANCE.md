# ANTIVIRUS AL AI integration governance

## Canonical development line

`integration/release-candidate-stable` is the consolidated release-candidate line for the current Android product. It is based on the advanced scanner/protection chain (`fix/serial-android-emulator-ci`) and ports in the signed Cloud Worker and consent-gated hash reputation client. This is a candidate branch, not the production default branch.

New work should branch from this line and open a PR back into it. Do not continue feature work on older sibling branches and later attempt a broad merge. Port one coherent feature at a time, with its tests and documentation.

## Product invariants

1. The application manifest must retain the launcher activity and both launcher icon references.
2. Adaptive and legacy launcher resources must resolve to the checked-in guardian artwork. CI pins the reviewed `guardian_robot.webp` Git blob; changing the artwork requires an intentional, reviewed update to that pin.
3. APK packaging must report an application icon, not merely compile the source XML.
4. The dashboard, scan center, Store, Vault, file scanner, device scan engine, protection service, quarantine vault, scan reports, and signed-feed verifier must remain present unless an explicitly reviewed product change replaces them.
5. Online hash reputation is a separate, opt-in second opinion. It sends only SHA-256; a missing record is UNKNOWN and never means clean. It never silently changes the local verdict.
6. Cloud Worker publication validates the signed feed server-side; private signing keys are never stored in Android or in this repository.

## Required pull-request gates

- Android debug APK assembles and its package, signature and launcher icon are inspected.
- Python regression tests pass, including launcher-resource and core-product invariant checks.
- Kotlin unit tests and Android lint pass.
- Native C++ scanner tests pass.
- Emulator smoke tests on API 33 and 35 pass. API 36 remains executed but is advisory while the hosted emulator intermittently fails during Package Manager installation with ADB `Broken pipe`; it must be re-promoted to a hard gate after runner stability is verified.
- Cloud Worker security tests pass, including signature validation, tampering, key pinning, expiry, rollback, bounds, rate limiting and fail-closed behavior.
- An unsigned release AAB preflight is not a store-signed release.

## Merge discipline

No automatic merge to `main`, no production Worker deployment, no production secret updates, and no Play release are performed by this integration line. Promote only after the full stacked PR chain is reviewed, all hard gates are green, the product owner approves the exact commit, and release-only operational checks are completed.
