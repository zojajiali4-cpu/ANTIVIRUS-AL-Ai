# ANTIVIRUS AL AI — Finalization plan (2026-11-28)

## Decision

**Status: not ready for a public commercial release.** The Android implementation has a green CI result on the current integration candidate, but production malware intelligence, the trained ML model, full-device validation, publisher signing, and store compliance are still open gates. Do not describe the app as a fully validated or competitive antivirus until those gates are closed.

This plan separates source-code integration from evidence needed to make a release claim. It is intentionally conservative: a successful build proves that the application can be assembled and tested, not that the detection engine has production malware coverage.

## Verified repository and CI state

- Repository: `zojajiali4-cpu/ANTIVIRUS-AL-Ai`; default branch: `main`.
- Dataset-intake / no-CI work branch: `hardening/complete-antivirus-no-ci`, last reviewed at `4bd2f8525a73d35cac92e99f3d1ec8c80e3cb9ce`. The AndroMD importer exists on this branch, but the two raw CSV payloads have not been uploaded to Git LFS and the full importer has not been run.
- Android integration candidate: `hardening/daily-antivirus-upgrades`, head `9fb29610a704a91b7ae273a87cbbb5a0b061df51`, tracked by draft PR #36 into `fix/serial-android-emulator-ci`.
- PR #36 validation: workflow run [46160753730](https://github.com/zojajiali4-cpu/ANTIVIRUS-AL-Ai/actions/runs/46160753730) completed successfully on 2026-11-28. All six jobs passed: debug APK assembly/signature/archive checks, Python/native and Kotlin unit tests plus Android lint, Android instrumentation on API 33, 35 and 36, and unsigned release-AAB preflight.
- The APK produced by that workflow is **debug-signed and test-only**. Its build metadata explicitly says `DEBUG_ONLY_NOT_FOR_STORE_RELEASE`. The AAB job is an unsigned preflight, not a publisher-signed release.
- Draft PR #37 integrates `fix/serial-android-emulator-ci` into `main`. Its stated dependency is PR #36. Correct integration order is #36 review/merge first, then full review and fresh CI on #37. Neither PR is to be merged automatically.

The green run validates the exact PR #36 merge candidate used by CI; it does not mean the separate no-CI dataset branch was built or validated.

## Current product and detection boundaries

- Device quick/deep scan limits on the integration candidate are 100,000 files, 25 GiB aggregate, and 200 MiB per file. Android-protected paths and other apps' private data remain inaccessible. Any traversal/permission/size gap must remain visible as incomplete or skipped coverage.
- PR #36 restores the Storage Cleaner and improves scan completion accounting. Cleaner findings are review candidates, not malware verdicts; nothing is deleted without explicit selection and confirmation.
- The native C++ streaming matcher is connected to the scan pipeline, but its built-in rule is only a harmless self-test marker until a signed production content-rule bundle is published.
- The local hash database contains a benign development fixture only. No production signed threat-feed object is published on the `security-feed` branch at the time of this plan.
- ML feature extraction/training tools exist, but `active-model.json` is absent and runtime inference remains `NOT_CONFIGURED`. Do not display an active/validated AI model status.
- APK/DEX/ELF and archive analysis is static. It does not execute APKs, inspect other apps' private processes, or provide full network/VPN protection.
- Real-time monitoring is limited to user-enabled foreground monitoring of selected Android-accessible shared-storage paths and exposed install events; it is not whole-device, all-app, or network-wide monitoring.

## Work plan and acceptance gates

### Gate 1 — Integrate the tested Android changes

1. Review the full PR #36 diff, especially storage permissions, cleaner deletion flow, scan-scope accounting, quarantine operations, and service lifecycle.
2. Confirm the green run belongs to the exact PR head and that all six jobs remain successful.
3. Obtain the repository owner's explicit review, then merge PR #36 into its declared base branch.
4. Review PR #37 as a separate integration into `main`; check the full diff, workflow permissions, manifest changes, version metadata, mergeability, and fresh CI on the final combined head.
5. Keep both merges review-gated. Never force-update `main` or merge a draft PR merely because CI is green.

**Exit evidence:** reviewed diffs, a green final combined CI run, and owner-approved merges.

### Gate 2 — Complete AndroMD dataset intake

1. Put the original `AndroMD_ZeroOne_Dataset.csv` and `AndroMD_MNF_Dataset.csv` files in Termux Downloads.
2. Clone `hardening/complete-antivirus-no-ci`, install Git LFS, authenticate to the owner repository, and run `tools/import_andromd_datasets.py` with both CSV paths.
3. Require the script's full-file checks to pass: exact pinned headers/order, 600,298 rows per file, expected label totals, binary/numeric field validity, unique SHA-256 values, and one-to-one SHA/label correspondence between the two views.
4. Verify both LFS objects exist remotely and the remote branch head matches the local import commit. Do not treat a partial/sample inspection as a complete import.
5. Obtain original feature-key definitions and matching semantics for the ZeroOne view. The third KeyCount view is optional and has not been inspected.

**Exit evidence:** remote LFS objects, full validator output, file hashes, row/label totals, dataset provenance and license record.

### Gate 3 — Build and validate the model correctly

1. Keep ZeroOne and MNF as separate feature views until their semantics are reproduced exactly. Their columns do not map directly to the app's existing 37-feature schema.
2. Implement versioned on-device extractors for each selected dataset view. Do not rename features or fabricate missing features.
3. Obtain genuine package/family grouping metadata. SHA-256 is an exact sample identifier, not a family-group key.
4. Create group-disjoint train, calibration, and untouched test splits; avoid near-duplicate and family leakage.
5. Evaluate recall, false-negative rate, false-positive rate, precision, F1, ROC-AUC, PR-AUC, supported-format coverage, and confidence intervals. Report benign, malware, PUA, and unknown classes separately.
6. Benchmark on representative Android devices for CPU, peak memory, heat, battery, and inference latency.
7. Package a model only after independent review of provenance, license, metrics, and device cost. Until then, inference remains `NOT_CONFIGURED`.

**Exit evidence:** reproducible training/evaluation report, model checksum and schema version, on-device parity tests, and documented go/no-go thresholds.

### Gate 4 — Activate production threat intelligence safely

1. Review every content rule's source, exact semantics, attribution, license, grouping threshold, and false-positive impact. The current FallSpy-derived group is candidate/suspicious evidence, not proof of malware execution.
2. Verify provider terms and commercial authorization separately for every enabled source. An owner-set approval flag is not proof that a provider granted commercial rights.
3. Configure the `threat-feed-publisher` GitHub environment with main-only deployment rules and an approval reviewer. Move the approved secrets into that environment; never send private keys or API credentials in chat.
4. Run the non-publishing key-check operation. Confirm that the private key matches the public key pinned in the Android code.
5. Only after licensing/review approval, publish signed feed and content-rule bundles; verify remote objects, signature, key ID, expiry, monotonic version, source provenance, and Android install/rollback behavior.
6. Keep unavailable/expired/invalid intelligence visibly distinct from a clean scan result.

**Exit evidence:** at least one production signed feed and reviewed rule bundle successfully installed by the app, with expiry, tamper, offline, and rollback tests passing.

### Gate 5 — Validate on physical devices and the intended corpus

1. Install the exact candidate on physical devices spanning supported Android versions, including the owner's Samsung Android 13 device.
2. Test permission granted/denied/revoked states, SAF fallback, low storage, large files, damaged archives, cancellation, background execution, Doze, network loss, quarantine restore, and cleaner selection/confirmation.
3. Run the controlled 60,000-file corpus and compare discovered, scanned, skipped, unknown, malware, suspicious, and cleaner totals against an external manifest.
4. Measure elapsed time, files/second, MiB/second, CPU, memory, thermal state, and battery drain. Do not claim a speed advantage without a same-device, same-corpus comparison.
5. Independently evaluate detection and false positives with lawful, isolated samples. Never use live malware on personal devices or user data.

**Exit evidence:** signed test report with device/build IDs, corpus manifest, raw counts, metrics, and resolved critical/high defects.

### Gate 6 — Prepare the Cafe Bazaar commercial release

1. Confirm the final package ID, owner account, app title, description, category, support address, app icon, screenshots, content rating, and update-signing continuity in the Bazaar developer console.
2. Publish a public, app-specific privacy policy and link it in the app and the store listing. Complete any store data/permission declarations accurately.
3. Review the necessity and user disclosure for `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, foreground-service special-use, and notifications. Confirm the current Bazaar policy and reviewer requirements for each sensitive permission.
4. Complete the actual Cafe Bazaar billing integration and test purchase, restore, cancellation, trial, renewal, and entitlement expiry end-to-end before advertising a paid plan. A UI store/catalog alone is not an operational subscription system.
5. Provision a production keystore owned and securely backed up by the publisher. Configure the protected `publisher-release` environment and its five environment-scoped secrets. Never commit the keystore or share passwords in chat.
6. Build a publisher-signed APK/AAB for the exact reviewed commit; verify package ID, version code, signer fingerprint, archive integrity, and SHA-256. Keep the upload key consistent with the first published release.
7. Submit to an internal/limited track first, install the store-delivered build, complete smoke tests, then proceed to public release only after approval.

**Exit evidence:** signed release artifact, verified publisher certificate, privacy/store materials, permission disclosures, working billing, store approval, and an installed store-delivered build.

## Release recommendation

The current 0.3.0 candidate is suitable for continued controlled testing, not yet for a public claim of a fully operational AI antivirus. A limited beta could be considered only with truthful feature descriptions and explicit disclosures about missing live signatures/model inference. A commercial v1.0 launch should wait for the relevant detection, feed, device, policy, signing, and billing gates above.

## Owner-provided inputs still required

- Successful execution of the AndroMD LFS importer on the original files.
- Any original dataset feature-key documentation and trustworthy family/package-group metadata.
- Provider commercial-use decisions and environment approvals.
- Production keystore provisioning in the protected GitHub environment.
- Cafe Bazaar developer-console review and final listing/account decisions.

**Do not post private keys, API credentials, keystore passwords, or customer files into repository issues or chat.**
