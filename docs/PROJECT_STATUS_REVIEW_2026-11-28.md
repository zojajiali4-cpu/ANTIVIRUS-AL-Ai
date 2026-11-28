# ANTIVIRUS AL AI — Engineering Status Review (2026-11-28)

**Overall status: development/hardening branch only. Not release-ready. No CI, build, test, model training, or production-feed publication was performed for this review.**

## 1. Repository and integration state

- Reviewed branch: `hardening/complete-antivirus-no-ci`.
- Default branch: `main`.
- At review time the branch comparison reported **467 commits ahead and 4 commits behind main** (`diverged`).
- No open pull request was found for this branch.
- The latest commit reviewed had **zero Actions runs**.
- Android CI on this branch is configured for `push: main`, `pull_request`, and manual dispatch. Creating a PR now would trigger the Android workflow; do not open one until the user authorizes the final validation.
- Main contains four later workflow-only commits (including a manual old-failed-run cleanup workflow and a manual key-verification workflow) that are not yet integrated here. They need review before any future merge; do not merge or force-update main during dataset intake.

## 2. AndroMD intake

The uploaded research files are present as conversation attachments but **the raw CSV payloads are not yet in the repository**. The `datasets/` directory contains only its README. Root `.gitattributes` configures `datasets/AndroMD_*.csv` for Git LFS.

### Uploaded files

| Dataset | Size | Data rows | Columns | Data features |
|---|---:|---:|---:|---:|
| ZeroOne | 184,104,393 bytes | 600,298 | 119 | 116 binary indicators + numeric `TOTCLASSES` |
| MNF | 403,328,807 bytes | 600,298 | 302 | 300 binary manifest/permission indicators |

The Mendeley Data V1 record reports 600,298 apps: 397,814 legitimate and 202,484 malicious, and lists three views: KeyCount, ZeroOne, and MNF. It lists CC BY 4.0. The KeyCount file is approximately 204 MB and has not been uploaded or inspected in this project.

### Import protection now implemented

`tools/import_andromd_datasets.py` is a streaming importer for the two uploaded CSVs. It now:
- pins the exact original 119-column ZeroOne header/order and 302-column MNF header/order;
- validates all rows, field counts, SHA-256 shape, labels, binary features, and numeric `TOTCLASSES`;
- rejects duplicate SHA-256 values within each CSV;
- enforces the published 600,298-row and per-class totals;
- calculates the full-file SHA-256;
- when both files are supplied, requires one-to-one SHA-256 coverage and identical labels before staging either file;
- checks the exact GitHub repository and branch, the Git LFS attributes, clean working tree, and free disk space;
- stages only the supplied CSVs through Git LFS, pushes the LFS objects and branch, then verifies the remote branch SHA.

**The full-file importer has not been run yet.** Earlier checks were sampled inspections only. The importer must be run from Termux or another Git LFS-capable client. The two uploaded originals total 587,433,200 bytes; the script conservatively requires roughly 1.34 GiB free in the clone's filesystem for worktree copies, LFS objects, and temporary validation data. GitHub Free includes 10 GiB LFS storage and 10 GiB monthly download bandwidth, but the account's remaining usage is not exposed by the available connector.

## 3. AI/ML readiness

- The Android inference runtime and Python trainer agree on the exact existing **37-feature schema and feature order**.
- `app/src/main/assets/ml/` contains only a README; **`active-model.json` is absent**.
- Runtime therefore remains `NOT_CONFIGURED`; no production ML inference is active.
- ZeroOne has 116 code-token/key-presence indicators plus `TOTCLASSES`; MNF has 300 manifest/permission indicators. A comparison found zero exact feature-name matches with the current 37-feature schema.
- Neither CSV has a package identity or malware-family `family_group`. A file SHA-256 is not a valid replacement for a family/package grouping key.

### Required before model training

1. Complete the real LFS upload and the full CSV checks.
2. Obtain the original feature-key definitions/matching rules and reproduce their exact semantics. ZeroOne is derived from patterns searched in decompiled Java source; checking only the current eight selected DEX API references is not equivalent.
3. Implement separate, versioned Android extractors for the ZeroOne and MNF views (and KeyCount only if that third view is adopted).
4. Acquire trustworthy package/family grouping metadata. Do not invent groups or use sample hashes as group IDs.
5. Use group-disjoint train/calibration/untouched-test splits and a separate time-based test when feasible. Report FPR, recall, precision, F1, ROC-AUC, PR-AUC, coverage, class/group counts, and false-negative analysis.
6. Benchmark false positives and on-device CPU, memory, heat, battery, and latency before packaging a bounded model.
7. Keep the current 37-feature model separate unless a reviewed feature mapping is actually extracted on-device. Do not rename arbitrary columns, synthesize missing features, or treat the paper's published accuracy as Antivirus AL AI performance.

## 4. Detection and threat-intelligence readiness

- The app's scanner is a static-analysis MVP: package metadata, selected DEX API references, selected ELF symbol strings, bounded archive inspection, hashing, and heuristic evidence are implemented.
- The local indicator database contains only a benign development test fixture; it is not a production malware-signature database.
- The native C++ matcher currently has only its harmless engine self-test pattern until a signed production rule bundle is published.
- DEX/ELF references are capability indicators, not proof of execution. There is no on-device dynamic sandbox for other apps' private processes.
- The threat-feed client now points to the active repository's `security-feed/threat-feed/latest.alfeed` URL, but the active repository currently has no `security-feed` branch and no signed production feed object. The feed publisher is restricted to `main`; required secret values and environment approvals have not been inspected and must never be exposed in logs/chat.
- Provider commercial terms and operator approvals must be confirmed before enabling any provider. A configured signing key does not itself create a malware feed.

## 5. Store/release readiness

Verified source configuration on this branch:
- application ID: `com.antivirusalai`;
- version: `0.3.0`, version code `3`;
- minimum SDK: 26;
- target/compile SDK: 36.

Google Play's current new-app/update target requirement is Android 16 / API 36 from 31 August 2026; the branch meets that target-SDK floor. That does **not** establish policy approval.

The manifest requests `MANAGE_EXTERNAL_STORAGE` and `QUERY_ALL_PACKAGES`. Google Play lists antivirus as a potentially permitted use for both, but requires the relevant declaration, core-function justification, and appropriate user disclosure/consent. The app also declares foreground-service use that needs accurate use-case/disclosure review.

Release blockers documented in `PLAY_RELEASE_READINESS.md` remain:
- no production signing keystore or signed release AAB;
- no verified final release build for this exact branch;
- privacy-policy page and in-app/store links not complete;
- Data Safety and permission declarations not complete;
- store listing assets, support and content-rating package not fully verified;
- independent malware detection evaluation and application security review not complete.

For Cafe Bazaar, check its current publisher rules separately; Google Play policy requirements apply only to a Google Play submission.

## 6. Ordered next actions

**P0 — data transfer:** From Termux, clone this branch and run the import tool with both original CSV paths. It will stop before staging if any row, header, label total, duplicate hash, cross-dataset mapping, remote, or disk-space check fails. After the command returns, verify the GitHub tree contains Git LFS pointers and the corresponding LFS objects can be retrieved.

**P1 — source reproduction:** Obtain/verify the exact AndroMD frozen feature-key lists and preprocessing details. Decide whether to fetch the optional KeyCount view. Secure package/family grouping metadata.

**P1 — model work:** Implement dedicated ZeroOne/MNF feature extraction and training/validation; do not switch the current production model state away from `NOT_CONFIGURED` until all release gates pass.

**P1 — intelligence:** Complete the protected signing-key check, provider/legal approvals, a reviewed signed content-rule bundle, and a first valid signed feed only after this branch's integration into the protected publisher path is approved.

**P2 — release:** Resolve main-branch divergence, review code and permissions, obtain explicit authorization for one final CI/build validation, then create a signed AAB and complete independent/security/store checks. Do not open a PR or merge before the CI authorization.

## 7. Work performed during this review

- Re-queried the active GitHub branch, main comparison, workflows, PR list, dataset directory, model assets, Android manifest, Gradle configuration, ML runtime/trainer schema, and threat-feed endpoint.
- Added exact header-order and published class-count validation to the LFS importer.
- Added exact repository-origin and free-disk preflight checks to the importer.
- Updated ZeroOne/MNF audit reports and the dataset README, including the pending KeyCount view.
- Corrected the stale threat-feed URL in `docs/SCANNING_COVERAGE.md`.
- Added this consolidated review.
- No raw dataset was uploaded, no model was trained, no APK/AAB was built, no test was run, no CI workflow was triggered, and `main` was not modified.
