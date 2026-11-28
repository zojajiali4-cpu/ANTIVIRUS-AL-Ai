# AndroMD MNF Dataset — Intake Audit

**Status: valid research-corpus candidate for a separate manifest model; not compatible with the current 37-feature model as-is. Not trained or activated.**

## Source and provenance

- File received: `AndroMD_MNF_Dataset.csv`
- Published dataset: [AndroMD Android Malware Dataset, Mendeley Data, V1](https://data.mendeley.com/datasets/pwyj5b3khp/1)
- DOI: [10.17632/pwyj5b3khp.1](https://doi.org/10.17632/pwyj5b3khp.1)
- Authors: Arvind Prasad and Shalini Chandra (2025)
- Dataset landing page lists CC BY 4.0.
- Published record reports 600,298 apps: 397,814 legitimate and 202,484 malicious. These counts are source-reported and are enforced by the import tool; the complete local MNF file has not yet passed that tool.

## File and schema inspection

- File size: **403,328,807 bytes** (about 384.5 MiB).
- Parsed line count: **600,299**, including the header; therefore 600,298 data rows.
- Header width: **302 columns**:
  - `sha256`: sample hash;
  - 300 manifest/permission indicators;
  - `Label`: class label.
- Three separated windows were inspected (2,999 data rows total). In those windows, each row had 302 fields, labels were non-empty `Benign` / `Malware`, SHA-256 values were 64 hex characters, all 300 feature cells were 0/1, and no duplicate hash occurred within each individual window.
- This was sampled checking only, not a full-file or global duplicate scan.

## Meaning and compatibility

MNF represents binary indicators for AndroidManifest permissions/declarations. It is a distinct manifest view, not the existing 37-feature APK multi-view schema. A header-level comparison found zero exact feature-name matches with the current 37 features.

The current trainer also requires a non-empty `family_group` value for group-disjoint evaluation. This CSV contains no package identity or family group; SHA-256 must not be relabelled as a group.

## Full validation and LFS import tool

The branch includes `tools/import_andromd_datasets.py`. It streams the complete file, checks the exact frozen 302-column header/order, validates every row's field count, 64-hex SHA-256, label, and 300 binary values, rejects global duplicate hashes, enforces the published row and class counts, and computes the file SHA-256.

When both MNF and ZeroOne are supplied, the tool also verifies one-to-one SHA-256 coverage and exact label agreement before staging either CSV. **The full-file scan and join check have not yet been executed**, because the raw CSVs are not yet in Git LFS.

## Decision and remaining work

1. Do not feed MNF directly into the current 37-feature trainer.
2. Complete full-file validation and push the original CSV through Git LFS.
3. Build a separately versioned manifest feature extractor that emits the exact 300 indicators, or document and validate a justified reduced feature set.
4. Obtain real package/family grouping metadata; do not invent it or substitute file hashes.
5. Evaluate group-disjoint train/calibration/test splits and report false-positive rate, recall and other metrics on an untouched test set.
6. Keep production ML **NOT_CONFIGURED** until on-device extraction parity, independent validation, and mobile resource constraints are established.

## Storage decision

The owner approved storing the full AndroMD research CSVs in this development repository **through Git LFS only**. Root `.gitattributes` tracks `datasets/AndroMD_*.csv`; intended path for this file: `datasets/AndroMD_MNF_Dataset.csv`.

The 403,328,807-byte file exceeds GitHub's 100 MiB hard limit for a normal Git object. **The raw MNF CSV is not yet in GitHub.** The GitHub connector accepts UTF-8 text rather than a 403 MB binary upload, and file materialization is limited to 100 MiB. No placeholder LFS pointer was created. The real object must be pushed using Git LFS from Termux or another Git-capable client. GitHub Free includes 10 GiB LFS storage and 10 GiB monthly download bandwidth; remaining account usage is not exposed to this connector.

## Work performed

- Inspected the CSV header, parsed line count, and three separated 1,000-line windows.
- Compared all 300 feature names against the exact 37-feature trainer schema (zero exact matches).
- Added exact-header and published-class-count gates to the LFS importer.
- No raw dataset, model artifact, generated APK, training, build, test, or GitHub Actions run was performed.
