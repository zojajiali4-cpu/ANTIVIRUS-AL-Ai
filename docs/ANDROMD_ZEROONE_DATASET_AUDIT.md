# AndroMD ZeroOne Dataset — Intake Audit

**Status: valid research-corpus candidate; not compatible with the current 37-feature model as-is. Not trained or activated.**

## Source and provenance

- Uploaded file: `AndroMD_ZeroOne_Dataset.csv`
- Dataset: [AndroMD Android Malware Dataset, Mendeley Data, Version 1](https://data.mendeley.com/datasets/pwyj5b3khp/1)
- DOI: [10.17632/pwyj5b3khp.1](https://doi.org/10.17632/pwyj5b3khp.1)
- Dataset contributors: Arvind Prasad and Shalini Chandra (2025)
- The Mendeley record lists the dataset under **CC BY 4.0**.
- The accompanying research article is “AndroMD: An Android malware detection framework based on source code analysis and permission scanning,” *Results in Engineering*, Volume 28 (December 2025), DOI [10.1016/j.rineng.2025.107050](https://doi.org/10.1016/j.rineng.2025.107050).

The published dataset record reports 600,298 apps: 397,814 legitimate and 202,484 malicious (66.27% / 33.73%). These class totals are source-reported; this intake did not independently recount all labels in the 184 MB CSV.

## File and schema inspection

- File size: **184,104,393 bytes** (175.58 MiB).
- Parsed line count: **600,299**, including the header; therefore 600,298 data rows.
- Header width: **119 columns**:
  - `sha256`: sample hash;
  - `TOTCLASSES`: numeric class-count field;
  - 116 token/API/key-presence indicators;
  - `Label`: class label.
- The 116 sampled indicator fields contain binary values (0/1). `TOTCLASSES` is numeric and must not be treated as a binary flag.
- The labels observed in inspected rows are `Benign` and `Malware`.

### Sampled integrity checks

Four separated records were inspected (first data row, a middle row, and the final two rows). Each inspected row had:
- exactly 119 comma-separated fields;
- a 64-character hexadecimal SHA-256;
- 116 feature cells restricted to 0/1;
- a numeric `TOTCLASSES` value;
- a non-empty `Benign` or `Malware` label.

This is a **sample check only**, not a full-file validation, complete missing-value scan, or global duplicate-SHA scan. The paper describes the source records as free of duplicates and missing values, but that statement has not been independently verified against every row of this uploaded copy.

## What ZeroOne represents

The paper describes ZeroOne as binary presence/absence indicators derived from keywords and method/API patterns found in decompiled Java code. It is a code-token/static-source view of an APK, not a manifest-permission-only dataset. This makes it complementary to the AndroMD MNF subset previously uploaded.

The paper states that the three AndroMD subsets share the same record sequence and SHA-256/label information. If both ZeroOne and MNF are retained, a future merge may be possible, but the implementation must still verify every corresponding SHA-256 and label before joining; the published statement alone is not a row-level merge proof.

## Compatibility with the current Antivirus ALai model

The current trainer in `tools/train_multiview_model.py` requires the exact versioned 37-feature schema, a label column, and a non-empty `family_group` column. Its default label field is lowercase `label`; this CSV uses `Label`, which could be selected with `--label-column Label`, but that does not solve the feature mismatch.

A header-level comparison found **zero exact feature-name matches** between the 117 ZeroOne feature columns and the current 37 model features.

The current 37-feature model expects APK/package metadata, specific permission flags, selected DEX/API evidence, native ELF symbols, archive structure, and analysis-coverage flags. ZeroOne instead records its own keyword-presence vector and `TOTCLASSES`. These are different feature definitions and extraction semantics; renaming the columns or filling absent columns with guessed values would invalidate the training data.

The CSV has no dedicated package identifier or malware-family/group identifier. `PKG_NAME` is one of the binary key columns, not a package identity value. `sha256` identifies an individual file and is not a safe substitute for a package/family group.

## Decision and safe integration path

1. **Do not pass this CSV to the existing 37-feature trainer.**
2. Preserve it as a candidate for a separately versioned ZeroOne model schema (117 input fields: one numeric `TOTCLASSES` value plus 116 binary indicators), with documented extraction semantics that can be reproduced from APK/DEX on-device.
3. Validate all 600,298 rows, including field counts, numeric/binary domains, labels, missing values, and global SHA-256 uniqueness.
4. Obtain package/family grouping metadata from a reliable source. Do not synthesize groups or rename SHA-256 as a group identifier.
5. If combining ZeroOne with MNF, join only after checking all SHA-256 and label pairs. Record the joined schema and its exact feature order.
6. Train and evaluate with package/family-disjoint train, calibration, and untouched test groups. Report false-positive rate, recall, precision, F1, ROC-AUC, PR-AUC, class counts, and group counts.
7. Keep the production model state **NOT_CONFIGURED** until the matching extractor, full validation, independent evaluation, and model packaging are complete.

## Licence and attribution

The source record lists CC BY 4.0. That licence permits commercial reuse and adaptation subject to attribution, a link to the licence, and indicating changes. Preserve the source title, contributors, DOI, licence link, and a clear statement that Antivirus ALai is not endorsed by the dataset authors. Review the complete licence and source record before any redistribution.

Suggested attribution:

> Prasad, Arvind; Chandra, Shalini (2025). “AndroMD Android Malware Dataset”, Mendeley Data, Version 1. https://doi.org/10.17632/pwyj5b3khp.1. Licensed under CC BY 4.0. Dataset adapted for research/feature evaluation by Antivirus ALai; modifications, if any, must be stated.

## Git LFS storage

The file is 175.58 MiB, above GitHub's 100 MiB hard limit for an ordinary Git object. The repository now has a targeted Git LFS rule for `datasets/AndroMD_*.csv`; the intended repository path is `datasets/AndroMD_ZeroOne_Dataset.csv`.

**The raw CSV has not been uploaded to GitHub yet.** The connected GitHub file-write operation accepts UTF-8 text only, and the file service could not materialize this 184 MB upload because its per-file materialization limit is 100 MiB. Do not create a fake LFS pointer or claim the binary is present. The actual LFS object still needs to be pushed from a Git LFS-capable client. Git LFS storage/bandwidth quotas must be checked before repeated downloads or updates.

## Work performed

- Read the CSV header and confirmed 119 columns.
- Confirmed 600,299 parsed lines including the header.
- Inspected four separated data rows and checked their field count, SHA-256 shape, 116 binary indicator values, numeric `TOTCLASSES`, and labels.
- Compared all 117 ZeroOne feature-column names with the trainer's exact 37-feature list.
- Reviewed the repository's trainer/schema documentation and the published AndroMD dataset/article descriptions.
- Added Git LFS tracking configuration for AndroMD CSVs under `datasets/`.
- No raw CSV, model artifact, or synthetic data was committed. No training, build, test, or GitHub Actions workflow was run.
