# AndroMD ZeroOne Dataset — Intake Audit

**Status: valid research-corpus candidate; not compatible with the current 37-feature model as-is. Not trained or activated.**

## Source and provenance

- Uploaded file: `AndroMD_ZeroOne_Dataset.csv`
- Dataset: [AndroMD Android Malware Dataset, Mendeley Data, Version 1](https://data.mendeley.com/datasets/pwyj5b3khp/1)
- DOI: [10.17632/pwyj5b3khp.1](https://doi.org/10.17632/pwyj5b3khp.1)
- Dataset contributors: Arvind Prasad and Shalini Chandra (2025)
- The Mendeley record lists the dataset under **CC BY 4.0**.
- The accompanying research article is “AndroMD: An Android malware detection framework based on source code analysis and permission scanning,” *Results in Engineering*, Volume 28 (December 2025), DOI [10.1016/j.rineng.2025.107050](https://doi.org/10.1016/j.rineng.2025.107050).

The published dataset record reports 600,298 apps: 397,814 legitimate and 202,484 malicious (66.27% / 33.73%). These are source-reported totals and are now enforced as import validation gates; the complete uploaded CSV has not yet passed the importer.

## File and schema inspection

- File size: **184,104,393 bytes** (175.58 MiB).
- Parsed line count: **600,299**, including the header; therefore 600,298 data rows.
- Header width: **119 columns**:
  - `sha256`: sample hash;
  - `TOTCLASSES`: numeric field;
  - 116 token/API/key-presence indicators;
  - `Label`: class label.
- Four separated rows were inspected; all 116 indicator values were binary (0/1), `TOTCLASSES` was an integer, SHA-256 values had 64 hex characters, and labels were `Benign` or `Malware`.

### Meaning and extraction semantics

The paper describes ZeroOne as presence/absence indicators derived from selected keywords and method/API patterns found in decompiled Java code: a key is 1 when present in the source and 0 otherwise. The research pipeline processes APK DEX/code, extracts Java classes, and searches the resulting source representation. This is not equivalent to simply checking arbitrary DEX strings or mapping the columns to the app's existing 37 features. The exact matching rules and frozen feature order must be replicated before any production extractor is approved.

## Compatibility with the current Antivirus ALai model

The current trainer in `tools/train_multiview_model.py` requires the exact versioned 37-feature schema and a non-empty `family_group` column. Its default label field is lowercase `label`; this CSV uses `Label`.

A header-level comparison found **zero exact feature-name matches** between the 117 ZeroOne data columns (116 binary indicators plus `TOTCLASSES`) and the current 37 model features. ZeroOne therefore needs its own versioned schema and model pipeline, or a carefully designed multi-view model with separately extracted features. Renaming columns or filling missing fields with guessed values would invalidate training.

The CSV has no dedicated package identifier or malware-family/group identifier. `PKG_NAME` is one of the binary feature names, not a package identity value. SHA-256 identifies a file, not a package/family group.

## Full validation and LFS import tool

The branch now includes `tools/import_andromd_datasets.py`. It performs a streaming full-file parse, locks the exact frozen header/order for ZeroOne and MNF, checks every row's field count, 64-hex SHA-256, label, binary feature domain and ZeroOne `TOTCLASSES`, rejects duplicate hashes, enforces the published 600,298-row and class totals, and computes a full-file SHA-256.

When both CSVs are supplied, it additionally requires exact one-to-one SHA-256 coverage and identical labels before staging either file. It stages only the supplied CSVs under the root Git LFS rule. **This full validation and cross-dataset join check have not yet been run**, because the raw files have not been pushed from a Git LFS-capable client.

## Decision and remaining work

1. Do not pass this CSV to the current 37-feature trainer.
2. Complete full-file validation and commit the actual binary through Git LFS.
3. Obtain reliable package/family grouping metadata. Never substitute SHA-256 as `family_group`.
4. Recover and document the exact source feature-matching rules and reproduce them in an on-device DEX/code extractor.
5. Train with package/family-disjoint train, calibration, and untouched test groups; report FPR, recall, precision, F1, ROC-AUC and PR-AUC.
6. Keep production ML **NOT_CONFIGURED** until extraction parity, independent metrics, mobile resource tests, and model signing/packaging are complete.

## Licence and attribution

The Mendeley record lists CC BY 4.0, which permits commercial reuse/adaptation subject to attribution, licence link, and notice of changes. Preserve the source title, contributors, DOI, licence link, and state that Antivirus ALai is not endorsed by the authors. Review upstream rights and the source record before redistribution.

Suggested attribution:

> Prasad, Arvind; Chandra, Shalini (2025). “AndroMD Android Malware Dataset”, Mendeley Data, Version 1. https://doi.org/10.17632/pwyj5b3khp.1. Licensed under CC BY 4.0. Dataset adapted for research/feature evaluation by Antivirus ALai; modifications, if any, must be stated.

## Git LFS storage

The ZeroOne file is 175.58 MiB, above GitHub's 100 MiB hard limit for an ordinary Git object. Root `.gitattributes` tracks `datasets/AndroMD_*.csv` through Git LFS. Intended path: `datasets/AndroMD_ZeroOne_Dataset.csv`.

**The raw CSV has not been uploaded to GitHub yet.** The connector cannot write a 184 MB binary LFS object and the file service cannot materialize files larger than 100 MiB. No fake LFS pointer has been created. The actual LFS object still needs to be pushed from Termux or another Git LFS-capable client. GitHub Free includes 10 GiB LFS storage and 10 GiB monthly download bandwidth; the account's remaining balance is not visible from this connector.

## Work performed

- Confirmed attachment size, line count and 119-column header.
- Inspected four separated records.
- Compared all 117 data columns with the current trainer's 37 feature names (zero exact matches).
- Added exact-header and published-class-count gates to the importer.
- No raw CSV, trained model, synthetic data, APK, build, test, or GitHub Actions run was added/performed.
