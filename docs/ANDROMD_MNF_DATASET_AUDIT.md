# AndroMD MNF Dataset — Intake Audit

**Status: reviewed candidate; not approved as input to the current 37-feature model.**

## Source and provenance

- File received: `AndroMD_MNF_Dataset.csv`
- Published dataset: [AndroMD Android Malware Dataset, Mendeley Data, V1](https://data.mendeley.com/datasets/pwyj5b3khp/1)
- DOI: [10.17632/pwyj5b3khp.1](https://doi.org/10.17632/pwyj5b3khp.1)
- Authors: Arvind Prasad and Shalini Chandra (2025)
- Dataset landing page lists CC BY 4.0. Preserve attribution and verify any upstream/source-specific terms before redistributing derivatives or samples.
- The published record describes 600,298 apps: 397,814 legitimate and 202,484 malicious. These are source-published totals; this audit did not independently recount every label in the 403 MB file.

## File and schema inspection

The uploaded file is 403,328,807 bytes. The parsed file contains 600,299 lines including the header, matching 600,298 data rows.

The header has 302 columns:
- `sha256`: sample hash;
- 300 binary manifest/permission feature columns;
- `Label`: class label.

The dataset's MNF subset is based on permissions declared in AndroidManifest.xml. The 300 feature names are manifest permission/permission-related indicators, not the APK multi-view feature set used by this app.

### Sampled integrity checks

Three separated windows were inspected: the first 999 data rows, 1,000 rows around line 300,000, and the final 1,000 rows (2,999 data rows total).

Within those inspected windows:
- every row had 302 comma-separated fields;
- labels were non-empty and used `Benign` / `Malware`;
- each SHA-256 value had 64 hexadecimal characters;
- all 300 feature cells were `0` or `1`;
- no duplicate SHA-256 values were observed within an individual inspected window.

This is a sampled check, not a full 600,298-row validation or a global duplicate scan. The sampled class mix differed substantially by window (the final 1,000 rows were all labelled `Malware`), so do not split the CSV by taking its first or last contiguous rows.

## Compatibility with the current Antivirus ALai model

The current trainer in `tools/train_multiview_model.py` requires the exact versioned 37-feature schema, a label column, and a non-empty `family_group` column. Its default label field is lowercase `label`; this CSV uses `Label`, which can be supplied with `--label-column Label`.

A name-level comparison found **zero exact matches** between the 300 MNF feature names and the current 37 model feature names. Some permission concepts could potentially be mapped to individual model permission flags after a source-to-runtime semantic audit, but that does not fill the missing views.

The current 37-feature schema also includes values that this MNF file does not provide, including APK size/target SDK and exported-component/debug state, DEX/API references, native ELF symbols, archive structure, and analysis-coverage flags.

Most importantly, the CSV has no package identifier or malware-family/group identifier. `sha256` identifies a specific binary; it is not a safe substitute for package/family grouping. The current trainer requires group-disjoint train/calibration/test splits to reduce leakage. Do not rename `sha256` to `family_group`.

## Decision and safe next step

1. **Do not feed this file directly to the existing 37-feature trainer.** It will fail the required-schema/group checks, and inventing missing values or renaming unrelated columns would create an invalid training set.
2. Keep this dataset as a candidate for a **separate manifest-permissions model**. That would require a separately versioned schema, matching on-device manifest feature extraction for the same 300 indicators (or a rigorously documented reduced subset), and package/family metadata for group-disjoint evaluation.
3. Before any training, complete a full-file validation, establish package/family groups, define a documented mapping, and evaluate false-positive rate and recall on a genuinely independent holdout.
4. Keep the production model status `NOT_CONFIGURED` until the model has been trained, independently evaluated, reviewed, and packaged. This audit does not train or activate a model.

## Storage decision

Do not commit the raw CSV to ordinary Git history. At 403,328,807 bytes, it exceeds GitHub's 100 MiB hard limit for a normal Git object. GitHub recommends Git LFS or storing generated/large data outside Git; for this project, keep the raw research corpus outside the source repository and commit only small, reproducible tooling and audit documentation. See [GitHub repository limits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits).

## Work performed

- Inspected the uploaded CSV header, total parsed line count, and three separated 1,000-line windows (the first window includes the header).
- Compared all 300 CSV feature names against the trainer's exact 37-feature list.
- Reviewed the current trainer and model-schema documentation.
- No raw dataset, model artifact, generated APK, or synthetic data was added.
- No build, test, or GitHub Actions workflow was run.
