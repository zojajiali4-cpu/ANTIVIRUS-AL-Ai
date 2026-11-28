# AndroMD research datasets

This directory is reserved for the AndroMD CSV research corpus. Large CSV payloads must be stored through Git LFS; ordinary Git blobs are not suitable.

## Source

Prasad, Arvind; Chandra, Shalini (2025), *AndroMD Android Malware Dataset*, Mendeley Data, Version 1, DOI: https://doi.org/10.17632/pwyj5b3khp.1. The dataset record lists CC BY 4.0. Retain attribution, link to the licence, and identify modifications. The dataset is not endorsed by the authors.

## Dataset views

- `AndroMD_ZeroOne_Dataset.csv`: one SHA-256 identifier, `TOTCLASSES`, 116 binary source-code/token indicators, and `Label` (119 columns total).
- `AndroMD_MNF_Dataset.csv`: one SHA-256 identifier, 300 binary AndroidManifest/permission indicators, and `Label` (302 columns total).
- The published record reports 600,298 apps, 397,814 legitimate and 202,484 malicious samples.

The ZeroOne and MNF feature views are not the current 37-feature on-device model schema. Do not rename columns, synthesize missing fields, or activate the production ML model based on these files alone. A dedicated extractor/schema, full-file checks, package/family grouping, group-disjoint evaluation, and release gates are required first.

## Import from Android / Termux

The branch includes `tools/import_andromd_datasets.py`. It checks the full CSV contents, validates every record, rejects duplicate SHA-256 values, computes file hashes, and, when both datasets are supplied, verifies exact SHA-256 and label alignment. It then stages only the supplied CSV files via Git LFS and pushes to `hardening/complete-antivirus-no-ci`.

Example after installing `git`, `git-lfs`, and `python`, authenticating with GitHub CLI, and cloning this branch:

```bash
python tools/import_andromd_datasets.py \
  --zeroone ~/storage/downloads/AndroMD_ZeroOne_Dataset.csv \
  --mnf ~/storage/downloads/AndroMD_MNF_Dataset.csv
```

Either `--zeroone` or `--mnf` may be used on its own. If uploading only one, the cross-dataset alignment check cannot run. Check the repository owner's Git LFS storage allowance before pushing. A successful Git LFS push consumes storage; future downloads consume bandwidth.

This tool does not train a model and does not run builds, tests, or GitHub Actions.
