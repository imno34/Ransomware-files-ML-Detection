# Ransomware-ML-Detection: Pipeline Reference

Please note that this is AI-generated.

## 1. Project Goal

The repository implements an end-to-end ML pipeline:
1. Parse raw files and build a feature dataset.
2. Prepare augmentation candidate subsets.
3. Apply targeted encryption transforms.
4. Merge augmented rows into a target split.
5. Vectorize features and train classifiers.

## 2. Repository Layout

```text
programm_code/
  config/
    features.yaml
    augmentation.yaml
  featurizers/
    extract.py
    sniff.py
    parser_registry.py
    features_a.py
    features_b.py
    features_c.py
    parsers_A/
    parsers_B/
  training/
    dataset.py
    vectorize.py
    train_LGBM.py
    train_MLP.py
    train_RFC.py
  augmentation/
    initial_split.py
    independent_test.py
    targeted_encryption.py
    merge_augmented_data.py
  additional_data/
    ... auxiliary research scripts
```

## 3. Data Contracts

### 3.1 Classes

- `benign`
- `benign-encrypted`
- `ransomware-encrypted`

### 3.2 Filename Parsing

`training/dataset.py` uses class-dependent filename parsing:
- `parse_filename_metadata_default()` for `benign` and `benign-encrypted`
- `parse_filename_metadata_ransomware()` for `ransomware-encrypted`

Parsed fields:
- `sequence_id`
- `orig_ext`
- `extra`
- `curr_ext`

Grouping keys:
- `group_id = "<sequence_id>-<orig_ext>"`, fallback to `filename` if parsing fails
- `pair_id = group_id` when `extra` is empty, otherwise `pair_id = group_id-extra`

### 3.3 Service Columns (Canonical Order)

The canonical service-column order (used by `dataset.py` and `targeted_encryption.py`) is:
1. `path`
2. `gt_class`
3. `sequence_id`
4. `orig_ext`
5. `extra`
6. `curr_ext`
7. `group_id`
8. `pair_id`
9. `is_augmented`
10. `aug_encryption`
11. `aug_parent`

## 4. Core Pipeline

### 4.1 Build Dataset and Splits

Script: `training/dataset.py`

What it does:
1. Recursively scans class folders.
2. Parses filename metadata.
3. Extracts features via `featurizers.extract.extract_feats()`.
4. Builds `dataset.csv`.
5. Performs stratified grouped split by `group_id`.
6. Writes `train.csv`, `valid.csv`, `test.csv`.

CLI:
```bash
python training/dataset.py --idir <input_root> --odir <output_dir> [--workers 6] [--chunksize 32] [--fallback]
```

Outputs:
- `<output_dir>/dataset.csv`
- `<output_dir>/train.csv`
- `<output_dir>/valid.csv`
- `<output_dir>/test.csv`

Current service-field behavior in base dataset:
- `is_augmented = False`
- `aug_encryption = None`
- `aug_parent = None`

### 4.2 Prepare Augmentation Candidates (Base)

Script: `augmentation/initial_split.py`

What it does:
1. Loads an input CSV.
2. Filters to `benign` and `benign-encrypted`.
3. Filters by `orig_ext` using `orig_ext_quotas` from `config/augmentation.yaml`.
4. Samples by quotas up to `--pool-fraction`.
5. Copies selected files into `augmented/files_to_augment` next to input CSV.

CLI:
```bash
python augmentation/initial_split.py --incsv <input_csv> --froot <files_root> --pool-fraction <0..1>
```

### 4.3 Prepare Independent Control Subset

Script: `augmentation/independent_test.py`

What it does:
1. Reuses `initial_split.py` logic.
2. Excludes rows where candidate `pair_id` exists in exclusion CSV column `aug_parent`.
3. Copies selected files to `augmented/files_to_augment` next to input CSV.

CLI:
```bash
python augmentation/independent_test.py --incsv <input_csv> --excsv <exclusions_csv> --froot <files_root> --pool-fraction <0..1>
```

Important:
- target size is computed from the pool **after** all filters and exclusions;
- repeated runs can overwrite contents in `augmented/files_to_augment`.

### 4.4 Encrypt and Parse Augmented Files

Script: `augmentation/targeted_encryption.py`

What it does:
1. Copies files from input dir to `<output_dir>/augmented_files-{alg[-alg...]}`.
2. Splits files by `algorithm_quotas` from `config/augmentation.yaml`.
3. Applies exactly one algorithm per file:
   - `header-only`
   - `intermittent`
   - `hybrid`
   - `adaptive`
4. Renames files with `-aug` suffix.
5. Parses augmented files and writes output CSV.

CLI:
```bash
python augmentation/targeted_encryption.py --fdir <files_to_augment_dir> --odir <output_dir>
```

Artifact naming:
- folder: `augmented_files-{alg}` or `augmented_files-{alg1}-{alg2}-...`
- CSV: `aug-{alg}.csv` or `aug-{alg1}-{alg2}-....csv`

Augmented-row behavior:
- `gt_class = ransomware-encrypted`
- `is_augmented = True`
- `aug_encryption = <algorithm>`
- `aug_parent = pair_id` of original pre-augmentation file

Augmented `pair_id` logic:
- if `extra` is empty: `pair_id = group_id`
- if `extra` is not empty: remove regex `\b-?aug\b` from `extra`, then:
  - if result is empty: `pair_id = group_id`
  - else: `pair_id = group_id-extra_clean`

Algorithm note:
- `intermittent` starts encryption from block 2 (first 64KB block is skipped).

Crypto note:
- AES-128-GCM is used as a byte transform; nonce/tag are not persisted.

### 4.5 Merge Augmented Data into Target Split

Script: `augmentation/merge_augmented_data.py`

What it does:
1. Loads augmented CSV.
2. Loads target CSV.
3. Concatenates rows (no deduplication).
4. Saves merged CSV.

CLI:
```bash
python augmentation/merge_augmented_data.py --acsv <augmented_csv> --tcsv <target_csv> --odir <output_dir>
```

Current output filename in code:
- `augmented_sample.csv`

## 5. Feature Extraction Architecture

### 5.1 `featurizers/sniff.py`

Responsibilities:
- magic-based format detection (`magic_ok`, `magic_family`, `format_family`)
- file size features (`size_bytes`, `log_size`)
- fallback format inference (`pdf`/`ooxml`) when magic fails:
  - `fallback_used`
  - `fallback_format_family`

### 5.2 `featurizers/extract.py`

Execution flow:
1. `sniff.sniff(...)`
2. parser A (`parsers_A`) by format family
3. aggregator A (`features_a.py`)
4. parser B (`parsers_B`) for encryption features when structure is valid
5. aggregator B (`features_b.py`)
6. statistical aggregator C (`features_c.py`)
7. strict schema validation against `config/features.yaml`

CLI:
```bash
python -m featurizers.extract [--fallback] <INPUT_PATH> <OUTPUT_DIR>
```

### 5.3 `featurizers/parser_registry.py`

Auto-discovers:
- `parsers_A` for structural parsers
- `parsers_B` for encryption parsers

## 6. Configuration

### 6.1 `config/features.yaml`

Defines:
- sniffer/global settings
- enabled format families
- full feature schema and types

### 6.2 `config/augmentation.yaml`

Defines:
- `orig_ext_quotas` for extension-based sampling
- `algorithm_quotas` for augmentation algorithm distribution

Both mappings are validated to sum to `1.0`.

## 7. Vectorization and Training

Vectorization script:
- `training/vectorize.py`

Training scripts:
- `training/train_LGBM.py`
- `training/train_MLP.py`
- `training/train_RFC.py`

Common behavior:
- read `train/valid/test.csv`
- create/use `vectorized/` under split directory
- save `X_*.npy`, `y_*.npy`, `feature_list.json`, `label_map.json`, `class_weights.json`
- compute metrics, ROC, `valid_predictions.csv`

## 8. Minimal Runbook

1. Build dataset:
```bash
python training/dataset.py --idir <raw_dataset_root> --odir <splits_dir> --fallback
```

2. Prepare augmentation candidates:
```bash
python augmentation/initial_split.py --incsv <splits_dir/train.csv> --froot <raw_dataset_root> --pool-fraction 0.3
```

3. Encrypt and parse augmented files:
```bash
python augmentation/targeted_encryption.py --fdir <splits_dir/augmented/files_to_augment> --odir <splits_dir/augmented>
```

4. Merge augmented data into train:
```bash
python augmentation/merge_augmented_data.py --acsv <splits_dir/augmented/aug-<alg>.csv> --tcsv <splits_dir/train.csv> --odir <splits_dir/augmented>
```

5. Train model (LGBM example):
```bash
python training/train_LGBM.py <splits_dir> <train_output_dir> --train-split <splits_dir/augmented/augmented_sample.csv>
```

## 9. Dependencies

Core libraries:
- `pandas`
- `numpy`
- `scikit-learn`
- `matplotlib`
- `lightgbm`
- `pyyaml`
- `pycryptodome`
- `olefile`
