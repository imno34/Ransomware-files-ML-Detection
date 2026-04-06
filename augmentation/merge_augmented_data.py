from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

OUTPUT_FILENAME = "augmented_sample.csv"


def merge_augmented_data(
    augmented_csv_path: Path,
    target_csv_path: Path,
    output_dir: Path,
) -> Path:
    if not augmented_csv_path.is_file():
        raise FileNotFoundError(f"Augmented CSV not found: {augmented_csv_path}")
    if not target_csv_path.is_file():
        raise FileNotFoundError(f"Target CSV not found: {target_csv_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    augmented_df = pd.read_csv(augmented_csv_path)
    target_df = pd.read_csv(target_csv_path)

    # Объединение строк без дедупликации: целевая выборка + аугментированная выборка.
    merged_df = pd.concat([target_df, augmented_df], ignore_index=True)

    output_path = output_dir / OUTPUT_FILENAME
    merged_df.to_csv(output_path, index=False, encoding="utf-8")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge augmented CSV with target CSV.")
    parser.add_argument(
        "--acsv",
        type=Path,
        required=True,
        help="Path to CSV file with augmented samples.",
    )
    parser.add_argument(
        "--tcsv",
        type=Path,
        required=True,
        help="Path to CSV file with target dataset split.",
    )
    parser.add_argument(
        "--odir",
        type=Path,
        required=True,
        help="Directory where augmented_train.csv will be written.",
    )
    args = parser.parse_args()

    output_path = merge_augmented_data(
        augmented_csv_path=args.acsv.resolve(),
        target_csv_path=args.tcsv.resolve(),
        output_dir=args.odir.resolve(),
    )
    print(f"Merged CSV saved to: {output_path}")


if __name__ == "__main__":
    main()
