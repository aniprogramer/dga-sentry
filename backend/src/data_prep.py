"""
Data Preparation Module for DGA Domain Detection.

Acquires domain data from public, reproducible sources and prepares it
for model training with stratified train/val/test splits.

Primary source: chrmor/DGA_domains_dataset (GitHub)
  - ~675K domains from 25 DGA malware families + Alexa Top 1M benign domains
  - Source: Netlab 360 OpenData Project (DGA) + Alexa (benign)
  - License: Public research data

Fallback: Synthetic DGA generation + Tranco Top 1M benign list
"""

import os
import subprocess
import hashlib
import random
import string
import logging
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# --- Constants ---
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DATA_PROCESSED = PROJECT_ROOT / "data" / "processed"
DATASET_REPO = "https://github.com/chrmor/DGA_domains_dataset.git"
DATASET_DIR = DATA_RAW / "DGA_domains_dataset"

# Target dataset size — use full dataset if training stays under 15 min,
# otherwise fall back to this sample size
MAX_SAMPLES_PER_CLASS = None  # None = use all available


def clone_dataset() -> bool:
    """Clone the chrmor/DGA_domains_dataset repository."""
    if DATASET_DIR.exists():
        logger.info("Dataset already cloned at %s", DATASET_DIR)
        return True

    DATA_RAW.mkdir(parents=True, exist_ok=True)
    logger.info("Cloning dataset from %s ...", DATASET_REPO)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", DATASET_REPO, str(DATASET_DIR)],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        logger.info("Dataset cloned successfully.")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logger.warning("Failed to clone dataset: %s", e)
        return False


def load_chrmor_dataset() -> pd.DataFrame:
    """
    Load domains from the chrmor/DGA_domains_dataset repository.

    The repo contains CSV files (dga_domains_full.csv) with the format:
        type,family,domain
    where type is 'dga' or 'legit', family is the DGA family name or 'alexa',
    and domain is the full domain string. No header row.
    """
    csv_path = DATASET_DIR / "dga_domains_full.csv"
    if not csv_path.exists():
        logger.warning("dga_domains_full.csv not found at %s", csv_path)
        return pd.DataFrame(columns=["domain", "label", "family"])

    logger.info("Loading dataset from %s ...", csv_path)
    df = pd.read_csv(
        csv_path,
        header=None,
        names=["type", "family", "domain"],
        dtype=str,
    )

    # Map type column to numeric labels
    df["label"] = (df["type"] == "dga").astype(int)
    df["family"] = df["family"].str.lower().str.strip()
    df["domain"] = df["domain"].str.lower().str.strip().str.rstrip(".")

    # Drop rows with missing domains
    df = df.dropna(subset=["domain"])
    df = df[df["domain"].str.len() >= 2]

    # Rename family for benign domains
    df.loc[df["label"] == 0, "family"] = "legitimate"

    result = df[["domain", "label", "family"]].reset_index(drop=True)

    logger.info(
        "Loaded %d domains (%d benign, %d malicious, %d DGA families) from chrmor dataset",
        len(result),
        (result["label"] == 0).sum(),
        (result["label"] == 1).sum(),
        result[result["label"] == 1]["family"].nunique(),
    )
    return result


# --- Fallback: Synthetic DGA Generation ---

def _generate_random_dga(n: int, seed: int = 42) -> list[str]:
    """Character-random DGA: uniformly random alphanumeric strings."""
    rng = random.Random(seed)
    domains = []
    for _ in range(n):
        length = rng.randint(8, 24)
        domain = "".join(rng.choices(string.ascii_lowercase + string.digits, k=length))
        domains.append(domain)
    return domains


def _generate_hash_dga(n: int, seed: int = 42) -> list[str]:
    """Hash-based DGA: MD5 of sequential seeds, truncated."""
    domains = []
    for i in range(n):
        h = hashlib.md5(f"{seed}_{i}".encode()).hexdigest()
        length = 10 + (i % 15)
        domains.append(h[:length])
    return domains


def _generate_wordlist_dga(n: int, seed: int = 42) -> list[str]:
    """Word-concatenation DGA: combines short word fragments."""
    fragments = [
        "sun", "red", "box", "net", "web", "fly", "sky", "fox", "log", "run",
        "cat", "dog", "bat", "fin", "jet", "hub", "orb", "zen", "gem", "arc",
        "dex", "ion", "lux", "nova", "byte", "core", "data", "echo", "flux",
    ]
    rng = random.Random(seed)
    domains = []
    for _ in range(n):
        num_parts = rng.randint(2, 4)
        domain = "".join(rng.choices(fragments, k=num_parts))
        # Optionally append digits
        if rng.random() < 0.3:
            domain += str(rng.randint(0, 999))
        domains.append(domain)
    return domains


def generate_synthetic_malicious(n: int = 50000) -> pd.DataFrame:
    """Generate synthetic DGA domains as a fallback data source."""
    logger.info("Generating %d synthetic DGA domains ...", n)
    per_type = n // 3
    remainder = n - 3 * per_type

    domains = []
    families = []

    for domain in _generate_random_dga(per_type, seed=42):
        domains.append(domain)
        families.append("synthetic_random")

    for domain in _generate_hash_dga(per_type, seed=43):
        domains.append(domain)
        families.append("synthetic_hash")

    for domain in _generate_wordlist_dga(per_type + remainder, seed=44):
        domains.append(domain)
        families.append("synthetic_wordlist")

    return pd.DataFrame({
        "domain": domains,
        "label": 1,
        "family": families,
    })


def balance_and_split(df: pd.DataFrame) -> pd.DataFrame:
    """
    Balance classes to 50/50 and create stratified train/val/test splits.

    Split ratios: 70% train / 15% validation / 15% test (stratified by label).
    """
    # Remove duplicates
    original_len = len(df)
    df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True)
    logger.info("Removed %d duplicates, %d domains remaining", original_len - len(df), len(df))

    # Balance classes
    benign = df[df["label"] == 0]
    malicious = df[df["label"] == 1]

    min_class_size = min(len(benign), len(malicious))
    if MAX_SAMPLES_PER_CLASS is not None:
        min_class_size = min(min_class_size, MAX_SAMPLES_PER_CLASS)

    logger.info("Balancing to %d samples per class (%d total)", min_class_size, min_class_size * 2)

    benign_sampled = benign.sample(n=min_class_size, random_state=42)
    malicious_sampled = malicious.sample(n=min_class_size, random_state=42)

    df_balanced = pd.concat([benign_sampled, malicious_sampled], ignore_index=True)

    # Stratified split: 70/15/15
    train_df, temp_df = train_test_split(
        df_balanced, test_size=0.30, random_state=42, stratify=df_balanced["label"]
    )
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, random_state=42, stratify=temp_df["label"]
    )

    train_df = train_df.assign(split="train")
    val_df = val_df.assign(split="val")
    test_df = test_df.assign(split="test")

    result = pd.concat([train_df, val_df, test_df], ignore_index=True)

    logger.info(
        "Split sizes — train: %d, val: %d, test: %d",
        len(train_df), len(val_df), len(test_df),
    )
    return result


def run_pipeline() -> Path:
    """Execute the full data preparation pipeline."""
    DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
    output_path = DATA_PROCESSED / "v1_domains.csv"

    # Attempt to clone and load the real dataset
    if clone_dataset():
        df = load_chrmor_dataset()
        if len(df) > 0:
            data_source = "chrmor/DGA_domains_dataset (GitHub)"
        else:
            logger.warning("Cloned repo yielded no domains, falling back to synthetic data.")
            df = generate_synthetic_malicious()
            data_source = "synthetic (fallback)"
    else:
        logger.warning("Clone failed, using synthetic DGA domains as fallback.")
        df = generate_synthetic_malicious()
        data_source = "synthetic (fallback)"

    # If we only have malicious (synthetic fallback), note it
    if (df["label"] == 0).sum() == 0:
        logger.warning(
            "No benign domains found. In production, supplement with Tranco Top 1M. "
            "For now, generating simple benign-like domains."
        )
        # Create simple benign-like domains from common patterns
        benign_domains = [
            f"{''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 12)))}.com"
            for _ in range(len(df))
        ]
        benign_df = pd.DataFrame({
            "domain": benign_domains,
            "label": 0,
            "family": "synthetic_benign",
        })
        df = pd.concat([df, benign_df], ignore_index=True)

    # Balance and split
    result = balance_and_split(df)

    # Save
    result.to_csv(output_path, index=False)
    logger.info("Saved processed dataset to %s", output_path)
    logger.info("Data source: %s", data_source)

    # Print summary statistics
    print("\n" + "=" * 60)
    print("DATA PREPARATION SUMMARY")
    print("=" * 60)
    print(f"Source: {data_source}")
    print(f"Total samples: {len(result)}")
    print(f"Label distribution:\n{result['label'].value_counts().to_string()}")
    print(f"Split distribution:\n{result['split'].value_counts().to_string()}")
    print(f"DGA families: {result[result['label'] == 1]['family'].nunique()}")
    print(f"Output: {output_path}")
    print("=" * 60 + "\n")

    return output_path


if __name__ == "__main__":
    run_pipeline()
