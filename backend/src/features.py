"""
Feature Engineering Module for DGA Domain Detection.

Extracts lexical and statistical features from domain strings for
classification as legitimate or DGA-generated. These features are based
on established DGA-detection literature, particularly:

  Schüppen, S., Teuber, D., Herrmann, P., & Meyer, U. (2018).
  "FANCI: Feature-based Automated NXDomain Classification and Intelligence."
  USENIX Security Symposium.

The feature set includes character distribution metrics, n-gram frequency
analysis, and structural indicators that capture the statistical differences
between human-chosen and algorithmically-generated domain names.

This module is designed to be fast and dependency-light for inference-time
use in the FastAPI serving layer.
"""

import math
import re
import pickle
import logging
from pathlib import Path
from collections import Counter

import numpy as np
import tldextract
import wordninja

logger = logging.getLogger(__name__)

# --- Constants ---
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
HEX_CHARS = set("0123456789abcdef")
MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
NGRAM_MODEL_PATH = MODELS_DIR / "ngram_model.pkl"


def decode_idn(domain: str) -> str:
    """
    Normalize and decode an Internationalized Domain Name (IDN) from Punycode
    ('xn--...') representation to Unicode.

    Uses standard Python idna codecs with fallback to the idna package.
    Raises ValueError if the Punycode format is malformed or invalid.
    """
    domain = domain.strip().rstrip(".")
    if "xn--" in domain.lower():
        try:
            return domain.encode("ascii").decode("idna").lower()
        except Exception:
            try:
                import idna
                return idna.decode(domain.lower())
            except Exception as e:
                raise ValueError(f"Invalid IDN / Punycode format: {domain}") from e
    return domain.lower()


def sanitize_and_validate_domain(domain: str) -> str:
    """
    Centralized validation and normalization helper enforcing RFC 1034 / RFC 1035
    and RFC 5890/5891 DNS rules:
    - Enforces string type, strips whitespace, converts to lowercase.
    - Strips optional single trailing dot (FQDN representation, e.g. 'example.com.' -> 'example.com').
    - Disallows spaces and ASCII control characters.
    - Total length between 1 and 253 characters.
    - Splits into labels by '.'; disallows empty labels (e.g. consecutive dots '..').
    - Each label length between 1 and 63 characters.
    - Labels must not start or end with a hyphen ('-').
    - Disallows invalid symbols (e.g. '_', '@', punctuation).
    - Top-level domain (last label) cannot be all-numeric and must contain at least one alphabetic character.
    - Decodes Punycode/IDN to Unicode representation.

    Returns:
        Sanitized and decoded domain string.

    Raises:
        ValueError: If domain fails any RFC DNS rule or contains malformed Punycode.
    """
    if not isinstance(domain, str):
        raise ValueError("Domain must be a string")
    v = domain.strip().lower()
    if not v:
        raise ValueError("Domain cannot be empty")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in v):
        raise ValueError("Domain cannot contain whitespace or control characters")
    if v.endswith("."):
        v = v[:-1]
    if not v:
        raise ValueError("Domain cannot be empty")
    if len(v) > 253:
        raise ValueError(f"Domain length ({len(v)}) exceeds maximum allowed length of 253 characters")

    labels = v.split(".")
    if any(len(label) == 0 for label in labels):
        raise ValueError("Domain cannot contain empty labels (e.g. consecutive dots)")

    for label in labels:
        if len(label) > 63:
            raise ValueError(f"Label exceeds maximum allowed length of 63 characters: {label[:20]}...")
        if label.startswith("-") or label.endswith("-"):
            raise ValueError(f"Label cannot start or end with a hyphen: {label}")
        if not all(c.isalnum() or c == "-" for c in label):
            raise ValueError(f"Label contains invalid characters: {label}")

    tld = labels[-1]
    if tld.isdigit():
        raise ValueError(f"Top-level domain cannot be all-numeric: {tld}")
    if not any(c.isalpha() for c in tld):
        raise ValueError(f"Top-level domain must contain alphabetic characters: {tld}")

    # Normalize IDN / Punycode to Unicode
    decoded = decode_idn(v)
    return decoded


def strip_tld(domain: str) -> str:
    """
    Extract the second-level domain (SLD) by stripping TLD and subdomain
    using tldextract. Returns the registered domain name without TLD.
    Automatically decodes IDN / Punycode representation before extraction.

    Examples:
        'www.google.com' -> 'google'
        'mail.yahoo.co.uk' -> 'yahoo'
        'xjkqwrtzp.info' -> 'xjkqwrtzp'
        'xn--mller-kva.de' -> 'müller'
    """
    domain_clean = decode_idn(domain.strip().rstrip("."))
    extracted = tldextract.extract(domain_clean)
    return (extracted.domain or domain_clean).lower()


def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness in character distribution,
    which is characteristic of DGA-generated domains.
    H(X) = -Σ p(x) * log2(p(x))
    """
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 6)


def gini_index(s: str) -> float:
    """
    Calculate Gini index of character frequency distribution.

    Gini index measures inequality in character distribution.
    DGA domains tend to have more uniform distributions (higher Gini),
    while legitimate domains have skewed distributions (lower Gini).
    """
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    probabilities = [count / length for count in counter.values()]
    return round(1.0 - sum(p ** 2 for p in probabilities), 6)


def vowel_consonant_ratio(s: str) -> float:
    """Ratio of vowels to consonants. Legitimate domains tend to have more vowels."""
    if not s:
        return 0.0
    vowel_count = sum(1 for c in s if c in VOWELS)
    consonant_count = sum(1 for c in s if c in CONSONANTS)
    if consonant_count == 0:
        return float(vowel_count) if vowel_count > 0 else 0.0
    return round(vowel_count / consonant_count, 6)


def digit_ratio(s: str) -> float:
    """Fraction of characters that are digits."""
    if not s:
        return 0.0
    return round(sum(1 for c in s if c.isdigit()) / len(s), 6)


def hex_char_ratio(s: str) -> float:
    """
    Fraction of characters that are valid hexadecimal characters [0-9a-f].

    Hash-based DGAs produce domains that are substrings of hex digests,
    so they have hex_char_ratio close to 1.0.
    """
    if not s:
        return 0.0
    return round(sum(1 for c in s if c in HEX_CHARS) / len(s), 6)


def max_consecutive_consonants(s: str) -> int:
    """
    Length of the longest consecutive consonant run.

    DGA domains tend to have longer consonant runs since they don't
    follow natural language phonotactic rules.
    """
    if not s:
        return 0
    max_run = 0
    current_run = 0
    for c in s:
        if c in CONSONANTS:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 0
    return max_run


def unique_char_ratio(s: str) -> float:
    """Ratio of distinct characters to total length."""
    if not s:
        return 0.0
    return round(len(set(s)) / len(s), 6)


def digit_as_first_char(s: str) -> int:
    """Boolean flag (0/1): does the domain start with a digit?"""
    if not s:
        return 0
    return 1 if s[0].isdigit() else 0


def vowel_consonant_transition_rate(s: str) -> float:
    """
    Calculate the frequency of switches between vowels and consonants.

    Normalized by total possible transitions: transitions / max(len(s) - 1, 1).
    Phonotactically natural words exhibit alternating patterns, whereas
    consonant-heavy or vowel-heavy random strings exhibit lower rates.
    """
    if len(s) <= 1:
        return 0.0
    transitions = 0
    for i in range(len(s) - 1):
        c1, c2 = s[i], s[i + 1]
        if (c1 in VOWELS and c2 in CONSONANTS) or (c1 in CONSONANTS and c2 in VOWELS):
            transitions += 1
    return round(transitions / (len(s) - 1), 6)


def extract_word_features(s: str) -> tuple[int, float]:
    """
    Extract dictionary word segmentation metrics using wordninja.

    Filters for valid alphabetic sub-words of length >= 3 to ignore spurious
    single characters or 2-letter fragments from random noise.

    Returns:
        tuple of (segmented_word_count, valid_word_ratio)
    """
    if not s:
        return 0, 0.0

    words = wordninja.split(s)
    valid_words = [w for w in words if len(w) >= 3 and w.isalpha()]
    segmented_word_count = len(valid_words)
    matched_char_count = sum(len(w) for w in valid_words)
    valid_word_ratio = round(min(matched_char_count / max(len(s), 1), 1.0), 6)

    return segmented_word_count, valid_word_ratio


# --- N-gram Scoring ---

def build_ngram_model(domains: list[str], n: int = 2) -> dict:
    """
    Build a character n-gram frequency model from legitimate domains.

    This creates a probability distribution over character bigrams observed
    in the benign training corpus. At inference time, a domain's average
    log-probability under this model indicates how "normal" its character
    sequences look — DGA domains score much lower.

    Args:
        domains: List of legitimate domain strings (SLDs, TLD already stripped)
        n: N-gram size (default 2 for bigrams)

    Returns:
        Dictionary with 'ngram_counts', 'total', and 'n' keys
    """
    ngram_counts: Counter = Counter()
    total = 0

    for domain in domains:
        sld = strip_tld(domain) if "." in domain else domain.lower()
        if len(sld) < n:
            continue
        for i in range(len(sld) - n + 1):
            ngram = sld[i:i + n]
            ngram_counts[ngram] += 1
            total += 1

    model = {
        "ngram_counts": dict(ngram_counts),
        "total": total,
        "n": n,
        "vocab_size": len(ngram_counts),
    }

    logger.info(
        "Built %d-gram model: %d unique n-grams, %d total occurrences",
        n, len(ngram_counts), total,
    )
    return model


def ngram_score(s: str, model: dict) -> float:
    """
    Score a domain string against the n-gram model.

    Returns the average log-probability of character n-grams.
    Uses Laplace smoothing to handle unseen n-grams.
    More negative scores indicate the domain looks less like legitimate domains.
    """
    if not s or not model:
        return 0.0

    n = model.get("n", 2)
    if len(s) < n:
        return -10.0  # Penalty for very short domains

    ngram_counts = model.get("ngram_counts", {})
    total = model.get("total", 1)
    vocab_size = model.get("vocab_size", 1)

    log_probs = []
    for i in range(len(s) - n + 1):
        ngram = s[i:i + n]
        # Laplace smoothing
        count = ngram_counts.get(ngram, 0)
        prob = (count + 1) / (total + vocab_size)
        log_probs.append(math.log2(prob))

    return round(sum(log_probs) / len(log_probs), 6) if log_probs else -10.0


# --- Global n-gram model (loaded once) ---
_ngram_model: dict | None = None


def load_ngram_model() -> dict:
    """Load the pre-built n-gram model from disk."""
    global _ngram_model
    if _ngram_model is not None:
        return _ngram_model

    if NGRAM_MODEL_PATH.exists():
        with open(NGRAM_MODEL_PATH, "rb") as f:
            _ngram_model = pickle.load(f)
        logger.info("Loaded n-gram model from %s", NGRAM_MODEL_PATH)
    else:
        logger.warning("N-gram model not found at %s, using empty model", NGRAM_MODEL_PATH)
        _ngram_model = {"ngram_counts": {}, "total": 1, "n": 2, "vocab_size": 1}

    return _ngram_model


def save_ngram_model(model: dict) -> None:
    """Save the n-gram model to disk."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(NGRAM_MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    logger.info("Saved n-gram model to %s", NGRAM_MODEL_PATH)


# --- Main Feature Extraction ---

# Ordered list of feature names for consistent DataFrame columns
FEATURE_NAMES = [
    "length",
    "entropy",
    "vowel_consonant_ratio",
    "digit_ratio",
    "hex_char_ratio",
    "gini_index",
    "max_consonant_run",
    "digit_first",
    "n_gram_score",
    "unique_char_ratio",
    "segmented_word_count",
    "valid_word_ratio",
    "vowel_consonant_transition_rate",
]


def extract_features(domain: str, ngram_model: dict | None = None) -> dict:
    """
    Extract all features from a single domain string.

    This is the core function called at inference time by the API.
    It strips the TLD, then computes lexical and statistical features
    on the second-level domain (SLD).

    Args:
        domain: Full domain string (e.g., 'example.com' or just 'example')
        ngram_model: Pre-built n-gram model dict. If None, loads from disk.

    Returns:
        Dictionary mapping feature names to their computed values.
    """
    # Strip TLD to get the second-level domain (decoding IDN if needed)
    sld = strip_tld(domain) if "." in domain else decode_idn(domain.strip().rstrip("."))

    # Load n-gram model if not provided
    if ngram_model is None:
        ngram_model = load_ngram_model()

    # Extract word segmentation features in a single pass
    segmented_word_count, valid_word_ratio = extract_word_features(sld)

    return {
        "length": len(sld),
        "entropy": shannon_entropy(sld),
        "vowel_consonant_ratio": vowel_consonant_ratio(sld),
        "digit_ratio": digit_ratio(sld),
        "hex_char_ratio": hex_char_ratio(sld),
        "gini_index": gini_index(sld),
        "max_consonant_run": max_consecutive_consonants(sld),
        "digit_first": digit_as_first_char(sld),
        "n_gram_score": ngram_score(sld, ngram_model),
        "unique_char_ratio": unique_char_ratio(sld),
        "segmented_word_count": segmented_word_count,
        "valid_word_ratio": valid_word_ratio,
        "vowel_consonant_transition_rate": vowel_consonant_transition_rate(sld),
    }


def batch_extract_features(domains: list[str], ngram_model: dict | None = None) -> "pd.DataFrame":
    """
    Extract features for a list of domains, returning a DataFrame.

    Args:
        domains: List of domain strings
        ngram_model: Pre-built n-gram model. If None, loads from disk.

    Returns:
        pandas DataFrame with one row per domain and feature columns.
    """
    import pandas as pd

    if ngram_model is None:
        ngram_model = load_ngram_model()

    features_list = [extract_features(d, ngram_model) for d in domains]
    return pd.DataFrame(features_list, columns=FEATURE_NAMES)
