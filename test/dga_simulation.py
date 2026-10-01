#!/usr/bin/env python3
"""
DGA (Domain Generation Algorithm) Simulation and Testing Suite.

This script simulates various real-world and synthetic DGA algorithms commonly used
by malware families to generate command-and-control (C2) rendezvous domains:

1. Conficker-like DGA (Arithmetic / Linear Congruential Generator + Date Seed)
2. Necurs / CryptoLocker-like DGA (PRNG Pseudo-random character generator)
3. Bamital-like DGA (Hash / Digest based algorithm)
4. Matsnu / Suppobox-like DGA (Dictionary / Wordlist concatenation)
5. Dyn-DGA (Subdomain hopping / high-entropy label generation)

Additionally, it can evaluate the generated domains:
- Locally using the project's feature extractor and trained model
- Remotely against the running FastAPI /predict endpoint
"""

import sys
import os
import time
import math
import hashlib
import random
import string
import argparse
from datetime import datetime, date
from pathlib import Path

# Add project root to sys.path so project modules can be loaded if available
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =====================================================================
# 1. DGA ALGORITHM SIMULATIONS
# =====================================================================

class DGASimulator:
    """Simulates various malware DGA strategies."""

    TLD_POOL = ["com", "net", "org", "info", "biz", "ru", "cc", "top", "xyz"]

    @classmethod
    def conficker_style(cls, current_date: date = None, count: int = 5) -> list[dict]:
        """
        Conficker (A/B style):
        Uses a date-seeded PRNG (Linear Congruential Generator) to generate
        character sequences of length 8 to 11.
        """
        if current_date is None:
            current_date = date.today()

        # Seed derived from date
        seed = current_date.year * 10000 + current_date.month * 100 + current_date.day
        domains = []

        for i in range(count):
            # Classic LCG formula: seed = (seed * a + c) % m
            length = 8 + (seed % 4)  # 8 to 11 characters
            domain_chars = []
            for _ in range(length):
                seed = (seed * 1664525 + 1013904223) % (2**32)
                char = chr(ord('a') + (seed % 26))
                domain_chars.append(char)

            tld = cls.TLD_POOL[(seed >> 8) % len(cls.TLD_POOL)]
            domain_name = f"{''.join(domain_chars)}.{tld}"
            domains.append({
                "domain": domain_name,
                "family": "Conficker-style (Date LCG)",
                "seed": f"date={current_date.isoformat()}, index={i}"
            })
        return domains

    @classmethod
    def cryptolocker_style(cls, seed: int = None, count: int = 5) -> list[dict]:
        """
        CryptoLocker / Necurs style:
        Generates pseudo-random strings with variable lengths (12 to 20 chars),
        high character entropy, and uniform letter distribution.
        """
        if seed is None:
            seed = int(time.time())
        rng = random.Random(seed)
        domains = []

        for i in range(count):
            length = rng.randint(12, 20)
            # CryptoLocker domains typically consist of lowercase letters
            domain_chars = [rng.choice(string.ascii_lowercase) for _ in range(length)]
            tld = rng.choice(["com", "net", "biz", "ru", "org"])
            domain_name = f"{''.join(domain_chars)}.{tld}"
            domains.append({
                "domain": domain_name,
                "family": "CryptoLocker-style (High-Entropy PRNG)",
                "seed": f"seed={seed}, i={i}"
            })
        return domains

    @classmethod
    def bamital_style(cls, base_seed: str = "c2_beacon", count: int = 5) -> list[dict]:
        """
        Bamital / Hash-based DGA:
        Hashes consecutive counter values (e.g. MD5 or SHA256) and truncates
        the hex output to form domain labels.
        """
        domains = []
        for i in range(count):
            digest = hashlib.md5(f"{base_seed}_{i}_{date.today()}".encode("utf-8")).hexdigest()
            length = 12 + (i % 8)
            domain_label = digest[:length]
            tld = cls.TLD_POOL[i % len(cls.TLD_POOL)]
            domain_name = f"{domain_label}.{tld}"
            domains.append({
                "domain": domain_name,
                "family": "Bamital-style (MD5 Hex Digest)",
                "seed": f"key={base_seed}_{i}"
            })
        return domains

    @classmethod
    def matsnu_style(cls, seed: int = None, count: int = 5) -> list[dict]:
        """
        Matsnu / Suppobox style (Dictionary / Wordlist Concatenation):
        Concatenates 2 to 3 natural language words to mimic benign domains
        and bypass naive character entropy filters.
        """
        wordlist = [
            "cyber", "guard", "cloud", "shadow", "winter", "forest", "matrix",
            "silver", "beacon", "delta", "system", "valley", "signal", "hunter",
            "shield", "stream", "packet", "vector", "source", "falcon", "nexus"
        ]
        if seed is None:
            seed = 42
        rng = random.Random(seed)
        domains = []

        for i in range(count):
            word_count = rng.randint(2, 3)
            selected = rng.sample(wordlist, word_count)
            domain_label = "".join(selected)
            # Occasionally append a small number
            if rng.random() < 0.4:
                domain_label += str(rng.randint(10, 99))
            tld = rng.choice(["com", "org", "net"])
            domain_name = f"{domain_label}.{tld}"
            domains.append({
                "domain": domain_name,
                "family": "Matsnu-style (Wordlist Concatenation)",
                "seed": f"seed={seed}, i={i}"
            })
        return domains

    @classmethod
    def dyn_subdomain_style(cls, count: int = 5) -> list[dict]:
        """
        Dynamic DNS / Fast-Flux subdomain DGA:
        Generates random subdomains pointed to dynamic DNS providers.
        """
        ddns_providers = ["hopto.org", "zapto.org", "ddns.net", "bounceme.net"]
        domains = []
        for i in range(count):
            label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
            provider = random.choice(ddns_providers)
            domains.append({
                "domain": f"{label}.{provider}",
                "family": "FastFlux/DDNS Subdomain DGA",
                "seed": f"random_k=14, i={i}"
            })
        return domains


# =====================================================================
# 2. LOCAL METRICS & EVALUATION (ENTROPY & LEXICAL)
# =====================================================================

def calculate_shannon_entropy(s: str) -> float:
    """Calculates Shannon entropy of string s (in bits)."""
    if not s:
        return 0.0
    probabilities = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probabilities)


def analyze_domain(domain_str: str) -> dict:
    """Quick lexical metric breakdown for a domain."""
    name_part = domain_str.split(".")[0]
    entropy = calculate_shannon_entropy(name_part)
    vowels = sum(1 for c in name_part if c in "aeiou")
    consonants = sum(1 for c in name_part if c in "bcdfghjklmnpqrstvwxyz")
    digits = sum(1 for c in name_part if c.isdigit())
    v_c_ratio = round(vowels / max(consonants, 1), 3)

    return {
        "length": len(name_part),
        "entropy": round(entropy, 3),
        "vowel_consonant_ratio": v_c_ratio,
        "digit_count": digits,
    }


# =====================================================================
# 3. RUN WITH ML MODEL OR LIVE API
# =====================================================================

def test_against_live_api(domains: list[str], api_url: str = "http://localhost:8000"):
    """Sends simulated domains to the project's running FastAPI backend."""
    try:
        import urllib.request
        import json

        endpoint = f"{api_url.rstrip('/')}/predict/batch"
        payload = json.dumps({"domains": domains}).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        print(f"\n📡 Querying API at: {endpoint} ...")
        with urllib.request.urlopen(req, timeout=5) as response:
            result = json.loads(response.read().decode("utf-8"))
            return result.get("predictions", [])
    except Exception as e:
        print(f"⚠️  Live API test skipped: could not connect to {api_url} ({e})")
        return None


def test_with_local_model(domains: list[str]):
    """Attempts to test using the local pre-trained model directly if present."""
    models_dir = PROJECT_ROOT / "backend" / "models"
    model_path = models_dir / "best_model.joblib"
    scaler_path = models_dir / "scaler.joblib"

    if not model_path.exists():
        return None

    try:
        import joblib
        from backend.src.features import extract_features, load_ngram_model
        import numpy as np

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path) if scaler_path.exists() else None
        ngram = load_ngram_model()

        results = []
        for d in domains:
            feat = extract_features(d, ngram_model=ngram).reshape(1, -1)
            if scaler:
                feat = scaler.transform(feat)
            prob = float(model.predict_proba(feat)[0, 1])
            is_dga = bool(prob >= 0.5)
            results.append({
                "domain": d,
                "is_dga": is_dga,
                "confidence": round(prob if is_dga else (1 - prob), 4),
                "malicious_probability": round(prob, 4)
            })
        return results
    except Exception as err:
        return None


# =====================================================================
# 4. MAIN CLI DRIVER
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="DGA Algorithm Simulation & Testing Suite")
    parser.add_argument("--count", type=int, default=3, help="Number of domains per DGA family (default: 3)")
    parser.add_argument("--api-url", type=str, default="http://localhost:8000", help="FastAPI backend URL")
    args = parser.parse_args()

    print("=" * 80)
    print("   CYBER SECURITY PROJECT: DGA ALGORITHM SIMULATION SUITE")
    print("=" * 80)

    # Generate domains from each family
    families = [
        DGASimulator.conficker_style(count=args.count),
        DGASimulator.cryptolocker_style(count=args.count),
        DGASimulator.bamital_style(count=args.count),
        DGASimulator.matsnu_style(count=args.count),
        DGASimulator.dyn_subdomain_style(count=args.count),
    ]

    all_generated = []
    for f in families:
        all_generated.extend(f)

    # Print Generated DGA domains with their mathematical & lexical characteristics
    print(f"\n[+] Generated {len(all_generated)} DGA domains across 5 malware algorithm types:\n")
    header_fmt = "{:<32} {:<32} {:<8} {:<8}"
    print(header_fmt.format("Domain", "Family / Strategy", "Entropy", "Length"))
    print("-" * 84)

    for item in all_generated:
        d = item["domain"]
        stats = analyze_domain(d)
        print(header_fmt.format(d, item["family"], stats["entropy"], stats["length"]))

    # Benign control sample for contrast
    print("\n" + "-" * 84)
    print("BENIGN CONTROL COMPARISON:")
    benign_samples = ["google.com", "wikipedia.org", "github.com"]
    for b in benign_samples:
        stats = analyze_domain(b)
        print(header_fmt.format(b, "Benign (Human Chosen)", stats["entropy"], stats["length"]))
    print("-" * 84)

    # Run ML Model or API Detection
    domain_list = [item["domain"] for item in all_generated] + benign_samples
    
    # 1. Try Live API first
    api_preds = test_against_live_api(domain_list, args.api_url)
    
    if api_preds:
        print("\n[+] API ML Detection Results:")
        pred_fmt = "{:<32} {:<12} {:<12} {:<12}"
        print(pred_fmt.format("Domain", "Prediction", "Confidence", "DGA Probability"))
        print("-" * 72)
        for p in api_preds:
            tag = "MALICIOUS" if p.get("is_dga") else "BENIGN"
            prob = p.get("malicious_probability", p.get("probability", 0.0))
            conf = p.get("confidence", 0.0)
            print(pred_fmt.format(p["domain"], tag, f"{conf:.2%}", f"{prob:.4f}"))
    else:
        # 2. Try Local Joblib Model
        local_preds = test_with_local_model(domain_list)
        if local_preds:
            print("\n[+] Local Model Inference Results:")
            pred_fmt = "{:<32} {:<12} {:<12} {:<12}"
            print(pred_fmt.format("Domain", "Prediction", "Confidence", "DGA Probability"))
            print("-" * 72)
            for p in local_preds:
                tag = "MALICIOUS" if p["is_dga"] else "BENIGN"
                print(pred_fmt.format(p["domain"], tag, f"{p['confidence']:.2%}", f"{p['malicious_probability']:.4f}"))
        else:
            print("\n💡 Tip: Start your backend (e.g. `docker compose up` or via conda) to see real-time ML detection predictions.")

    print("\n" + "=" * 80)
    print("Simulation completed successfully.")
    print("=" * 80)


if __name__ == "__main__":
    main()
