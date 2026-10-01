"""
Unit tests for the feature engineering module.

Tests cover individual feature functions and the main extract_features interface.
"""

import pytest
from backend.src.features import (
    extract_features,
    shannon_entropy,
    gini_index,
    vowel_consonant_ratio,
    digit_ratio,
    hex_char_ratio,
    max_consecutive_consonants,
    unique_char_ratio,
    digit_as_first_char,
    strip_tld,
    build_ngram_model,
    ngram_score,
    vowel_consonant_transition_rate,
    extract_word_features,
    decode_idn,
    sanitize_and_validate_domain,
    FEATURE_NAMES,
)


class TestDecodeIDN:
    def test_decode_idn_german(self):
        assert decode_idn("xn--mller-kva.de") == "müller.de"

    def test_decode_idn_cjk_arabic(self):
        assert decode_idn("xn--fsqu00a.xn--4gbrim") == "例子.موقع"

    def test_decode_idn_ascii_noop(self):
        assert decode_idn("google.com") == "google.com"

    def test_decode_idn_malformed_punycode_raises(self):
        with pytest.raises(ValueError, match="Invalid IDN / Punycode format"):
            decode_idn("xn--99999999999999999")


class TestStripTLD:
    def test_simple_domain(self):
        assert strip_tld("google.com") == "google"

    def test_subdomain(self):
        assert strip_tld("mail.google.com") == "google"

    def test_country_tld(self):
        assert strip_tld("bbc.co.uk") == "bbc"

    def test_bare_domain(self):
        """When no TLD is present, tldextract may put it all in domain."""
        result = strip_tld("xjkqwrtzp")
        assert result == "xjkqwrtzp"

    def test_idn_punycode_domain(self):
        """Punycode domain should decode and extract Unicode SLD."""
        assert strip_tld("xn--mller-kva.de") == "müller"


class TestShannonEntropy:
    def test_single_char(self):
        """A string of identical characters has 0 entropy."""
        assert shannon_entropy("aaaaaa") == 0.0

    def test_max_entropy(self):
        """All unique characters should have high entropy."""
        result = shannon_entropy("abcdefghij")
        assert result > 3.0  # log2(10) ≈ 3.32

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_known_value(self):
        """'ab' has exactly 1.0 bit of entropy."""
        assert shannon_entropy("ab") == 1.0


class TestGiniIndex:
    def test_uniform(self):
        """All unique chars → high Gini."""
        result = gini_index("abcdef")
        assert result > 0.8

    def test_single_char(self):
        """Identical chars → Gini = 0."""
        assert gini_index("aaaa") == 0.0

    def test_empty(self):
        assert gini_index("") == 0.0


class TestVowelConsonantRatio:
    def test_all_vowels(self):
        result = vowel_consonant_ratio("aeiou")
        assert result == 5.0  # 5 vowels / 0 consonants → returns float(5)

    def test_all_consonants(self):
        result = vowel_consonant_ratio("bcdfg")
        assert result == 0.0

    def test_mixed(self):
        result = vowel_consonant_ratio("google")
        # g, g, l → 3 consonants; o, o, e → 3 vowels → ratio = 1.0
        assert result == 1.0

    def test_empty(self):
        assert vowel_consonant_ratio("") == 0.0


class TestDigitRatio:
    def test_no_digits(self):
        assert digit_ratio("google") == 0.0

    def test_all_digits(self):
        assert digit_ratio("12345") == 1.0

    def test_mixed(self):
        result = digit_ratio("abc123")
        assert abs(result - 0.5) < 0.01


class TestHexCharRatio:
    def test_all_hex(self):
        assert hex_char_ratio("abcdef0123") == 1.0

    def test_non_hex(self):
        result = hex_char_ratio("xyz")
        assert result == 0.0

    def test_mixed(self):
        # 'a1g' → a,1 are hex (2/3), g is not
        result = hex_char_ratio("a1g")
        assert abs(result - 2 / 3) < 0.01


class TestMaxConsecutiveConsonants:
    def test_no_consonants(self):
        assert max_consecutive_consonants("aeiou") == 0

    def test_all_consonants(self):
        assert max_consecutive_consonants("bcdfg") == 5

    def test_mixed(self):
        # "strengths" → 'str' = 3, 'ngths' = 5 (n,g,t,h,s)
        assert max_consecutive_consonants("strengths") == 5

    def test_empty(self):
        assert max_consecutive_consonants("") == 0


class TestUniqueCharRatio:
    def test_all_unique(self):
        assert unique_char_ratio("abcdef") == 1.0

    def test_all_same(self):
        result = unique_char_ratio("aaaaaa")
        assert abs(result - 1 / 6) < 0.01


class TestDigitAsFirstChar:
    def test_starts_with_digit(self):
        assert digit_as_first_char("1google") == 1

    def test_starts_with_letter(self):
        assert digit_as_first_char("google") == 0

    def test_empty(self):
        assert digit_as_first_char("") == 0


class TestVowelConsonantTransitionRate:
    def test_alternating(self):
        assert vowel_consonant_transition_rate("abababab") == 1.0

    def test_clustered(self):
        assert abs(vowel_consonant_transition_rate("aaaabbbb") - 0.142857) < 1e-4

    def test_empty(self):
        assert vowel_consonant_transition_rate("") == 0.0

    def test_single_char(self):
        assert vowel_consonant_transition_rate("a") == 0.0


class TestWordFeatures:
    def test_concatenated_words(self):
        count, ratio = extract_word_features("brothernerveplacebringconsult")
        assert count >= 4
        assert ratio > 0.85

    def test_random_consonants(self):
        count, ratio = extract_word_features("vxzklpmnq")
        assert count == 0
        assert ratio == 0.0

    def test_single_real_word(self):
        count, ratio = extract_word_features("google")
        assert count == 1
        assert ratio == 1.0

    def test_empty(self):
        count, ratio = extract_word_features("")
        assert count == 0
        assert ratio == 0.0


class TestExtractFeatures:
    """Integration tests for the full extract_features function."""

    def setup_method(self):
        """Build a small n-gram model for testing."""
        benign_domains = ["google", "facebook", "amazon", "microsoft", "wikipedia"]
        self.ngram_model = build_ngram_model(benign_domains)

    def test_legitimate_domain(self):
        """Known benign domain should have low entropy and reasonable n-gram score."""
        features = extract_features("google.com", self.ngram_model)

        assert isinstance(features, dict)
        assert set(features.keys()) == set(FEATURE_NAMES)
        assert features["length"] == 6  # "google"
        assert features["entropy"] < 3.0  # relatively low
        assert features["vowel_consonant_ratio"] > 0.5  # has vowels
        assert features["digit_ratio"] == 0.0
        assert features["digit_first"] == 0

    def test_dga_like_domain(self):
        """Synthetic DGA-like domain should have high entropy and long consonant runs."""
        features = extract_features("xjkqwrtzplmn.com", self.ngram_model)

        assert features["entropy"] > 3.0  # high entropy
        assert features["max_consonant_run"] >= 5  # long consonant streak
        assert features["vowel_consonant_ratio"] < 0.3  # few vowels
        assert features["n_gram_score"] < -5.0  # unusual bigrams

    def test_hash_based_dga(self):
        """Hash-like domain should have high hex_char_ratio."""
        features = extract_features("a3f2b1c4d5e6.net", self.ngram_model)

        assert features["hex_char_ratio"] > 0.8
        assert features["digit_ratio"] > 0.3

    def test_all_features_present(self):
        """Every feature name should be present in output."""
        assert len(FEATURE_NAMES) == 13
        features = extract_features("test.com", self.ngram_model)
        assert len(features) == 13
        for name in FEATURE_NAMES:
            assert name in features, f"Missing feature: {name}"

    def test_feature_types(self):
        """All features should be numeric."""
        features = extract_features("example.org", self.ngram_model)
        for name, value in features.items():
            assert isinstance(value, (int, float)), f"{name} is not numeric: {type(value)}"

    def test_idn_feature_extraction(self):
        """Punycode domain should decode to Unicode and produce valid numeric features."""
        features = extract_features("xn--mller-kva.de", self.ngram_model)
        assert features["length"] == 6  # 'müller' has 6 characters
        for name in FEATURE_NAMES:
            assert name in features
            assert isinstance(features[name], (int, float))


class TestNgramModel:
    def test_build_model(self):
        model = build_ngram_model(["google", "facebook", "amazon"])
        assert "ngram_counts" in model
        assert "total" in model
        assert model["total"] > 0

    def test_score_known_domain(self):
        model = build_ngram_model(["google", "facebook", "amazon"])
        # 'google' bigrams should score well since it's in the training set
        score = ngram_score("google", model)
        assert score > -10.0

    def test_score_random_domain(self):
        model = build_ngram_model(["google", "facebook", "amazon"])
        score = ngram_score("xzqjkw", model)
        # Random should score worse than a known domain
        known_score = ngram_score("google", model)
        assert score < known_score
