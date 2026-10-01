"""
API endpoint tests using FastAPI's TestClient.

These tests mock the model artifacts to avoid requiring trained models
for CI/testing purposes.
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend.src.features import FEATURE_NAMES


# Mock the model artifacts before importing the app
@pytest.fixture(autouse=True)
def mock_model_artifacts():
    """Mock model artifacts so tests don't need actual trained models."""
    # Create a mock model that returns predictions
    mock_model = MagicMock()
    mock_model.predict.side_effect = lambda X: np.ones(len(X), dtype=int)
    mock_model.predict_proba.side_effect = lambda X: np.tile([0.15, 0.85], (len(X), 1))

    # Create a mock scaler
    mock_scaler = MagicMock()
    mock_scaler.transform.side_effect = lambda X: np.zeros((len(X), len(FEATURE_NAMES)))

    # Create mock model info
    mock_info = {
        "model_type": "xgboost",
        "metrics": {
            "accuracy": 0.95,
            "precision": 0.94,
            "recall": 0.96,
            "f1_score": 0.95,
            "roc_auc": 0.98,
            "train_time_seconds": 12.5,
        },
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "train_size": 47250,
        "val_size": 10125,
        "test_size": 10125,
        "thresholds": {
            "threshold_suspicious": 0.35,
            "threshold_malicious": 0.75,
        },
    }

    # Mock ngram model
    mock_ngram = {
        "ngram_counts": {"go": 10, "oo": 8, "og": 5, "gl": 3, "le": 7},
        "total": 100,
        "n": 2,
        "vocab_size": 5,
    }

    # Mock family model & encoder
    mock_family_model = MagicMock()
    mock_family_model.predict_proba.side_effect = lambda X: np.tile([0.85, 0.15], (len(X), 1))
    mock_family_encoder = MagicMock()
    mock_family_encoder.inverse_transform.side_effect = lambda indices: np.array(["emotet" if i == 0 else "conficker" for i in indices])

    # Mock booster and explainer for TreeSHAP
    mock_booster = MagicMock()
    # 13 features: positive and negative impacts, plus bias term (14 values total)
    sample_contribs = np.array([
        0.45,   # length
        0.35,   # entropy
        -0.10,  # vowel_consonant_ratio
        0.05,   # digit_ratio
        0.20,   # hex_char_ratio
        -0.05,  # gini_index
        0.15,   # max_consonant_run
        -0.02,  # digit_first
        -0.30,  # n_gram_score
        0.08,   # unique_char_ratio
        0.02,   # segmented_word_count
        -0.15,  # valid_word_ratio
        0.01,   # vowel_consonant_transition_rate
        0.50,   # bias margin
    ])
    mock_booster.predict.side_effect = lambda dmat, pred_contribs=False: np.tile(
        sample_contribs,
        (dmat.num_row(), 1),
    )
    mock_model.get_booster.return_value = mock_booster

    mock_explainer = MagicMock()
    mock_explainer.shap_values.side_effect = lambda X: np.tile(
        sample_contribs[:-1],
        (len(X), 1),
    )

    from backend.src.api.drift_detector import FeatureDriftDetector
    mock_baseline = np.random.RandomState(42).normal(loc=10.0, scale=2.0, size=(200, len(FEATURE_NAMES)))
    mock_detector = FeatureDriftDetector(mock_baseline, feature_names=FEATURE_NAMES, min_samples=50)

    with patch("backend.src.api.main._model", mock_model), \
         patch("backend.src.api.main._scaler", mock_scaler), \
         patch("backend.src.api.main._model_info", mock_info), \
         patch("backend.src.api.main._ngram_model", mock_ngram), \
         patch("backend.src.api.main._family_model", mock_family_model), \
         patch("backend.src.api.main._family_encoder", mock_family_encoder), \
         patch("backend.src.api.main._explainer", mock_explainer), \
         patch("backend.src.api.main._drift_detector", mock_detector):
        yield


@pytest.fixture
def client():
    """Create a test client with mocked lifespan."""
    from backend.src.api import main as main_module
    from backend.src.api.main import app, _prediction_cache

    # Override the lifespan to avoid loading real model files
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def mock_lifespan(app):
        yield

    app.router.lifespan_context = mock_lifespan
    app.state.limiter.enabled = False
    _prediction_cache.clear()
    if getattr(main_module, "_drift_detector", None) is not None:
        main_module._drift_detector.clear()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_schema(self, client):
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
        assert "model_loaded" in data
        assert "cache" in data
        assert "hits" in data["cache"]


class TestModelInfoEndpoint:
    def test_model_info_returns_200(self, client):
        response = client.get("/model-info")
        assert response.status_code == 200

    def test_model_info_has_expected_fields(self, client):
        response = client.get("/model-info")
        data = response.json()
        assert "model_type" in data
        assert "metrics" in data
        assert "n_features" in data
        assert "feature_names" in data
        assert data["n_features"] == len(FEATURE_NAMES)

    def test_model_info_metrics(self, client):
        response = client.get("/model-info")
        metrics = response.json()["metrics"]
        assert "f1_score" in metrics
        assert "accuracy" in metrics
        assert "roc_auc" in metrics


class TestPredictEndpoint:
    def test_predict_single_domain(self, client):
        response = client.post("/predict", json={"domain": "google.com"})
        assert response.status_code == 200

    def test_predict_response_schema(self, client):
        response = client.post("/predict", json={"domain": "google.com"})
        data = response.json()
        assert "prediction" in data
        pred = data["prediction"]
        assert "domain" in pred
        assert "label" in pred
        assert "confidence" in pred
        assert "risk_tier" in pred
        assert "action" in pred
        assert "malicious_probability" in pred
        assert pred["risk_tier"] in ("safe", "suspicious", "malicious")
        assert pred["action"] in ("allow", "monitor", "block")
        assert pred["label"] in ("legitimate", "suspicious", "malicious")
        assert 0.0 <= pred["confidence"] <= 1.0
        assert 0.0 <= pred["malicious_probability"] <= 1.0
        assert "family" in pred
        assert "family_confidence" in pred

    def test_three_tier_confidence_bands(self, client):
        """Verify operating point threshold calibration across safe, suspicious, and malicious tiers."""
        # 1. Low malicious probability (0.10) -> safe / allow / legitimate
        with patch("backend.src.api.main._model") as mock_m:
            mock_m.predict_proba.side_effect = lambda X: np.tile([0.90, 0.10], (len(X), 1))
            resp = client.post("/predict", json={"domain": "safe-domain.com"})
            assert resp.status_code == 200
            pred = resp.json()["prediction"]
            assert pred["risk_tier"] == "safe"
            assert pred["action"] == "allow"
            assert pred["label"] == "legitimate"
            assert pred["malicious_probability"] == 0.10
            assert pred["confidence"] == 0.90
            assert pred["family"] == "legitimate"
            assert pred["family_confidence"] is None

        # 2. Medium malicious probability (0.55) -> suspicious / monitor / suspicious + family attribution
        with patch("backend.src.api.main._model") as mock_m:
            mock_m.predict_proba.side_effect = lambda X: np.tile([0.45, 0.55], (len(X), 1))
            resp = client.post("/predict", json={"domain": "borderline-dga.org"})
            assert resp.status_code == 200
            pred = resp.json()["prediction"]
            assert pred["risk_tier"] == "suspicious"
            assert pred["action"] == "monitor"
            assert pred["label"] == "suspicious"
            assert pred["malicious_probability"] == 0.55
            assert pred["confidence"] == 0.55
            assert pred["family"] == "emotet"
            assert pred["family_confidence"] == 0.85

        # 3. High malicious probability (0.90) -> malicious / block / malicious + family attribution
        with patch("backend.src.api.main._model") as mock_m:
            mock_m.predict_proba.side_effect = lambda X: np.tile([0.10, 0.90], (len(X), 1))
            resp = client.post("/predict", json={"domain": "high-confidence-dga.biz"})
            assert resp.status_code == 200
            pred = resp.json()["prediction"]
            assert pred["risk_tier"] == "malicious"
            assert pred["action"] == "block"
            assert pred["label"] == "malicious"
            assert pred["malicious_probability"] == 0.90
            assert pred["confidence"] == 0.90
            assert pred["family"] == "emotet"
            assert pred["family_confidence"] == 0.85

    def test_predict_malicious_has_family_attribution(self, client):
        """Malicious domains must have attributed DGA family and family_confidence."""
        response = client.post("/predict", json={"domain": "xjkqwrtzp.info"})
        assert response.status_code == 200
        pred = response.json()["prediction"]
        assert pred["label"] == "malicious"
        assert pred["risk_tier"] == "malicious"
        assert pred["action"] == "block"
        assert pred["family"] == "emotet"
        assert pred["family_confidence"] == 0.85

    def test_predict_legitimate_has_legitimate_family(self, client):
        """Legitimate domains must have family='legitimate' and family_confidence=None."""
        with patch("backend.src.api.main._model") as mock_m:
            mock_m.predict_proba.side_effect = lambda X: np.tile([0.95, 0.05], (len(X), 1))
            response = client.post("/predict", json={"domain": "google.com"})
            assert response.status_code == 200
            pred = response.json()["prediction"]
            assert pred["label"] == "legitimate"
            assert pred["risk_tier"] == "safe"
            assert pred["action"] == "allow"
            assert pred["family"] == "legitimate"
            assert pred["family_confidence"] is None

    def test_graceful_degradation_without_family_model(self, client):
        """If family model is None, malicious predictions still succeed with family=None."""
        with patch("backend.src.api.main._family_model", None):
            response = client.post("/predict", json={"domain": "xjkqwrtzp.info"})
            assert response.status_code == 200
            pred = response.json()["prediction"]
            assert pred["label"] == "malicious"
            assert pred["risk_tier"] == "malicious"
            assert pred["action"] == "block"
            assert pred["family"] is None
            assert pred["family_confidence"] is None

    def test_predict_returns_features(self, client):
        response = client.post("/predict", json={"domain": "example.com"})
        features = response.json()["prediction"]["features"]
        for feat in FEATURE_NAMES:
            assert feat in features, f"Missing feature: {feat}"

    def test_predict_empty_domain_fails(self, client):
        response = client.post("/predict", json={"domain": ""})
        assert response.status_code == 422

    def test_predict_domain_with_spaces_fails(self, client):
        response = client.post("/predict", json={"domain": "goo gle.com"})
        assert response.status_code == 422

    def test_predict_missing_domain_fails(self, client):
        response = client.post("/predict", json={})
        assert response.status_code == 422


class TestBatchPredictEndpoint:
    def test_batch_predict(self, client):
        response = client.post(
            "/predict/batch",
            json={"domains": ["google.com", "xjkqwrtzp.info"]},
        )
        assert response.status_code == 200

    def test_batch_predict_response_schema(self, client):
        response = client.post(
            "/predict/batch",
            json={"domains": ["google.com", "facebook.com"]},
        )
        data = response.json()
        assert "predictions" in data
        assert "total" in data
        assert data["total"] == 2
        assert len(data["predictions"]) == 2
        pred = data["predictions"][0]
        assert "risk_tier" in pred
        assert "action" in pred
        assert "malicious_probability" in pred
        assert pred["risk_tier"] in ("safe", "suspicious", "malicious")
        assert pred["action"] in ("allow", "monitor", "block")

    def test_batch_predict_empty_list_fails(self, client):
        response = client.post("/predict/batch", json={"domains": []})
        assert response.status_code == 422

    def test_batch_predict_matches_single_predictions(self, client):
        """Verify predict_batch produces identical predictions to sequential single predictions."""
        domains = ["google.com", "xjkqwrtzp.info", "facebook.com", "somelongdganame12345.biz"]

        # Run batch prediction
        batch_resp = client.post("/predict/batch", json={"domains": domains})
        assert batch_resp.status_code == 200
        batch_preds = batch_resp.json()["predictions"]

        # Run sequential single predictions
        single_preds = []
        for d in domains:
            single_resp = client.post("/predict", json={"domain": d})
            assert single_resp.status_code == 200
            single_preds.append(single_resp.json()["prediction"])

        assert len(batch_preds) == len(single_preds) == len(domains)
        for b_pred, s_pred in zip(batch_preds, single_preds):
            assert b_pred["domain"] == s_pred["domain"]
            assert b_pred["label"] == s_pred["label"]
            assert b_pred["risk_tier"] == s_pred["risk_tier"]
            assert b_pred["action"] == s_pred["action"]
            assert b_pred["malicious_probability"] == s_pred["malicious_probability"]
            assert b_pred["confidence"] == s_pred["confidence"]
            assert b_pred["family"] == s_pred["family"]
            assert b_pred["family_confidence"] == s_pred["family_confidence"]
            assert b_pred["features"] == s_pred["features"]

    def test_batch_predict_family_attribution(self, client):
        """Verify batch prediction attributes families to malicious domains and marks benign as legitimate."""
        # Custom mock: 1st domain is legitimate, 2nd domain is malicious
        def mock_predict(X):
            preds = np.zeros(len(X), dtype=int)
            if len(X) > 1:
                preds[1] = 1  # 2nd is malicious
            return preds

        def mock_predict_proba(X):
            probs = np.tile([0.9, 0.1], (len(X), 1))
            if len(X) > 1:
                probs[1] = [0.1, 0.9]
            return probs

        with patch("backend.src.api.main._model") as mock_m:
            mock_m.predict.side_effect = mock_predict
            mock_m.predict_proba.side_effect = mock_predict_proba

            response = client.post("/predict/batch", json={"domains": ["benign.com", "malicious-dga.org"]})
            assert response.status_code == 200
            preds = response.json()["predictions"]
            assert preds[0]["label"] == "legitimate"
            assert preds[0]["risk_tier"] == "safe"
            assert preds[0]["action"] == "allow"
            assert preds[0]["family"] == "legitimate"
            assert preds[0]["family_confidence"] is None

            assert preds[1]["label"] == "malicious"
            assert preds[1]["risk_tier"] == "malicious"
            assert preds[1]["action"] == "block"
            assert preds[1]["family"] == "emotet"
            assert preds[1]["family_confidence"] == 0.85

    def test_batch_predict_performance_100_domains(self, client):
        """Verify batch endpoint functions cleanly for a full batch of 100 domains."""
        domains = [f"domain{i:03d}-test.com" for i in range(100)]
        response = client.post("/predict/batch", json={"domains": domains})
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 100
        assert len(data["predictions"]) == 100
        for i, pred in enumerate(data["predictions"]):
            assert pred["domain"] == domains[i]
            assert pred["label"] in ("legitimate", "suspicious", "malicious")
            assert pred["risk_tier"] in ("safe", "suspicious", "malicious")
            assert pred["action"] in ("allow", "monitor", "block")
            assert 0.0 <= pred["malicious_probability"] <= 1.0
            assert 0.0 <= pred["confidence"] <= 1.0
            assert "length" in pred["features"]


class TestOpenAPIDocs:
    def test_docs_accessible(self, client):
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_schema(self, client):
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "paths" in schema
        assert "/predict" in schema["paths"]
        assert "/health" in schema["paths"]
        assert "/model-info" in schema["paths"]
        assert "/cache-stats" in schema["paths"]


class TestHostnameSanitization:
    """Unit and endpoint tests for RFC-compliant DNS sanitization and IDN normalization."""

    def test_validate_hostname_valid_cases(self):
        from backend.src.api.main import validate_hostname

        assert validate_hostname("google.com") == "google.com"
        assert validate_hostname("google.com.") == "google.com"
        assert validate_hostname("a.b.c.example.com") == "a.b.c.example.com"
        assert validate_hostname("mail.google.co.uk") == "mail.google.co.uk"
        assert validate_hostname("xn--mller-kva.de") == "müller.de"
        assert validate_hostname("xn--fsqu00a.xn--4gbrim") == "例子.موقع"
        assert validate_hostname("xn--google-pra.com") == "g×oogle.com"

    def test_validate_hostname_rejections(self):
        from backend.src.api.main import validate_hostname

        # Label length > 63
        with pytest.raises(ValueError, match="exceeds maximum allowed length of 63"):
            validate_hostname("a" * 64 + ".com")

        # Total length > 253
        with pytest.raises(ValueError, match="exceeds maximum allowed length of 253"):
            validate_hostname("a." * 130 + "com")

        # Whitespace / control chars
        with pytest.raises(ValueError, match="whitespace or control characters"):
            validate_hostname("foo bar.com")
        with pytest.raises(ValueError, match="whitespace or control characters"):
            validate_hostname("foo\tbar.com")

        # Invalid characters
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("bad_domain.com")
        with pytest.raises(ValueError, match="invalid characters"):
            validate_hostname("foo@bar.com")

        # Hyphen boundaries
        with pytest.raises(ValueError, match="cannot start or end with a hyphen"):
            validate_hostname("-bad.com")
        with pytest.raises(ValueError, match="cannot start or end with a hyphen"):
            validate_hostname("bad-.com")

        # Consecutive dots
        with pytest.raises(ValueError, match="empty labels"):
            validate_hostname("foo..bar.com")

        # All-numeric TLD
        with pytest.raises(ValueError, match="cannot be all-numeric"):
            validate_hostname("example.123")

        # Malformed Punycode
        with pytest.raises(ValueError, match="Invalid IDN / Punycode format"):
            validate_hostname("xn--99999999999999999")

    def test_predict_endpoint_rfc_validation(self, client):
        # Trailing dot allowed and normalized
        resp = client.post("/predict", json={"domain": "google.com."})
        assert resp.status_code == 200
        assert resp.json()["prediction"]["domain"] == "google.com"

        # Punycode allowed and decoded
        resp = client.post("/predict", json={"domain": "xn--mller-kva.de"})
        assert resp.status_code == 200
        assert resp.json()["prediction"]["domain"] == "müller.de"

        # RFC violations return 422
        assert client.post("/predict", json={"domain": "bad_domain.com"}).status_code == 422
        assert client.post("/predict", json={"domain": "example.123"}).status_code == 422
        assert client.post("/predict", json={"domain": "foo..bar.com"}).status_code == 422
        assert client.post("/predict", json={"domain": "-bad.com"}).status_code == 422
        assert client.post("/predict", json={"domain": "xn--99999999999999999"}).status_code == 422

    def test_batch_predict_rfc_validation(self, client):
        # Mixed batch with 1 invalid domain fails entirely with 422
        resp = client.post(
            "/predict/batch",
            json={"domains": ["google.com", "bad_domain.com", "facebook.com"]},
        )
        assert resp.status_code == 422

        # Valid batch with Punycode and trailing dots succeeds with 200
        resp = client.post(
            "/predict/batch",
            json={"domains": ["google.com.", "xn--mller-kva.de"]},
        )
        assert resp.status_code == 200
        preds = resp.json()["predictions"]
        assert preds[0]["domain"] == "google.com"
        assert preds[1]["domain"] == "müller.de"


class TestRateLimitingAndCORS:
    """Tests for endpoint throttling (HTTP 429), client IP extraction, and strict CORS configuration."""

    def test_cors_preflight_configuration(self, client):
        """Verify strict allowed methods and headers on CORS preflight."""
        resp = client.options(
            "/predict",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            },
        )
        assert resp.status_code == 200
        allow_methods = resp.headers.get("access-control-allow-methods", "")
        for method in ["GET", "POST", "OPTIONS"]:
            assert method in allow_methods

        allow_headers = resp.headers.get("access-control-allow-headers", "").lower()
        for header in ["content-type", "authorization", "accept", "x-requested-with"]:
            assert header in allow_headers

    def test_cors_origin_restriction(self, client):
        """Verify unregistered origins do not receive allow-origin access."""
        resp = client.post(
            "/predict",
            json={"domain": "example.com"},
            headers={"Origin": "http://unauthorized-attacker.com"},
        )
        assert resp.headers.get("access-control-allow-origin") != "http://unauthorized-attacker.com"

    def test_rate_limiting_single_predict(self, client):
        """Verify 60/minute rate limit enforcement and Retry-After header on /predict."""
        from backend.src.api.main import app

        try:
            app.state.limiter.enabled = True
            client_headers = {"X-Forwarded-For": "198.51.100.10"}

            # Send 60 requests (allowed)
            for _ in range(60):
                res = client.post("/predict", json={"domain": "example.com"}, headers=client_headers)
                assert res.status_code == 200

            # 61st request should be throttled
            throttled_res = client.post("/predict", json={"domain": "example.com"}, headers=client_headers)
            assert throttled_res.status_code == 429
            assert "Retry-After" in throttled_res.headers
            body = throttled_res.json()
            assert "Rate limit exceeded" in body.get("error", "") or "Rate limit exceeded" in body.get("detail", "")
        finally:
            app.state.limiter.enabled = False

    def test_rate_limiting_batch_predict(self, client):
        """Verify 15/minute rate limit enforcement on /predict/batch."""
        from backend.src.api.main import app

        try:
            app.state.limiter.enabled = True
            client_headers = {"X-Forwarded-For": "198.51.100.20"}

            # Send 15 batch requests (allowed)
            for _ in range(15):
                res = client.post("/predict/batch", json={"domains": ["example.com"]}, headers=client_headers)
                assert res.status_code == 200

            # 16th request should be throttled
            throttled_res = client.post("/predict/batch", json={"domains": ["example.com"]}, headers=client_headers)
            assert throttled_res.status_code == 429
            assert "Retry-After" in throttled_res.headers
        finally:
            app.state.limiter.enabled = False

    def test_rate_limiting_proxy_ip_isolation(self, client):
        """Verify rate limits are isolated per client IP via X-Forwarded-For."""
        from backend.src.api.main import app

        try:
            app.state.limiter.enabled = True
            ip_a_headers = {"X-Forwarded-For": "198.51.100.31, 10.0.0.1"}
            ip_b_headers = {"X-Forwarded-For": "198.51.100.32, 10.0.0.1"}

            # Exhaust IP A quota for batch (15)
            for _ in range(15):
                res = client.post("/predict/batch", json={"domains": ["example.com"]}, headers=ip_a_headers)
                assert res.status_code == 200

            # IP A is throttled
            assert client.post("/predict/batch", json={"domains": ["example.com"]}, headers=ip_a_headers).status_code == 429

            # IP B still has fresh quota and succeeds
            res_b = client.post("/predict/batch", json={"domains": ["example.com"]}, headers=ip_b_headers)
            assert res_b.status_code == 200
        finally:
            app.state.limiter.enabled = False


class TestPredictionCache:
    """Tests for in-memory LRU prediction cache, batch partitioning, and observability metrics."""

    def test_cache_single_prediction_hit(self, client):
        """Verify first call records a miss and second call records a hit returning identical result."""
        # 1. First call -> cache miss
        resp1 = client.post("/predict", json={"domain": "google.com"})
        assert resp1.status_code == 200
        pred1 = resp1.json()["prediction"]

        stats1 = client.get("/cache-stats").json()
        assert stats1["hits"] == 0
        assert stats1["misses"] == 1
        assert stats1["size"] == 1

        # 2. Second call -> cache hit
        resp2 = client.post("/predict", json={"domain": "google.com"})
        assert resp2.status_code == 200
        pred2 = resp2.json()["prediction"]

        stats2 = client.get("/cache-stats").json()
        assert stats2["hits"] == 1
        assert stats2["misses"] == 1
        assert stats2["hit_ratio"] == 0.5
        assert pred1 == pred2

    def test_cache_batch_partitioning(self, client):
        """Verify batch prediction partitions domains into hits and misses while preserving order."""
        batch_1 = ["alpha.com", "bravo.com", "charlie.com", "delta.com"]
        resp1 = client.post("/predict/batch", json={"domains": batch_1})
        assert resp1.status_code == 200
        preds1 = resp1.json()["predictions"]
        assert [p["domain"] for p in preds1] == batch_1

        stats1 = client.get("/cache-stats").json()
        assert stats1["hits"] == 0
        assert stats1["misses"] == 4

        # Second batch with 2 overlapping domains and 2 new domains
        batch_2 = ["bravo.com", "echo.com", "delta.com", "foxtrot.com"]
        resp2 = client.post("/predict/batch", json={"domains": batch_2})
        assert resp2.status_code == 200
        preds2 = resp2.json()["predictions"]
        assert [p["domain"] for p in preds2] == batch_2

        # Verify cached overlapping predictions match previous predictions exactly
        assert preds2[0] == preds1[1]  # bravo.com
        assert preds2[2] == preds1[3]  # delta.com

        stats2 = client.get("/cache-stats").json()
        assert stats2["hits"] == 2
        assert stats2["misses"] == 6  # 4 + 2 new misses
        assert stats2["size"] == 6

    def test_cache_lru_eviction(self):
        """Verify bounded capacity and LRU eviction policy."""
        from backend.src.api.cache import PredictionCache

        cache = PredictionCache(max_size=2, enabled=True)
        cache.set("domain1.com", {"result": 1})
        cache.set("domain2.com", {"result": 2})
        assert cache.stats()["size"] == 2
        assert cache.stats()["evictions"] == 0

        # Access domain1 to make domain2 the least recently used
        assert cache.get("domain1.com") == {"result": 1}

        # Add domain3 -> triggers eviction of domain2
        cache.set("domain3.com", {"result": 3})
        assert cache.stats()["size"] == 2
        assert cache.stats()["evictions"] == 1
        assert cache.get("domain2.com") is None
        assert cache.get("domain1.com") == {"result": 1}
        assert cache.get("domain3.com") == {"result": 3}

    def test_cache_disabled_mode(self, client):
        """Verify cache bypass when disabled."""
        from backend.src.api.main import _prediction_cache

        try:
            _prediction_cache.enabled = False
            client.post("/predict", json={"domain": "disabled-test.com"})
            client.post("/predict", json={"domain": "disabled-test.com"})

            stats = client.get("/cache-stats").json()
            assert stats["enabled"] is False
            assert stats["hits"] == 0
            assert stats["misses"] == 0
            assert stats["size"] == 0
        finally:
            _prediction_cache.enabled = True

    def test_cache_stats_endpoint(self, client):
        """Verify /cache-stats returns expected keys and metrics."""
        resp = client.get("/cache-stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert "enabled" in stats
        assert "size" in stats
        assert "max_size" in stats
        assert "hits" in stats
        assert "misses" in stats
        assert "evictions" in stats
        assert "hit_ratio" in stats
        assert isinstance(stats["hit_ratio"], float)


class TestPredictionExplainability:
    """Test suite for TreeSHAP feature attributions and risk factors."""

    def test_prediction_contains_shap_explanations(self, client):
        """Verify single prediction returns all 13 feature contributions and top risk factors."""
        response = client.post("/predict", json={"domain": "vxzklpmnq123.biz"})
        assert response.status_code == 200
        pred = response.json()["prediction"]

        assert "feature_contributions" in pred
        contribs = pred["feature_contributions"]
        assert contribs is not None
        assert len(contribs) == 13
        assert "length" in contribs
        assert "entropy" in contribs
        assert "valid_word_ratio" in contribs

        assert "top_risk_factors" in pred
        top_risks = pred["top_risk_factors"]
        assert top_risks is not None
        assert 1 <= len(top_risks) <= 3
        first_risk = top_risks[0]
        assert "feature" in first_risk
        assert "display_name" in first_risk
        assert "value" in first_risk
        assert "impact" in first_risk
        assert first_risk["impact"] > 0

    def test_top_risk_factors_ordering(self, client):
        """Verify top_risk_factors are strictly ordered descending by positive impact."""
        response = client.post("/predict", json={"domain": "malicious-test-risk.org"})
        assert response.status_code == 200
        top_risks = response.json()["prediction"]["top_risk_factors"]

        assert len(top_risks) <= 3
        impacts = [item["impact"] for item in top_risks]
        assert all(imp > 0 for imp in impacts)
        assert impacts == sorted(impacts, reverse=True)

        # Check display name is human-readable
        for item in top_risks:
            assert item["display_name"] != item["feature"]
            assert len(item["display_name"]) > 0

    def test_batch_prediction_shap_alignment(self, client):
        """Verify batch prediction computes and aligns SHAP contributions for every domain."""
        domains = ["test-batch-a.com", "test-batch-b.net", "test-batch-c.org"]
        response = client.post("/predict/batch", json={"domains": domains})
        assert response.status_code == 200
        data = response.json()

        assert len(data["predictions"]) == 3
        for pred in data["predictions"]:
            assert pred["feature_contributions"] is not None
            assert len(pred["feature_contributions"]) == 13
            assert pred["top_risk_factors"] is not None
            assert len(pred["top_risk_factors"]) <= 3

    def test_cache_preserves_shap_explanations(self, client):
        """Verify cached predictions retain identical SHAP contributions and top risk factors."""
        domain = "cached-explainability-test.com"
        resp1 = client.post("/predict", json={"domain": domain})
        assert resp1.status_code == 200
        pred1 = resp1.json()["prediction"]

        # Second request hits cache
        resp2 = client.post("/predict", json={"domain": domain})
        assert resp2.status_code == 200
        pred2 = resp2.json()["prediction"]

        assert pred1["feature_contributions"] == pred2["feature_contributions"]
        assert pred1["top_risk_factors"] == pred2["top_risk_factors"]

    def test_explainability_graceful_fallback(self, client):
        """Verify graceful fallback with None explanations when explainability is disabled."""
        from unittest.mock import patch
        import os

        with patch.dict(os.environ, {"EXPLAINABILITY_ENABLED": "false"}):
            resp = client.post("/predict", json={"domain": "disabled-shap-domain.com"})
            assert resp.status_code == 200
            pred = resp.json()["prediction"]
            assert pred["feature_contributions"] is None
            assert pred["top_risk_factors"] is None


class TestDnsEnrichment:
    """Tests for live external DNS resolution and threat status enrichment."""

    def test_predict_single_dns_disabled_by_default(self, client):
        """Verify resolve_dns is false by default and returns no dns_enrichment."""
        response = client.post("/predict", json={"domain": "example-default.com"})
        assert response.status_code == 200
        pred = response.json()["prediction"]
        assert pred["dns_enrichment"] is None

    def test_predict_single_dns_active(self, client):
        """Verify resolve_dns=true returns active DNS operational telemetry."""
        mock_dns = {
            "resolved": True,
            "operational_status": "active",
            "ip_addresses": ["93.184.216.34", "93.184.216.35"],
            "name_servers": ["a.iana-servers.net", "b.iana-servers.net"],
            "mail_servers": ["mail.example.com"],
            "dnssec_validated": False,
            "response_time_ms": 14.2,
        }

        with patch("backend.src.api.main.resolve_domain_dns", return_value=mock_dns) as mock_resolve:
            response = client.post(
                "/predict?resolve_dns=true",
                json={"domain": "example-active.com"},
            )
            assert response.status_code == 200
            mock_resolve.assert_called_once_with("example-active.com", timeout=2.0)
            pred = response.json()["prediction"]
            assert pred["dns_enrichment"] is not None
            dns_res = pred["dns_enrichment"]
            assert dns_res["resolved"] is True
            assert dns_res["operational_status"] == "active"
            assert dns_res["ip_addresses"] == ["93.184.216.34", "93.184.216.35"]
            assert dns_res["name_servers"] == ["a.iana-servers.net", "b.iana-servers.net"]
            assert "93.184.216.34" in dns_res["threat_summary"]

    def test_predict_single_dns_nxdomain(self, client):
        """Verify NXDOMAIN status correctly informs dormant candidate rendezvous point."""
        mock_dns = {
            "resolved": False,
            "operational_status": "nxdomain",
            "ip_addresses": [],
            "name_servers": [],
            "mail_servers": [],
            "dnssec_validated": False,
            "response_time_ms": 9.5,
        }

        with patch("backend.src.api.main.resolve_domain_dns", return_value=mock_dns):
            response = client.post(
                "/predict?resolve_dns=true",
                json={"domain": "dormant-candidate.biz"},
            )
            assert response.status_code == 200
            pred = response.json()["prediction"]
            assert pred["dns_enrichment"] is not None
            dns_res = pred["dns_enrichment"]
            assert dns_res["resolved"] is False
            assert dns_res["operational_status"] == "nxdomain"
            assert "NXDOMAIN" in dns_res["threat_summary"]

    def test_predict_single_dns_timeout_graceful_degradation(self, client):
        """Verify upstream DNS timeout degrades gracefully without failing ML classification."""
        mock_dns = {
            "resolved": False,
            "operational_status": "timeout",
            "ip_addresses": [],
            "name_servers": [],
            "mail_servers": [],
            "dnssec_validated": False,
            "response_time_ms": 2001.0,
        }

        with patch("backend.src.api.main.resolve_domain_dns", return_value=mock_dns):
            response = client.post(
                "/predict?resolve_dns=true",
                json={"domain": "timeout-domain.net"},
            )
            assert response.status_code == 200
            pred = response.json()["prediction"]
            assert pred["dns_enrichment"] is not None
            dns_res = pred["dns_enrichment"]
            assert dns_res["operational_status"] == "timeout"
            assert dns_res["resolved"] is False
            assert "Timeout" in dns_res["threat_summary"]

    def test_predict_batch_dns_enrichment(self, client):
        """Verify batch resolution resolves multiple domains concurrently."""
        mock_dns_active = {
            "resolved": True,
            "operational_status": "active",
            "ip_addresses": ["1.2.3.4"],
            "name_servers": [],
            "mail_servers": [],
            "dnssec_validated": False,
            "response_time_ms": 11.0,
        }

        with patch("backend.src.api.main.resolve_domain_dns", return_value=mock_dns_active) as mock_resolve:
            domains = ["batch-dns-1.com", "batch-dns-2.com", "batch-dns-3.com"]
            response = client.post(
                "/predict/batch?resolve_dns=true",
                json={"domains": domains},
            )
            assert response.status_code == 200
            assert mock_resolve.call_count == 3
            data = response.json()
            assert len(data["predictions"]) == 3
            for pred in data["predictions"]:
                assert pred["dns_enrichment"] is not None
                assert pred["dns_enrichment"]["operational_status"] == "active"
                assert pred["dns_enrichment"]["ip_addresses"] == ["1.2.3.4"]

    def test_compute_threat_summary_logic(self):
        """Unit test threat summary message formulation across combinations."""
        from backend.src.api.dns_resolver import compute_threat_summary

        # Malicious + active
        s1 = compute_threat_summary("malicious", "active", ["192.168.1.1"])
        assert "Active C2 Server" in s1
        assert "Immediate Network Block" in s1

        # Suspicious + active
        s2 = compute_threat_summary("suspicious", "active", ["10.0.0.1"])
        assert "Active Suspicious Host" in s2
        assert "Endpoint Monitoring" in s2

        # Safe + active
        s3 = compute_threat_summary("safe", "active", ["142.250.190.46"])
        assert "Legitimate Active Domain" in s3

        # Malicious + nxdomain
        s4 = compute_threat_summary("malicious", "nxdomain", [])
        assert "Dormant DGA" in s4
        assert "NXDOMAIN" in s4

        # Timeout
        s5 = compute_threat_summary("malicious", "timeout", [])
        assert "Resolution Timeout" in s5


class TestDriftDetection:
    """Test suite for continuous statistical feature drift detection."""

    def test_drift_detector_class_insufficient_samples(self):
        from backend.src.api.drift_detector import FeatureDriftDetector
        baseline = np.random.RandomState(42).normal(10.0, 2.0, size=(100, 13))
        detector = FeatureDriftDetector(baseline, min_samples=50)

        report = detector.compute_drift()
        assert report["status"] == "insufficient_data"
        assert report["current_samples"] == 0
        assert report["min_samples_required"] == 50
        assert report["drift_detected"] is False
        assert report["recommended_action"] == "healthy"

    def test_drift_detector_class_healthy_baseline(self):
        from backend.src.api.drift_detector import FeatureDriftDetector
        rng = np.random.RandomState(42)
        baseline = rng.normal(10.0, 2.0, size=(200, 13))
        detector = FeatureDriftDetector(baseline, min_samples=50)

        # Ingest 100 samples drawn from the same distribution
        curr_samples = rng.normal(10.0, 2.0, size=(100, 13))
        detector.record_batch(curr_samples)

        assert detector.get_sample_count() == 100
        report = detector.compute_drift()
        assert report["status"] == "evaluated"
        assert report["current_samples"] == 100
        assert report["drift_detected"] is False
        assert report["recommended_action"] == "healthy"
        assert report["drift_score"] < 0.30

    def test_drift_detector_class_drift_detected(self):
        from backend.src.api.drift_detector import FeatureDriftDetector
        rng = np.random.RandomState(42)
        baseline = rng.normal(10.0, 2.0, size=(200, 13))
        detector = FeatureDriftDetector(baseline, min_samples=50)

        # Ingest 100 samples from a heavily shifted distribution across all features
        shifted_samples = rng.normal(50.0, 5.0, size=(100, 13))
        detector.record_batch(shifted_samples)

        report = detector.compute_drift()
        assert report["status"] == "evaluated"
        assert report["drift_detected"] is True
        assert report["drift_score"] >= 0.40
        assert report["recommended_action"] == "retrain_recommended"
        assert len(report["drifted_features"]) > 0

    def test_drift_report_endpoint_insufficient(self, client):
        response = client.get("/drift-report")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "insufficient_data"
        assert data["current_samples"] == 0

    def test_drift_report_endpoint_healthy_traffic(self, client):
        from backend.src.api import main as main_module
        rng = np.random.RandomState(123)
        healthy_samples = rng.normal(10.0, 2.0, size=(100, len(FEATURE_NAMES)))
        main_module._drift_detector.record_batch(healthy_samples)

        response = client.get("/drift-report")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "evaluated"
        assert data["current_samples"] == 100
        assert data["drift_detected"] is False
        assert data["recommended_action"] == "healthy"

    def test_drift_report_endpoint_drifted_traffic(self, client):
        from backend.src.api import main as main_module
        rng = np.random.RandomState(999)
        drifted_samples = rng.normal(100.0, 1.0, size=(100, len(FEATURE_NAMES)))
        main_module._drift_detector.record_batch(drifted_samples)

        response = client.get("/drift-report")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "evaluated"
        assert data["drift_detected"] is True
        assert data["recommended_action"] in ("investigate", "retrain_recommended")
        assert data["drifted_features_count"] > 0

    def test_drift_reset_endpoint(self, client):
        from backend.src.api import main as main_module
        main_module._drift_detector.record([1.0] * len(FEATURE_NAMES))
        assert main_module._drift_detector.get_sample_count() == 1

        # Unauthorized reset without header
        res_unauth = client.post("/drift-report/reset")
        assert res_unauth.status_code == 401

        # Unauthorized reset with bad header
        res_bad = client.post("/drift-report/reset", headers={"X-Admin-Key": "wrong-key"})
        assert res_bad.status_code == 401

        # Authorized reset
        res_ok = client.post("/drift-report/reset", headers={"X-Admin-Key": "admin-secret-key"})
        assert res_ok.status_code == 200
        assert res_ok.json() == {"status": "cleared", "current_samples": 0}
        assert main_module._drift_detector.get_sample_count() == 0

    def test_predict_records_in_drift_detector(self, client):
        from backend.src.api import main as main_module
        main_module._drift_detector.clear()
        assert main_module._drift_detector.get_sample_count() == 0

        # Predict single domain
        client.post("/predict", json={"domain": "drift-test-1.com"})
        assert main_module._drift_detector.get_sample_count() == 1

        # Batch predict 3 domains
        client.post("/predict/batch", json={"domains": ["d1.com", "d2.com", "d3.com"]})
        assert main_module._drift_detector.get_sample_count() == 4


class TestRetrainEndpoint:
    """Test suite for automated model retraining hook."""

    def test_retrain_unauthorized_without_key(self, client):
        response = client.post("/retrain")
        assert response.status_code == 401
        assert "Invalid or missing X-Admin-Key" in response.json()["detail"]

    def test_retrain_unauthorized_wrong_key(self, client):
        response = client.post("/retrain", headers={"X-Admin-Key": "invalid-pass"})
        assert response.status_code == 401

    def test_retrain_trigger_success(self, client):
        with patch("backend.src.api.main._execute_retraining") as mock_exec:
            response = client.post("/retrain", headers={"X-Admin-Key": "admin-secret-key"})
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "started"
            assert "started_at" in data

    def test_retrain_conflict_when_already_running(self, client):
        from backend.src.api import main as main_module
        with main_module._retraining_lock:
            main_module._retraining_status["status"] = "running"

        try:
            response = client.post("/retrain", headers={"X-Admin-Key": "admin-secret-key"})
            assert response.status_code == 409
            assert "already running" in response.json()["detail"]
        finally:
            with main_module._retraining_lock:
                main_module._retraining_status["status"] = "idle"

    def test_retrain_status_endpoint(self, client):
        response = client.get("/retrain/status")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ("idle", "running", "completed", "failed")


