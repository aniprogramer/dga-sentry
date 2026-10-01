"""
FastAPI Application for DGA Domain Detection.

Serves the trained ML model as a REST API with endpoints for:
- Single and batch domain prediction
- Health checks
- Model metadata

IMPORTANT DESIGN NOTE (concurrency):
    The /predict endpoint uses a synchronous `def` handler (not `async def`).
    This is deliberate: scikit-learn and XGBoost inference calls are CPU-bound
    and blocking. FastAPI automatically runs synchronous route handlers in an
    external threadpool (via Starlette's `run_in_threadpool`), which prevents
    the event loop from being blocked under concurrent load. If this were
    `async def`, the blocking model.predict() call would freeze all other
    request processing until it returned.

    See: https://fastapi.tiangolo.com/async/#path-operation-functions
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import threading
import warnings

import joblib
import numpy as np
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from backend.src.features import (
    extract_features,
    load_ngram_model,
    sanitize_and_validate_domain,
    FEATURE_NAMES,
)
from backend.src.api.cache import PredictionCache
from backend.src.api.dns_resolver import (
    resolve_domain_dns,
    compute_threat_summary,
)
from backend.src.api.drift_detector import FeatureDriftDetector

validate_hostname = sanitize_and_validate_domain


def get_client_ip(request: Request) -> str:
    """
    Extract client IP address, checking X-Forwarded-For header for reverse proxies.
    Falls back to request.client.host or '127.0.0.1'.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        if client_ip:
            return client_ip
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom exception handler for rate limit violations returning 429 and Retry-After header."""
    retry_after = "60"
    if getattr(exc, "limit", None):
        try:
            retry_after = str(int(exc.limit.get_expiry()))
        except Exception:
            retry_after = "60"

    return JSONResponse(
        status_code=429,
        content={
            "error": f"Rate limit exceeded: {exc.detail}",
            "detail": f"Rate limit exceeded: {exc.detail}",
        },
        headers={"Retry-After": retry_after},
    )

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).resolve().parent.parent.parent / "models"

# --- Global state for loaded model artifacts ---
_model = None
_scaler = None
_model_info = None
_ngram_model = None
_family_model = None
_family_encoder = None
_explainer = None
_thresholds = {"threshold_suspicious": 0.35, "threshold_malicious": 0.75}
_drift_detector: FeatureDriftDetector | None = None

_retraining_lock = threading.Lock()
_retraining_status: dict[str, str | None] = {
    "status": "idle",
    "started_at": None,
    "completed_at": None,
    "error": None,
}
RETRAIN_ADMIN_KEY = os.getenv("RETRAIN_ADMIN_KEY", "admin-secret-key")

FEATURE_DISPLAY_NAMES = {
    "length": "Domain Length",
    "entropy": "Shannon Entropy",
    "vowel_consonant_ratio": "Vowel/Consonant Ratio",
    "digit_ratio": "Digit Ratio",
    "hex_char_ratio": "Hexadecimal Ratio",
    "gini_index": "Gini Impurity Index",
    "max_consonant_run": "Max Consecutive Consonants",
    "digit_first": "Starts With Digit",
    "n_gram_score": "Bigram Log-Likelihood",
    "unique_char_ratio": "Unique Character Ratio",
    "segmented_word_count": "Dictionary Word Count",
    "valid_word_ratio": "Dictionary Character Ratio",
    "vowel_consonant_transition_rate": "Vowel/Consonant Transition Rate",
}


def _load_models():
    """Load or reload model artifacts and baseline reference from disk into global state."""
    global _model, _scaler, _model_info, _ngram_model, _family_model, _family_encoder, _thresholds, _explainer, _drift_detector

    logger.info("Loading model artifacts from %s ...", MODELS_DIR)

    model_path = MODELS_DIR / "best_model.joblib"
    scaler_path = MODELS_DIR / "scaler.joblib"
    info_path = MODELS_DIR / "model_info.joblib"
    family_model_path = MODELS_DIR / "family_model.joblib"
    family_encoder_path = MODELS_DIR / "family_encoder.joblib"
    baseline_path = MODELS_DIR / "baseline_reference.npz"

    if not model_path.exists():
        logger.error("Model file not found at %s", model_path)
        raise RuntimeError(f"Model file not found: {model_path}")

    _model = joblib.load(model_path)
    _scaler = joblib.load(scaler_path) if scaler_path.exists() else None
    _model_info = joblib.load(info_path) if info_path.exists() else {}
    _ngram_model = load_ngram_model()

    # Load family attribution artifacts with graceful degradation
    if family_model_path.exists() and family_encoder_path.exists():
        _family_model = joblib.load(family_model_path)
        _family_encoder = joblib.load(family_encoder_path)
        logger.info("Loaded family attribution model and encoder successfully.")
    else:
        _family_model = None
        _family_encoder = None
        logger.warning(
            "Family attribution model artifacts not found (%s, %s). Running in binary-only mode.",
            family_model_path,
            family_encoder_path,
        )

    # Initialize TreeSHAP explainer with graceful degradation
    explain_enabled = os.getenv("EXPLAINABILITY_ENABLED", "true").lower() == "true"
    if explain_enabled and _model is not None:
        try:
            import shap
            _explainer = shap.TreeExplainer(_model)
            logger.info("TreeExplainer successfully initialized.")
        except Exception as expl_err:
            logger.warning(
                "TreeExplainer initialization failed (%s). Native booster or fallback will be used if available.",
                expl_err,
            )
            _explainer = None
    else:
        _explainer = None
        if not explain_enabled:
            logger.info("Explainability is disabled via EXPLAINABILITY_ENABLED=false.")

    # Calibrated operating thresholds
    _thresholds = _model_info.get(
        "thresholds",
        {"threshold_suspicious": 0.35, "threshold_malicious": 0.75},
    )
    logger.info("Using operating thresholds: %s", _thresholds)

    # Continuous drift detection baseline reference
    if baseline_path.exists():
        try:
            baseline_data = np.load(baseline_path)
            baseline_mat = baseline_data["baseline"]
            names = list(baseline_data["feature_names"]) if "feature_names" in baseline_data else FEATURE_NAMES
            _drift_detector = FeatureDriftDetector(baseline_mat, feature_names=names)
            logger.info("Loaded baseline reference (%d samples) for drift detection", len(baseline_mat))
        except Exception as e:
            logger.warning("Failed to load baseline reference for drift detection: %s", e)
            _drift_detector = None
    else:
        logger.warning("Baseline reference not found at %s. Drift detection disabled.", baseline_path)
        _drift_detector = None


def _execute_retraining():
    """Background task function to re-execute model training and refresh models in-memory."""
    global _retraining_status
    with _retraining_lock:
        _retraining_status["status"] = "running"
        _retraining_status["started_at"] = datetime.now(timezone.utc).isoformat()
        _retraining_status["completed_at"] = None
        _retraining_status["error"] = None

    try:
        logger.info("Starting background model retraining...")
        from backend.src.train import run_training
        run_training()
        _load_models()
        with _retraining_lock:
            _retraining_status["status"] = "completed"
            _retraining_status["completed_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("Background model retraining completed successfully.")
    except Exception as e:
        logger.error("Background model retraining failed: %s", e, exc_info=True)
        with _retraining_lock:
            _retraining_status["status"] = "failed"
            _retraining_status["error"] = str(e)
            _retraining_status["completed_at"] = datetime.now(timezone.utc).isoformat()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model artifacts once at startup, not per-request."""
    _load_models()
    logger.info(
        "Model loaded: %s (F1=%.4f)",
        _model_info.get("model_type", "unknown") if _model_info else "unknown",
        _model_info.get("metrics", {}).get("f1_score", 0.0) if _model_info else 0.0,
    )

    yield

    # Cleanup (if needed)
    logger.info("Shutting down API.")


# --- Pydantic Models ---

class DomainRequest(BaseModel):
    """Request model for single domain prediction."""
    domain: str = Field(..., description="Domain name to check")

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return validate_hostname(v)


class BatchDomainRequest(BaseModel):
    """Request model for batch domain prediction."""
    domains: list[str] = Field(..., min_length=1, max_length=100, description="List of domain names")

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Domain list cannot be empty")
        return [validate_hostname(d) for d in v]


class RiskFactor(BaseModel):
    """Significant positive feature contribution increasing malicious risk."""
    feature: str
    display_name: str
    value: float
    impact: float


class DnsEnrichmentResult(BaseModel):
    """Structured live external DNS resolution and threat status telemetry."""
    resolved: bool
    operational_status: str = Field(
        ...,
        description="'active', 'nxdomain', 'unresolved', 'timeout', or 'error'",
    )
    ip_addresses: list[str] = Field(default_factory=list)
    name_servers: list[str] = Field(default_factory=list)
    mail_servers: list[str] = Field(default_factory=list)
    dnssec_validated: bool = False
    response_time_ms: float
    threat_summary: str


class PredictionResult(BaseModel):
    """Response model for a single domain prediction with SOC three-tier framework and explainability."""
    domain: str
    label: str  # "legitimate", "suspicious", or "malicious"
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_tier: str = Field(..., description="'safe', 'suspicious', or 'malicious'")
    action: str = Field(..., description="'allow', 'monitor', or 'block'")
    malicious_probability: float = Field(..., ge=0.0, le=1.0, description="Calibrated positive class probability")
    family: str | None = Field(default=None, description="Suspected DGA family if non-safe")
    family_confidence: float | None = Field(default=None, ge=0.0, le=1.0, description="Confidence in malware family classification")
    feature_contributions: dict[str, float] | None = Field(
        default=None,
        description="Signed SHAP attribution per feature (positive values increase malicious probability)",
    )
    top_risk_factors: list[RiskFactor] | None = Field(
        default=None,
        description="Top 3 positive feature contributions driving malicious classification",
    )
    dns_enrichment: DnsEnrichmentResult | None = Field(
        default=None,
        description="Live external DNS resolution and operational threat telemetry (when resolve_dns=True)",
    )
    features: dict[str, float]


class SinglePredictionResponse(BaseModel):
    """Response for single domain prediction."""
    prediction: PredictionResult


class BatchPredictionResponse(BaseModel):
    """Response for batch domain prediction."""
    predictions: list[PredictionResult]
    total: int


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    cache: dict | None = None
    drift_detector: dict | None = None


class ModelInfoResponse(BaseModel):
    model_type: str
    metrics: dict
    n_features: int
    feature_names: list[str]
    train_size: int
    val_size: int
    test_size: int


class DriftFeatureMetrics(BaseModel):
    ks_statistic: float
    p_value: float
    drifted: bool
    baseline_mean: float
    current_mean: float
    baseline_std: float
    current_std: float


class DriftReportResponse(BaseModel):
    status: str
    current_samples: int
    min_samples_required: int
    baseline_samples: int
    drift_detected: bool
    drift_score: float
    drifted_features_count: int
    total_features: int
    drifted_features: list[str]
    recommended_action: str
    features: dict[str, DriftFeatureMetrics]


class RetrainResponse(BaseModel):
    status: str
    message: str
    started_at: str | None = None


class RetrainStatusResponse(BaseModel):
    status: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None


# --- App ---

# Prediction Cache
CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "10000"))
CACHE_ENABLED = os.getenv("CACHE_ENABLED", "true").lower() == "true"
_prediction_cache = PredictionCache(max_size=CACHE_MAX_SIZE, enabled=CACHE_ENABLED)

# --- CORS Configuration ---
DEFAULT_ORIGINS = [
    "http://localhost:5173",      # Vite dev server
    "http://localhost:3000",      # Docker frontend legacy
    "http://localhost:3100",      # Docker frontend custom port
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3100",
]

ALLOWED_ORIGINS = list(DEFAULT_ORIGINS)
deployed_frontend = os.getenv("FRONTEND_ORIGIN", "")
if deployed_frontend:
    for origin in deployed_frontend.split(","):
        origin_clean = origin.strip()
        if origin_clean and origin_clean not in ALLOWED_ORIGINS:
            ALLOWED_ORIGINS.append(origin_clean)

ALLOWED_METHODS = ["GET", "POST", "OPTIONS"]
ALLOWED_HEADERS = ["Content-Type", "Authorization", "Accept", "X-Requested-With", "X-Admin-Key"]

RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
limiter = Limiter(
    key_func=get_client_ip,
    enabled=RATE_LIMIT_ENABLED,
    default_limits=["120/minute"],
)

app = FastAPI(
    title="DGA Domain Detector API",
    description=(
        "Detects malicious domains generated by Domain Generation Algorithms (DGAs) "
        "using lexical feature analysis and machine learning. "
        "Based on established DGA-detection literature (Schüppen et al., FANCI, 2018)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=ALLOWED_METHODS,
    allow_headers=ALLOWED_HEADERS,
)


def _compute_shap_values(X_scaled: np.ndarray) -> np.ndarray | None:
    """
    Compute SHAP attribution values for a 2D scaled feature matrix of shape (N, 13).
    Returns an array of shape (N, 13) or None if explainability is unavailable/disabled.
    """
    explain_enabled = os.getenv("EXPLAINABILITY_ENABLED", "true").lower() == "true"
    if not explain_enabled or _model is None:
        return None

    try:
        # 1. Native XGBoost booster calculation (fastest: <0.2ms C++ execution)
        if hasattr(_model, "get_booster"):
            try:
                booster = _model.get_booster()
                if booster is not None:
                    import xgboost as xgb
                    dmat = xgb.DMatrix(X_scaled)
                    contribs = booster.predict(dmat, pred_contribs=True)
                    contribs = np.asarray(contribs)
                    if contribs.ndim == 2:
                        if contribs.shape[1] == len(FEATURE_NAMES) + 1:
                            return contribs[:, :-1]
                        elif contribs.shape[1] == len(FEATURE_NAMES):
                            return contribs
            except Exception as booster_err:
                logger.debug("Native booster predict failed (%s), trying _explainer fallback", booster_err)

        # 2. General SHAP TreeExplainer if available
        if _explainer is not None and hasattr(_explainer, "shap_values"):
            vals = _explainer.shap_values(X_scaled)
            if isinstance(vals, list) and len(vals) == 2:
                vals_arr = np.asarray(vals[1])
            else:
                vals_arr = np.asarray(vals)
            if vals_arr.ndim == 2 and vals_arr.shape[1] == len(FEATURE_NAMES):
                return vals_arr

        # 3. Linear model fallback (e.g. Logistic Regression)
        if hasattr(_model, "coef_"):
            coef = np.asarray(_model.coef_).reshape(1, -1)
            if coef.shape[1] == len(FEATURE_NAMES):
                return X_scaled * coef

    except Exception as e:
        logger.warning("Error computing SHAP values: %s. Falling back to None.", e)
        return None

    return None


def _extract_explanations(
    feature_dict: dict[str, float],
    shap_row: np.ndarray | None,
) -> tuple[dict[str, float] | None, list[RiskFactor] | None]:
    """
    Format SHAP attributions into a feature_contributions dict and top_risk_factors list.
    """
    if shap_row is None:
        return None, None

    contribs = {FEATURE_NAMES[k]: round(float(shap_row[k]), 4) for k in range(len(FEATURE_NAMES))}

    # Extract positive factors: sort features where contribs[f] > 0 by impact descending. Take top 3.
    pos_factors = [
        (name, impact)
        for name, impact in contribs.items()
        if impact > 0
    ]
    pos_factors.sort(key=lambda x: x[1], reverse=True)
    top_3 = pos_factors[:3]

    top_risk_factors = [
        RiskFactor(
            feature=name,
            display_name=FEATURE_DISPLAY_NAMES.get(name, name),
            value=round(float(feature_dict.get(name, 0.0)), 4),
            impact=impact,
        )
        for name, impact in top_3
    ]

    return contribs, top_risk_factors


def _predict_domain(domain: str) -> PredictionResult:
    """
    Run prediction for a single domain.

    Internal helper used by the single domain prediction endpoint.
    Checks the in-memory prediction cache before running feature extraction
    and model inference. Eliminates pandas.DataFrame overhead by using a 2D
    NumPy array directly. Applies calibrated three-tier decision classification:
      - p < threshold_suspicious: risk_tier="safe", action="allow", label="legitimate"
      - threshold_suspicious <= p < threshold_malicious: risk_tier="suspicious", action="monitor", label="suspicious"
      - p >= threshold_malicious: risk_tier="malicious", action="block", label="malicious"
    Stage 2 family attribution is run on both "suspicious" and "malicious" domains.
    """
    cached = _prediction_cache.get(domain)
    if cached is not None:
        if _drift_detector is not None:
            _drift_detector.record([cached.features[name] for name in FEATURE_NAMES])
        return cached

    # Extract features
    features = extract_features(domain, _ngram_model)

    # Build 2D NumPy array with cached feature order
    row = [features[name] for name in FEATURE_NAMES]
    if _drift_detector is not None:
        _drift_detector.record(row)

    feature_values = np.array([row], dtype=np.float32)

    # Scale features — suppress scikit-learn feature name warning
    if _scaler is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            feature_values = _scaler.transform(feature_values)

    # Stage 1: Binary prediction & positive class probability
    probabilities = _model.predict_proba(feature_values)[0]
    p_mal = float(probabilities[1])

    # Compute SHAP values
    shap_matrix = _compute_shap_values(feature_values)
    shap_row = shap_matrix[0] if shap_matrix is not None and len(shap_matrix) > 0 else None
    feat_contribs, top_risk_factors = _extract_explanations(features, shap_row)

    t_susp = _thresholds.get("threshold_suspicious", 0.35)
    t_mal = _thresholds.get("threshold_malicious", 0.75)

    if p_mal >= t_mal:
        risk_tier = "malicious"
        action = "block"
        label = "malicious"
        confidence = round(p_mal, 4)
    elif p_mal >= t_susp:
        risk_tier = "suspicious"
        action = "monitor"
        label = "suspicious"
        confidence = round(p_mal, 4)
    else:
        risk_tier = "safe"
        action = "allow"
        label = "legitimate"
        confidence = round(1.0 - p_mal, 4)

    # Stage 2: Family attribution for non-safe domains
    family = None
    family_confidence = None

    if risk_tier in ("suspicious", "malicious"):
        if _family_model is not None and _family_encoder is not None:
            fam_probs = _family_model.predict_proba(feature_values)[0]
            fam_idx = int(np.argmax(fam_probs))
            family = str(_family_encoder.inverse_transform([fam_idx])[0])
            family_confidence = round(float(fam_probs[fam_idx]), 4)
    else:
        family = "legitimate"
        family_confidence = None

    result = PredictionResult(
        domain=domain,
        label=label,
        confidence=confidence,
        risk_tier=risk_tier,
        action=action,
        malicious_probability=round(p_mal, 4),
        family=family,
        family_confidence=family_confidence,
        feature_contributions=feat_contribs,
        top_risk_factors=top_risk_factors,
        features={k: round(v, 4) for k, v in features.items()},
    )
    _prediction_cache.set(domain, result)
    return result


def _predict_domains_batch(domains: list[str]) -> list[PredictionResult]:
    """
    Run vectorized prediction for a batch of domains with cache partitioning.

    Partitions incoming domains into cache hits and misses. Runs vectorized
    feature extraction and inference exclusively on cache misses, updating
    the cache with newly computed predictions while strictly preserving
    the original domain ordering in the returned results.
    """
    if not domains:
        return []

    results: list[PredictionResult | None] = [None] * len(domains)
    miss_indices: list[int] = []
    miss_domains: list[str] = []

    for i, domain in enumerate(domains):
        cached = _prediction_cache.get(domain)
        if cached is not None:
            results[i] = cached
        else:
            miss_indices.append(i)
            miss_domains.append(domain)

    if not miss_domains:
        return [r for r in results if r is not None]

    # 1. Extract lexical features for cache misses in one pass
    features_list = [extract_features(d, _ngram_model) for d in miss_domains]

    # 2. Stack feature vectors into a contiguous NumPy matrix of shape (N, num_features)
    matrix = np.array(
        [[f[col] for col in FEATURE_NAMES] for f in features_list],
        dtype=np.float32,
    )

    # 3. Executes a single vectorized _scaler.transform(X) call
    if _scaler is not None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            X_scaled = _scaler.transform(matrix)
    else:
        X_scaled = matrix

    # 4. Stage 1: Vectorized positive class probabilities
    probs = _model.predict_proba(X_scaled)
    mal_probs = probs[:, 1]

    # Vectorized SHAP explanations for un-cached domains
    shap_matrix = _compute_shap_values(X_scaled)

    t_susp = _thresholds.get("threshold_suspicious", 0.35)
    t_mal = _thresholds.get("threshold_malicious", 0.75)

    conds = [
        mal_probs >= t_mal,
        mal_probs >= t_susp,
    ]
    tiers = np.select(conds, ["malicious", "suspicious"], default="safe")
    actions = np.select(conds, ["block", "monitor"], default="allow")
    labels = np.select(conds, ["malicious", "suspicious"], default="legitimate")
    confidences = np.where(
        tiers == "safe",
        np.round(1.0 - mal_probs, 4),
        np.round(mal_probs, 4),
    )

    # 5. Stage 2: Vectorized family attribution for non-safe domains (suspicious & malicious)
    non_safe_indices = [i for i, tier in enumerate(tiers) if tier in ("suspicious", "malicious")]
    families: list[str | None] = ["legitimate" if t == "safe" else None for t in tiers]
    family_confidences: list[float | None] = [None] * len(miss_domains)

    if non_safe_indices and _family_model is not None and _family_encoder is not None:
        non_safe_matrix = X_scaled[non_safe_indices]
        fam_probs = _family_model.predict_proba(non_safe_matrix)
        top_indices = np.argmax(fam_probs, axis=1)
        decoded_families = _family_encoder.inverse_transform(top_indices)

        for row_idx, orig_idx in enumerate(non_safe_indices):
            fam_idx = top_indices[row_idx]
            families[orig_idx] = str(decoded_families[row_idx])
            family_confidences[orig_idx] = round(float(fam_probs[row_idx, fam_idx]), 4)

    # 6. Populate results array and store new predictions in cache
    for j, domain in enumerate(miss_domains):
        shap_row = shap_matrix[j] if shap_matrix is not None and j < len(shap_matrix) else None
        feat_contribs, top_risk_factors = _extract_explanations(features_list[j], shap_row)

        computed_res = PredictionResult(
            domain=domain,
            label=str(labels[j]),
            confidence=float(confidences[j]),
            risk_tier=str(tiers[j]),
            action=str(actions[j]),
            malicious_probability=round(float(mal_probs[j]), 4),
            family=families[j],
            family_confidence=family_confidences[j],
            feature_contributions=feat_contribs,
            top_risk_factors=top_risk_factors,
            features={k: round(v, 4) for k, v in features_list[j].items()},
        )
        _prediction_cache.set(domain, computed_res)
        results[miss_indices[j]] = computed_res

    final_results = [r for r in results if r is not None]
    if _drift_detector is not None and final_results:
        _drift_detector.record_batch(
            [[r.features[col] for col in FEATURE_NAMES] for r in final_results]
        )
    return final_results


def _enrich_result_with_dns(
    result: PredictionResult,
    timeout: float = 2.0,
) -> PredictionResult:
    """Perform live external DNS resolution and attach DnsEnrichmentResult."""
    dns_data = resolve_domain_dns(result.domain, timeout=timeout)
    summary = compute_threat_summary(
        risk_tier=result.risk_tier,
        operational_status=dns_data["operational_status"],
        ips=dns_data["ip_addresses"],
    )
    enrichment = DnsEnrichmentResult(
        resolved=dns_data["resolved"],
        operational_status=dns_data["operational_status"],
        ip_addresses=dns_data["ip_addresses"],
        name_servers=dns_data["name_servers"],
        mail_servers=dns_data["mail_servers"],
        dnssec_validated=dns_data["dnssec_validated"],
        response_time_ms=dns_data["response_time_ms"],
        threat_summary=summary,
    )
    return result.model_copy(update={"dns_enrichment": enrichment})


def _enrich_results_batch_with_dns(
    results: list[PredictionResult],
    max_workers: int = 20,
    timeout: float = 2.0,
) -> list[PredictionResult]:
    """Perform concurrent live external DNS resolution across a batch of domains."""
    if not results:
        return []
    workers = min(max_workers, len(results))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        enriched_results = list(
            executor.map(
                lambda r: _enrich_result_with_dns(r, timeout=timeout),
                results,
            )
        )
    return enriched_results


# --- Routes ---
# NOTE: All prediction endpoints use synchronous `def` (not `async def`)
# so that FastAPI runs them in a threadpool, preventing the blocking
# model.predict() call from freezing the async event loop.


@app.get("/health", response_model=HealthResponse, tags=["System"])
@limiter.limit("120/minute")
def health_check(request: Request):
    """Basic health check endpoint."""
    drift_info = None
    if _drift_detector is not None:
        drift_info = {
            "enabled": True,
            "current_samples": _drift_detector.get_sample_count(),
            "baseline_samples": len(_drift_detector.baseline_matrix),
        }
    else:
        drift_info = {"enabled": False}

    return HealthResponse(
        status="healthy",
        model_loaded=_model is not None,
        cache=_prediction_cache.stats(),
        drift_detector=drift_info,
    )


@app.get("/cache-stats", tags=["System"])
@limiter.limit("120/minute")
def cache_stats(request: Request):
    """Returns in-memory prediction cache statistics."""
    return _prediction_cache.stats()


@app.get("/model-info", response_model=ModelInfoResponse, tags=["System"])
@limiter.limit("120/minute")
def model_info(request: Request):
    """Returns current model version and key metrics."""
    if not _model_info:
        raise HTTPException(status_code=503, detail="Model info not available")

    return ModelInfoResponse(
        model_type=_model_info.get("model_type", "unknown"),
        metrics=_model_info.get("metrics", {}),
        n_features=_model_info.get("n_features", 0),
        feature_names=_model_info.get("feature_names", []),
        train_size=_model_info.get("train_size", 0),
        val_size=_model_info.get("val_size", 0),
        test_size=_model_info.get("test_size", 0),
    )


@app.post("/predict", response_model=SinglePredictionResponse, tags=["Prediction"])
@limiter.limit("60/minute")
def predict_single(
    request: Request,
    domain_req: DomainRequest,
    resolve_dns: bool = False,
):
    """
    Predict whether a single domain is legitimate or DGA-generated.

    Returns the predicted label, confidence score, and the feature values
    that drove the prediction.

    If resolve_dns=True, performs opt-in live external DNS resolution
    to enrich the operational threat state (Active C2 vs Dormant NXDOMAIN).

    This handler is a synchronous `def` — FastAPI automatically runs it in
    its threadpool so the blocking sklearn/xgboost inference doesn't block
    the event loop under concurrent load.
    """
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    result = _predict_domain(domain_req.domain)
    if resolve_dns:
        result = _enrich_result_with_dns(result)
    return SinglePredictionResponse(prediction=result)


@app.post("/predict/batch", response_model=BatchPredictionResponse, tags=["Prediction"])
@limiter.limit("15/minute")
def predict_batch(
    request: Request,
    batch_req: BatchDomainRequest,
    resolve_dns: bool = False,
):
    """
    Predict whether multiple domains are legitimate or DGA-generated.

    Accepts up to 100 domains and returns predictions for each.

    If resolve_dns=True, performs concurrent external DNS resolution
    across domains using worker threads.

    Uses synchronous `def` for the same concurrency reason as /predict.
    """
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    results = _predict_domains_batch(batch_req.domains)
    if resolve_dns:
        results = _enrich_results_batch_with_dns(results)
    return BatchPredictionResponse(predictions=results, total=len(results))


@app.get(
    "/drift-report",
    response_model=DriftReportResponse,
    tags=["Monitoring"],
    summary="Continuous Feature Drift Report",
    description="Returns two-sample Kolmogorov-Smirnov test statistics against baseline reference data across all 13 lexical features.",
)
@limiter.limit("60/minute")
def drift_report(request: Request):
    """
    Returns continuous feature drift analysis against baseline reference data.
    Performs two-sample Kolmogorov-Smirnov tests across all 13 lexical features.
    """
    if _drift_detector is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Drift detector is not initialized (baseline reference missing)",
        )
    return _drift_detector.compute_drift()


@app.post(
    "/drift-report/reset",
    tags=["Monitoring"],
    summary="Reset Drift Sliding Window",
    description="Clears the in-memory sliding window for drift detection. Requires X-Admin-Key authentication.",
)
@limiter.limit("30/minute")
def reset_drift_window(
    request: Request,
    x_admin_key: str | None = Header(None, alias="X-Admin-Key"),
):
    """Clear the sliding window of the drift detector (requires admin key)."""
    if RETRAIN_ADMIN_KEY and x_admin_key != RETRAIN_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Admin-Key header",
        )
    if _drift_detector is not None:
        _drift_detector.clear()
    return {"status": "cleared", "current_samples": 0}


@app.post(
    "/retrain",
    response_model=RetrainResponse,
    tags=["Retraining"],
    summary="Trigger Model Retraining",
    description="Triggers asynchronous model retraining in a background thread. Requires X-Admin-Key authentication.",
)
@limiter.limit("5/minute")
def trigger_retraining(
    request: Request,
    background_tasks: BackgroundTasks,
    x_admin_key: str | None = Header(None, alias="X-Admin-Key"),
):
    """
    Trigger an asynchronous model retraining job.
    Protected by X-Admin-Key header authentication.
    """
    if RETRAIN_ADMIN_KEY and x_admin_key != RETRAIN_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Admin-Key header",
        )

    with _retraining_lock:
        if _retraining_status["status"] == "running":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Retraining job is already running",
            )

    started_at = datetime.now(timezone.utc).isoformat()
    background_tasks.add_task(_execute_retraining)
    return RetrainResponse(
        status="started",
        message="Model retraining initiated in background",
        started_at=started_at,
    )


@app.get(
    "/retrain/status",
    response_model=RetrainStatusResponse,
    tags=["Retraining"],
    summary="Model Retraining Job Status",
    description="Returns the status of background model retraining execution.",
)
@limiter.limit("60/minute")
def get_retrain_status(request: Request):
    """Returns the status of the background model retraining job."""
    with _retraining_lock:
        return RetrainStatusResponse(**_retraining_status)

