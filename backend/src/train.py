"""
Model Training Module for DGA Domain Detection.

Trains three classifiers (Logistic Regression, Random Forest, XGBoost)
with full MLflow experiment tracking. Selects the best model by F1-score
on the validation set and saves it for API serving.

All runs are logged to MLflow with hyperparameters, metrics, and model
artifacts, providing a screenshot-able experiment history.
"""

import logging
import os
import time
from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
import mlflow.xgboost
from mlflow.tracking import MlflowClient
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier

from backend.src.features import (
    batch_extract_features,
    build_ngram_model,
    save_ngram_model,
    FEATURE_NAMES,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
MLRUNS_DIR = PROJECT_ROOT / "mlruns"
SQLITE_DB_PATH = MLRUNS_DIR / "mlflow.db"
ARTIFACTS_DIR = MLRUNS_DIR / "artifacts"

# Model configurations
MODELS = {
    "logistic_regression": {
        "class": LogisticRegression,
        "params": {
            "C": 1.0,
            "max_iter": 1000,
            "solver": "lbfgs",
            "random_state": 42,
        },
    },
    "random_forest": {
        "class": RandomForestClassifier,
        "params": {
            "n_estimators": 200,
            "max_depth": 20,
            "min_samples_split": 5,
            "min_samples_leaf": 2,
            "random_state": 42,
            "n_jobs": -1,
        },
    },
    "xgboost": {
        "class": XGBClassifier,
        "params": {
            "n_estimators": 300,
            "max_depth": 8,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "random_state": 42,
            "eval_metric": "logloss",
            "n_jobs": -1,
        },
    },
}


def load_data() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Load the processed dataset and split into train/val/test DataFrames."""
    data_path = DATA_DIR / "v1_domains.csv"
    if not data_path.exists():
        raise FileNotFoundError(
            f"Processed dataset not found at {data_path}. "
            "Run data_prep.py first."
        )

    df = pd.read_csv(data_path)
    train_df = df[df["split"] == "train"].copy()
    val_df = df[df["split"] == "val"].copy()
    test_df = df[df["split"] == "test"].copy()

    max_samples = os.getenv("MAX_SAMPLES_PER_CLASS")
    if max_samples:
        max_n = int(max_samples)
        train_df = train_df.groupby("label", group_keys=False).apply(lambda x: x.sample(min(len(x), max_n), random_state=42))
        val_df = val_df.groupby("label", group_keys=False).apply(lambda x: x.sample(min(len(x), max_n // 4), random_state=42))
        test_df = test_df.groupby("label", group_keys=False).apply(lambda x: x.sample(min(len(x), max_n // 4), random_state=42))

    logger.info("Loaded data — train: %d, val: %d, test: %d", len(train_df), len(val_df), len(test_df))
    return train_df, val_df, test_df


def prepare_features(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler]:
    """
    Extract features and scale them.

    Also builds and saves the n-gram model from benign training domains.
    """
    # Build n-gram model from benign training domains
    benign_train = train_df[train_df["label"] == 0]["domain"].tolist()
    logger.info("Building n-gram model from %d benign training domains ...", len(benign_train))
    ngram_model = build_ngram_model(benign_train)
    save_ngram_model(ngram_model)

    # Extract features
    logger.info("Extracting features for training set (%d domains) ...", len(train_df))
    X_train = batch_extract_features(train_df["domain"].tolist(), ngram_model)

    logger.info("Extracting features for validation set (%d domains) ...", len(val_df))
    X_val = batch_extract_features(val_df["domain"].tolist(), ngram_model)

    logger.info("Extracting features for test set (%d domains) ...", len(test_df))
    X_test = batch_extract_features(test_df["domain"].tolist(), ngram_model)

    y_train = train_df["label"].values
    y_val = val_df["label"].values
    y_test = test_df["label"].values

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_val_scaled, X_test_scaled, y_train, y_val, y_test, scaler, X_val


def train_and_evaluate(
    model_name: str,
    model_config: dict,
    X_train: np.ndarray,
    X_val: np.ndarray,
    y_train: np.ndarray,
    y_val: np.ndarray,
) -> tuple[object, dict]:
    """
    Train a model, evaluate on validation set, and log everything to MLflow.

    Returns the trained model and a metrics dictionary.
    """
    logger.info("Training %s ...", model_name)
    start_time = time.time()

    model = model_config["class"](**model_config["params"])
    model.fit(X_train, y_train)

    train_time = time.time() - start_time
    logger.info("%s trained in %.1f seconds", model_name, train_time)

    # Predictions
    y_pred = model.predict(X_val)
    y_prob = model.predict_proba(X_val)[:, 1]

    # Metrics
    metrics = {
        "accuracy": accuracy_score(y_val, y_pred),
        "precision": precision_score(y_val, y_pred),
        "recall": recall_score(y_val, y_pred),
        "f1_score": f1_score(y_val, y_pred),
        "roc_auc": roc_auc_score(y_val, y_prob),
        "train_time_seconds": train_time,
    }

    logger.info(
        "%s — F1: %.4f, Accuracy: %.4f, ROC-AUC: %.4f",
        model_name, metrics["f1_score"], metrics["accuracy"], metrics["roc_auc"],
    )

    return model, metrics


def train_family_classifier(
    X_train_mal: np.ndarray,
    y_train_fam: np.ndarray,
    X_val_mal: np.ndarray,
    y_val_fam: np.ndarray,
) -> tuple[object, LabelEncoder, dict]:
    """
    Train a multiclass classifier to attribute malicious domains to DGA malware families.

    Fits a LabelEncoder on malicious training family labels, then trains a
    RandomForestClassifier on malicious domain feature representations.
    """
    logger.info("Training multiclass family classifier on %d samples ...", len(y_train_fam))
    start_time = time.time()

    encoder = LabelEncoder()
    y_train_enc = encoder.fit_transform(y_train_fam)
    y_val_enc = encoder.transform(y_val_fam)

    family_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=16,
        random_state=42,
        n_jobs=-1,
    )
    family_model.fit(X_train_mal, y_train_enc)

    train_time = time.time() - start_time
    logger.info("Family classifier trained in %.1f seconds", train_time)

    # Evaluate on validation malicious data
    y_val_pred = family_model.predict(X_val_mal)
    metrics = {
        "top1_accuracy": accuracy_score(y_val_enc, y_val_pred),
        "macro_f1": f1_score(y_val_enc, y_val_pred, average="macro", zero_division=0),
        "n_families": len(encoder.classes_),
        "families": list(encoder.classes_),
        "train_time_seconds": train_time,
    }

    logger.info(
        "Family classifier — Top-1 Accuracy: %.4f, Macro F1: %.4f across %d families",
        metrics["top1_accuracy"],
        metrics["macro_f1"],
        metrics["n_families"],
    )

    return family_model, encoder, metrics


def compute_operating_thresholds(
    y_val: np.ndarray,
    y_prob: np.ndarray,
    target_fpr: float = 0.005,
) -> dict[str, float]:
    """
    Compute calibrated operating thresholds from validation predictions.

    - threshold_malicious: Calibrated high-confidence threshold where FPR <= target_fpr (0.5%).
    - threshold_suspicious: Lower-bound threshold capturing high recall (~95%) for SOC monitoring.
    """
    fpr, tpr, thresholds = roc_curve(y_val, y_prob)

    # Locate threshold where FPR <= target_fpr
    valid_indices = np.where(fpr <= target_fpr)[0]
    if len(valid_indices) > 0:
        idx = valid_indices[-1]
        t_mal = thresholds[idx]
        if np.isinf(t_mal) or t_mal > 1.0 or t_mal <= 0.0:
            t_mal = 0.75
    else:
        t_mal = 0.75

    # Locate suspicious threshold where Recall (TPR) >= 95%
    recall_indices = np.where(tpr >= 0.95)[0]
    if len(recall_indices) > 0:
        idx_susp = recall_indices[0]
        t_susp = thresholds[idx_susp]
        if np.isinf(t_susp) or t_susp > 1.0 or t_susp <= 0.0:
            t_susp = 0.35
    else:
        t_susp = 0.35

    # Ensure suspicious threshold is strictly below malicious threshold
    if t_susp >= t_mal:
        t_susp = max(0.1, round(t_mal * 0.5, 4))

    return {
        "threshold_suspicious": round(float(t_susp), 4),
        "threshold_malicious": round(float(t_mal), 4),
    }


def run_training() -> dict:
    """
    Execute the full training pipeline.

    Returns a dictionary of {model_name: (model, metrics)} for all trained models.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    MLRUNS_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Set MLflow tracking to portable SQLite store with centralized artifact storage
    tracking_uri = os.getenv(
        "MLFLOW_TRACKING_URI",
        f"sqlite:///{SQLITE_DB_PATH.resolve().as_posix()}",
    )
    mlflow.set_tracking_uri(tracking_uri)

    client = MlflowClient()
    experiment_name = "dga-domain-detection"
    experiment = client.get_experiment_by_name(experiment_name)
    if experiment is None:
        client.create_experiment(
            name=experiment_name,
            artifact_location=ARTIFACTS_DIR.resolve().as_uri(),
        )
    mlflow.set_experiment(experiment_name)

    # Load and prepare data
    train_df, val_df, test_df = load_data()
    X_train, X_val, X_test, y_train, y_val, y_test, scaler, X_val_unscaled = prepare_features(
        train_df, val_df, test_df
    )

    # Save scaler
    scaler_path = MODELS_DIR / "scaler.joblib"
    joblib.dump(scaler, scaler_path)
    logger.info("Saved scaler to %s", scaler_path)

    # Save test data for evaluation
    test_data_path = MODELS_DIR / "test_data.npz"
    np.savez(test_data_path, X_test=X_test, y_test=y_test)

    # Save baseline reference sample for continuous drift detection
    baseline_sample_size = min(2500, len(X_val_unscaled))
    rng = np.random.default_rng(42)
    indices = rng.choice(len(X_val_unscaled), size=baseline_sample_size, replace=False)
    baseline_sample = X_val_unscaled[indices]
    baseline_path = MODELS_DIR / "baseline_reference.npz"
    np.savez(baseline_path, baseline=baseline_sample, feature_names=np.array(FEATURE_NAMES))
    logger.info("Saved baseline reference (%d samples) to %s", len(baseline_sample), baseline_path)

    # Train all models
    results = {}
    best_model_name = None
    best_f1 = -1.0

    for model_name, model_config in MODELS.items():
        with mlflow.start_run(run_name=model_name):
            # Log parameters
            mlflow.log_params(model_config["params"])
            mlflow.log_param("model_type", model_name)
            mlflow.log_param("n_features", X_train.shape[1])
            mlflow.log_param("feature_names", str(FEATURE_NAMES))
            mlflow.log_param("train_size", X_train.shape[0])
            mlflow.log_param("val_size", X_val.shape[0])

            # Train and evaluate
            model, metrics = train_and_evaluate(
                model_name, model_config, X_train, X_val, y_train, y_val
            )

            # Log metrics
            mlflow.log_metrics(metrics)

            # Log model artifact
            if model_name == "xgboost":
                mlflow.xgboost.log_model(model, artifact_path="model")
            else:
                mlflow.sklearn.log_model(model, artifact_path="model")

            results[model_name] = (model, metrics)

            # Track best model
            if metrics["f1_score"] > best_f1:
                best_f1 = metrics["f1_score"]
                best_model_name = model_name

    # Save the best model
    best_model, best_metrics = results[best_model_name]
    best_model_path = MODELS_DIR / "best_model.joblib"
    joblib.dump(best_model, best_model_path)
    logger.info("Best model: %s (F1=%.4f), saved to %s", best_model_name, best_f1, best_model_path)

    # Compute operating thresholds from validation set
    y_val_probs = best_model.predict_proba(X_val)[:, 1]
    thresholds = compute_operating_thresholds(y_val, y_val_probs)
    logger.info("Calibrated operating thresholds: %s", thresholds)

    # Train secondary multiclass family attribution classifier
    mal_train_mask = (y_train == 1)
    mal_val_mask = (y_val == 1)
    y_train_fam = train_df.loc[train_df["label"] == 1, "family"].values
    y_val_fam = val_df.loc[val_df["label"] == 1, "family"].values

    family_model, family_encoder, family_metrics = train_family_classifier(
        X_train[mal_train_mask],
        y_train_fam,
        X_val[mal_val_mask],
        y_val_fam,
    )

    family_model_path = MODELS_DIR / "family_model.joblib"
    family_encoder_path = MODELS_DIR / "family_encoder.joblib"
    joblib.dump(family_model, family_model_path)
    joblib.dump(family_encoder, family_encoder_path)
    logger.info("Saved family attribution model to %s and encoder to %s", family_model_path, family_encoder_path)

    # Save model info for the API
    model_info = {
        "model_type": best_model_name,
        "metrics": best_metrics,
        "thresholds": thresholds,
        "family_metrics": family_metrics,
        "feature_names": FEATURE_NAMES,
        "n_features": X_train.shape[1],
        "train_size": X_train.shape[0],
        "val_size": X_val.shape[0],
        "test_size": X_test.shape[0],
    }
    joblib.dump(model_info, MODELS_DIR / "model_info.joblib")

    # Print summary
    print("\n" + "=" * 70)
    print("TRAINING SUMMARY")
    print("=" * 70)
    print(f"{'Model':<25} {'Accuracy':>10} {'Precision':>10} {'Recall':>10} {'F1':>10} {'ROC-AUC':>10}")
    print("-" * 70)
    for name, (_, m) in results.items():
        marker = " ★" if name == best_model_name else ""
        print(
            f"{name:<25} {m['accuracy']:>10.4f} {m['precision']:>10.4f} "
            f"{m['recall']:>10.4f} {m['f1_score']:>10.4f} {m['roc_auc']:>10.4f}{marker}"
        )
    print("=" * 70)
    print(f"Best model: {best_model_name} (selected by F1-score)")
    print(f"Saved to: {best_model_path}")
    print("=" * 70 + "\n")

    return results


if __name__ == "__main__":
    run_training()
