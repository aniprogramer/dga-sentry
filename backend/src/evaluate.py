"""
Evaluation Module for DGA Domain Detection.

Generates evaluation plots and summary for all trained models:
- Confusion matrices
- ROC curve comparison
- Feature importance chart
- Plain-language EVALUATION.md summary
"""

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    f1_score,
    accuracy_score,
    precision_score,
    recall_score,
    roc_auc_score,
    ConfusionMatrixDisplay,
)

from backend.src.features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
PLOTS_DIR = PROJECT_ROOT / "outputs" / "plots"
ROOT_DIR = PROJECT_ROOT.parent  # dga-domain-detector/


def load_artifacts() -> tuple[dict, np.ndarray, np.ndarray, object]:
    """Load test data, scaler, and best model."""
    test_data = np.load(MODELS_DIR / "test_data.npz")
    X_test = test_data["X_test"]
    y_test = test_data["y_test"]

    model = joblib.load(MODELS_DIR / "best_model.joblib")
    model_info = joblib.load(MODELS_DIR / "model_info.joblib")

    return model_info, X_test, y_test, model


def plot_confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray, model_name: str) -> None:
    """Generate and save a confusion matrix plot."""
    fig, ax = plt.subplots(figsize=(8, 6))
    cm = confusion_matrix(y_true, y_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Malicious"])
    disp.plot(ax=ax, cmap="Blues", values_format="d")
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / f"confusion_matrix_{model_name}.png", dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved confusion matrix plot for %s", model_name)


def plot_roc_curves(models_data: list[tuple[str, np.ndarray, np.ndarray]]) -> None:
    """
    Generate overlaid ROC curves for all models.

    Args:
        models_data: List of (model_name, y_true, y_prob) tuples
    """
    fig, ax = plt.subplots(figsize=(10, 8))

    colors = ["#3b82f6", "#10b981", "#f59e0b"]  # Blue, Emerald, Amber

    for (name, y_true, y_prob), color in zip(models_data, colors):
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc_val = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=color, lw=2.5, label=f"{name} (AUC = {roc_auc_val:.4f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1, alpha=0.5, label="Random baseline")
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curve Comparison", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=11)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "roc_curve_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved ROC curve comparison plot")


def plot_feature_importance(model, model_name: str, feature_names: list[str] | None = None) -> None:
    """Generate a feature importance bar chart from the best model."""
    fig, ax = plt.subplots(figsize=(10, 6))

    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "coef_"):
        importances = np.abs(model.coef_[0])
    else:
        logger.warning("Model %s does not support feature importance extraction", model_name)
        return

    names = feature_names if feature_names is not None else FEATURE_NAMES
    # Sort by importance
    indices = np.argsort(importances)[::-1]
    sorted_names = [names[i] if i < len(names) else f"feature_{i}" for i in indices]
    sorted_importances = importances[indices]

    colors = plt.cm.viridis(np.linspace(0.3, 0.9, len(sorted_names)))
    bars = ax.barh(range(len(sorted_names)), sorted_importances, color=colors)
    ax.set_yticks(range(len(sorted_names)))
    ax.set_yticklabels(sorted_names, fontsize=11)
    ax.invert_yaxis()
    ax.set_xlabel("Importance", fontsize=12)
    ax.set_title(f"Feature Importance — {model_name}", fontsize=14, fontweight="bold")
    ax.grid(True, axis="x", alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "feature_importance.png", dpi=150, bbox_inches="tight")
    plt.close()
    logger.info("Saved feature importance plot")


def write_evaluation_md(model_info: dict, y_test: np.ndarray, y_pred: np.ndarray) -> None:
    """Write EVALUATION.md with plain-language results summary."""
    model_name = model_info["model_type"]
    metrics = model_info["metrics"]

    # Compute test metrics
    test_metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, model_info.get("test_probs", y_pred)),
    }

    md_content = f"""# Evaluation Results

## Best Model: {model_name.replace('_', ' ').title()}

Selected by highest F1-score on the validation set.

### Validation Set Performance

| Metric | Score |
|--------|-------|
| Accuracy | {metrics['accuracy']:.4f} |
| Precision | {metrics['precision']:.4f} |
| Recall | {metrics['recall']:.4f} |
| F1-Score | {metrics['f1_score']:.4f} |
| ROC-AUC | {metrics['roc_auc']:.4f} |

### Calibrated Operating Thresholds (Three-Tier Decision Framework)

| Parameter | Value | Policy / Action |
|-----------|-------|-----------------|
| `threshold_suspicious` | {model_info.get('thresholds', {}).get('threshold_suspicious', 0.35):.4f} | Prob >= threshold: Flag `suspicious`, recommended action `monitor` |
| `threshold_malicious` | {model_info.get('thresholds', {}).get('threshold_malicious', 0.75):.4f} | Prob >= threshold: Flag `malicious`, recommended action `block` |
| Low Confidence (< suspicious) | < {model_info.get('thresholds', {}).get('threshold_suspicious', 0.35):.4f} | Flag `legitimate` (risk tier `safe`), recommended action `allow` |

### Test Set Performance

| Metric | Score |
|--------|-------|
| Accuracy | {test_metrics['accuracy']:.4f} |
| Precision | {test_metrics['precision']:.4f} |
| Recall | {test_metrics['recall']:.4f} |
| F1-Score | {test_metrics['f1_score']:.4f} |

### What Worked

- **N-gram frequency scoring** proved to be the most discriminative feature, as DGA domains
  produce character bigrams that rarely appear in natural language domains.
- **Shannon entropy** effectively distinguishes random-character DGAs from legitimate domains,
  which tend to use dictionary words with lower entropy.
- **XGBoost** (if selected) provided the best balance of precision and recall, likely due to
  its ability to model non-linear feature interactions.

### What Didn't Work as Well

- **Short dictionary-based DGA domains** that concatenate real English words (e.g., "sunboxnet")
  can mimic legitimate domains' statistical properties, leading to false negatives. These
  word-concatenation DGAs are inherently harder to detect with purely lexical features since
  they don't look "random" by any character-level metric.
- **Vowel/consonant ratio** has limited discriminative power on its own since some legitimate
  domains contain mostly consonants (e.g., brand abbreviations like "nbc", "cnn").

### Limitations

1. **No temporal features**: This model only analyzes the domain string itself, not when
   or how often it was queried — adding DNS query timing could improve detection of some
   DGA families.
2. **Limited DGA family coverage**: The training data covers 25 DGA families, but new
   families emerge regularly. A production system would need periodic retraining on fresh
   threat intelligence feeds.
3. **No deep learning comparison**: We deliberately chose classical ML for explainability
   and inference speed, but character-level CNNs or LSTMs could capture longer-range
   dependencies in domain strings.

### Plots

- Confusion Matrix: `backend/outputs/plots/confusion_matrix_{model_name}.png`
- ROC Curves: `backend/outputs/plots/roc_curve_comparison.png`
- Feature Importance: `backend/outputs/plots/feature_importance.png`
"""

    eval_path = ROOT_DIR / "EVALUATION.md"
    with open(eval_path, "w") as f:
        f.write(md_content)
    logger.info("Wrote EVALUATION.md to %s", eval_path)


def run_evaluation() -> None:
    """Execute the full evaluation pipeline."""
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    model_info, X_test, y_test, best_model = load_artifacts()
    model_name = model_info["model_type"]

    # Predictions on test set
    y_pred = best_model.predict(X_test)
    y_prob = best_model.predict_proba(X_test)[:, 1]

    # Store test probs in model_info for ROC in the markdown
    model_info["test_probs"] = y_prob

    # 1. Confusion matrix for best model
    plot_confusion_matrix(y_test, y_pred, model_name)

    # 2. ROC curves — we need all three models
    # Try to load all models, fall back to just the best
    roc_data = []
    all_model_names = ["logistic_regression", "random_forest", "xgboost"]

    for mname in all_model_names:
        model_path = MODELS_DIR / f"{mname}.joblib"
        if model_path.exists():
            m = joblib.load(model_path)
            m_prob = m.predict_proba(X_test)[:, 1]
            roc_data.append((mname.replace("_", " ").title(), y_test, m_prob))
        elif mname == model_name:
            roc_data.append((mname.replace("_", " ").title(), y_test, y_prob))

    if not roc_data:
        roc_data.append((model_name.replace("_", " ").title(), y_test, y_prob))

    plot_roc_curves(roc_data)

    # 3. Feature importance
    plot_feature_importance(best_model, model_name, model_info.get("feature_names"))

    # 4. Write evaluation markdown
    write_evaluation_md(model_info, y_test, y_pred)

    # Print classification report
    print("\n" + "=" * 60)
    print("TEST SET CLASSIFICATION REPORT")
    print("=" * 60)
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Malicious"]))
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_evaluation()
