"""
Statistical Continuous Drift Detector for DGA Lexical Features.

Maintains an in-memory thread-safe sliding window of incoming feature vectors
and computes two-sample Kolmogorov-Smirnov (KS) tests against the training
baseline distribution.
"""

from collections import deque
import logging
import threading
import numpy as np
import scipy.stats

from backend.src.features import FEATURE_NAMES

logger = logging.getLogger(__name__)


class FeatureDriftDetector:
    """
    Monitors distribution shift across lexical features using a sliding window.

    Performs two-sample Kolmogorov-Smirnov (KS) tests between inference traffic
    and a reference baseline feature matrix.
    """

    def __init__(
        self,
        baseline_matrix: np.ndarray,
        feature_names: list[str] | None = None,
        max_window: int = 2000,
        min_samples: int = 50,
        p_val_threshold: float = 0.05,
        ks_stat_threshold: float = 0.15,
        alert_drift_ratio: float = 0.30,
        retrain_drift_ratio: float = 0.40,
    ) -> None:
        """
        Initialize the drift detector.

        Args:
            baseline_matrix: Reference feature matrix of shape (M, num_features).
            feature_names: List of feature names corresponding to matrix columns.
            max_window: Maximum capacity of the sliding window.
            min_samples: Minimum samples required in window before computing KS test.
            p_val_threshold: Significance level below which difference is significant.
            ks_stat_threshold: Minimum KS statistic distance to declare feature drift.
            alert_drift_ratio: Fraction of drifted features triggering 'investigate' alert.
            retrain_drift_ratio: Fraction of drifted features triggering 'retrain_recommended'.
        """
        self.baseline_matrix = np.asarray(baseline_matrix, dtype=np.float64)
        self.feature_names = feature_names if feature_names is not None else FEATURE_NAMES
        self.max_window = max_window
        self.min_samples = min_samples
        self.p_val_threshold = p_val_threshold
        self.ks_stat_threshold = ks_stat_threshold
        self.alert_drift_ratio = alert_drift_ratio
        self.retrain_drift_ratio = retrain_drift_ratio

        self._window: deque = deque(maxlen=max_window)
        self._lock = threading.Lock()

    def record(self, feature_row: list[float] | np.ndarray) -> None:
        """
        Append a single feature vector to the sliding window (thread-safe, O(1)).
        """
        row_list = feature_row.tolist() if isinstance(feature_row, np.ndarray) else list(feature_row)
        with self._lock:
            self._window.append(row_list)

    def record_batch(self, feature_matrix: list[list[float]] | np.ndarray) -> None:
        """
        Append multiple feature vectors to the sliding window (thread-safe).
        """
        if isinstance(feature_matrix, np.ndarray):
            rows = feature_matrix.tolist()
        else:
            rows = [list(r) for r in feature_matrix]

        with self._lock:
            for r in rows:
                self._window.append(r)

    def clear(self) -> None:
        """
        Clear the current sliding window (thread-safe).
        """
        with self._lock:
            self._window.clear()

    def get_sample_count(self) -> int:
        """
        Return the current number of samples stored in the sliding window.
        """
        with self._lock:
            return len(self._window)

    def compute_drift(self) -> dict:
        """
        Compute two-sample KS drift statistics comparing current sliding window to baseline.

        Returns a detailed dictionary containing per-feature metrics, drift score,
        and recommended operational action.
        """
        with self._lock:
            current_samples_count = len(self._window)
            if current_samples_count < self.min_samples:
                return {
                    "status": "insufficient_data",
                    "current_samples": current_samples_count,
                    "min_samples_required": self.min_samples,
                    "baseline_samples": len(self.baseline_matrix),
                    "drift_detected": False,
                    "drift_score": 0.0,
                    "drifted_features_count": 0,
                    "total_features": len(self.feature_names),
                    "drifted_features": [],
                    "recommended_action": "healthy",
                    "features": {},
                }

            # Copy snapshot within lock to minimize lock contention during computation
            current_matrix = np.array(list(self._window), dtype=np.float64)

        feature_reports: dict[str, dict] = {}
        drifted_features: list[str] = []

        num_features = min(self.baseline_matrix.shape[1], current_matrix.shape[1], len(self.feature_names))

        for col_idx in range(num_features):
            col_name = self.feature_names[col_idx]
            base_col = self.baseline_matrix[:, col_idx]
            curr_col = current_matrix[:, col_idx]

            ks_res = scipy.stats.ks_2samp(base_col, curr_col)
            stat = float(ks_res.statistic)
            pval = float(ks_res.pvalue)

            is_drifted = bool(pval < self.p_val_threshold and stat > self.ks_stat_threshold)
            if is_drifted:
                drifted_features.append(col_name)

            feature_reports[col_name] = {
                "ks_statistic": round(stat, 4),
                "p_value": round(pval, 6),
                "drifted": is_drifted,
                "baseline_mean": round(float(np.mean(base_col)), 4),
                "current_mean": round(float(np.mean(curr_col)), 4),
                "baseline_std": round(float(np.std(base_col)), 4),
                "current_std": round(float(np.std(curr_col)), 4),
            }

        drift_score = round(len(drifted_features) / float(num_features), 4) if num_features > 0 else 0.0
        drift_detected = drift_score >= self.alert_drift_ratio

        if drift_score >= self.retrain_drift_ratio:
            recommended_action = "retrain_recommended"
        elif drift_score >= self.alert_drift_ratio:
            recommended_action = "investigate"
        else:
            recommended_action = "healthy"

        return {
            "status": "evaluated",
            "current_samples": current_samples_count,
            "min_samples_required": self.min_samples,
            "baseline_samples": len(self.baseline_matrix),
            "drift_detected": drift_detected,
            "drift_score": drift_score,
            "drifted_features_count": len(drifted_features),
            "total_features": num_features,
            "drifted_features": drifted_features,
            "recommended_action": recommended_action,
            "features": feature_reports,
        }
