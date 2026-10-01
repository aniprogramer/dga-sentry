# Evaluation Results

## Best Model: Xgboost

Selected by highest F1-score on the validation set.

### Validation Set Performance

| Metric | Score |
|--------|-------|
| Accuracy | 0.8828 |
| Precision | 0.9344 |
| Recall | 0.8234 |
| F1-Score | 0.8754 |
| ROC-AUC | 0.9454 |

### Test Set Performance

| Metric | Score |
|--------|-------|
| Accuracy | 0.8827 |
| Precision | 0.9332 |
| Recall | 0.8243 |
| F1-Score | 0.8754 |

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

- Confusion Matrix: `backend/outputs/plots/confusion_matrix_xgboost.png`
- ROC Curves: `backend/outputs/plots/roc_curve_comparison.png`
- Feature Importance: `backend/outputs/plots/feature_importance.png`
