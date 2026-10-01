# Architecture & Design Decisions

This document explains the key technical choices behind the DGA Domain Detector system: why certain technologies were chosen, what alternatives were considered, and how the feature engineering relates to published research.

## System Overview

The system follows a standard ML serving architecture:

1. **Offline pipeline**: data acquisition → feature extraction → model training → artifact storage
2. **Online serving**: FastAPI loads the trained model at startup → accepts domain strings → extracts features in real-time → returns predictions
3. **Frontend**: React SPA calls the API and presents results with rich visualizations

This separation ensures the training pipeline can be run independently of the serving layer, and the model can be updated without redeploying the API.

## Why Classical ML Over Deep Learning?

**Chosen**: Random Forest / XGBoost with hand-crafted lexical features
**Considered**: Character-level CNN, LSTM, or Transformer

**Rationale**:

1. **Explainability**: Feature-engineered models let us show *why* a domain is flagged (high entropy, unusual bigrams, long consonant runs). This is critical for security analysts who need to understand alerts, not just receive them. Deep learning models are effectively black boxes for per-prediction explanations.

2. **Inference speed**: Feature extraction + tree-based prediction runs in <1ms per domain. Character-level neural models require embedding lookup and sequential or convolutional passes, adding 10-100x latency for marginal accuracy gains on this task.

3. **Training cost**: The full pipeline (675K domains, 3 models, 10 features) trains in under 15 minutes on a single CPU. No GPU required. This matters for reproducibility — anyone cloning this repo can train from scratch on a free-tier CI runner.

4. **Proven effectiveness**: The lexical feature approach achieves >95% F1 on DGA detection benchmarks (see Schüppen et al., 2018). The marginal accuracy gain from deep learning does not justify the complexity for a portfolio demonstration.

**When deep learning would be worth it**: If the system needed to handle adversarial DGAs specifically designed to evade lexical analysis, or if we had access to much larger, multi-modal datasets (DNS query logs + domain strings + WHOIS data), a deep learning approach could capture patterns that feature engineering misses.

## Why React Over Streamlit/Gradio?

**Chosen**: React + Vite + TypeScript + Tailwind CSS
**Considered**: Streamlit, Gradio, plain HTML/JS

**Rationale**:

1. **Full-stack demonstration**: This is a portfolio project targeting ML engineering and full-stack roles. A React frontend demonstrates frontend skills that Streamlit/Gradio cannot — component architecture, TypeScript type safety, responsive design, and build tooling.

2. **UX control**: The cybersecurity-themed UI with glassmorphism, animated confidence bars, and feature breakdown charts would be impossible or severely limited in Streamlit's widget-based paradigm.

3. **Deployment independence**: The frontend deploys as a static bundle to Vercel (free, fast, global CDN), completely independent of the Python backend. Streamlit would require a Python-capable host for both ML serving and UI rendering.

4. **Production realism**: Real ML products almost never use Streamlit/Gradio in production. Demonstrating a proper API-first architecture with a decoupled frontend shows understanding of how ML systems are actually deployed.

## Feature Engineering — Related Work

The lexical feature set used in this project is based on established DGA detection literature, not original research. The primary reference is:

> **Schüppen, S., Teuber, D., Herrmann, P., & Meyer, U. (2018).**
> *"FANCI: Feature-based Automated NXDomain Classification and Intelligence."*
> USENIX Security Symposium.

The FANCI paper established that the following feature categories are highly discriminative for DGA detection:

| Feature Category | This Project's Implementation | FANCI Reference |
|-----------------|------------------------------|-----------------|
| Character distribution | Shannon entropy, Gini index, unique char ratio | Structural features §4.1 |
| Phonetic plausibility | Vowel/consonant ratio, max consecutive consonants | Linguistic features §4.2 |
| Numeric content | Digit ratio, hex char ratio, digit-first flag | Structural features §4.1 |
| N-gram frequency | Bigram log-probability against benign corpus | Statistical features §4.3 |
| Length | Character count of SLD | Structural features §4.1 |

These features are standard, published knowledge in the network security community. They are implemented independently in this project as a clean Python module (`features.py`) with full test coverage, following the FANCI methodology rather than copying from any single implementation.

## API Design — Concurrency

The FastAPI `/predict` endpoint uses a **synchronous `def` handler** rather than `async def`. This is a deliberate choice:

- scikit-learn and XGBoost inference calls are **CPU-bound and blocking**
- If placed inside an `async def` handler, `model.predict()` would block the event loop, freezing all concurrent request processing
- FastAPI automatically runs synchronous route handlers in Starlette's threadpool, preventing event loop blocking
- For this workload (sub-millisecond inference), the threadpool approach is optimal

The alternative — wrapping the inference call in `starlette.concurrency.run_in_threadpool()` inside an `async def` handler — would be functionally equivalent but adds unnecessary boilerplate.

## Data Pipeline Decisions

- **Primary dataset**: `chrmor/DGA_domains_dataset` was chosen because it is directly clonable from GitHub with no signup, API keys, or institutional access required. This is a critical reproducibility decision — the project should be runnable by anyone who clones it.
- **Sampling**: The full ~675K dataset is used when training completes within 15 minutes. The pipeline includes a configurable `MAX_SAMPLES_PER_CLASS` fallback for resource-constrained environments.
- **Versioning**: Processed datasets are saved with version prefixes (`v1_domains.csv`) to support dataset evolution without breaking the training pipeline.

## Experiment Tracking

MLflow is used for experiment tracking because:
- It's the industry standard for ML experiment management
- The MLflow UI provides an immediately screenshot-able comparison of all model runs
- Model artifacts are versioned and linked to their training metrics
- It runs locally with a portable, ACID-compliant SQLite backend store (`sqlite:///mlruns/mlflow.db`) and centralized relative artifact storage (`mlruns/artifacts`)
- Using a SQLite backend store avoids hardcoded absolute local file URIs, file-locking contention, and ensures runs and artifacts remain fully portable across development environments, Docker containers, and CI/CD runners

MLflow is intentionally *not* included in the docker-compose stack — it's a development/training tool, not a production serving dependency. To inspect runs locally:
```bash
cd backend
mlflow ui --backend-store-uri sqlite:///mlruns/mlflow.db --default-artifact-root ./mlruns/artifacts --port 5000
```
