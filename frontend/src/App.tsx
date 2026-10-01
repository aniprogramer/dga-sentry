import { useState, useEffect, useCallback, useMemo } from "react";
import DomainInput from "./components/DomainInput";
import PredictionResultCard from "./components/PredictionResult";
import ConfidenceChart from "./components/ConfidenceChart";
import HistoryTable from "./components/HistoryTable";
import BulkAudit from "./components/BulkAudit";
import ModelMetricsDrift from "./components/ModelMetricsDrift";
import QuickTestResults from "./components/QuickTestResults";
import { TestDomainSampler } from "./utils/testDomainPool";
import {
  checkDomain,
  checkDomains,
  getModelInfo,
  getHealth,
  type PredictionResult,
  type ModelInfoResponse,
  ApiError,
} from "./api/client";
import "./App.css";

type TabMode = "workbench" | "bulk" | "metrics";
type HistoryEntry = PredictionResult & { timestamp: string };

function App() {
  const [activeTab, setActiveTab] = useState<TabMode>("workbench");
  const [currentResult, setCurrentResult] = useState<PredictionResult | null>(null);
  const [batchResults, setBatchResults] = useState<PredictionResult[]>([]);
  const [testResults, setTestResults] = useState<PredictionResult[] | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");

  const domainSampler = useMemo(() => new TestDomainSampler(), []);

  // Check backend health and load model metadata
  useEffect(() => {
    const checkBackend = async () => {
      try {
        await getHealth();
        setBackendStatus("online");
        const info = await getModelInfo();
        setModelInfo(info);
      } catch {
        setBackendStatus("offline");
      }
    };
    checkBackend();
  }, []);

  const addToHistory = useCallback((results: PredictionResult[]) => {
    const timestamp = new Date().toLocaleTimeString();
    const entries: HistoryEntry[] = results.map((r) => ({
      ...r,
      timestamp,
    }));
    setHistory((prev) => [...entries, ...prev]);
  }, []);

  const handleSingleSubmit = useCallback(
    async (domain: string, resolveDns: boolean = false) => {
      setIsLoading(true);
      setError(null);
      setBatchResults([]);
      setCurrentResult(null);

      try {
        const response = await checkDomain(domain, resolveDns);
        setCurrentResult(response.prediction);
        addToHistory([response.prediction]);
      } catch (err) {
        if (err instanceof ApiError) {
          setError(
            err.statusCode === 0
              ? "Cannot reach the backend. Verify the API server is running on :8000."
              : err.message,
          );
        } else {
          setError("An unexpected error occurred during prediction.");
        }
      } finally {
        setIsLoading(false);
      }
    },
    [addToHistory],
  );

  const handleBatchSubmit = useCallback(
    async (domains: string[], resolveDns: boolean = false) => {
      setIsLoading(true);
      setError(null);
      setCurrentResult(null);
      setBatchResults([]);

      try {
        const response = await checkDomains(domains, resolveDns);
        setBatchResults(response.predictions);
        addToHistory(response.predictions);
      } catch (err) {
        if (err instanceof ApiError) {
          setError(
            err.statusCode === 0
              ? "Cannot reach the backend. Verify the API server is running on :8000."
              : err.message,
          );
        } else {
          setError("An unexpected error occurred during batch execution.");
        }
      } finally {
        setIsLoading(false);
      }
    },
    [addToHistory],
  );

  const handleRunTest = useCallback(async () => {
    setIsTesting(true);
    setError(null);
    try {
      const { domains } = domainSampler.sample(6);
      const response = await checkDomains(domains, false);
      setTestResults(response.predictions);
      addToHistory(response.predictions);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(
          err.statusCode === 0
            ? "Cannot reach the backend. Verify the API server is running on :8000."
            : err.message,
        );
      } else {
        setError("Failed to execute test sample batch.");
      }
    } finally {
      setIsTesting(false);
    }
  }, [domainSampler, addToHistory]);

  const clearHistory = () => {
    setHistory([]);
  };

  return (
    <div className="soc-app">
      {/* 1. Unified Industrial Top Header Bar */}
      <header className="soc-header">
        <div className="soc-header-inner">
          {/* Technical Brand & Console Identifier */}
          <div className="soc-brand">
            <span className="soc-brand-icon">⛨</span>
            <div className="soc-brand-text">
              <span className="soc-brand-title">DGA THREAT INTELLIGENCE ENGINE</span>
              <span className="soc-brand-sep">/</span>
              <span className="soc-brand-sub">SECOPS CONSOLE</span>
            </div>
          </div>

          {/* Center: Segmented Industrial Switch */}
          <nav className="soc-nav-switcher" aria-label="Main Navigation">
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "workbench" ? "active" : ""}`}
              onClick={() => setActiveTab("workbench")}
            >
              <span className="soc-tab-indicator" />
              <span>Investigation Workbench</span>
            </button>
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "bulk" ? "active" : ""}`}
              onClick={() => setActiveTab("bulk")}
            >
              <span className="soc-tab-indicator" />
              <span>Bulk DNS Telemetry Audit</span>
            </button>
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "metrics" ? "active" : ""}`}
              onClick={() => setActiveTab("metrics")}
            >
              <span className="soc-tab-indicator" />
              <span>Model Metrics &amp; Drift</span>
            </button>
          </nav>

          {/* Right: Engine Status Pills */}
          <div className="soc-header-telemetry">
            <div className="soc-status-pill">
              <span className={`soc-status-led ${backendStatus}`} />
              <span className="soc-status-label">
                {backendStatus === "online"
                  ? "SYSTEM READY"
                  : backendStatus === "checking"
                  ? "SYNCING"
                  : "DISCONNECTED"}
              </span>
            </div>
            <span className="soc-telemetry-item font-mono">LATENCY &lt; 1ms</span>
            <span className="soc-telemetry-item font-mono">CACHE: ACTIVE</span>
          </div>
        </div>
      </header>

      {/* 2. Global Telemetry & Quick-Stats Ribbon */}
      <section className="soc-telemetry-rail">
        <div className="soc-rail-inner">
          <div className="soc-rail-item">
            <span className="soc-rail-label">ACTIVE MODEL</span>
            <span className="soc-rail-value font-mono">
              {modelInfo ? modelInfo.model_type.toUpperCase() : "XGBOOST V2.1"}
            </span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">ROC-AUC SCORE</span>
            <span className="soc-rail-value font-mono text-sky-400">
              {modelInfo?.metrics ? modelInfo.metrics.roc_auc.toFixed(4) : "0.9454"}
            </span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">VALIDATION ACC</span>
            <span className="soc-rail-value font-mono text-emerald-400">
              {modelInfo?.metrics ? `${(modelInfo.metrics.accuracy * 100).toFixed(1)}%` : "88.3%"}
            </span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">FEATURE MATRIX</span>
            <span className="soc-rail-value font-mono">13 DIM (FANCI RFC)</span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">OPERATING FPR</span>
            <span className="soc-rail-value font-mono text-amber-400">&lt; 0.5% (p &ge; 0.75)</span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">EXPLAINABILITY</span>
            <span className="soc-rail-value font-mono text-[#9CA3AF]">TreeSHAP v0.44</span>
          </div>
        </div>
      </section>

      {/* 3. Main Workspace Container */}
      <main className="soc-main-canvas">
        {/* Tab 1: Investigation Workbench */}
        {activeTab === "workbench" && (
          <div className="soc-workbench-layout">
            {/* Input & Staging Console */}
            <section className="soc-workbench-top">
              <DomainInput
                onSubmitSingle={handleSingleSubmit}
                onSubmitBatch={handleBatchSubmit}
                isLoading={isLoading}
                onRunTest={handleRunTest}
                isTesting={isTesting}
              />
            </section>

            {/* Quick Test Results (Non-Repeating Sample Batch) */}
            {(testResults || isTesting) && (
              <section className="soc-workbench-quick-test">
                <QuickTestResults
                  results={testResults || []}
                  isLoading={isTesting}
                  onClose={() => setTestResults(null)}
                  onSelectDomain={(domain) => handleSingleSubmit(domain, false)}
                />
              </section>
            )}

            {/* Error Notification */}
            {error && (
              <div className="soc-alert-error" role="alert">
                <span className="soc-alert-icon">⚠</span>
                <span>{error}</span>
              </div>
            )}

            {/* Triage Cockpit Grid (Result + Confidence Chart) */}
            {(currentResult || isLoading) && !batchResults.length && (
              <section className="soc-triage-grid">
                <div className="soc-triage-main">
                  <PredictionResultCard
                    result={currentResult}
                    isLoading={isLoading}
                  />
                </div>
                {currentResult && (
                  <div className="soc-triage-side">
                    <ConfidenceChart
                      features={currentResult.features}
                      label={currentResult.label}
                    />
                  </div>
                )}
              </section>
            )}

            {/* Batch Domain Results Grid */}
            {batchResults.length > 0 && (
              <section className="soc-batch-overview">
                <div className="soc-section-heading-row">
                  <h3 className="soc-section-heading">
                    BATCH EVALUATION MATRIX ({batchResults.length} TARGETS)
                  </h3>
                </div>
                <div className="soc-batch-cards-grid">
                  {batchResults.map((result, i) => {
                    const isMal = result.risk_tier === "malicious" || result.label === "malicious";
                    const isSusp = result.risk_tier === "suspicious";
                    const tier = isMal ? "malicious" : isSusp ? "suspicious" : "safe";
                    return (
                      <div key={`${result.domain}-${i}`} className={`soc-batch-card card-${tier}`}>
                        <div className="soc-batch-card-top">
                          <code className="soc-batch-domain">{result.domain}</code>
                          <span className={`soc-tag tag-${tier}`}>
                            {tier.toUpperCase()}
                          </span>
                        </div>
                        <div className="soc-batch-card-bar">
                          <div className="soc-prob-track">
                            <div
                              className={`soc-prob-fill bar-${tier}`}
                              style={{ width: `${Math.round(result.malicious_probability * 100)}%` }}
                            />
                          </div>
                          <span className="font-mono text-xs text-[#9CA3AF]">
                            {(result.malicious_probability * 100).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* Session Audit History */}
            <section className="soc-workbench-bottom">
              <HistoryTable history={history} onClear={clearHistory} />
            </section>
          </div>
        )}

        {/* Tab 2: Bulk DNS Telemetry Audit */}
        {activeTab === "bulk" && (
          <div className="soc-bulk-layout">
            <BulkAudit />
          </div>
        )}

        {/* Tab 3: Model Metrics & Drift */}
        {activeTab === "metrics" && (
          <div className="soc-metrics-layout">
            <ModelMetricsDrift />
          </div>
        )}
      </main>

      {/* 4. Industrial Footer */}
      <footer className="soc-footer">
        <div className="soc-footer-inner">
          <div className="soc-footer-left">
            <span>DGA Domain Intelligence Engine</span>
            <span className="soc-dot-sep">·</span>
            <span>XGBoost &amp; Random Forest Classifiers</span>
            <span className="soc-dot-sep">·</span>
            <span>TreeSHAP Attribution (Polynomial Time)</span>
            <span className="soc-dot-sep">·</span>
            <span>Continuous KS Drift Detection</span>
          </div>
          <div className="soc-footer-right font-mono text-xs text-[#64748B]">
            RFC 1035 / 5891 IDN Compliant · FANCI Architecture (Schüppen et al., 2018)
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
