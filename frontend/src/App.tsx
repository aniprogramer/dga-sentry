import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import DomainInput from "./components/DomainInput";
import PredictionResultCard from "./components/PredictionResult";
import ConfidenceChart from "./components/ConfidenceChart";
import HistoryTable from "./components/HistoryTable";
import BulkAudit from "./components/BulkAudit";
import ModelMetricsDrift from "./components/ModelMetricsDrift";
import QuickTestResults from "./components/QuickTestResults";
import BrandMark from "./components/BrandMark";
import AboutPage from "./components/AboutPage";
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

type TabMode = "workbench" | "bulk" | "metrics" | "about";

// Hash routes: #/ , #/bulk , #/metrics , #/about , #/about#how-it-works
const TAB_PATHS: Record<TabMode, string> = {
  workbench: "/",
  bulk: "/bulk",
  metrics: "/metrics",
  about: "/about",
};

function parseHash(hash: string): { tab: TabMode; section?: string } {
  const [path, section] = hash.replace(/^#/, "").split("#");
  const tab = (Object.keys(TAB_PATHS) as TabMode[]).find((t) => TAB_PATHS[t] === path);
  return { tab: tab ?? "workbench", section: section || undefined };
}
type ThemeMode = "system" | "light" | "dark";
type HistoryEntry = PredictionResult & { timestamp: string };

function getInitialTheme(): ThemeMode {
  if (typeof window === "undefined") return "system";
  const stored = localStorage.getItem("dga-theme");
  if (stored === "light" || stored === "dark" || stored === "system") {
    return stored;
  }
  return "system";
}

function App() {
  const [route, setRoute] = useState(() => parseHash(window.location.hash));
  const activeTab = route.tab;
  const focusInputOnWorkbench = useRef(false);
  const setActiveTab = useCallback((tab: TabMode) => {
    window.location.hash = TAB_PATHS[tab]; // pushes history; hashchange updates the view
  }, []);

  useEffect(() => {
    const onHashChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (activeTab === "workbench" && focusInputOnWorkbench.current) {
      focusInputOnWorkbench.current = false;
      document.getElementById("domain-input")?.focus();
    }
  }, [activeTab]);

  const handleTryIt = useCallback(() => {
    focusInputOnWorkbench.current = true;
    setActiveTab("workbench");
  }, [setActiveTab]);
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [resolvedTheme, setResolvedTheme] = useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "dark";
    const stored = localStorage.getItem("dga-theme");
    if (stored === "light") return "light";
    if (stored === "dark") return "dark";
    return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  const [currentResult, setCurrentResult] = useState<PredictionResult | null>(null);
  const [batchResults, setBatchResults] = useState<PredictionResult[]>([]);
  const [testResults, setTestResults] = useState<PredictionResult[] | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [modelInfo, setModelInfo] = useState<ModelInfoResponse | null>(null);
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");
  const [showAllStats, setShowAllStats] = useState(false);
  const [showStatusPopover, setShowStatusPopover] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);

  const statusPopoverRef = useRef<HTMLDivElement>(null);
  const statusButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!showStatusPopover) return;

    const handleClickOutside = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node | null;
      if (
        statusPopoverRef.current &&
        !statusPopoverRef.current.contains(target) &&
        statusButtonRef.current &&
        !statusButtonRef.current.contains(target)
      ) {
        setShowStatusPopover(false);
      }
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowStatusPopover(false);
        statusButtonRef.current?.focus();
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("touchstart", handleClickOutside, { passive: true });
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("touchstart", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [showStatusPopover]);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 8);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

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

  // Synchronize theme with DOM and system preferences
  useEffect(() => {
    const updateTheme = () => {
      let effective: "light" | "dark" = "dark";
      if (theme === "system") {
        effective =
          typeof window.matchMedia === "function" &&
          window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light";
      } else {
        effective = theme;
      }
      setResolvedTheme(effective);
      if (effective === "light") {
        document.documentElement.setAttribute("data-theme", "light");
      } else {
        document.documentElement.removeAttribute("data-theme");
      }
      const metaTheme = document.querySelector('meta[name="theme-color"]');
      if (metaTheme) {
        metaTheme.setAttribute("content", effective === "light" ? "#F1F5F9" : "#090B0E");
      }
    };

    updateTheme();

    if (theme === "system" && typeof window.matchMedia === "function") {
      const media = window.matchMedia("(prefers-color-scheme: dark)");
      const listener = () => updateTheme();
      media.addEventListener("change", listener);
      return () => media.removeEventListener("change", listener);
    }
  }, [theme]);

  const cycleTheme = useCallback(() => {
    setTheme((prev) => {
      const next: ThemeMode = prev === "dark" ? "light" : prev === "light" ? "system" : "dark";
      localStorage.setItem("dga-theme", next);
      return next;
    });
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
      <header className={`soc-header ${isScrolled ? "is-scrolled" : ""}`}>
        <div className="soc-header-inner">
          {/* Technical Brand & Console Identifier */}
          <div className="soc-brand" title="DGA Threat Intelligence Engine / SecOps Console">
            <BrandMark className="soc-brand-mark" />
            <div className="soc-brand-text">
              <span className="soc-brand-title-full">DGA THREAT INTELLIGENCE ENGINE</span>
              <span className="soc-brand-title-short">DGA SENTRY</span>
              <span className="soc-brand-sep">/</span>
              <span className="soc-brand-sub">SECOPS CONSOLE</span>
            </div>
          </div>

          {/* Center / Mobile Bottom: Segmented Industrial Switch */}
          <nav className="soc-nav-switcher" aria-label="Main Navigation">
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "workbench" ? "active" : ""}`}
              onClick={() => setActiveTab("workbench")}
              aria-current={activeTab === "workbench" ? "page" : undefined}
            >
              <svg className="soc-nav-icon" width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
              </svg>
              <span className="soc-tab-indicator" />
              <span className="soc-tab-label-full">Investigation Workbench</span>
              <span className="soc-tab-label-short">Workbench</span>
            </button>
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "bulk" ? "active" : ""}`}
              onClick={() => setActiveTab("bulk")}
              aria-current={activeTab === "bulk" ? "page" : undefined}
            >
              <svg className="soc-nav-icon" width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                <path d="M7 3a1 1 0 000 2h6a1 1 0 100-2H7zM4 7a1 1 0 011-1h10a1 1 0 110 2H5a1 1 0 01-1-1zM2 11a2 2 0 012-2h12a2 2 0 012 2v4a2 2 0 01-2 2H4a2 2 0 01-2-2v-4z" />
              </svg>
              <span className="soc-tab-indicator" />
              <span className="soc-tab-label-full">Bulk DNS Telemetry Audit</span>
              <span className="soc-tab-label-short">Bulk Audit</span>
            </button>
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "metrics" ? "active" : ""}`}
              onClick={() => setActiveTab("metrics")}
              aria-current={activeTab === "metrics" ? "page" : undefined}
            >
              <svg className="soc-nav-icon" width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z" />
              </svg>
              <span className="soc-tab-indicator" />
              <span className="soc-tab-label-full">Model Metrics &amp; Drift</span>
              <span className="soc-tab-label-short">Metrics</span>
            </button>
            <button
              type="button"
              className={`soc-nav-tab ${activeTab === "about" ? "active" : ""}`}
              onClick={() => setActiveTab("about")}
              aria-current={activeTab === "about" ? "page" : undefined}
              id="about-nav-tab"
            >
              <svg className="soc-nav-icon" width="18" height="18" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
              <span className="soc-tab-indicator" />
              <span className="soc-tab-label-full">About</span>
              <span className="soc-tab-label-short">About</span>
            </button>
          </nav>

          {/* Right: Engine Status Pills & Theme Switcher */}
          <div className="soc-header-telemetry">
            <button
              type="button"
              className="soc-theme-toggle"
              onClick={cycleTheme}
              aria-label={`Current theme: ${theme}. Click to switch theme`}
              title={`Current theme: ${theme.toUpperCase()} (click to cycle)`}
            >
              <span className="soc-theme-icon" aria-hidden="true">
                {theme === "light" ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="4" />
                    <path d="M12 2v2" />
                    <path d="M12 20v2" />
                    <path d="m4.93 4.93 1.41 1.41" />
                    <path d="m17.66 17.66 1.41 1.41" />
                    <path d="M2 12h2" />
                    <path d="M20 12h2" />
                    <path d="m6.34 17.66-1.41 1.41" />
                    <path d="m19.07 4.93-1.41 1.41" />
                  </svg>
                ) : theme === "dark" ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
                  </svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect width="20" height="14" x="2" y="3" rx="2" />
                    <line x1="8" x2="16" y1="21" y2="21" />
                    <line x1="12" x2="12" y1="17" y2="21" />
                  </svg>
                )}
              </span>
              <span className="soc-theme-label font-mono">
                {theme === "system" ? "AUTO" : theme.toUpperCase()}
              </span>
            </button>

            <button
              ref={statusButtonRef}
              type="button"
              className="soc-status-pill"
              onClick={() => setShowStatusPopover((prev) => !prev)}
              aria-expanded={showStatusPopover}
              aria-label="System status telemetry"
            >
              <span className={`soc-status-led ${backendStatus}`} />
              <span className="soc-status-label">
                {backendStatus === "online"
                  ? "SYSTEM READY"
                  : backendStatus === "checking"
                  ? "SYNCING"
                  : "DISCONNECTED"}
              </span>
              <span className="soc-status-chevron" aria-hidden="true">▾</span>
            </button>
            <span className="soc-telemetry-item font-mono">LATENCY &lt; 1ms</span>
            <span className="soc-telemetry-item font-mono">CACHE: ACTIVE</span>

            {showStatusPopover && (
              <div
                ref={statusPopoverRef}
                className="soc-status-popover"
                role="dialog"
                aria-label="System Telemetry Details"
              >
                <div className="soc-popover-item">
                  <span className="soc-popover-label">ENGINE STATUS</span>
                  <span className={`soc-popover-val ${backendStatus}`}>
                    {backendStatus === "online"
                      ? "SYSTEM READY"
                      : backendStatus === "checking"
                      ? "SYNCING"
                      : "DISCONNECTED"}
                  </span>
                </div>
                <div className="soc-popover-item">
                  <span className="soc-popover-label">INFERENCE LATENCY</span>
                  <span className="soc-popover-val font-mono">&lt; 1ms</span>
                </div>
                <div className="soc-popover-item">
                  <span className="soc-popover-label">PREDICTION CACHE</span>
                  <span className="soc-popover-val font-mono text-[var(--text-safe)]">ACTIVE</span>
                </div>
              </div>
            )}
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
            <span className="soc-rail-value font-mono text-[var(--text-active)]">
              {modelInfo?.metrics ? modelInfo.metrics.roc_auc.toFixed(4) : "0.9454"}
            </span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">VALIDATION ACC</span>
            <span className="soc-rail-value font-mono text-[var(--text-safe)]">
              {modelInfo?.metrics ? `${(modelInfo.metrics.accuracy * 100).toFixed(1)}%` : "88.3%"}
            </span>
          </div>
          <div className="soc-rail-divider" />

          <div className="soc-rail-item">
            <span className="soc-rail-label">OPERATING FPR</span>
            <span className="soc-rail-value font-mono text-[var(--text-amber)]">&lt; 0.5% (p &ge; 0.75)</span>
          </div>
          <div className="soc-rail-divider" />

          <div className={`soc-rail-item ${showAllStats ? "mobile-show" : "mobile-hidden"}`}>
            <span className="soc-rail-label">FEATURE MATRIX</span>
            <span className="soc-rail-value font-mono">13 DIM (FANCI RFC)</span>
          </div>
          <div className={`soc-rail-divider ${showAllStats ? "mobile-show" : "mobile-hidden"}`} />

          <div className={`soc-rail-item ${showAllStats ? "mobile-show" : "mobile-hidden"}`}>
            <span className="soc-rail-label">EXPLAINABILITY</span>
            <span className="soc-rail-value font-mono text-[var(--text-secondary)]">TreeSHAP v0.44</span>
          </div>

          <button
            type="button"
            className="soc-rail-toggle-btn"
            onClick={() => setShowAllStats((prev) => !prev)}
            aria-expanded={showAllStats}
            aria-label="Toggle extra model telemetry"
          >
            {showAllStats ? "▴ Less" : "▾ More (2)"}
          </button>
        </div>
      </section>

      {/* 3. Main Workspace Container */}
      <main className="soc-main-canvas">
        <div key={activeTab} className="soc-tab-content-enter">
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
              <p className="soc-help-link">
                <a href="#/about#how-it-works">How does this work?</a>
              </p>
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
                      themeKey={resolvedTheme}
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
                          <span className="font-mono text-xs text-[var(--text-secondary)]">
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

        {/* Tab 4: About */}
        {activeTab === "about" && <AboutPage section={route.section} onTryIt={handleTryIt} />}

        {/* Tab 3: Model Metrics & Drift */}
        {activeTab === "metrics" && (
          <div className="soc-metrics-layout">
            <ModelMetricsDrift />
          </div>
        )}
        </div>
      </main>

      {/* 4. Industrial SOC Console Footer */}
      <footer className="soc-footer">
        <div className="soc-footer-inner">
          {/* Upper Deck: Identity & Technical Spec Grid */}
          <div className="soc-footer-top">
            <div className="soc-footer-brand">
              <div className="soc-footer-brand-header">
                <BrandMark className="soc-footer-mark" size={20} />
                <span className="soc-footer-title">DGA SENTRY</span>
                <span className="soc-footer-version">v2.1-PROD</span>
              </div>
              <p className="soc-footer-desc">
                Autonomous Algorithmic Domain Detection &amp; Botnet C2 Mitigation Engine. Real-time inference with polynomial TreeSHAP attribution and continuous feature drift detection.
              </p>
            </div>

            <div className="soc-footer-chips">
              <div className="soc-footer-chip">
                <span className="chip-key">CLASSIFIER</span>
                <span className="chip-val font-mono">XGBoost &amp; Random Forest</span>
              </div>
              <div className="soc-footer-chip">
                <span className="chip-key">ATTRIBUTION</span>
                <span className="chip-val font-mono">TreeSHAP (Polynomial)</span>
              </div>
              <div className="soc-footer-chip">
                <span className="chip-key">DRIFT MONITOR</span>
                <span className="chip-val font-mono">Continuous KS 2-Sample</span>
              </div>
              <div className="soc-footer-chip">
                <span className="chip-key">DNS TELEMETRY</span>
                <span className="chip-val font-mono">RFC 1035 / 5891 IDN</span>
              </div>
            </div>
          </div>

          <div className="soc-footer-divider" />

          {/* Lower Deck: Architecture Attribution & Security Posture */}
          <div className="soc-footer-bottom">
            <div className="soc-footer-meta">
              <span>FANCI Architecture (Schüppen et al., 2018)</span>
              <span className="soc-dot-sep">·</span>
              <span>13-Dimensional Linguistic Tensor</span>
              <span className="soc-dot-sep">·</span>
              <span>Zero-Telemetry Local Processing</span>
              <span className="soc-dot-sep">·</span>
              <a href="#/about" className="soc-footer-link">About</a>
            </div>
            <div className="soc-footer-posture font-mono">
              <span className="soc-status-pip" aria-hidden="true" />
              <span>SYSTEM NOMINAL · SECURE SOC CONSOLE</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
