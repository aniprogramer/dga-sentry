import type { PredictionResult } from "../api/client";

interface QuickTestResultsProps {
  results: PredictionResult[];
  isLoading?: boolean;
  onClose: () => void;
  onSelectDomain: (domain: string) => void;
}

export default function QuickTestResults({
  results,
  isLoading = false,
  onClose,
  onSelectDomain,
}: QuickTestResultsProps) {
  if (isLoading) {
    return (
      <div className="soc-quick-test-panel loading">
        <div className="soc-quick-loading-row">
          <span className="soc-spinner" />
          <span className="font-mono text-xs text-[#9CA3AF]">
            EXECUTING VECTORIZED BATCH TEST (PREDICT_BATCH)...
          </span>
        </div>
      </div>
    );
  }

  if (!results || results.length === 0) return null;

  const okCount = results.filter(
    (r) => r.risk_tier === "safe" || r.label === "legitimate",
  ).length;
  const notOkCount = results.length - okCount;

  return (
    <div className="soc-quick-test-panel" data-testid="quick-test-results">
      {/* Header */}
      <div className="soc-quick-test-header">
        <div className="soc-quick-header-title">
          <span className="soc-quick-icon">⚡</span>
          <span className="soc-quick-heading">
            QUICK TEST AUDIT RESULTS ({results.length} DOMAINS TESTED)
          </span>
          <div className="soc-quick-summary-tags">
            <span className="soc-summary-pill pill-ok">{okCount} OK (CLEAN)</span>
            <span className="soc-summary-pill pill-not-ok">{notOkCount} NOT OK (DGA / THREAT)</span>
          </div>
        </div>

        <button
          type="button"
          className="soc-quick-close-btn"
          onClick={onClose}
          aria-label="Close test results"
          title="Close quick test panel"
        >
          ✕
        </button>
      </div>

      {/* Domain Rows */}
      <div className="soc-quick-rows-list">
        {results.map((r, idx) => {
          const isOk = r.risk_tier === "safe" || r.label === "legitimate";
          const probPercent = Math.round(r.malicious_probability * 100);

          return (
            <div
              key={`${r.domain}-${idx}`}
              className={`soc-quick-row ${isOk ? "row-ok" : "row-not-ok"}`}
            >
              {/* Domain & Family */}
              <div className="soc-quick-domain-col">
                <span className="soc-quick-idx font-mono">{idx + 1}.</span>
                <code className="soc-quick-fqdn">{r.domain}</code>
                {!isOk && r.family && r.family !== "legitimate" && (
                  <span className="soc-family-chip">
                    [{r.family.toUpperCase()}]
                  </span>
                )}
              </div>

              {/* Large Verdict Badge */}
              <div className="soc-quick-verdict-col">
                {isOk ? (
                  <div className="soc-test-badge badge-ok">
                    <span className="soc-test-badge-icon">✓</span>
                    <span className="soc-test-badge-text">OK</span>
                    <span className="soc-test-badge-sub">Legitimate / Clean</span>
                  </div>
                ) : (
                  <div className="soc-test-badge badge-not-ok">
                    <span className="soc-test-badge-icon">⚠</span>
                    <span className="soc-test-badge-text">NOT OK</span>
                    <span className="soc-test-badge-sub">
                      {r.risk_tier === "suspicious" ? "Suspicious DGA" : "Malicious DGA"}
                    </span>
                  </div>
                )}
              </div>

              {/* Confidence & Probability */}
              <div className="soc-quick-score-col">
                <div className="soc-score-metric">
                  <span className="soc-score-label">MALICIOUS PROB</span>
                  <div className="soc-score-gauge-wrap">
                    <div className="soc-score-track">
                      <div
                        className={`soc-score-fill ${isOk ? "bar-ok" : "bar-not-ok"}`}
                        style={{ width: `${probPercent}%` }}
                      />
                    </div>
                    <span className="soc-score-num font-mono">{probPercent}%</span>
                  </div>
                </div>
              </div>

              {/* Inspect Action */}
              <div className="soc-quick-action-col">
                <button
                  type="button"
                  className="soc-btn-inspect"
                  onClick={() => onSelectDomain(r.domain)}
                  title={`Inspect ${r.domain} in deep triage workbench`}
                >
                  <span>Inspect</span>
                  <span className="soc-inspect-arrow">→</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
