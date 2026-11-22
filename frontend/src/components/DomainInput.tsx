import { useState, useRef, useMemo, useEffect } from "react";
import {
  MAX_BATCH_SIZE,
  MESSAGES,
  NOTE_MESSAGES,
  WARNING_MESSAGES,
  normalizeAndValidate,
  parseBatch,
} from "../lib/domain";

const DEBOUNCE_MS = 600;

interface DomainInputProps {
  onSubmitSingle: (domain: string, resolveDns?: boolean) => void;
  onSubmitBatch: (domains: string[], resolveDns?: boolean) => void;
  isLoading: boolean;
  onRunTest?: () => void;
  isTesting?: boolean;
}

const QUICK_SAMPLES = [
  { label: "Google.com (Benign)", value: "google.com", dga: false },
  { label: "Emotet C2", value: "xjkqwrtzp129.info", dga: true },
  { label: "Matsnu Wordlist", value: "brothernerveplacebringconsult.com", dga: true },
  { label: "Punycode IDN", value: "xn--80abnkkiqomm6gva.xn--p1ai", dga: false },
];

export default function DomainInput({
  onSubmitSingle,
  onSubmitBatch,
  isLoading,
  onRunTest,
  isTesting = false,
}: DomainInputProps) {
  const [domain, setDomain] = useState("");
  const [batchMode, setBatchMode] = useState(false);
  const [batchText, setBatchText] = useState("");
  const [resolveDns, setResolveDns] = useState(false);
  const [error, setError] = useState("");
  const [showFeedback, setShowFeedback] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const trimmed = domain.trim();
  const result = useMemo(() => (trimmed ? normalizeAndValidate(domain) : null), [domain, trimmed]);
  const isInvalid = result !== null && !result.ok;
  const batchLines = useMemo(() => parseBatch(batchText), [batchText]);
  const batchValid = batchLines.filter((l) => l.status === "valid" || l.status === "normalized");
  const batchTooMany = batchValid.length > MAX_BATCH_SIZE;

  // Do not show errors on the first keystroke: wait for a pause (or blur/submit).
  useEffect(() => {
    if (!trimmed) return;
    const t = setTimeout(() => setShowFeedback(true), DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [domain, trimmed]);

  const handleSingleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!result) {
      setShowFeedback(true);
      return;
    }
    if (!result.ok) {
      setShowFeedback(true);
      return;
    }
    setShowFeedback(false);
    setDomain("");
    onSubmitSingle(trimmed, resolveDns);
  };

  const handleBatchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (batchValid.length === 0) {
      setError("Please enter at least one valid domain");
      return;
    }
    if (batchTooMany) {
      setError(MESSAGES.TOO_MANY_DOMAINS);
      return;
    }
    setError("");
    onSubmitBatch(batchValid.map((l) => l.raw), resolveDns);
  };

  const handleSelectSample = (sampleVal: string) => {
    setDomain(sampleVal);
    setShowFeedback(false);
    setError("");
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  return (
    <div className="soc-console-card">
      {/* Console Subheader / Mode Switch */}
      <div className="soc-console-header">
        <div className="soc-console-title">
          <span className="soc-terminal-prompt">❯</span>
          <span className="soc-console-label">Target Domain Console</span>
        </div>
        <div className="soc-mode-pills">
          <button
            type="button"
            className={`soc-mode-btn ${!batchMode ? "active" : ""}`}
            onClick={() => {
              setBatchMode(false);
              setError("");
            }}
            id="single-mode-btn"
          >
            Single Domain
          </button>
          <button
            type="button"
            className={`soc-mode-btn ${batchMode ? "active" : ""}`}
            onClick={() => {
              setBatchMode(true);
              setError("");
            }}
            id="batch-mode-btn"
          >
            Batch Check
          </button>
        </div>
      </div>

      {/* Single Mode Input */}
      {!batchMode ? (
        <form onSubmit={handleSingleSubmit} className="soc-input-form">
          <div className="soc-command-bar">
            <span className="soc-command-prompt">❯</span>
            <input
              ref={inputRef}
              id="domain-input"
              type="text"
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setShowFeedback(false);
              }}
              onBlur={() => trimmed && setShowFeedback(true)}
              aria-invalid={showFeedback && isInvalid}
              aria-describedby="domain-feedback"
              placeholder="Enter domain name, FQDN, or Punycode (e.g. google.com)"
              className="soc-terminal-input"
              disabled={isLoading}
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="submit"
              className="soc-btn-primary"
              disabled={isLoading || !trimmed || isInvalid}
              id="check-domain-btn"
            >
              {isLoading ? (
                <span className="soc-spinner" />
              ) : (
                <>
                  <span>Analyze</span>
                  <kbd className="soc-kbd-hint">↵</kbd>
                </>
              )}
            </button>
          </div>
          <div id="domain-feedback" className="soc-feedback" role="status" aria-live="polite">
            {showFeedback && result && !result.ok && (
              <span className="soc-feedback-error" data-code={result.code}>
                {result.message}
              </span>
            )}
            {showFeedback && result?.ok && (
              <>
                {result.info.notes.map((n) => (
                  <span key={n} className="soc-feedback-note">
                    {n === "EXTRACTED_FROM_URL"
                      ? `Analyzing ${result.info.display} from the URL you pasted. `
                      : `${NOTE_MESSAGES[n]} `}
                  </span>
                ))}
                {result.info.warnings.map((w) => (
                  <span key={w} className="soc-feedback-warning">
                    {WARNING_MESSAGES[w]}{" "}
                  </span>
                ))}
              </>
            )}
          </div>
        </form>
      ) : (
        /* Batch Mode Textarea */
        <form onSubmit={handleBatchSubmit} className="soc-input-form">
          <textarea
            id="batch-input"
            value={batchText}
            onChange={(e) => {
              setBatchText(e.target.value);
              if (error) setError("");
            }}
            aria-describedby="batch-status-list"
            placeholder={"Paste domains, one per line:\ngoogle.com\nxjkqwrtzp.info\namazon.com"}
            className="soc-terminal-textarea"
            disabled={isLoading}
            rows={5}
            spellCheck={false}
          />
          {batchLines.length > 0 && (
            <ul id="batch-status-list" className="soc-batch-status" aria-label="Batch input status">
              {batchLines.map((l, i) => (
                <li key={i} data-status={l.status}>
                  <code>{l.raw}</code>{" "}
                  {l.status === "valid" && <span>valid</span>}
                  {l.status === "normalized" && <span>normalized to {l.ascii}</span>}
                  {l.status === "invalid" && <span>invalid: {l.message}</span>}
                  {l.status === "duplicate" && <span>duplicate removed</span>}
                </li>
              ))}
            </ul>
          )}
          {batchTooMany && (
            <div className="soc-feedback-error" role="alert">{MESSAGES.TOO_MANY_DOMAINS}</div>
          )}
          <div className="soc-batch-footer">
            <span className="soc-batch-count">
              {batchValid.length} valid of {batchLines.length} entered (max {MAX_BATCH_SIZE})
            </span>
            <button
              type="submit"
              className="soc-btn-primary"
              disabled={isLoading || batchValid.length === 0 || batchTooMany}
              id="batch-submit-btn"
            >
              {isLoading ? (
                <span className="soc-spinner" />
              ) : (
                <>
                  <span>Analyze</span>
                  <kbd className="soc-kbd-hint">↵</kbd>
                </>
              )}
            </button>
          </div>
        </form>
      )}

      {/* Metadata & Quick Options Toolbar */}
      <div className="soc-toolbar">
        {/* Left Toolbar Controls */}
        <div className="soc-toolbar-left">
          {/* Live DNS Resolver Toggle */}
          <label className="soc-checkbox-label">
            <input
              type="checkbox"
              checked={resolveDns}
              onChange={(e) => setResolveDns(e.target.checked)}
              disabled={isLoading}
              className="soc-checkbox"
            />
            <span className="soc-checkbox-text">
              Resolve Live DNS &amp; C2 State
              <span className="soc-checkbox-sub"> (A / AAAA / NS telemetry)</span>
            </span>
          </label>

          {/* Quick Sample Chips */}
          {!batchMode && (
            <div className="soc-sample-chips">
              <span className="soc-chips-label">Samples:</span>
              {QUICK_SAMPLES.map((sample) => (
                <button
                  key={sample.value}
                  type="button"
                  className={`soc-sample-chip ${sample.dga ? "chip-threat" : "chip-benign"}`}
                  onClick={() => handleSelectSample(sample.value)}
                  disabled={isLoading}
                >
                  {sample.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Right Toolbar: Run Test Button */}
        {onRunTest && (
          <div className="soc-toolbar-right">
            <button
              type="button"
              className="soc-btn-test"
              onClick={onRunTest}
              disabled={isLoading || isTesting}
              id="run-test-btn"
              title="Run 6 non-repeating mixed sample domains (benign vs DGA botnet)"
            >
              {isTesting ? (
                <>
                  <span className="soc-spinner small" />
                  <span>Running Test...</span>
                </>
              ) : (
                <>
                  <svg
                    className="soc-test-icon"
                    width="14"
                    height="14"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2" />
                    <path d="M8.5 2h7" />
                    <path d="M7 16h10" />
                  </svg>
                  <span className="soc-btn-test-text">Run Test</span>
                  <span className="soc-btn-test-badge">(Sample Batch)</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div className="soc-alert-error" role="alert">
          <span className="soc-alert-icon">⚠</span>
          <span>{error}</span>
        </div>
      )}
    </div>
  );
}
