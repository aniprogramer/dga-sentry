import { useState, useRef } from "react";

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
  const inputRef = useRef<HTMLInputElement>(null);

  const validateDomain = (d: string): boolean => {
    const trimmed = d.trim();
    if (!trimmed) {
      setError("Please enter a domain name");
      return false;
    }
    if (/\s/.test(trimmed)) {
      setError("Domain cannot contain whitespace");
      return false;
    }
    if (trimmed.length > 253) {
      setError("Domain exceeds RFC limit (max 253 characters)");
      return false;
    }
    setError("");
    return true;
  };

  const handleSingleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateDomain(domain)) {
      onSubmitSingle(domain.trim().toLowerCase(), resolveDns);
    }
  };

  const handleBatchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const domains = batchText
      .split("\n")
      .map((d) => d.trim().toLowerCase())
      .filter((d) => d.length > 0 && d.length <= 253 && !/\s/.test(d));

    if (domains.length === 0) {
      setError("Please enter at least one valid domain");
      return;
    }
    if (domains.length > 100) {
      setError("Maximum 100 domains per batch");
      return;
    }
    setError("");
    onSubmitBatch(domains, resolveDns);
  };

  const handleSelectSample = (sampleVal: string) => {
    setDomain(sampleVal);
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
                if (error) setError("");
              }}
              placeholder="Enter domain name, FQDN, or Punycode (e.g. google.com)"
              className="soc-terminal-input"
              disabled={isLoading}
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="submit"
              className="soc-btn-primary"
              disabled={isLoading || !domain.trim()}
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
            placeholder={"Paste domains, one per line:\ngoogle.com\nxjkqwrtzp.info\namazon.com"}
            className="soc-terminal-textarea"
            disabled={isLoading}
            rows={5}
            spellCheck={false}
          />
          <div className="soc-batch-footer">
            <span className="soc-batch-count">
              {batchText.split("\n").filter((d) => d.trim()).length} domain(s) staged
            </span>
            <button
              type="submit"
              className="soc-btn-primary"
              disabled={isLoading || !batchText.trim()}
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
                  <span className="soc-bolt-icon">⚡</span>
                  <span>Run Test (Sample Batch)</span>
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
