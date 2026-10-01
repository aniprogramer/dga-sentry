import { useState, useRef, useMemo, useCallback, Fragment } from "react";
import {
  predictBatch,
  type PredictionResult,
  ApiError,
} from "../api/client";
import {
  extractDomainsFromText,
  extractDomainsFromCSV,
} from "../utils/domainExtractor";

const CHUNK_SIZE = 50;
const PAGE_SIZE = 25;

const SAMPLE_DNS_LOG = `# Zeek DNS Log Sample
#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto trans_id rcode query
1712345601.123 C12345 192.168.1.100 54321 8.8.8.8 53 udp 1001 0 google.com
1712345602.456 C12346 192.168.1.101 54322 8.8.8.8 53 udp 1002 0 vxzklpmnq123.biz
1712345603.789 C12347 192.168.1.102 54323 8.8.8.8 53 udp 1003 0 brothernerveplacebringconsult.com
1712345604.012 C12348 192.168.1.103 54324 8.8.8.8 53 udp 1004 0 cloudflare.com
1712345605.345 C12349 192.168.1.104 54325 8.8.8.8 53 udp 1005 0 msnbc.com
1712345606.678 C12350 192.168.1.105 54326 8.8.8.8 53 udp 1006 0 xjkqwrtzp129.info
1712345607.901 C12351 192.168.1.106 54327 8.8.8.8 53 udp 1007 0 github.com
1712345608.234 C12352 192.168.1.107 54328 8.8.8.8 53 udp 1008 0 sistertownground.com
1712345609.567 C12353 192.168.1.108 54329 8.8.8.8 53 udp 1009 0 apple.com
1712345610.890 C12354 192.168.1.109 54330 8.8.8.8 53 udp 1010 0 ybnpqklwzx089.cc
`;

function sanitizeCsvField(field: string | number | null | undefined): string {
  if (field === null || field === undefined) return '""';
  let str = String(field);

  // Prevent CSV injection: if cell starts with =, +, -, @, prefix with a single quote
  if (/^[=+\-@]/.test(str)) {
    str = `'${str}`;
  }

  // Escape inner quotes
  str = str.replace(/"/g, '""');
  return `"${str}"`;
}

export default function BulkAudit() {
  const [inputMode, setInputMode] = useState<"upload" | "text">("upload");
  const [rawText, setRawText] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [extractedDomains, setExtractedDomains] = useState<string[]>([]);
  const [isAuditing, setIsAuditing] = useState(false);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [auditResults, setAuditResults] = useState<PredictionResult[]>([]);
  const [resolveDns, setResolveDns] = useState(false);
  const [filterTier, setFilterTier] = useState<"all" | "safe" | "suspicious" | "malicious">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const abortRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Handle Raw Text Change
  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setRawText(val);
    const parsed = extractDomainsFromText(val);
    setExtractedDomains(parsed);
  };

  // Load Sample
  const handleLoadSample = () => {
    setInputMode("text");
    setRawText(SAMPLE_DNS_LOG);
    const parsed = extractDomainsFromText(SAMPLE_DNS_LOG);
    setExtractedDomains(parsed);
    setFileName(null);
  };

  // Process File
  const processFile = (file: File) => {
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (!content) return;

      let parsed: string[] = [];
      if (file.name.endsWith(".csv")) {
        parsed = extractDomainsFromCSV(content);
      } else {
        parsed = extractDomainsFromText(content);
      }
      setExtractedDomains(parsed);
      setRawText("");
    };
    reader.readAsText(file);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processFile(file);
    }
  };

  // Reset inputs
  const handleClear = () => {
    setRawText("");
    setFileName(null);
    setExtractedDomains([]);
    setAuditResults([]);
    setProgress({ current: 0, total: 0 });
    setAuditError(null);
    setResolveDns(false);
    setCurrentPage(1);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Run Bulk Audit with chunking and rate-limit backoff
  const handleStartAudit = async () => {
    if (extractedDomains.length === 0 || isAuditing) return;

    setIsAuditing(true);
    setAuditError(null);
    setAuditResults([]);
    setProgress({ current: 0, total: extractedDomains.length });
    abortRef.current = false;

    const allResults: PredictionResult[] = [];
    const chunks: string[][] = [];

    for (let i = 0; i < extractedDomains.length; i += CHUNK_SIZE) {
      chunks.push(extractedDomains.slice(i, i + CHUNK_SIZE));
    }

    try {
      for (let i = 0; i < chunks.length; i++) {
        if (abortRef.current) break;

        const chunk = chunks[i];
        let success = false;
        let retries = 0;

        while (!success && retries < 3 && !abortRef.current) {
          try {
            const resp = await predictBatch(chunk, resolveDns);
            allResults.push(...resp.predictions);
            setAuditResults([...allResults]);
            setProgress({
              current: allResults.length,
              total: extractedDomains.length,
            });
            success = true;

            // Small pace delay to stay within rate limits (15 batch reqs/min)
            if (i < chunks.length - 1 && !abortRef.current) {
              await new Promise((resolve) => setTimeout(resolve, 250));
            }
          } catch (err) {
            retries++;
            if (err instanceof ApiError && err.statusCode === 429) {
              // Rate limited - wait for retryAfter or backoff
              const waitSeconds = err.retryAfter || 2;
              setAuditError(
                `Rate limit encountered. Pacing requests... retrying in ${waitSeconds}s (attempt ${retries}/3)`,
              );
              await new Promise((resolve) => setTimeout(resolve, waitSeconds * 1000));
            } else {
              if (retries >= 3) throw err;
              await new Promise((resolve) => setTimeout(resolve, 1000));
            }
          }
        }
      }
    } catch (err) {
      setAuditError(
        err instanceof Error ? err.message : "An error occurred during bulk audit.",
      );
    } finally {
      setIsAuditing(false);
      abortRef.current = false;
    }
  };

  const handleCancelAudit = () => {
    abortRef.current = true;
    setIsAuditing(false);
  };

  // Executive Metrics
  const summaryMetrics = useMemo(() => {
    let safeCount = 0;
    let suspiciousCount = 0;
    let maliciousCount = 0;
    const familyCounts: Record<string, number> = {};

    for (const r of auditResults) {
      if (r.risk_tier === "safe") safeCount++;
      else if (r.risk_tier === "suspicious") suspiciousCount++;
      else if (r.risk_tier === "malicious") maliciousCount++;

      if (r.family && r.family !== "legitimate") {
        familyCounts[r.family] = (familyCounts[r.family] || 0) + 1;
      }
    }

    const sortedFamilies = Object.entries(familyCounts).sort(
      ([, a], [, b]) => b - a,
    );

    return {
      total: auditResults.length,
      safeCount,
      suspiciousCount,
      maliciousCount,
      families: sortedFamilies,
    };
  }, [auditResults]);

  // Filtered & Paginated Results
  const filteredResults = useMemo(() => {
    return auditResults.filter((r) => {
      const matchesTier =
        filterTier === "all" ? true : r.risk_tier === filterTier;
      const matchesSearch =
        searchQuery.trim() === ""
          ? true
          : r.domain.toLowerCase().includes(searchQuery.toLowerCase().trim());
      return matchesTier && matchesSearch;
    });
  }, [auditResults, filterTier, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / PAGE_SIZE));
  const paginatedResults = useMemo(() => {
    const start = (currentPage - 1) * PAGE_SIZE;
    return filteredResults.slice(start, start + PAGE_SIZE);
  }, [filteredResults, currentPage]);

  // Export to CSV
  const handleExportCSV = useCallback(() => {
    if (auditResults.length === 0) return;

    const headers = [
      "domain",
      "risk_tier",
      "action",
      "dns_status",
      "dns_resolved_ips",
      "label",
      "confidence",
      "malicious_probability",
      "family",
      "family_confidence",
      "top_risk_factors",
      "dns_threat_summary",
    ];

    const rows = auditResults.map((r) => {
      const topRisksStr = (r.top_risk_factors || [])
        .map((f) => `${f.display_name}: +${f.impact.toFixed(4)}`)
        .join("; ");

      const ipsStr = (r.dns_enrichment?.ip_addresses || []).join("; ");

      return [
        sanitizeCsvField(r.domain),
        sanitizeCsvField(r.risk_tier),
        sanitizeCsvField(r.action),
        sanitizeCsvField(r.dns_enrichment?.operational_status || "N/A"),
        sanitizeCsvField(ipsStr || "None"),
        sanitizeCsvField(r.label),
        sanitizeCsvField(r.confidence),
        sanitizeCsvField(r.malicious_probability),
        sanitizeCsvField(r.family || "N/A"),
        sanitizeCsvField(r.family_confidence !== null ? r.family_confidence : "N/A"),
        sanitizeCsvField(topRisksStr),
        sanitizeCsvField(r.dns_enrichment?.threat_summary || "N/A"),
      ].join(",");
    });

    const csvContent = [headers.join(","), ...rows].join("\r\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    link.setAttribute("href", url);
    link.setAttribute("download", `domain_audit_report_${timestamp}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, [auditResults]);

  const progressPercent =
    progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;

  return (
    <div className="bulk-audit-container">
      {/* Section Header */}
      <div className="bulk-header">
        <div>
          <h2 className="bulk-title">Bulk DNS Log & Telemetry Audit</h2>
          <p className="bulk-subtitle">
            Ingest DNS query logs, proxy captures, or CSV domain exports. Vectorized
            batch scoring with TreeSHAP marginal attribution and family attribution.
          </p>
        </div>
        <button
          type="button"
          className="sample-btn"
          onClick={handleLoadSample}
          disabled={isAuditing}
        >
          <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path d="M7 3a1 1 0 000 2h6a1 1 0 100-2H7zM4 7a1 1 0 011-1h10a1 1 0 110 2H5a1 1 0 01-1-1zM2 11a2 2 0 012-2h12a2 2 0 012 2v4a2 2 0 01-2 2H4a2 2 0 01-2-2v-4z" />
          </svg>
          Load Sample DNS Log
        </button>
      </div>

      {/* Input Mode Selector */}
      <div className="bulk-mode-toggle">
        <button
          type="button"
          className={`toggle-tab ${inputMode === "upload" ? "active" : ""}`}
          onClick={() => setInputMode("upload")}
          disabled={isAuditing}
        >
          <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path
              fillRule="evenodd"
              d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z"
              clipRule="evenodd"
            />
          </svg>
          File Upload (.csv, .txt, .log)
        </button>
        <button
          type="button"
          className={`toggle-tab ${inputMode === "text" ? "active" : ""}`}
          onClick={() => setInputMode("text")}
          disabled={isAuditing}
        >
          <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
            <path
              fillRule="evenodd"
              d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 3a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm0 4a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm0 4a1 1 0 011-1h4a1 1 0 110 2H7a1 1 0 01-1-1z"
              clipRule="evenodd"
            />
          </svg>
          Paste Raw Text / Domains
        </button>
      </div>

      {/* Input Card */}
      <div className="bulk-input-card">
        {inputMode === "upload" ? (
          <div
            className={`file-dropzone ${isDragging ? "dragging" : ""}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,.txt,.log"
              style={{ display: "none" }}
              onChange={handleFileChange}
              disabled={isAuditing}
            />
            <div className="dropzone-content">
              <div className="dropzone-icon">
                <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.233-2.33 3 3 0 013.758 3.848A3.752 3.752 0 0118 19.5H6.75z" />
                </svg>
              </div>
              {fileName ? (
                <div className="file-info">
                  <span className="file-name">{fileName}</span>
                  <span className="file-extracted">
                    Extracted {extractedDomains.length} unique domain
                    {extractedDomains.length === 1 ? "" : "s"}
                  </span>
                </div>
              ) : (
                <div className="dropzone-text">
                  <span className="dropzone-primary">
                    Drop DNS log or CSV file here, or browse
                  </span>
                  <span className="dropzone-hint">
                    Supports Zeek DNS logs, firewall CSVs, Pi-hole exports, or plain text lists
                  </span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="textarea-container">
            <textarea
              className="bulk-textarea"
              placeholder="Paste domain names, URLs, or query logs (one per line, comma, or space-separated)..."
              value={rawText}
              onChange={handleTextChange}
              disabled={isAuditing}
              rows={6}
            />
            {extractedDomains.length > 0 && (
              <div className="domain-count-badge">
                {extractedDomains.length} unique domain
                {extractedDomains.length === 1 ? "" : "s"} detected
              </div>
            )}
          </div>
        )}

        {/* Action Controls */}
        <div className="bulk-action-bar">
          <div className="bulk-status-meta">
            {extractedDomains.length > 0 && (
              <span className="ready-indicator">
                Ready to audit: <strong>{extractedDomains.length}</strong> domains (in{" "}
                {Math.ceil(extractedDomains.length / CHUNK_SIZE)} chunk
                {Math.ceil(extractedDomains.length / CHUNK_SIZE) === 1 ? "" : "s"})
              </span>
            )}
          </div>
          <div className="bulk-buttons">
            <label className="bulk-dns-toggle-label">
              <input
                type="checkbox"
                checked={resolveDns}
                onChange={(e) => setResolveDns(e.target.checked)}
                disabled={isAuditing}
                className="bulk-dns-checkbox"
              />
              <span className="bulk-dns-text">Resolve Live DNS (Slower)</span>
            </label>
            <button
              type="button"
              className="bulk-clear-btn"
              onClick={handleClear}
              disabled={isAuditing || (extractedDomains.length === 0 && !fileName)}
            >
              Clear
            </button>
            {isAuditing ? (
              <button
                type="button"
                className="bulk-cancel-btn"
                onClick={handleCancelAudit}
              >
                Cancel Audit
              </button>
            ) : (
              <button
                type="button"
                className="bulk-start-btn"
                onClick={handleStartAudit}
                disabled={extractedDomains.length === 0}
              >
                <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clipRule="evenodd" />
                </svg>
                Run Audit
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        {isAuditing && (
          <div className="audit-progress-section">
            <div className="progress-labels">
              <span className="progress-state">
                Auditing domains... {progress.current} / {progress.total}
              </span>
              <span className="progress-pct">{progressPercent}%</span>
            </div>
            <div className="progress-track">
              <div
                className="progress-fill"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>
        )}

        {auditError && (
          <div className="bulk-error-alert" role="alert">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span>{auditError}</span>
          </div>
        )}
      </div>

      {/* Audit Executive Summary */}
      {auditResults.length > 0 && (
        <div className="bulk-summary-section">
          <div className="summary-cards-grid">
            <div className="summary-card total">
              <span className="card-label">Total Audited</span>
              <span className="card-value">{summaryMetrics.total}</span>
              <span className="card-subtext">100% of input</span>
            </div>
            <div className="summary-card safe">
              <span className="card-label">Safe (Allow)</span>
              <span className="card-value green">{summaryMetrics.safeCount}</span>
              <span className="card-subtext">
                {Math.round((summaryMetrics.safeCount / summaryMetrics.total) * 100)}%
              </span>
            </div>
            <div className="summary-card suspicious">
              <span className="card-label">Suspicious (Monitor)</span>
              <span className="card-value amber">{summaryMetrics.suspiciousCount}</span>
              <span className="card-subtext">
                {Math.round((summaryMetrics.suspiciousCount / summaryMetrics.total) * 100)}%
              </span>
            </div>
            <div className="summary-card malicious">
              <span className="card-label">Malicious (Block)</span>
              <span className="card-value red">{summaryMetrics.maliciousCount}</span>
              <span className="card-subtext">
                {Math.round((summaryMetrics.maliciousCount / summaryMetrics.total) * 100)}%
              </span>
            </div>
          </div>

          {/* Malware Family Breakdown */}
          {summaryMetrics.families.length > 0 && (
            <div className="family-breakdown-card">
              <h4 className="family-title">Detected Threat Families</h4>
              <div className="family-tags-list">
                {summaryMetrics.families.map(([family, count]) => (
                  <span key={family} className="family-tag">
                    <span className="family-name">{family}</span>
                    <span className="family-badge">{count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Results Table Section */}
      {auditResults.length > 0 && (
        <div className="bulk-results-card">
          <div className="table-controls-bar">
            {/* Filter Tabs */}
            <div className="tier-filter-tabs">
              <button
                type="button"
                className={`filter-btn ${filterTier === "all" ? "active" : ""}`}
                onClick={() => { setFilterTier("all"); setCurrentPage(1); }}
              >
                All ({auditResults.length})
              </button>
              <button
                type="button"
                className={`filter-btn red ${filterTier === "malicious" ? "active" : ""}`}
                onClick={() => { setFilterTier("malicious"); setCurrentPage(1); }}
              >
                Malicious ({summaryMetrics.maliciousCount})
              </button>
              <button
                type="button"
                className={`filter-btn amber ${filterTier === "suspicious" ? "active" : ""}`}
                onClick={() => { setFilterTier("suspicious"); setCurrentPage(1); }}
              >
                Suspicious ({summaryMetrics.suspiciousCount})
              </button>
              <button
                type="button"
                className={`filter-btn green ${filterTier === "safe" ? "active" : ""}`}
                onClick={() => { setFilterTier("safe"); setCurrentPage(1); }}
              >
                Safe ({summaryMetrics.safeCount})
              </button>
            </div>

            {/* Search & Export */}
            <div className="table-right-actions">
              <input
                type="text"
                className="domain-search-input"
                placeholder="Search domain..."
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
              />
              <button
                type="button"
                className="export-csv-btn"
                onClick={handleExportCSV}
              >
                <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
                </svg>
                Export CSV
              </button>
            </div>
          </div>

          {/* Table */}
          <div className="table-wrapper">
            <table className="bulk-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Risk Tier</th>
                  <th>Action</th>
                  <th>DNS State</th>
                  <th>Malicious Prob</th>
                  <th>Threat Attribution</th>
                  <th>Top Risk Factor</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {paginatedResults.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="empty-table-cell">
                      No domains match the selected filter.
                    </td>
                  </tr>
                ) : (
                  paginatedResults.map((r) => {
                    const isExpanded = expandedRow === r.domain;
                    const topFactor = r.top_risk_factors?.[0];

                    return (
                      <Fragment key={r.domain}>
                        <tr
                          className={`bulk-row ${isExpanded ? "expanded" : ""}`}
                        >
                          <td className="domain-cell">
                            <code>{r.domain}</code>
                          </td>
                          <td>
                            <span className={`tier-badge ${r.risk_tier}`}>
                              {r.risk_tier.toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <span className={`action-badge ${r.action}`}>
                              {r.action.toUpperCase()}
                            </span>
                          </td>
                          <td className="dns-cell">
                            {r.dns_enrichment ? (
                              <span
                                className={`dns-table-badge ${
                                  r.dns_enrichment.operational_status === "active"
                                    ? r.risk_tier === "malicious"
                                      ? "c2-active"
                                      : "safe-active"
                                    : r.dns_enrichment.operational_status === "nxdomain"
                                    ? "nxdomain"
                                    : "other"
                                }`}
                                title={r.dns_enrichment.threat_summary}
                              >
                                {r.dns_enrichment.operational_status === "active"
                                  ? r.risk_tier === "malicious"
                                    ? "C2 ACTIVE"
                                    : "ACTIVE"
                                  : r.dns_enrichment.operational_status.toUpperCase()}
                              </span>
                            ) : (
                              <span className="none-label">—</span>
                            )}
                          </td>
                          <td>
                            <div className="prob-bar-container">
                              <div className="prob-track">
                                <div
                                  className={`prob-fill ${r.risk_tier}`}
                                  style={{
                                    width: `${Math.round(r.malicious_probability * 100)}%`,
                                  }}
                                />
                              </div>
                              <span className="prob-text">
                                {(r.malicious_probability * 100).toFixed(1)}%
                              </span>
                            </div>
                          </td>
                          <td className="family-cell">
                            {r.family && r.family !== "legitimate" ? (
                              <span className="threat-family-badge">
                                <strong>{r.family}</strong>
                                {r.family_confidence !== null && (
                                  <span className="fam-conf">
                                    {" "}
                                    ({Math.round(r.family_confidence * 100)}%)
                                  </span>
                                )}
                              </span>
                            ) : (
                              <span className="clean-label">Legitimate</span>
                            )}
                          </td>
                          <td className="factor-cell">
                            {topFactor ? (
                              <span className="factor-pill">
                                {topFactor.display_name}: +{topFactor.impact.toFixed(2)}
                              </span>
                            ) : (
                              <span className="none-label">—</span>
                            )}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="expand-btn"
                              onClick={() =>
                                setExpandedRow(isExpanded ? null : r.domain)
                              }
                              aria-label="Toggle feature attributions"
                              title="Toggle feature attributions"
                            >
                              {isExpanded ? "▲" : "▼"}
                            </button>
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr className="expanded-detail-row">
                            <td colSpan={8}>
                              <div className="detail-panel">
                                {r.dns_enrichment && (
                                  <div className="detail-section">
                                    <h5 className="detail-heading">
                                      Live DNS & Operational State ({r.dns_enrichment.response_time_ms} ms)
                                    </h5>
                                    <div
                                      className={`dns-summary-callout ${
                                        r.dns_enrichment.operational_status === "active" &&
                                        r.risk_tier === "malicious"
                                          ? "alert-danger"
                                          : "alert-info"
                                      }`}
                                    >
                                      {r.dns_enrichment.threat_summary}
                                    </div>
                                    {r.dns_enrichment.ip_addresses.length > 0 && (
                                      <div className="record-pills" style={{ marginTop: "0.5rem" }}>
                                        <span className="record-label" style={{ marginRight: "0.5rem" }}>
                                          IPs:
                                        </span>
                                        {r.dns_enrichment.ip_addresses.map((ip) => (
                                          <code key={ip} className="ip-pill">
                                            {ip}
                                          </code>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )}

                                <div className="detail-section">
                                  <h5 className="detail-heading">
                                    Top Risk Drivers (TreeSHAP Positive Marginal Attributions)
                                  </h5>
                                  {r.top_risk_factors && r.top_risk_factors.length > 0 ? (
                                    <div className="risk-factors-grid">
                                      {r.top_risk_factors.map((rf) => (
                                        <div key={rf.feature} className="risk-factor-item">
                                          <div className="rf-header">
                                            <span className="rf-name">{rf.display_name}</span>
                                            <span className="rf-impact">+{rf.impact.toFixed(4)}</span>
                                          </div>
                                          <div className="rf-val">Value: {rf.value.toFixed(4)}</div>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <p className="no-factors-text">
                                      No positive risk drivers. Domain features are predominantly benign.
                                    </p>
                                  )}
                                </div>

                                <div className="detail-section">
                                  <h5 className="detail-heading">All Lexical Feature Values</h5>
                                  <div className="lexical-features-grid">
                                    {Object.entries(r.features).map(([key, val]) => (
                                      <div key={key} className="lexical-item">
                                        <span className="lex-key">{key}</span>
                                        <span className="lex-val">{val.toFixed(4)}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination-bar">
              <span className="pagination-info">
                Showing {(currentPage - 1) * PAGE_SIZE + 1}–
                {Math.min(currentPage * PAGE_SIZE, filteredResults.length)} of{" "}
                {filteredResults.length} domains
              </span>
              <div className="pagination-buttons">
                <button
                  type="button"
                  className="page-btn"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </button>
                <span className="page-indicator">
                  Page {currentPage} of {totalPages}
                </span>
                <button
                  type="button"
                  className="page-btn"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
