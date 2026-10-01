import { useState } from "react";
import type { PredictionResult } from "../api/client";

interface PredictionResultProps {
  result: PredictionResult | null;
  isLoading: boolean;
}

const FEATURE_NAMES_ORDER = [
  "length",
  "entropy",
  "n_gram_score",
  "max_consonant_run",
  "vowel_consonant_ratio",
  "digit_ratio",
  "hex_char_ratio",
  "gini_index",
  "unique_char_ratio",
  "digit_first",
  "segmented_word_count",
  "valid_word_ratio",
  "vowel_consonant_transition_rate",
];

const FEATURE_DISPLAY_TITLES: Record<string, string> = {
  length: "Domain Length",
  entropy: "Shannon Entropy",
  n_gram_score: "Bigram Log-Likelihood",
  max_consonant_run: "Max Consonant Run",
  vowel_consonant_ratio: "Vowel/Consonant Ratio",
  digit_ratio: "Digit Ratio",
  hex_char_ratio: "Hexadecimal Ratio",
  gini_index: "Gini Impurity Index",
  unique_char_ratio: "Unique Character Ratio",
  digit_first: "Starts with Digit",
  segmented_word_count: "Dictionary Words",
  valid_word_ratio: "Dictionary Char Ratio",
  vowel_consonant_transition_rate: "V/C Transition Rate",
};

export default function PredictionResultCard({
  result,
  isLoading,
}: PredictionResultProps) {
  const [copied, setCopied] = useState(false);

  if (isLoading) {
    return (
      <div className="soc-triage-card loading">
        <div className="soc-scanning-wrapper">
          <div className="soc-radar-scanner" />
          <div className="soc-scanning-text">
            <span className="soc-pulse-dot" />
            EVALUATING LEXICAL TENSORS &amp; OPERATING THRESHOLDS...
          </div>
        </div>
      </div>
    );
  }

  if (!result) return null;

  const isMalicious = result.risk_tier === "malicious" || result.label === "malicious";
  const isSuspicious = result.risk_tier === "suspicious";
  const tier = isMalicious ? "malicious" : isSuspicious ? "suspicious" : "safe";

  const probPercent = (result.malicious_probability * 100).toFixed(1);
  const actionText = isMalicious
    ? "BLOCK / MALICIOUS"
    : isSuspicious
    ? "MONITOR / SUSPICIOUS"
    : "ALLOW / SAFE";

  const handleCopy = () => {
    navigator.clipboard.writeText(result.domain);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Operational status computation
  let opStatusText = "STATIC INFERENCE (DNS BYPASS)";
  let opStatusClass = "op-static";
  let opIpSummary = "";

  if (result.dns_enrichment) {
    const dns = result.dns_enrichment;
    if (dns.operational_status === "active") {
      opStatusText = isMalicious ? "ACTIVE C2 SERVER" : "ACTIVE HOST";
      opStatusClass = isMalicious ? "op-c2" : "op-active";
      opIpSummary = dns.ip_addresses.length > 0 ? `(${dns.ip_addresses[0]}${dns.ip_addresses.length > 1 ? ` +${dns.ip_addresses.length - 1}` : ""})` : "";
    } else if (dns.operational_status === "nxdomain") {
      opStatusText = "NXDOMAIN (DORMANT)";
      opStatusClass = "op-nxdomain";
    } else if (dns.operational_status === "timeout") {
      opStatusText = "RESOLUTION TIMEOUT";
      opStatusClass = "op-timeout";
    } else {
      opStatusText = dns.operational_status.toUpperCase();
      opStatusClass = "op-warning";
    }
  }

  return (
    <div className={`soc-triage-card tier-${tier}`}>
      {/* 1. Incident Triage Verdict Header */}
      <div className="soc-triage-header">
        <div className="soc-header-left">
          <span className="soc-meta-tag">TARGET FQDN</span>
          <div className="soc-target-fqdn">
            <code className="soc-domain-text">{result.domain}</code>
            <button
              type="button"
              className="soc-copy-btn"
              onClick={handleCopy}
              title="Copy FQDN"
            >
              {copied ? "COPIED" : "COPY"}
            </button>
          </div>
        </div>

        <div className="soc-header-right">
          <div className={`soc-verdict-badge badge-${tier}`}>
            <span className="soc-badge-icon">
              {isMalicious ? "☒" : isSuspicious ? "⚠" : "☑"}
            </span>
            <span className="soc-badge-text">{actionText}</span>
          </div>
        </div>
      </div>

      {/* 2. Core Metrics Matrix (4-Column Enterprise Rail) */}
      <div className="soc-metrics-matrix">
        {/* Metric 1: Malicious Probability */}
        <div className="soc-metric-box">
          <span className="soc-metric-label">MALICIOUS PROBABILITY</span>
          <div className="soc-metric-row">
            <span className={`soc-metric-value text-${tier}`}>
              {probPercent}%
            </span>
            <span className="soc-metric-badge">
              Calibrated FPR &lt;0.5%
            </span>
          </div>
          <div className="soc-gauge-track">
            <div
              className={`soc-gauge-bar bar-${tier}`}
              style={{ width: `${Math.min(100, Math.max(0, result.malicious_probability * 100))}%` }}
            />
          </div>
        </div>

        {/* Metric 2: Attributed Threat Family */}
        <div className="soc-metric-box">
          <span className="soc-metric-label">MALWARE FAMILY ATTRIBUTION</span>
          <div className="soc-metric-main">
            <span className="soc-family-name">
              {result.family && result.family !== "legitimate"
                ? result.family.toUpperCase()
                : "BENIGN / NONE"}
            </span>
            {result.family_confidence !== null && result.family_confidence !== undefined && (
              <span className="soc-family-conf">
                {(result.family_confidence * 100).toFixed(0)}% conf
              </span>
            )}
          </div>
          <span className="soc-metric-caption">
            Stage 2 Multiclass Classifier
          </span>
        </div>

        {/* Metric 3: Operational DNS State */}
        <div className="soc-metric-box">
          <span className="soc-metric-label">NETWORK OPERATIONAL STATE</span>
          <div className="soc-metric-main">
            <span className={`soc-op-badge ${opStatusClass}`}>
              {opStatusText}
            </span>
          </div>
          <span className="soc-metric-caption font-mono">
            {opIpSummary || (result.dns_enrichment ? `${result.dns_enrichment.response_time_ms} ms RTT` : "Opt-in live DNS")}
          </span>
        </div>

        {/* Metric 4: Decision & Latency */}
        <div className="soc-metric-box">
          <span className="soc-metric-label">RECOMMENDED ACTION</span>
          <div className="soc-metric-main">
            <span className={`soc-action-badge action-${result.action || "allow"}`}>
              {(result.action || "ALLOW").toUpperCase()}
            </span>
          </div>
          <span className="soc-metric-caption">
            Threshold: p &ge; {isMalicious ? "0.75" : isSuspicious ? "0.35" : "< 0.35"}
          </span>
        </div>
      </div>

      {/* 3. TreeSHAP Feature Attribution (If available) */}
      {result.top_risk_factors && result.top_risk_factors.length > 0 && (
        <div className="soc-section-container">
          <div className="soc-section-title">
            <span className="soc-title-icon">✦</span>
            <span>TREESHAP MARGINAL RISK ATTRIBUTION (TOP 3 DRIVERS)</span>
          </div>
          <div className="soc-shap-list">
            {result.top_risk_factors.map((rf) => (
              <div key={rf.feature} className="soc-shap-item">
                <div className="soc-shap-header">
                  <span className="soc-shap-name">{rf.display_name}</span>
                  <div className="soc-shap-meta">
                    <span className="soc-shap-raw">Raw: {rf.value}</span>
                    <span className="soc-shap-impact">+{rf.impact.toFixed(4)} impact</span>
                  </div>
                </div>
                <div className="soc-shap-bar-bg">
                  <div
                    className="soc-shap-bar-fill"
                    style={{ width: `${Math.min(100, Math.max(5, rf.impact * 120))}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. Live DNS Telemetry Callout (If resolved) */}
      {result.dns_enrichment && (
        <div className="soc-section-container">
          <div className="soc-section-title">
            <span className="soc-title-icon">⛨</span>
            <span>LIVE DNS &amp; C2 INFRASTRUCTURE TELEMETRY</span>
          </div>
          <div className={`soc-dns-advisory ${result.dns_enrichment.operational_status === "active" && isMalicious ? "adv-danger" : "adv-neutral"}`}>
            <span className="soc-adv-badge">SOC ADVISORY</span>
            <span className="soc-adv-text">{result.dns_enrichment.threat_summary}</span>
          </div>

          <div className="soc-records-grid">
            <div className="soc-record-block">
              <span className="soc-record-title">RESOLVED IP ADDRESSES</span>
              {result.dns_enrichment.ip_addresses.length > 0 ? (
                <div className="soc-pills-row">
                  {result.dns_enrichment.ip_addresses.map((ip) => (
                    <code key={ip} className="soc-ip-pill">{ip}</code>
                  ))}
                </div>
              ) : (
                <span className="soc-record-empty">None (Unregistered / NXDOMAIN)</span>
              )}
            </div>

            {result.dns_enrichment.name_servers.length > 0 && (
              <div className="soc-record-block">
                <span className="soc-record-title">AUTHORITATIVE NAMESERVERS</span>
                <div className="soc-pills-row">
                  {result.dns_enrichment.name_servers.map((ns) => (
                    <code key={ns} className="soc-ns-pill">{ns}</code>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* 5. 13 Lexical Features Grid */}
      <div className="soc-section-container">
        <div className="soc-section-title">
          <span className="soc-title-icon">≡</span>
          <span>LEXICAL &amp; STATISTICAL FEATURE TENSORS (13 DIM)</span>
        </div>
        <div className="soc-features-grid">
          {FEATURE_NAMES_ORDER.map((featKey) => {
            const rawVal = (result.features as unknown as Record<string, number>)[featKey];
            if (rawVal === undefined || rawVal === null) return null;
            return (
              <div key={featKey} className="soc-feature-cell">
                <span className="soc-feat-label">{FEATURE_DISPLAY_TITLES[featKey] || featKey}</span>
                <span className="soc-feat-val">
                  {typeof rawVal === "number" ? rawVal.toFixed(rawVal % 1 === 0 ? 0 : 3) : rawVal}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
