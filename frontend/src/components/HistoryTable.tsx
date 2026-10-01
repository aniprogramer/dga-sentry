import type { PredictionResult } from "../api/client";

interface HistoryTableProps {
  history: Array<PredictionResult & { timestamp: string }>;
  onClear: () => void;
}

export default function HistoryTable({ history, onClear }: HistoryTableProps) {
  if (history.length === 0) return null;

  return (
    <div className="soc-history-card">
      <div className="soc-history-header">
        <div className="soc-history-title">
          <span className="soc-history-icon">◷</span>
          <span className="soc-history-heading">SESSION AUDIT LOG</span>
          <span className="soc-history-count">{history.length}</span>
        </div>
        <button
          type="button"
          className="soc-btn-ghost"
          onClick={onClear}
          id="clear-history-btn"
        >
          Clear Log
        </button>
      </div>

      <div className="soc-table-wrapper">
        <table className="soc-table">
          <thead>
            <tr>
              <th className="text-left">Target Domain (FQDN)</th>
              <th className="text-left">Risk Tier</th>
              <th className="text-left">Malicious Prob</th>
              <th className="text-left">Threat Family</th>
              <th className="text-right">Entropy</th>
              <th className="text-right">N-Gram LogP</th>
              <th className="text-right">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {history.map((item, i) => {
              const isMalicious = item.risk_tier === "malicious" || item.label === "malicious";
              const isSuspicious = item.risk_tier === "suspicious";
              const tier = isMalicious ? "malicious" : isSuspicious ? "suspicious" : "safe";

              return (
                <tr key={`${item.domain}-${i}`} className={`soc-row row-${tier}`}>
                  <td className="font-mono text-xs text-[#F3F4F6]">
                    <code>{item.domain}</code>
                  </td>
                  <td>
                    <span className={`soc-tag tag-${tier}`}>
                      {tier.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <div className="soc-prob-cell">
                      <div className="soc-prob-track">
                        <div
                          className={`soc-prob-fill bar-${tier}`}
                          style={{ width: `${Math.round(item.malicious_probability * 100)}%` }}
                        />
                      </div>
                      <span className="font-mono text-xs text-[#9CA3AF]">
                        {(item.malicious_probability * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="font-mono text-xs text-[#9CA3AF]">
                    {item.family && item.family !== "legitimate" ? item.family : "—"}
                  </td>
                  <td className="font-mono text-xs text-right text-[#9CA3AF]">
                    {item.features.entropy.toFixed(2)}
                  </td>
                  <td className="font-mono text-xs text-right text-[#9CA3AF]">
                    {item.features.n_gram_score.toFixed(2)}
                  </td>
                  <td className="font-mono text-xs text-right text-[#64748B]">
                    {item.timestamp}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
