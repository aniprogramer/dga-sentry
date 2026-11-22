import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { PredictionFeatures } from "../api/client";
import { useMemo } from "react";

function getCSSVar(name: string, fallback: string = ""): string {
  if (typeof window === "undefined") return fallback;
  const val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return val || fallback;
}

interface ConfidenceChartProps {
  features: PredictionFeatures;
  label: "legitimate" | "malicious";
  themeKey?: string;
}

// Human-readable feature names for display
const FEATURE_LABELS: Record<string, string> = {
  entropy: "Entropy",
  n_gram_score: "N-gram Score",
  length: "Length",
  vowel_consonant_ratio: "Vowel/Cons.",
  digit_ratio: "Digit Ratio",
  hex_char_ratio: "Hex Ratio",
  gini_index: "Gini Index",
  max_consonant_run: "Max Cons. Run",
  unique_char_ratio: "Unique Ratio",
  digit_first: "Digit First",
};

// Feature descriptions for tooltips
const FEATURE_DESCRIPTIONS: Record<string, string> = {
  entropy: "Shannon entropy of character distribution — higher = more random",
  n_gram_score:
    "Average log-probability of bigrams against legitimate domain corpus",
  length: "Number of characters in the second-level domain",
  vowel_consonant_ratio: "Ratio of vowels to consonants",
  digit_ratio: "Fraction of characters that are digits",
  hex_char_ratio: "Fraction of characters that are valid hexadecimal",
  gini_index: "Inequality measure of character frequency distribution",
  max_consonant_run: "Longest consecutive consonant streak",
  unique_char_ratio: "Ratio of distinct characters to total length",
  digit_first: "Whether the domain starts with a digit (0/1)",
};

function CustomTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: Array<{ payload: { name: string; value: number; key: string } }>;
}) {
  if (!active || !payload?.length) return null;
  const data = payload[0].payload;
  return (
    <div className="chart-tooltip">
      <p className="chart-tooltip-title">{data.name}</p>
      <p className="chart-tooltip-value">Value: {data.value.toFixed(4)}</p>
      <p className="chart-tooltip-desc">
        {FEATURE_DESCRIPTIONS[data.key] || ""}
      </p>
    </div>
  );
}

export default function ConfidenceChart({
  features,
  label,
  themeKey,
}: ConfidenceChartProps) {
  // Prepare data for chart — sort by absolute value for visual impact
  const data = Object.entries(features)
    .map(([key, value]) => ({
      key,
      name: FEATURE_LABELS[key] || key,
      value: Number(value),
    }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value));

  const { barColor, barColorLight, gridStroke, axisStroke, tickX, tickY } = useMemo(() => {
    const isLight =
      themeKey === "light" ||
      (typeof document !== "undefined" && document.documentElement.getAttribute("data-theme") === "light");
    return {
      barColor: label === "malicious"
        ? getCSSVar("--color-malicious", isLight ? "#E11D48" : "#F43F5E")
        : getCSSVar("--color-safe", isLight ? "#059669" : "#10B981"),
      barColorLight: label === "malicious"
        ? getCSSVar("--text-malicious", isLight ? "#BE123C" : "#FDA4AF")
        : getCSSVar("--text-safe", isLight ? "#047857" : "#34D399"),
      gridStroke: getCSSVar("--chart-grid", isLight ? "rgba(0,0,0,0.07)" : "rgba(255,255,255,0.06)"),
      axisStroke: getCSSVar("--chart-axis", isLight ? "rgba(0,0,0,0.12)" : "rgba(255,255,255,0.1)"),
      tickX: getCSSVar("--chart-tick-x", isLight ? "#64748B" : "#94a3b8"),
      tickY: getCSSVar("--chart-tick-y", isLight ? "#475569" : "#cbd5e1"),
    };
  }, [label, themeKey]);

  return (
    <div className="chart-container">
      <h3 className="chart-title">
        <svg
          width="20"
          height="20"
          viewBox="0 0 20 20"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <rect x="2" y="10" width="3" height="8" rx="0.5" />
          <rect x="7" y="6" width="3" height="12" rx="0.5" />
          <rect x="12" y="3" width="3" height="15" rx="0.5" />
          <path d="M2 2l16 0" strokeLinecap="round" />
        </svg>
        Feature Breakdown
      </h3>
      <div className="chart-wrapper">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 5, right: 15, left: 10, bottom: 5 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={gridStroke}
            />
            <XAxis
              type="number"
              tick={{ fill: tickX, fontSize: 12 }}
              axisLine={{ stroke: axisStroke }}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: tickY, fontSize: 11 }}
              axisLine={{ stroke: axisStroke }}
              width={85}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="value" radius={[0, 4, 4, 0]} animationDuration={800}>
              {data.map((_, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={index < 3 ? barColor : barColorLight}
                  fillOpacity={index < 3 ? 0.9 : 0.5}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
