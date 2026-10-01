/**
 * Typed API client for the DGA Domain Detector backend.
 *
 * Backend URL is read from the VITE_API_URL environment variable,
 * defaulting to http://localhost:8000 for local development.
 */

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// --- Response Types ---

export interface PredictionFeatures {
  length: number;
  entropy: number;
  vowel_consonant_ratio: number;
  digit_ratio: number;
  hex_char_ratio: number;
  gini_index: number;
  max_consonant_run: number;
  digit_first: number;
  n_gram_score: number;
  unique_char_ratio: number;
}

export interface RiskFactor {
  feature: string;
  display_name: string;
  value: number;
  impact: number;
}

export interface DnsEnrichmentResult {
  resolved: boolean;
  operational_status: "active" | "nxdomain" | "unresolved" | "timeout" | "error";
  ip_addresses: string[];
  name_servers: string[];
  mail_servers: string[];
  dnssec_validated: boolean;
  response_time_ms: number;
  threat_summary: string;
}

export interface PredictionResult {
  domain: string;
  label: "legitimate" | "malicious";
  confidence: number;
  risk_tier: "safe" | "suspicious" | "malicious";
  action: "allow" | "monitor" | "block";
  malicious_probability: number;
  family: string | null;
  family_confidence: number | null;
  feature_contributions?: Record<string, number> | null;
  top_risk_factors?: RiskFactor[] | null;
  dns_enrichment?: DnsEnrichmentResult | null;
  features: PredictionFeatures;
}

export interface SinglePredictionResponse {
  prediction: PredictionResult;
}

export interface BatchPredictionResponse {
  predictions: PredictionResult[];
  total: number;
}

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
}

export interface ModelMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
  train_time_seconds: number;
}

export interface ModelInfoResponse {
  model_type: string;
  metrics: ModelMetrics;
  n_features: number;
  feature_names: string[];
  train_size: number;
  val_size: number;
  test_size: number;
}

// --- API Error ---

export class ApiError extends Error {
  statusCode: number;
  retryAfter?: number;

  constructor(statusCode: number, message: string, retryAfter?: number) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.retryAfter = retryAfter;
  }
}

// --- Helper ---

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!response.ok) {
      const errorBody = await response.text();
      const retryHeader = response.headers.get("Retry-After");
      const retryAfter = retryHeader ? parseInt(retryHeader, 10) : undefined;
      throw new ApiError(
        response.status,
        `API error (${response.status}): ${errorBody}`,
        retryAfter,
      );
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, `Network error: ${(error as Error).message}`);
  }
}

// --- API Functions ---

export async function checkDomain(
  domain: string,
  resolveDns: boolean = false,
): Promise<SinglePredictionResponse> {
  const url = new URL(`${API_BASE}/predict`);
  if (resolveDns) {
    url.searchParams.set("resolve_dns", "true");
  }
  return fetchJson<SinglePredictionResponse>(url.toString(), {
    method: "POST",
    body: JSON.stringify({ domain }),
  });
}

export async function checkDomains(
  domains: string[],
  resolveDns: boolean = false,
): Promise<BatchPredictionResponse> {
  const url = new URL(`${API_BASE}/predict/batch`);
  if (resolveDns) {
    url.searchParams.set("resolve_dns", "true");
  }
  return fetchJson<BatchPredictionResponse>(url.toString(), {
    method: "POST",
    body: JSON.stringify({ domains }),
  });
}

export const predictDomain = checkDomain;
export const predictBatch = checkDomains;

export async function getHealth(): Promise<HealthResponse> {
  return fetchJson<HealthResponse>(`${API_BASE}/health`);
}

export async function getModelInfo(): Promise<ModelInfoResponse> {
  return fetchJson<ModelInfoResponse>(`${API_BASE}/model-info`);
}

export interface DriftFeatureMetrics {
  ks_statistic: number;
  p_value: number;
  drifted: boolean;
  baseline_mean: number;
  current_mean: number;
  baseline_std: number;
  current_std: number;
}

export interface DriftReportResponse {
  status: string;
  current_samples: number;
  min_samples_required: number;
  baseline_samples: number;
  drift_detected: boolean;
  drift_score: number;
  drifted_features_count: number;
  total_features: number;
  drifted_features: string[];
  recommended_action: "healthy" | "investigate" | "retrain_recommended";
  features: Record<string, DriftFeatureMetrics>;
}

export async function getDriftReport(): Promise<DriftReportResponse> {
  return fetchJson<DriftReportResponse>(`${API_BASE}/drift-report`);
}

