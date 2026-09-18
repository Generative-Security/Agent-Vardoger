import axios from "axios";
import { getToken, logout } from "../auth";
import { beginSignIn, cognitoConfigured } from "../signin";

// Base URL from env, defaulting to "/api" (proxied to the backend in dev).
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "/api",
});

// Attach the bearer token when present. In local dev (VARDOGER_AUTH_MODE=none)
// there is no token and the backend treats the caller as admin. No X-Client-*
// headers, no session-token header, no hardcoded account/role context.
api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) config.headers.set("Authorization", `Bearer ${token}`);
  return config;
});

// On 401 (missing/expired/invalid token), clear the stored token so the app
// stops sending a dead credential and can prompt for re-auth, instead of
// looping on silent 401s.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401) {
      logout();
      // In Cognito mode, a 401 means the token is missing/expired/invalid —
      // send the user back through the Hosted UI. In token mode the app falls
      // back to the access-token entry screen on the next render.
      if (cognitoConfigured()) {
        void beginSignIn();
      }
    }
    return Promise.reject(error);
  },
);

// ---------------------------------------------------------------------------
// Dashboard models — mirror control_plane/schemas/dashboard.py field-for-field.
// ---------------------------------------------------------------------------

export interface SessionInfo {
  session_id: string;
  created_at: number;
  scope_id: string;
  source: string;
  status: string;
  last_decision: string;
  last_risk_score: number;
  last_matched_signatures: string[];
  last_evaluated_at: number;
}

export interface SessionSummary {
  active_count: number;
  terminated_count: number;
  active_sessions: SessionInfo[];
  terminated_sessions: SessionInfo[];
}

export interface DetectionEvent {
  timestamp: string;
  session_id: string;
  decision: string;
  matched_signatures: string[];
  risk_score: number;
  attack_intents: string[];
  matched_policy_rules: string[];
}

export interface TimelinePoint {
  timestamp: string;
  detection_count: number;
  block_count: number;
  allow_count: number;
}

export interface CategoryBreakdown {
  category: string;
  count: number;
  percentage: number;
}

export interface SignatureHit {
  signature_id: string;
  category: string;
  hit_count: number;
  last_seen: string;
}

export interface Tier3Finding {
  event_id: string;
  timestamp: string;
  scope_id: string;
  // source = "<aws_account_id>/<agent>" segmentation attribute. A Tier 3
  // finding can span multiple sources within the scope (see affected_sources).
  source: string;
  // provenance holds the OLD meaning of "source" (e.g. "tier3").
  provenance: string;
  affected_sources: string[];
  burst_id: string;
  category: string;
  attack_style: string;
  confidence: number;
  affected_session_count: number;
  affected_sessions: string[];
  example_prompt_ids: string[];
  similarity_method: string;
  threshold_used: string;
  action_taken: string;
  kill_triggered: boolean;
  model_version: string;
}

// ---------------------------------------------------------------------------
// Prompt history — mirror control_plane/schemas/prompt_history.py.
// ---------------------------------------------------------------------------

export interface PromptHistoryRecord {
  scope_id: string;
  source: string;
  session_id: string;
  prompt_id: string;
  timestamp: string;
  prompt: string;
  decision: string;
  risk_score: number;
  matched_signatures: string[];
  attack_intents: string[];
  matched_policy_rules: string[];
  prompt_length: number;
  agent_runtime_arn: string;
  ingested_at: number;
  tier2_status: string;
  tier2_label: string;
  tier2_confidence: number;
  tier2_suspicious: boolean;
  tier2_risk_score: number;
  tier2_prompt_score: number;
  tier2_session_score_after: number;
  tier2_category: string;
  tier2_ml_verdict: string;
  tier2_action_taken: string;
  tier2_threshold_used: string;
  tier2_kill_triggered: boolean;
  tier2_safe_intent_reason: string;
  tier2_error: string;
}

export interface PromptHistoryResponse {
  records: PromptHistoryRecord[];
  count: number;
  scanned_count: number;
  warning: string;
}

export interface PromptHistoryFilters {
  source?: string;
  session_id?: string;
  decision?: string;
  keyword?: string;
  min_risk?: number;
  hours?: number;
  limit?: number;
}

// ---------------------------------------------------------------------------
// Management models — mirror control_plane/schemas/management.py.
// ---------------------------------------------------------------------------

export interface SourcesResponse {
  scope_id: string;
  sources: string[];
  count: number;
}

export interface SecurityPolicy {
  // Tier 2
  tier2_mode: string; // off | shadow | enforce
  tier2_default_kill_threshold: number;
  tier2_high_risk_threshold: number;
  tier2_require_repeated_malicious: boolean;
  tier2_min_malicious_verdicts_for_kill: number;
  tier2_allow_single_verdict_kill_threshold: number;
  // Tier 3
  tier3_mode: string; // off | shadow | enforce
  tier3_min_sessions_for_kill: number;
  tier3_similarity_threshold: number;
  tier3_kill_threshold: number;
  // Metadata
  policy_version: number;
  updated_by: string;
  updated_at: number;
}

export interface SignaturesResponse {
  community_count: number;
  categories: string[];
  premium_enabled: boolean;
  marketplace_link: string;
  aws_account_id: string;
}

export interface CustomSignatureRequest {
  signature_id: string;
  category: string;
  pattern: string;
  severity: string;
  description: string;
}

// Mirrors control_plane/schemas/management.py CustomSignatureResponse.
// A 200 means the signature was stored: a rejected pattern returns 400 and a
// failed write returns 503.
export interface CustomSignatureResponse {
  stored: boolean;
  signature_id: string;
  scope_id: string;
  store: string;
  error?: string;
  enforced?: boolean;
  note?: string;
}

export interface EvaluationSummary {
  scope_id: string;
  true_positive: number;
  true_negative: number;
  false_positive: number;
  false_negative: number;
  unknown: number;
  total: number;
}

export interface EvaluationRunResponse {
  status: string;
  run_id: string;
  detail: string;
}

export interface ManagedUpgradeInfo {
  telemetry_mode: string;
  handoff_text: string;
  intake_url: string;
  intent_recorded: boolean;
  instructions: string;
}

// ---------------------------------------------------------------------------
// Settings status — mirror control_plane/routers/settings.py status() dict.
// ---------------------------------------------------------------------------

export interface SettingsStatus {
  deployment_mode: string;
  auth_mode: string;
  scope_id: string;
  ml_endpoint_configured: boolean;
  tier3_enabled: boolean;
  global_kill_enabled: boolean;
  premium_signatures_configured: boolean;
  managed_intake_configured: boolean;
}

export interface HealthResponse {
  status: string;
  service: string;
}

// ---------------------------------------------------------------------------
// Test Console (live chat) — keep the sandbox request/response shape.
// ---------------------------------------------------------------------------

export interface ChatMessageRequest {
  prompt: string;
  session_id: string;
  gateway_url: string;
  tool_name: string;
  // Optional OAuth bearer token for gateways that enforce inbound auth. Sent as
  // Authorization: Bearer to the gateway; blank for open/dev gateways.
  gateway_token?: string;
  user_id?: string;
}

export interface ChatMessageResponse {
  status: string;
  response: string;
  session_id: string;
  message_count?: number;
  model?: string;
  raw?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// API surface — every endpoint under /api. Source is the only segmentation
// filter the frontend sends; scope_id is defaulted by the backend.
// ---------------------------------------------------------------------------

// Every dashboard panel in one response. Preferred over polling the six
// endpoints below: the backend derives all of them from a single scan, so this
// is one request and one table read instead of six of each.
export interface DashboardSummary {
  sessions: SessionSummary;
  detections: DetectionEvent[];
  timeline: TimelinePoint[];
  categories: CategoryBreakdown[];
  signatures: SignatureHit[];
  tier3_findings: Tier3Finding[];
}

export const dashboardApi = {
  summary: (hours = 24, interval = "1h", source = "") =>
    api.get<DashboardSummary>("/dashboard/summary", {
      params: { hours, interval, source },
    }),
  sessions: (source = "") =>
    api.get<SessionSummary>("/dashboard/sessions", { params: { source } }),
  detections: (hours = 24, source = "") =>
    api.get<DetectionEvent[]>("/dashboard/detections", { params: { hours, source } }),
  timeline: (hours = 24, interval = "1h", source = "") =>
    api.get<TimelinePoint[]>("/dashboard/detections/timeline", {
      params: { hours, interval, source },
    }),
  byCategory: (hours = 24, source = "") =>
    api.get<CategoryBreakdown[]>("/dashboard/detections/by-category", {
      params: { hours, source },
    }),
  bySignature: (hours = 24, source = "") =>
    api.get<SignatureHit[]>("/dashboard/detections/by-signature", {
      params: { hours, source },
    }),
  tier3Findings: (hours = 24, source = "") =>
    api.get<Tier3Finding[]>("/dashboard/tier3/findings", { params: { hours, source } }),
};

export const promptHistoryApi = {
  search: (filters: PromptHistoryFilters) =>
    api.get<PromptHistoryResponse>("/prompt-history/search", {
      params: {
        source: filters.source || "",
        session_id: filters.session_id || "",
        decision: filters.decision || "",
        keyword: filters.keyword || "",
        min_risk: filters.min_risk || 0,
        hours: filters.hours || 24,
        limit: filters.limit || 100,
      },
    }),
};

export const sourcesApi = {
  list: () => api.get<SourcesResponse>("/sources"),
};

export const policyApi = {
  get: () => api.get<SecurityPolicy>("/policy"),
  update: (policy: SecurityPolicy) => api.put<SecurityPolicy>("/policy", policy),
};

export const signaturesApi = {
  get: () => api.get<SignaturesResponse>("/signatures"),
  addCustom: (payload: CustomSignatureRequest) =>
    api.post<CustomSignatureResponse>("/signatures/custom", payload),
};

export const evaluationApi = {
  summary: (source = "") =>
    api.get<EvaluationSummary>("/evaluation", { params: { source } }),
  run: () => api.post<EvaluationRunResponse>("/evaluation/run"),
};

export const settingsApi = {
  status: () => api.get<SettingsStatus>("/settings/status"),
  managedUpgrade: () => api.get<ManagedUpgradeInfo>("/settings/managed-upgrade"),
  recordManagedUpgradeIntent: () =>
    api.post<ManagedUpgradeInfo>("/settings/managed-upgrade"),
};

export const healthApi = {
  get: () => api.get<HealthResponse>("/health"),
};

export const chatApi = {
  message: (payload: ChatMessageRequest) =>
    api.post<ChatMessageResponse>("/chat/message", payload),
};
