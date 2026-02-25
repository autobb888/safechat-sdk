/**
 * @safechat/client — Type Definitions
 * Mirrors SafeChat Cloud API response shapes.
 */

// ─── Config ─────────────────────────────────────────────────────

export interface SafeChatOptions {
  /** API key from the SafeChat dashboard (starts with sc_) */
  apiKey: string;
  /** Base64-encoded AES-256 encryption key (from dashboard). Enables E2E encryption. */
  encryptionKey?: string;
  /** API base URL. Defaults to https://safechat-api.autobb.app */
  baseUrl?: string;
  /** Request timeout in ms. Defaults to 30000. */
  timeout?: number;
}

// ─── Scan ───────────────────────────────────────────────────────

export type Classification = 'safe' | 'suspicious' | 'likely_injection';

export interface LayerResult {
  layer: string;
  score: number;
  flags: string[];
  details?: Record<string, unknown>;
}

export interface ScanResult {
  safe: boolean;
  score: number;
  classification: Classification;
  flags: string[];
  layers: LayerResult[];
  scannedAt: number;
}

// ─── File Scan ──────────────────────────────────────────────────

export interface FileScanResult {
  safe: boolean;
  sanitizedFilename: string;
  flags: string[];
  details: {
    pathTraversal: boolean;
    nullBytes: boolean;
    unicodeRLO: boolean;
    injectionInName: boolean;
    suspiciousMetadata: boolean;
  };
}

// ─── Wrap ───────────────────────────────────────────────────────

export interface WrappedMessage {
  formatted: string;
  metadata: {
    role: string;
    safetyScore: number;
    classification: Classification;
    timestamp: string;
    jobId?: string;
  };
}

export interface WrapResult {
  scan: ScanResult;
  wrapped: WrappedMessage;
}

export interface WrapOptions {
  role?: string;
  jobId?: string;
  sessionId?: string;
}

// ─── Canary ─────────────────────────────────────────────────────

export interface CanaryToken {
  token: string;
  sessionId: string;
  createdAt: number;
  injectionText: string;
}

export interface CanaryCheckResult {
  leaked: boolean;
  token?: string;
  sessionId?: string;
}

// ─── Usage & Plan ───────────────────────────────────────────────

export interface UsageResult {
  period: string;
  scan_count: number;
  block_count: number;
  limit: number | 'unlimited';
  remaining: number | 'unlimited';
}

export interface StatsResult {
  plan: string;
  period: string;
  scan_count: number;
  block_count: number;
  limit: number | 'unlimited';
}

export interface PlanResult {
  plan: string;
  limits: {
    /** Number of calls allowed per month. null when plan is unlimited (JSON serializes Infinity as null). */
    callsPerMonth: number | null;
    ratePerMinute: number;
  };
}

// ─── Keys ───────────────────────────────────────────────────────

export interface ApiKeyInfo {
  id: string;
  key_prefix: string;
  name: string | null;
  revoked_at: string | null;
  created_at: string;
  last_used_at: string | null;
}

export interface CreateKeyResult {
  id: string;
  key: string;
  prefix: string;
}

// ─── Errors ─────────────────────────────────────────────────────

export interface SafeChatErrorBody {
  error: string;
  details?: Array<{ field: string; message: string }>;
  limit?: number | string;
  plan?: string;
  message?: string;
}
