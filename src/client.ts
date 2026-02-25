/**
 * @safechat/client — SafeChat Cloud API Client
 */

import { encrypt, decrypt, type EncryptedPayload } from './crypto.js';
import type {
  SafeChatOptions,
  ScanResult,
  FileScanResult,
  WrapResult,
  WrapOptions,
  CanaryToken,
  CanaryCheckResult,
  UsageResult,
  StatsResult,
  PlanResult,
  ApiKeyInfo,
  CreateKeyResult,
  SafeChatErrorBody,
} from './types.js';

const DEFAULT_BASE_URL = 'https://safechat-api.autobb.app';
const DEFAULT_TIMEOUT = 30_000;

export class SafeChatError extends Error {
  constructor(
    message: string,
    public status: number,
    public body: SafeChatErrorBody,
  ) {
    super(message);
    this.name = 'SafeChatError';
  }
}

export class SafeChat {
  private apiKey: string;
  private encryptionKey?: string;
  private baseUrl: string;
  private timeout: number;

  constructor(options: SafeChatOptions) {
    if (!options.apiKey) {
      throw new Error('apiKey is required');
    }
    this.apiKey = options.apiKey;
    this.encryptionKey = options.encryptionKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
  }

  // ── Core Scanning ───────────────────────────────────────────────

  /** Scan text for prompt injection attacks. */
  async scan(text: string): Promise<ScanResult> {
    return this.post<ScanResult>('/v1/scan', { text });
  }

  /** Scan a filename (and optional metadata) for injection attempts. */
  async scanFile(filename: string, metadata?: Record<string, string | number>): Promise<FileScanResult> {
    return this.post<FileScanResult>('/v1/scan/file', { filename, metadata });
  }

  /** Scan and wrap a message with Microsoft Spotlighting delimiters. */
  async wrap(text: string, options?: WrapOptions): Promise<WrapResult> {
    return this.post<WrapResult>('/v1/wrap', { text, ...options });
  }

  // ── Canary Tokens ──────────────────────────────────────────────

  /** Create a canary token for leak detection in a session. */
  async createCanary(sessionId: string): Promise<CanaryToken> {
    return this.post<CanaryToken>('/v1/canary/create', { sessionId });
  }

  /** Check if agent output contains leaked canary tokens. */
  async checkCanary(text: string, sessionId?: string): Promise<CanaryCheckResult> {
    return this.post<CanaryCheckResult>('/v1/canary/check', { text, sessionId });
  }

  // ── Account ────────────────────────────────────────────────────

  /** Get current usage stats. */
  async usage(): Promise<UsageResult> {
    return this.get<UsageResult>('/v1/usage');
  }

  /** Get monitoring statistics. */
  async stats(): Promise<StatsResult> {
    return this.get<StatsResult>('/v1/stats');
  }

  /** Get current plan details. */
  async plan(): Promise<PlanResult> {
    return this.get<PlanResult>('/v1/plan');
  }

  /** List all API keys for this tenant. */
  async listKeys(): Promise<{ keys: ApiKeyInfo[] }> {
    return this.get<{ keys: ApiKeyInfo[] }>('/v1/keys');
  }

  /** Create a new API key. */
  async createKey(name?: string): Promise<CreateKeyResult> {
    return this.post<CreateKeyResult>('/v1/keys', { name });
  }

  /** Revoke an API key by ID. */
  async revokeKey(id: string): Promise<{ revoked: boolean }> {
    return this.del<{ revoked: boolean }>(`/v1/keys/${encodeURIComponent(id)}`);
  }

  // ── HTTP Transport ─────────────────────────────────────────────

  private async post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private async get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  private async del<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }

  private async request<T>(method: string, path: string, body?: Record<string, unknown>): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'X-API-Key': this.apiKey,
      'Accept': 'application/json',
    };

    let payload: string | undefined;

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';

      if (this.encryptionKey) {
        headers['X-Encrypted'] = 'true';
        const encrypted = encrypt(JSON.stringify(body), this.encryptionKey);
        payload = JSON.stringify(encrypted);
      } else {
        payload = JSON.stringify(body);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: payload,
        signal: controller.signal,
      });
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        throw new Error(`SafeChat request timed out after ${this.timeout}ms`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      let errorBody: SafeChatErrorBody;
      try {
        errorBody = await res.json() as SafeChatErrorBody;
      } catch {
        errorBody = { error: res.statusText };
      }
      throw new SafeChatError(errorBody.error || `HTTP ${res.status}`, res.status, errorBody);
    }

    // Decrypt response if server encrypted it
    const resEncrypted = res.headers.get('x-encrypted') === 'true';
    if (resEncrypted && this.encryptionKey) {
      const encryptedBody = await res.json() as EncryptedPayload;
      const plaintext = decrypt(encryptedBody, this.encryptionKey);
      return JSON.parse(plaintext) as T;
    }

    return await res.json() as T;
  }
}
