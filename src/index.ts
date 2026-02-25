/**
 * @safechat/client — Official SDK for SafeChat Cloud
 * Prompt injection detection, canary tokens, and message wrapping.
 *
 * @example
 * ```ts
 * import { SafeChat } from '@safechat/client'
 *
 * const sc = new SafeChat({ apiKey: 'sc_live_...' })
 * const result = await sc.scan('some user message')
 * if (!result.safe) console.warn('Blocked:', result.flags)
 * ```
 */

export { SafeChat, SafeChatError } from './client.js';
export type {
  SafeChatOptions,
  ScanResult,
  FileScanResult,
  WrapResult,
  WrapOptions,
  WrappedMessage,
  CanaryToken,
  CanaryCheckResult,
  UsageResult,
  StatsResult,
  PlanResult,
  ApiKeyInfo,
  CreateKeyResult,
  Classification,
  LayerResult,
  SafeChatErrorBody,
} from './types.js';
