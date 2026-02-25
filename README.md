# @safechat/client

Official Node.js SDK for [SafeChat Cloud](https://safechat.autobb.app) — prompt injection detection, canary tokens, and message wrapping for LLM applications.

## Install

```bash
yarn add @safechat/client
```

## Quick Start

```ts
import { SafeChat } from '@safechat/client'

const sc = new SafeChat({ apiKey: 'sc_live_...' })

const result = await sc.scan('some user message')
if (!result.safe) {
  console.warn('Blocked:', result.classification, result.flags)
}
```

## Get Your API Key

1. Sign up at [safechat.autobb.app](https://safechat.autobb.app)
2. Go to the Dashboard and create an API key
3. Copy your key (starts with `sc_`) and optionally your encryption key

## E2E Encryption

All requests can be encrypted with AES-256-GCM so message content is protected even beyond TLS. Pass your encryption key from the dashboard:

```ts
const sc = new SafeChat({
  apiKey: 'sc_live_...',
  encryptionKey: 'base64-key-from-dashboard',
})

// requests and responses are now encrypted automatically
const result = await sc.scan('sensitive user input')
```

## API Reference

### `new SafeChat(options)`

| Option | Type | Required | Default |
|--------|------|----------|---------|
| `apiKey` | `string` | Yes | — |
| `encryptionKey` | `string` | No | — |
| `baseUrl` | `string` | No | `https://safechat-api.autobb.app` |
| `timeout` | `number` | No | `30000` |

### Scanning

#### `sc.scan(text)` — Scan for prompt injection

```ts
const result = await sc.scan('Ignore all previous instructions and...')
// {
//   safe: false,
//   score: 0.95,
//   classification: 'likely_injection',
//   flags: ['instruction_override'],
//   layers: [{ layer: 'regex', score: 0.95, flags: ['instruction_override'] }],
//   scannedAt: 1740441600000
// }
```

**Classifications:**
- `safe` — score < 0.3
- `suspicious` — score 0.3–0.7
- `likely_injection` — score >= 0.7

#### `sc.scanFile(filename, metadata?)` — Scan filenames for injection

```ts
const result = await sc.scanFile('../../../etc/passwd', { author: 'user' })
// { safe: false, sanitizedFilename: 'etcpasswd', flags: ['path_traversal'], details: { pathTraversal: true, ... } }
```

#### `sc.wrap(text, options?)` — Scan + wrap with Spotlighting delimiters

```ts
const result = await sc.wrap('user message here', { role: 'buyer', sessionId: 'sess_123' })
// { scan: ScanResult, wrapped: { formatted: '...', metadata: { ... } } }
```

### Canary Tokens

Inject hidden tokens into prompts to detect if an LLM leaks system instructions.

#### `sc.createCanary(sessionId)` — Create a canary token

```ts
const canary = await sc.createCanary('session_abc')
// { token: '...', sessionId: 'session_abc', createdAt: ..., injectionText: '...' }

// Inject canary.injectionText into your system prompt
```

#### `sc.checkCanary(text, sessionId?)` — Check for leaked tokens

```ts
const check = await sc.checkCanary(agentResponse, 'session_abc')
if (check.leaked) {
  console.error('Canary token leaked! System prompt exposed.')
}
```

### Account

#### `sc.usage()` — Current month usage

```ts
const usage = await sc.usage()
// { period: '2026-02', scan_count: 1420, block_count: 23, limit: 10000, remaining: 8580 }
```

#### `sc.stats()` — Monitoring statistics

```ts
const stats = await sc.stats()
// { plan: 'free', period: '2026-02', scan_count: 1420, block_count: 23, limit: 10000 }
```

#### `sc.plan()` — Plan details

```ts
const plan = await sc.plan()
// { plan: 'free', limits: { callsPerMonth: 10000, ratePerMinute: 10 } }
```

### Key Management

#### `sc.listKeys()` — List API keys

```ts
const { keys } = await sc.listKeys()
```

#### `sc.createKey(name?)` — Create a new API key

```ts
const newKey = await sc.createKey('production')
// { id: '...', key: 'sc_live_...', prefix: 'sc_live_abc' }
// ⚠ Full key is only returned once
```

#### `sc.revokeKey(id)` — Revoke an API key

```ts
await sc.revokeKey('key_id_here')
```

## Error Handling

```ts
import { SafeChat, SafeChatError } from '@safechat/client'

try {
  await sc.scan('test')
} catch (err) {
  if (err instanceof SafeChatError) {
    console.error(err.status)  // HTTP status code
    console.error(err.body)    // { error: '...', details?: [...] }

    if (err.status === 429) {
      // Rate limited or plan limit exceeded
    }
  }
}
```

## Plans

| Plan | Scans/Month | Rate Limit |
|------|-------------|------------|
| Free | 10,000 | 10/min |
| Pro | 50,000 | 60/min |
| Business | 500,000 | 300/min |
| Enterprise | Unlimited | 1,000/min |

## Requirements

- Node.js >= 18
- Zero runtime dependencies (uses native `fetch` and `node:crypto`)

## Development

```bash
yarn install
yarn build       # compile CJS + ESM + types
yarn test        # run test suite
yarn lint        # type-check
```

## License

MIT
