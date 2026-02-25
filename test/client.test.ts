import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { SafeChat, SafeChatError } from '../src/index.js';

let server: ReturnType<typeof createServer>;
let port: number;
let lastRequest: { method: string; url: string; headers: Record<string, string>; body: string };

function mockHandler(handler: (req: { method: string; url: string; headers: Record<string, string>; body: unknown }) => { status?: number; body: unknown }) {
  return (req: IncomingMessage, res: ServerResponse) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      const parsed = data ? JSON.parse(data) : undefined;
      lastRequest = {
        method: req.method!,
        url: req.url!,
        headers: req.headers as Record<string, string>,
        body: data,
      };
      const result = handler({ method: req.method!, url: req.url!, headers: req.headers as Record<string, string>, body: parsed });
      res.writeHead(result.status ?? 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result.body));
    });
  };
}

describe('SafeChat Client', () => {
  beforeAll(async () => {
    server = createServer(mockHandler((req) => {
      if (req.url === '/v1/scan' && req.method === 'POST') {
        return {
          body: {
            safe: true,
            score: 0.05,
            classification: 'safe',
            flags: [],
            layers: [{ layer: 'regex', score: 0.05, flags: [] }],
            scannedAt: Date.now(),
          },
        };
      }
      if (req.url === '/v1/scan/file' && req.method === 'POST') {
        return {
          body: {
            safe: true,
            sanitizedFilename: 'test.txt',
            flags: [],
            details: { pathTraversal: false, nullBytes: false, unicodeRLO: false, injectionInName: false, suspiciousMetadata: false },
          },
        };
      }
      if (req.url === '/v1/usage' && req.method === 'GET') {
        return {
          body: { period: '2026-02', scan_count: 42, block_count: 3, limit: 10000, remaining: 9958 },
        };
      }
      if (req.url === '/v1/plan' && req.method === 'GET') {
        return {
          body: { plan: 'free', limits: { callsPerMonth: 10000, ratePerMinute: 10 } },
        };
      }
      return { status: 404, body: { error: 'Not found' } };
    }));

    await new Promise<void>((resolve) => {
      server.listen(0, () => {
        const addr = server.address();
        port = typeof addr === 'object' ? addr!.port : 0;
        resolve();
      });
    });
  });

  afterAll(() => server.close());

  afterEach(() => {
    lastRequest = undefined as unknown as typeof lastRequest;
  });

  it('sends API key header', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    await sc.scan('hello');
    expect(lastRequest.headers['x-api-key']).toBe('sc_test_123');
  });

  it('scan() returns ScanResult', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    const result = await sc.scan('hello world');
    expect(result.safe).toBe(true);
    expect(result.classification).toBe('safe');
    expect(result.score).toBeLessThan(0.3);
  });

  it('scanFile() returns FileScanResult', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    const result = await sc.scanFile('test.txt');
    expect(result.safe).toBe(true);
    expect(result.sanitizedFilename).toBe('test.txt');
  });

  it('usage() returns usage stats', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    const result = await sc.usage();
    expect(result.scan_count).toBe(42);
    expect(result.remaining).toBe(9958);
  });

  it('plan() returns plan info', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    const result = await sc.plan();
    expect(result.plan).toBe('free');
  });

  it('throws SafeChatError on 404', async () => {
    const sc = new SafeChat({ apiKey: 'sc_test_123', baseUrl: `http://localhost:${port}` });
    await expect(sc.stats()).rejects.toThrow(SafeChatError);
    try {
      await sc.stats();
    } catch (err) {
      expect(err).toBeInstanceOf(SafeChatError);
      expect((err as SafeChatError).status).toBe(404);
    }
  });

  it('throws on missing apiKey', () => {
    expect(() => new SafeChat({ apiKey: '' })).toThrow('apiKey is required');
  });

  it('sends encrypted payload when encryptionKey is set', async () => {
    // 32-byte key base64
    const key = Buffer.alloc(32, 0xab).toString('base64');
    const sc = new SafeChat({ apiKey: 'sc_test_123', encryptionKey: key, baseUrl: `http://localhost:${port}` });
    await sc.scan('test encrypted');
    expect(lastRequest.headers['x-encrypted']).toBe('true');
    const body = JSON.parse(lastRequest.body);
    expect(body).toHaveProperty('iv');
    expect(body).toHaveProperty('tag');
    expect(body).toHaveProperty('data');
  });
});
