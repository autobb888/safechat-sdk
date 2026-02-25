import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../src/crypto.js';

describe('AES-256-GCM Encryption', () => {
  const key = Buffer.alloc(32, 0xab).toString('base64');

  it('encrypts and decrypts a string', () => {
    const plaintext = '{"text":"hello world"}';
    const encrypted = encrypt(plaintext, key);
    expect(encrypted.iv).toBeTruthy();
    expect(encrypted.tag).toBeTruthy();
    expect(encrypted.data).toBeTruthy();
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('produces different ciphertext each time (random IV)', () => {
    const plaintext = 'same input';
    const a = encrypt(plaintext, key);
    const b = encrypt(plaintext, key);
    expect(a.data).not.toBe(b.data);
    expect(a.iv).not.toBe(b.iv);
  });

  it('rejects wrong key size', () => {
    const shortKey = Buffer.alloc(16).toString('base64');
    expect(() => encrypt('test', shortKey)).toThrow('expected 32 bytes');
  });

  it('rejects tampered data', () => {
    const encrypted = encrypt('test', key);
    encrypted.data = Buffer.from('tampered').toString('base64');
    expect(() => decrypt(encrypted, key)).toThrow();
  });

  it('handles unicode content', () => {
    const plaintext = '{"text":"Hello 🌍 café résumé 中文"}';
    const encrypted = encrypt(plaintext, key);
    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });
});
