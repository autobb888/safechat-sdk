/**
 * @safechat/client — AES-256-GCM Encryption
 * Matches SafeChat Cloud's server-side encryption format exactly.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;

export interface EncryptedPayload {
  iv: string;   // base64
  tag: string;  // base64
  data: string; // base64
}

export function encrypt(plaintext: string, keyBase64: string): EncryptedPayload {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error(`Invalid encryption key: expected 32 bytes (256-bit), got ${key.length}`);
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: encrypted.toString('base64'),
  };
}

export function decrypt(payload: EncryptedPayload, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error(`Invalid encryption key: expected 32 bytes (256-bit), got ${key.length}`);
  }
  const decipher = createDecipheriv(ALGO, key, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.data, 'base64')),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}
