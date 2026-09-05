import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword } from '../server/lib/passwords';
import { getAllowedOrigins } from '../server/lib/security';

describe('password hashing', () => {
  it('hashes and verifies bcrypt passwords', () => {
    const hash = hashPassword('SecurePass123!');
    expect(hash).not.toEqual('SecurePass123!');
    expect(verifyPassword('SecurePass123!', hash)).toBe(true);
    expect(verifyPassword('wrong', hash)).toBe(false);
  });

  it('still verifies legacy sha256 hashes', () => {
    const crypto = require('crypto') as typeof import('crypto');
    const legacy = crypto.createHash('sha256').update('sigma:oldpass').digest('hex');
    expect(verifyPassword('oldpass', legacy)).toBe(true);
    expect(verifyPassword('nope', legacy)).toBe(false);
  });
});

describe('CORS allowlist', () => {
  it('always includes localhost defaults', () => {
    const origins = getAllowedOrigins();
    expect(origins).toContain('http://localhost:3000');
    expect(origins).toContain('http://127.0.0.1:3000');
  });
});

describe('XSS sanitize', () => {
  it('strips script tags from strings', async () => {
    const xss = (await import('xss')).default;
    const dirty = '<script>alert(1)</script>Hello';
    const clean = xss(dirty, { whiteList: {}, stripIgnoreTag: true });
    expect(clean).not.toContain('<script>');
    expect(clean).toContain('Hello');
  });
});
