import crypto from 'node:crypto';

export class BachsError extends Error {
  constructor(message: string, public status = 502, public code = 'BACHS_ERROR') { super(message); }
}

export function bachsApiKey(): string {
  return (process.env.BACHS_API_KEY || '').trim();
}

export function bachsWebhookSecret(): string {
  return (process.env.BACHS_WEBHOOK_SECRET || '').trim();
}

export function isBachsConfigured(): boolean {
  return /^sk_(sandbox|live)_\S+$/.test(bachsApiKey());
}

export function bachsBaseUrl(): string {
  if (!isBachsConfigured()) throw new BachsError('Bachs is not configured. Set BACHS_API_KEY on the API server.', 503);
  return bachsApiKey().startsWith('sk_sandbox_') ? 'https://sandbox-api.bachs.io' : 'https://api.bachs.io';
}

export function frontendUrl(): string {
  return (process.env.FRONTEND_URL || process.env.APP_URL || 'https://sigmawealthsolution.com').replace(/\/$/, '');
}

export function bachsWebhookUrl(): string {
  return `${(process.env.PUBLIC_API_URL || 'https://sigmawealthsolutionbackend.onrender.com').replace(/\/$/, '')}/api/bachs/webhook`;
}

/** Bachs uses decimal strings in major units, never minor units. */
export function decimalAmount(value: unknown, allowZero = false): string {
  const text = String(value ?? '').trim();
  if (!/^\d+(\.\d{1,2})?$/.test(text)) throw new BachsError('Amount must have at most two decimal places.', 400);
  const [whole, fractional = ''] = text.split('.');
  const cents = BigInt(whole) * BigInt(100) + BigInt(fractional.padEnd(2, '0'));
  if (cents > BigInt(Number.MAX_SAFE_INTEGER) || (allowZero ? cents < BigInt(0) : cents <= BigInt(0))) {
    throw new BachsError('Amount is outside the supported range.', 400);
  }
  return `${cents / BigInt(100)}.${String(cents % BigInt(100)).padStart(2, '0')}`;
}

export async function bachsRequest<T = any>(endpoint: string, options: {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'; body?: unknown; idempotencyKey?: string; accountId?: string;
} = {}): Promise<T> {
  const method = options.method || 'GET';
  const base = bachsBaseUrl();
  if (method !== 'GET' && !options.idempotencyKey) throw new BachsError('A durable idempotency key is required.', 500);
  const headers: Record<string, string> = { Authorization: `Bearer ${bachsApiKey()}`, Accept: 'application/json' };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey;
  if (options.accountId) headers['X-Account-Id'] = options.accountId;
  let response: globalThis.Response;
  try {
    response = await fetch(`${base}${endpoint}`, {
      method, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new BachsError('Bachs could not be reached. The request may have been accepted; reconcile its reference before retrying.', 502, 'OUTCOME_UNKNOWN');
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    // Never expose upstream request details or credentials in an error.
    const code = String(data?.error_code || 'BACHS_ERROR');
    const message = String(data?.detail || data?.message || `Bachs request failed (${response.status}).`).replaceAll(bachsApiKey(), '[redacted]');
    throw new BachsError(message, response.status >= 500 ? 502 : response.status, code);
  }
  if (!data) throw new BachsError('Bachs returned an unreadable response.', 502, 'OUTCOME_UNKNOWN');
  return data as T;
}

/** Verify exact bytes, all rotation signatures, and a five-minute timestamp window. */
export function verifyBachsSignature(raw: Buffer, headers: {
  timestamp?: string; signature?: string; signatureV2?: string;
}, secret = bachsWebhookSecret(), now = Date.now()): boolean {
  if (!secret) return false;
  let timestamp = headers.timestamp || '';
  let signatures = [headers.signature || ''];
  if (headers.signatureV2) {
    const fields = headers.signatureV2.split(',').map(p => p.trim().split('='));
    const timestamps = fields.filter(([k]) => k === 't');
    if (timestamps.length !== 1) return false;
    timestamp = timestamps[0][1];
    signatures = fields.filter(([k]) => k === 'v1').map(([, v]) => v);
  }
  if (!/^\d+$/.test(timestamp) || Math.abs(now / 1000 - Number(timestamp)) > 300) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.`).update(raw).digest();
  return signatures.some(sig => /^[a-fA-F0-9]{64}$/.test(sig) && crypto.timingSafeEqual(expected, Buffer.from(sig, 'hex')));
}
