import type { Request, Response, NextFunction } from 'express';
import xss from 'xss';

const XSS_OPTIONS = {
  whiteList: {}, // strip all HTML tags
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style'],
};

function sanitizeValue(value: unknown): unknown {
  if (typeof value === 'string') {
    return xss(value, XSS_OPTIONS).trim();
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Skip large base64 image payloads — only allow data:image URLs, don't strip to empty
      if (k === 'imageUrl' || k === 'image_url' || k === 'receiptImageUrl') {
        if (typeof v === 'string' && (v.startsWith('data:image/') || v.startsWith('https://'))) {
          out[k] = v.length > 6_000_000 ? '' : v;
          continue;
        }
      }
      out[k] = sanitizeValue(v);
    }
    return out;
  }
  return value;
}

/** Strip HTML/script from JSON bodies (XSS). SQL is parameterized via Supabase client. */
export function sanitizeRequestBody(req: Request, _res: Response, next: NextFunction): void {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeValue(req.body);
  }
  if (req.query && typeof req.query === 'object') {
    for (const key of Object.keys(req.query)) {
      const val = req.query[key];
      if (typeof val === 'string') {
        (req.query as Record<string, unknown>)[key] = xss(val, XSS_OPTIONS).trim();
      }
    }
  }
  next();
}
