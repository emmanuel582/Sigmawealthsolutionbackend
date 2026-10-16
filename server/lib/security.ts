import type { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { concurrencyGuard } from './traffic.js';

/** Allowed browser origins for the Next.js frontend */
export function getAllowedOrigins(): string[] {
  const fromEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const appUrl = (process.env.APP_URL || process.env.FRONTEND_URL || '').replace(/\/$/, '');
  const defaults = process.env.NODE_ENV === 'production' ? ['https://sigmawealthsolution.com', 'https://www.sigmawealthsolution.com'] : ['http://localhost:3000', 'http://127.0.0.1:3000'];
  return Array.from(new Set([...defaults, ...fromEnv, ...(appUrl ? [appUrl] : [])]));
}

function isTrustedOrigin(origin: string): boolean {
  return getAllowedOrigins().includes(origin);
}

export function applySecurityMiddleware(app: Express): void {
  const isProd = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);
  app.disable('x-powered-by');
  app.use(concurrencyGuard());
  app.use('/api',(_req,res,next)=>{res.set('Cache-Control','no-store');next();});

  app.use(
    helmet({
      contentSecurityPolicy: false, // API JSON only; Next sets page CSP
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
      hsts: isProd
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      frameguard: { action: 'deny' },
      noSniff: true,
      xssFilter: true,
    })
  );

  // MITM mitigation: force HTTPS in production (set FORCE_HTTPS=1 on host)
  if (isProd && process.env.FORCE_HTTPS !== '0') {
    app.use((req, res, next) => {
      if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
      const host = req.headers.host || 'localhost';
      return res.redirect(301, `https://${host}${req.url}`);
    });
  }

  app.use(
    cors({
      origin(origin, callback) {
        if (!origin) return callback(null, true);

        if (!isProd) return callback(null, true);

        if (isTrustedOrigin(origin)) return callback(null, true);

        return callback(new Error('Not allowed by CORS'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key', 'X-Support-Token', 'X-Requested-With', 'Accept', 'Origin'],
      maxAge: 600,
    })
  );


  app.use(
    '/api/',
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: Number(process.env.API_RATE_LIMIT_MAX || 300),
      skip: req => req.originalUrl.split('?')[0] === '/api/bachs/webhook',
      standardHeaders: true,
      legacyHeaders: false,
      message: { message: 'Too many requests. Please try again later.' },
    })
  );

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.AUTH_RATE_LIMIT_MAX || 25),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many auth attempts. Please wait and try again.' },
  });
  app.use('/api/auth/', authLimiter);

  const supportLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.SUPPORT_RATE_LIMIT_MAX || 120),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many support requests. Please slow down.' },
  });
  app.use('/api/support/', supportLimiter);

  const paymentLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.PAYMENT_RATE_LIMIT_MAX || 60),
    skip: req => req.originalUrl.split('?')[0] === '/api/bachs/webhook',
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many payment attempts. Please try again later.' },
  });
  app.use('/api/bachs/webhook',rateLimit({windowMs:60_000,max:Number(process.env.WEBHOOK_RATE_LIMIT_MAX || 600),standardHeaders:true,legacyHeaders:false}));
  app.use('/api/bachs/', paymentLimiter);
  app.use('/api/payouts/', paymentLimiter);
  app.use('/api/admin/payouts/', paymentLimiter);
  app.use('/api/verify-account', paymentLimiter);
  app.use('/api/investor/connect/', paymentLimiter);
  app.use('/api/investor/bank-details', paymentLimiter);
}

/** Hide stack traces in production */
export function productionErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  const isProd = process.env.NODE_ENV === 'production';
  console.error('[API Error]', err.message === 'Not allowed by CORS' ? 'CORS_REJECTED' : (err as any).status === 413 ? 'BODY_TOO_LARGE' : (err as any).type === 'entity.parse.failed' ? 'INVALID_BODY' : 'REQUEST_FAILED');
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ message: 'Origin not allowed' });
    return;
  }
  if ((err as any).type === 'entity.parse.failed' || (err as any).status === 413) {
    res.status((err as any).status === 413 ? 413 : 400).json({ message: 'Invalid request body.' });
    return;
  }
  res.status(500).json({
    message: isProd ? 'Internal server error' : err.message,
  });
}
