import type { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

/** Allowed browser origins for the Next.js frontend */
export function getAllowedOrigins(): string[] {
  const fromEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const appUrl = (process.env.APP_URL || process.env.FRONTEND_URL || '').replace(/\/$/, '');
  const defaults = ['http://localhost:3000', 'http://127.0.0.1:3000'];
  return Array.from(new Set([...defaults, ...fromEnv, ...(appUrl ? [appUrl] : [])]));
}

function isTrustedOrigin(origin: string): boolean {
  if (
    origin.includes('localhost') ||
    origin.includes('127.0.0.1') ||
    origin.endsWith('.vercel.app') ||
    origin.endsWith('.onrender.com')
  ) {
    return true;
  }
  const allowed = getAllowedOrigins();
  return allowed.includes(origin) || allowed.includes('*');
}

export function applySecurityMiddleware(app: Express): void {
  const isProd = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

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
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
      maxAge: 600,
    })
  );

  app.options('*', cors());

  app.use(
    '/api/',
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max: Number(process.env.API_RATE_LIMIT_MAX || 300),
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
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many payment attempts. Please try again later.' },
  });
  app.use('/api/flutterwave/', paymentLimiter);
  app.use('/api/payouts/', paymentLimiter);
}

/** Hide stack traces in production */
export function productionErrorHandler(
  err: Error,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  const isProd = process.env.NODE_ENV === 'production';
  console.error('[API Error]', err.message);
  if (!isProd) console.error(err.stack);
  if (err.message === 'Not allowed by CORS') {
    res.status(403).json({ message: 'Origin not allowed' });
    return;
  }
  res.status(500).json({
    message: isProd ? 'Internal server error' : err.message,
  });
}
