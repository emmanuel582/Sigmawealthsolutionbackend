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
  const appUrl = (process.env.APP_URL || '').replace(/\/$/, '');
  const defaults = ['http://localhost:3000', 'http://127.0.0.1:3000'];
  return Array.from(new Set([...defaults, ...fromEnv, ...(appUrl ? [appUrl] : [])]));
}

export function applySecurityMiddleware(app: Express): void {
  const isProd = process.env.NODE_ENV === 'production';

  // Behind Next/ngrok/reverse proxy — needed for secure rate-limit + correct HTTPS detection
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: false, // API JSON only; Next sets page CSP
      crossOriginResourcePolicy: { policy: 'cross-origin' },
      hsts: isProd
        ? { maxAge: 31536000, includeSubDomains: true, preload: true }
        : false,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    })
  );

  // MITM: refuse plain HTTP in production when FORCE_HTTPS=1
  if (isProd && process.env.FORCE_HTTPS === '1') {
    app.use((req, res, next) => {
      if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    });
  }

  app.use(
    cors({
      origin(origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, server-to-server)
        if (!origin) return callback(null, true);

        // Always allow localhost, Vercel deployments, Render domains, or any domain explicitly permitted
        if (
          origin.includes('localhost') ||
          origin.includes('127.0.0.1') ||
          origin.endsWith('.vercel.app') ||
          origin.endsWith('.onrender.com') ||
          process.env.NODE_ENV !== 'production'
        ) {
          return callback(null, true);
        }

        const allowed = getAllowedOrigins();
        if (allowed.includes(origin) || allowed.includes('*')) {
          return callback(null, true);
        }

        // Allow all origins by default for seamless hosting across Vercel & Render
        return callback(null, true);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
    })
  );

  // Handle preflight requests for all routes cleanly
  app.options('*', cors());

  // Note: sanitizeRequestBody must run AFTER express.json() — applied in sigma-api.ts

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
