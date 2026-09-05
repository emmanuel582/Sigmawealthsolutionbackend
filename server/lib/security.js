import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
function getAllowedOrigins() {
  const fromEnv = (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const appUrl = (process.env.APP_URL || "").replace(/\/$/, "");
  const defaults = ["http://localhost:3000", "http://127.0.0.1:3000"];
  return Array.from(/* @__PURE__ */ new Set([...defaults, ...fromEnv, ...appUrl ? [appUrl] : []]));
}
function applySecurityMiddleware(app) {
  const isProd = process.env.NODE_ENV === "production";
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: false,
      // API JSON only; Next sets page CSP
      crossOriginResourcePolicy: { policy: "cross-origin" },
      hsts: isProd ? { maxAge: 31536e3, includeSubDomains: true, preload: true } : false,
      referrerPolicy: { policy: "strict-origin-when-cross-origin" }
    })
  );
  if (isProd && process.env.FORCE_HTTPS === "1") {
    app.use((req, res, next) => {
      if (req.secure || req.headers["x-forwarded-proto"] === "https") return next();
      return res.redirect(301, `https://${req.headers.host}${req.url}`);
    });
  }
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (origin.includes("localhost") || origin.includes("127.0.0.1") || origin.endsWith(".vercel.app") || origin.endsWith(".onrender.com") || process.env.NODE_ENV !== "production") {
          return callback(null, true);
        }
        const allowed = getAllowedOrigins();
        if (allowed.includes(origin) || allowed.includes("*")) {
          return callback(null, true);
        }
        return callback(null, true);
      },
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"]
    })
  );
  app.options("*", cors());
  app.use(
    "/api/",
    rateLimit({
      windowMs: 15 * 60 * 1e3,
      max: Number(process.env.API_RATE_LIMIT_MAX || 300),
      standardHeaders: true,
      legacyHeaders: false,
      message: { message: "Too many requests. Please try again later." }
    })
  );
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1e3,
    max: Number(process.env.AUTH_RATE_LIMIT_MAX || 25),
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many auth attempts. Please wait and try again." }
  });
  app.use("/api/auth/", authLimiter);
}
function productionErrorHandler(err, _req, res, _next) {
  const isProd = process.env.NODE_ENV === "production";
  console.error("[API Error]", err.message);
  if (!isProd) console.error(err.stack);
  if (err.message === "Not allowed by CORS") {
    res.status(403).json({ message: "Origin not allowed" });
    return;
  }
  res.status(500).json({
    message: isProd ? "Internal server error" : err.message
  });
}
export {
  applySecurityMiddleware,
  getAllowedOrigins,
  productionErrorHandler
};
