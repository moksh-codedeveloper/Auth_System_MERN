// index.js - Updated Express configuration
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from "cookie-parser";
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import authRoutes from './routes/UserRoutes.js';
import csrf from "csurf";

const app = express();

// ✅ Logging (Dev Only)
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// ✅ Helmet for security headers
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
}));

// ✅ CORS configuration - Updated for Next.js middleware
app.use(cors({
  origin: [
    process.env.CLIENT_URL || "http://localhost:3000",
    "http://localhost:3000" // Ensure localhost is always allowed in dev
  ],
  credentials: true, // allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-CSRF-Token'],
}));

// ✅ Body parser & cookies
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ✅ CSRF Protection - Modified for middleware compatibility
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
  },
  // Skip CSRF for refresh token endpoint since it's called by middleware
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
});

// Apply CSRF protection selectively
app.use((req, res, next) => {
  // Skip CSRF for refresh token endpoint
  if (req.path === '/api/auth/refreshToken') {
    return next();
  }
  return csrfProtection(req, res, next);
});

// ✅ CSRF Token Route (frontend will call this to get a token)
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ✅ Rate Limiting (global)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // limit IP to 100 requests per 15 mins
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// ✅ Route-specific rate limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // only 5 login attempts per 15 mins
  message: { message: "Too many login attempts, try again later." },
});
app.use("/api/auth/login", loginLimiter);

// ✅ Rate limiter for refresh token
const refreshLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 refresh attempts per 5 mins
  message: { message: "Too many refresh attempts, try again later." },
});
app.use("/api/auth/refreshToken", refreshLimiter);

// ✅ Routes
app.use("/api/auth", authRoutes);

// ✅ Health Check Route
app.get('/', (req, res) => {
  res.json({ message: 'Auth API is running ✅' });
});

// ✅ Centralized Error Handler
app.use((err, req, res, next) => {
  console.error("🔥 Error:", err.stack);
  
  // Handle CSRF errors
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      success: false,
      message: "Invalid CSRF token",
    });
  }
  
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Something broke!",
  });
});

export default app;