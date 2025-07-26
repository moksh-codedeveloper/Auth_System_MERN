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
      scriptSrc: ["'self'"], // Removed 'unsafe-inline' - reconsider if truly needed
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

// ✅ Body parser & cookies (Order is correct here)
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ✅ Rate Limiting (global) - MOVED UP for broader application
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // limit IP to 100 requests per 15 mins
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

// index.js - Fixed CSRF configuration

// ✅ CSRF Protection setup
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
});

// ✅ CSRF Token Route (NO CSRF protection on this route)
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ✅ Routes WITHOUT CSRF protection (for inter-service communication)
app.use("/api/auth", authRoutes); // JWT validation routes don't need CSRF

// ✅ Apply CSRF protection ONLY to specific routes that need it
// Only apply CSRF to routes that modify data and are called directly from frontend
// app.use("/api/files", csrfProtection); // If you have file routes that need CSRF
// app.use("/api/user-actions", csrfProtection); // Any user action routes

// Alternative approach - exclude specific routes:

app.use((req, res, next) => {
  // Skip CSRF for these routes (inter-service communication)
  const skipCSRF = [
    '/api/auth/refreshToken',
    '/api/auth/login',
    '/api/auth/profile',
    '/api/auth/logout'
  ];
  
  if (skipCSRF.includes(req.path)) {
    return next();
  }
  
  // Apply CSRF protection to all other routes
  return csrfProtection(req, res, next);
});

// ✅ Rate limiters (after CSRF setup)
// app.use("/api/auth/login", loginLimiter);
// app.use("/api/auth/refreshToken", refreshLimiter);

// ✅ Centralized Error Handler (same as before)
app.use((err, req, res, next) => {
  console.error("🔥 Error:", err.stack);

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