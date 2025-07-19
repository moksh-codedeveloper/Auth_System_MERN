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

// ✅ CORS configuration
app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:3000",
  credentials: true, // allow cookies
}));

// ✅ Body parser & cookies
app.use(express.json({ limit: '10mb' })); // limit payload size
app.use(cookieParser());

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Strict",
  },
});

// Apply CSRF protection for state-changing routes (POST, PUT, DELETE)
app.use(csrfProtection);

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
  message: "Too many login attempts, try again later.",
});
app.use("/api/auth/login", loginLimiter);

// ✅ Routes
app.use("/api/auth", authRoutes);

// ✅ Health Check Route
app.get('/', (req, res) => {
  res.json({ message: 'Auth API is running ✅' });
});

// ✅ Centralized Error Handler
app.use((err, req, res, next) => {
  console.error("🔥 Error:", err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Something broke!",
  });
});

export default app;
