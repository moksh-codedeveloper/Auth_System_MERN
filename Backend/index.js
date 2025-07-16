import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors());

// JSON Parsing
app.use(express.json());

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 100, // limit each IP to 100 requests
});
app.use(limiter);

// Health Check Route
app.get('/', (req, res) => {
  res.json({ message: 'Auth API is running ✅' });
});

export default app;