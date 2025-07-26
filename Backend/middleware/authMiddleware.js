// middleware/authMiddleware.js - Debug version
import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  console.log("🔍 JWT Middleware Debug:");
  console.log("Cookies:", req.cookies);
  console.log("Authorization header:", req.headers.authorization);
  
  let token = req.cookies?.token;
  
  if (!token) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      console.log("📡 Using Authorization header token");
    }
  } else {
    console.log("🍪 Using cookie token");
  }

  if (!token) {
    console.log("❌ No token found in cookies or headers");
    return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("✅ JWT decoded:", decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.log("❌ JWT verification failed:", error.message);
    console.log("Token that failed:", token);
    return res.status(403).json({ message: "Invalid JWT" });
  }
};