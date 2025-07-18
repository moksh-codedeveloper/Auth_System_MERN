// middleware/verifyToken.js
import jwt from "jsonwebtoken";
import { hotStore } from "../dsa_core/hotStoreInstances.js";

export const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ message: "No token provided" });

  if (!hotStore.isTokenValid(token)) {
    return res.status(403).json({ message: "Token expired or invalid" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid JWT" });
  }
};
