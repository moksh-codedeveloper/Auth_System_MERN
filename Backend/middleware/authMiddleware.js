import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: "Not authorized, no token found" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Attach user data to req for later use
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};
