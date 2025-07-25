import express from "express";
import { register, login, logout, getProfile } from "../controllers/auth.js";
import { verifyToken } from "../middleware/authMiddleware.js";
import { refreshTokenHandler } from "../controllers/auth.js";

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/login", login);
router.post("/refreshToken", refreshTokenHandler)

// Protected routes
router.post("/logout", verifyToken, logout);
router.get("/profile", verifyToken, getProfile);
export default router;
