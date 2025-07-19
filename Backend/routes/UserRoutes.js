import express from "express";
import { register, login, logout, getProfile } from "../controllers/auth.js";
import { verifyToken } from "../middleware/authMiddleware.js";
import { refreshTokenHandler } from "../controllers/auth.js";

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/login", login);

// Protected routes
router.get("/logout", logout);
router.get("/profile", verifyToken, getProfile);
router.post("/refreshToken", refreshTokenHandler)
export default router;
