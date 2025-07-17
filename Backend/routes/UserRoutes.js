import express from "express";
import { register, login, logout, getProfile } from "../controllers/authController.js";
import { verifyToken } from "../middlewares/authMiddleware.js";
import { refreshToken } from "../controllers/auth.js";

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/login", login);

// Protected routes
router.post("/logout", verifyToken, logout);
router.get("/profile", verifyToken, getProfile);
router.post("/refreshToken", refreshToken)
export default router;
