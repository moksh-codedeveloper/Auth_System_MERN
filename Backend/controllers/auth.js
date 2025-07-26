import prisma from "../db/db.js";
import bcrypt from "bcrypt";
import validator from "validator";
import { generateAccessToken, generateRefreshToken } from "../utils/token.js";
import { userDsa } from "../utils/dsa_user.js";

// REGISTER
export const register = async (req, res) => {
  const { email, name, password } = req.body;

  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  if (!validator.isStrongPassword(password)) {
    return res.status(400).json({ message: "Password is too weak" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    userDsa.addUser(email, { name, password: hashedPassword });

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (!existingUser) {
      await prisma.user.create({
        data: { email, name, password: hashedPassword },
      });
    }

    return res.status(201).json({ message: "Registered successfully" });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
};

// LOGIN
export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid)
      return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    console.log("Your tokens are generated");

    const addingRefreshToken = await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/",
    };
    const accessCookieOptions = {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 minutes
    };
    const refreshCookieOptions = {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };
    if (!addingRefreshToken) {
      return res.status(400).json({
        message: "Your data is not being stored buddy",
      });
    }
    userDsa.addToken(
      refreshToken,
      { userId: user.id },
      7 * 24 * 60 * 60 * 1000
    );

    res.cookie("token", accessToken, accessCookieOptions);
    res.cookie("refreshToken", refreshToken, refreshCookieOptions);
    return res.status(200).json({ message: "Logged in", accessToken });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
};

export const refreshTokenHandler = async (req, res) => {
  try {
    console.log("Refresh token request received");
    const oldToken = req.cookies?.refreshToken;
    if (!oldToken) return res.status(401).json({ message: "No refresh token" });

    const session = userDsa.getToken(oldToken);
    let userId;
    console.log("Processing refresh token for user:", userId);
    if (session) {
      userId = session.userId;
    } else {
      const dbToken = await prisma.refreshToken.findUnique({
        where: { token: oldToken },
      });
      if (!dbToken || dbToken.expiresAt < new Date()) {
        return res.status(403).json({ message: "Invalid or expired token" });
      }
      userId = dbToken.userId;
    }

    const newAccessToken = generateAccessToken({ id: userId });
    const newRefreshToken = generateRefreshToken({ id: userId });

    await prisma.refreshToken.update({
      where: { token: oldToken },
      data: {
        token: newRefreshToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });
    console.log("Refresh successful, new tokens generated");
    userDsa.removeToken(oldToken);
    userDsa.addToken(newRefreshToken, { userId }, 7 * 24 * 60 * 60 * 1000);
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      path: "/",
    };
    const accessCookieOptions = {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 minutes
    };
    const refreshCookieOptions = {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    };
    res.cookie("token", newAccessToken, accessCookieOptions);
    res.cookie("refreshToken", newRefreshToken, refreshCookieOptions);
    return res.status(200).json({
      message: "Token refreshed",
      accessToken: newAccessToken,
      refreshToken: newRefreshToken, // ADD THIS LINE
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
};

// LOGOUT
export const logout = async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (refreshToken) {
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
    userDsa.removeToken(refreshToken);
  }
  // Clear cookies
  const clearCookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
    path: "/",
  };
  res.cookie("token", "", clearCookieOptions);
  res.cookie("refreshToken", "", clearCookieOptions);
  return res.status(200).json({ message: "Logged out successfully" });
};

// GET PROFILE
export const getProfile = async (req, res) => {
  try {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    let user = [...userDsa.users.values()].find((u) => u.id === userId);
    if (!user) {
      user = await prisma.user.findUnique({ where: { id: userId } });
      if (!user) return res.status(404).json({ message: "User not found" });
      userDsa.addUser(user.email, user);
    }

    return res.status(200).json({
      message: "Profile retrieved successfully",
      user: { id: user.id, email: user.email, name: user.name },
    });
  } catch (error) {
    console.error("Profile error:", error);
    return res.status(500).json({ message: "Server error" });
  }
};
