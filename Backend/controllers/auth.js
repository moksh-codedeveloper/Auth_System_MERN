import prisma from "../db/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
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
      await prisma.user.create({ data: { email, name, password: hashedPassword } });
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
    if (!isValid) return res.status(401).json({ message: "Invalid credentials" });

    const accessToken = generateAccessToken({ id: user.id, email: user.email });
    const refreshToken = generateRefreshToken();

    await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    userDsa.addToken(refreshToken, { userId: user.id }, 7 * 24 * 60 * 60 * 1000);

    res.cookie("accessToken", accessToken, { httpOnly: true, sameSite: "Strict" });
    res.cookie("refreshToken", refreshToken, { httpOnly: true, sameSite: "Strict" });

    return res.status(200).json({ message: "Logged in", accessToken });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
};

// REFRESH TOKEN
export const refreshTokenHandler = async (req, res) => {
  const oldToken = req.cookies?.refreshToken;
  if (!oldToken) return res.status(401).json({ message: "No refresh token" });

  const session = userDsa.getToken(oldToken);
  let userId;

  if (session) {
    userId = session.userId;
  } else {
    const dbToken = await prisma.refreshToken.findUnique({ where: { token: oldToken } });
    if (!dbToken || dbToken.expiresAt < new Date()) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    userId = dbToken.userId;
  }

  const newAccessToken = generateAccessToken({ id: userId });
  const newRefreshToken = generateRefreshToken();

  await prisma.refreshToken.update({
    where: { token: oldToken },
    data: { token: newRefreshToken, expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) },
  });

  userDsa.removeToken(oldToken);
  userDsa.addToken(newRefreshToken, { userId }, 7 * 24 * 60 * 60 * 1000);

  res.cookie("accessToken", newAccessToken, { httpOnly: true });
  res.cookie("refreshToken", newRefreshToken, { httpOnly: true });

  return res.status(200).json({ message: "Token refreshed", accessToken: newAccessToken });
};

// LOGOUT
export const logout = async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  if (refreshToken) {
    await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
    userDsa.removeToken(refreshToken);
  }

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  return res.status(200).json({ message: "Logged out successfully" });
};

export const getProfile = async (req, res) => {
    const userId = req.user?.id;
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    let user = [...userDsa.users.values()].find(u => u.id === userId);
    if (!user) {
        user = await prisma.user.findUnique({ where: { id: userId } });
        if (!user) return res.status(404).json({ message: "User not found" });
        userDsa.addUser(user.email, user);
    }

    return res.status(200).json({ user: { id: user.id, email: user.email, name: user.name } });
};
