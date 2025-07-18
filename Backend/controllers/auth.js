// controllers/authController.js
import prisma from "../db/db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";
import { hotStore } from "../dsa_core/hotStoreInstances.js";
import { generateRefreshToken } from "../utils/token.js";
import { credentialChecker } from "../utils/credentials_validators.js";

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  const checker = credentialChecker(name, email, password);
  if (!checker.isValid) return res.status(400).json({ error: checker.error });

  try {
    const hashedPassword = await bcrypt.hash(password, 12);
    const added = hotStore.addUser(name, email, hashedPassword);
    const user = await prisma.user.findUnique({
      where: {
        email
      }
    })
    if(!user) {
      await prisma.user.createMany({
        data: {
          name: name,
          email: email,
          password: password
        }
      })
    }
    if (added) return res.status(409).json({ message: "User already exists" });
    console.log("user passed from here");
    console.log("User details which passed to the db is here", hotStore);
    return res.status(201).json({ message: "User queued for DB insert" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Registration failed" });
  }
};
export const login = async (req, res) => {
  let { email, password } = req.body;
  email = validator.normalizeEmail(email);
  if (!validator.isEmail(email))
    return res.status(400).json({ message: "Invalid email" });

  try {
    let user = await prisma.user.findUnique({ where: { email } });
    let isTempUser = false;

    // If user not in DB, check HotStore
    if(!user) {
      console.log("The user doesn't exist here");
      return res.status(404).json({message: "no user found"})
    }

    if (!user) return res.status(404).json({ message: "User not found" });
    const token = jwt.sign(
      { id: user.id || "temp", name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    const refreshToken = generateRefreshToken(user);
    hotStore.cacheToken(token, user.id || user.email); // Use email as key if no ID yet

    // Only persist refresh token if user exists in DB
    if (!isTempUser) {
      const hashedRefresh = await bcrypt.hash(refreshToken, 10);
      await prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: hashedRefresh },
      });
    }

    res.cookie("refreshtoken", refreshToken, { httpOnly: true });
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "Strict",
      secure: process.env.NODE_ENV === "production",
    });

    return res.status(200).json({
      token,
      isTempUser,
      message: isTempUser
        ? "Login successful (temporary session)"
        : "Login successful",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Login failed", error: err.message });
  }
};

export const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshtoken;
  if (!refreshToken) {
    return res
      .status(404)
      .json({ message: "NO refresh token found man how much unlucky are you" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN);
    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id,
      },
    });
    if (!user || !user.refreshToken) {
      return res.status(403).json({ message: "UNAUTHORIZED" });
    }
    const match = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!match) {
      return res.status(403).json({ message: "No valid token found" });
    }
    const generateNewToken = jwt.sign(
      { email: user.id, id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    const generateNewRefreshToken = generateRefreshToken(user);
    hotStore.cacheToken(generateNewToken, user.id);
    const hashedRefreshToken = await bcrypt.hash(generateNewRefreshToken, 10);
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshToken: hashedRefreshToken,
      },
    });
    res.cookies("refreshToken", generateNewRefreshToken, {
      httpOnly: true,
    });
    res.cookies("token", generateNewToken, {
      httpOnly: true,
    });
    return res.status(201).json({
      accessToken: generateNewToken,
      message: "you have this new token now use it with pride",
    });
  } catch (error) {
    return res.status(500).json({
      message:
        "Stop using the internet of the old stone age time please bro you will make your life more worse by doing this",
    });
  }
};

export const logout = async (req, res) => {
  try {
    if (!req.cookies.token || !req.cookies.refreshtoken) {
      console.log(
        "you are not authorized to logout just get the hell outta here"
      );
    }
    res.cookies("token", "", {
      httpOnly: true,
      expires: Date(0),
    });
    const userId = req.user?.id; // Make sure verifyToken middleware runs before logout
    if (!userId) return res.status(401).json({ message: "Unauthorized" });

    await prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });
    res.cookies("refreshtoken", "", {
      httpOnly: true,
      expires: Date(0),
    });
    hotStore.removeToken(req.cookies.token);
    hotStore.removeToken(req.cookies.refreshtoken);
    return res
      .status(200)
      .json({ message: "logout successfully touch some grass" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "the server is sleeping come tomorrow" });
  }
};
export const getProfile = async (req, res) => {
  try {
    // req.user comes from verifyToken middleware
    const userId = req.user.id;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { name: true, email: true }, // Do NOT return password
    });

    return res.status(200).json({
      message: "Profile fetched successfully",
      data: user,
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error fetching profile" });
  }
};
