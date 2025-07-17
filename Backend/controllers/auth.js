import {generateRefreshToken} from "../utils/token.js"
import prisma from "../db/db.js";
import { credentialChecker } from "../utils/credentials_validators";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator";
export const register = async (req, res) => {
  const { name, email, password } = req.body;
  const checker = credentialChecker(name, email, password);
  if (!checker.isValid) {
    return res.status(400).json({ error: checker.error });
  } else {
    try {
      const existingUser = await prisma.user.findUnique({ where: { email } });
      const existingName = await prisma.user.findUnique({ where: { name } });
      if (existingName || existingUser) {
        return res.status(401).json({
          message: "you exist bro just go in login page don't come here",
        });
      } else {
        const hashedPassword = await bcrypt.hash(password, 15);
        const user = await prisma.user.create({
          data: { name: name, email: email, password: hashedPassword },
        });
        return res.status(201).json({
          message: "you are created just go do party somewhere hheheheheheh",
          response: user,
        });
      }
    } catch (error) {
      return res
        .status(500)
        .json({ message: "this server is burned out let it rest" });
    }
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  email = validator.normalizeEmail(email);
  if (!validator.isEmail(email)) {
    return res.status(400).json({
      mesasage: "are you trying to fool around here lets do a chat!!",
    });
  } else {
    try {
      let verifyPassword = await bcrypt.compare(password, verifyEmail.password);
      let verifyEmail = await prisma.user.findUnique(email);
      if (!verifyEmail || !verifyPassword) {
        return res.status(400).json({
          message:
            "you are not there buddy first go ahead and register then comeback",
        });
      }
      const token = jwt.sign(
        {
          id: verifyEmail.id,
          name: verifyEmail.name,
          email: verifyEmail.email,
        },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      const refreshToken = generateRefreshToken(verifyEmail)
      const hashed_token = await bcrypt.hash(refreshToken, 10)
      await prisma.user.update({
        where: {id : user.id},
        data: {
          refreshToken: hashed_token
        }
      })
      res.cookie("refreshtoken", refreshToken, {
        httpOnly: true,
      })
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      return res
        .status(201)
        .json({
          data: token,
          message:
            "you are logged in meowwwwww thanks for making this far now go back to where you came you jerk",
        });
    } catch (error) {
      return res
        .status(500)
        .json({
          message:
            "your luck ran out better luck and cat next time and better come registered",
        });
    }
  }
};

export const refreshToken = async (req, res) => {
  const refreshToken = req.cookie.refreshtoken;
  if(!refreshToken){
    return res.status(404).json({message: "NO refresh token found man how much unlucky are you"})
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN)
    const user = await prisma.user.findUnique({
      where: {
        id: decoded.id
      }
    })
    if(!user || !user.refreshToken){
      return res.status(403).json({message: "UNAUTHORIZED"})
    }
    const match = await bcrypt.compare(refreshToken, user.refreshToken)
    if(!match){
      return res.status(403).json({message: "No valid token found"})
    }
    const generateNewToken = jwt.sign({email: user.id, id: user.id}, process.env.JWT_SECRET, {expiresIn: '1d'})
    const generateNewRefreshToken = generateRefreshToken(user)
    const hashedRefreshToken = await bcrypt.hash(generateNewRefreshToken, 10)
    await prisma.user.update({
      where: {
        id : user.id,
      },
      data: {
        refreshToken: hashedRefreshToken
      }
    })
    res.cookie("refreshToken", generateNewRefreshToken, {
      httpOnly: true
    })
    res.cookie("token", generateNewToken, {
      httpOnly: true
    })
    return res.status(201).json({
      accessToken: generateNewToken,
      message: "you have this new token now use it with pride"
    })
  } catch (error) {
    return res.status(500).json({message: "Stop using the internet of the old stone age time please bro you will make your life more worse by doing this"})
  }
}

export const logout = async (req, res) => {
  try {
    if(!req.cookie.token || !req.cookie.refreshtoken){
      console.log("you are not authorized to logout just get the hell outta here");
    }
    res.cookie("token", "", {
      httpOnly: true,
      expires: Date(0),
    });
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        refreshToken: null
      }
    })
    res.cookie("refreshtoken", "", {
      httpOnly: true,
      expires: Date(0)
    })

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
      select: { name: true, email: true}, // Do NOT return password
    });

    return res.status(200).json({
      message: "Profile fetched successfully",
      data: user,
    });
  } catch (error) {
    return res.status(500).json({ message: "Server error fetching profile" });
  }
}