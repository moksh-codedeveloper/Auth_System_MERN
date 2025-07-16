import prisma from "../db/db.js";
import { credentialChecker } from "../utils/credentials_validators";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken"
import validator from "validator"
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
        return res
          .status(401)
          .json({
            message: "you exist bro just go in login page don't come here",
          });
      } else {
        const hashedPassword = await bcrypt.hash(password, 15);
        const user = await prisma.user.create({
          data: { name: name, email: email, password: hashedPassword },
        });
        return res
          .status(201)
          .json({
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

export const login = async(req, res) => {
    const {email, password} = req.body;
    email = validator.normalizeEmail(email);
    if (!validator.isEmail(email)){
        return res.status(400).json({mesasage : "are you trying to fool around here lets do a chat!!"})
    }else {
        
    }
}