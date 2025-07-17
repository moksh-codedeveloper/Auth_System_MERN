import jwt from "jsonwebtoken"
export const generateRefreshToken = (user) => {
    return jwt.sign({id: user.id, email: user.email}, process.env.REFRESH_TOKEN, {expiresIn: "10d"})
}