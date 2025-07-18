import jwt from "jsonwebtoken"
export const generateRefreshToken = (user) => {
    return jwt.sign({id: user.id, email: user.email}, process.env.REFRESH_TOKEN, {expiresIn: "10d"})
}

export const generateAccessToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "15m" });
};