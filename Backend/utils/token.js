import jwt from "jsonwebtoken";

export const generateRefreshToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN, { expiresIn: "10d" });
};

export const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
};
