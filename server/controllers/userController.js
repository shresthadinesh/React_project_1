import User from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Register User: /api/user/register
export const register = async (req, res) => {
    
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.json({success: false, message: "Messing Details" });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser)
            return res.json({success: false, message: "User already exists" });
        

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
        });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "7d",
        });

        res.cookie("token", token, {
            httpOnly: true, //Prevent JavaScript to access the cookie
            secure: process.env.NODE_ENV === "production", //Use secure cookies in production
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",  //csrf protection
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days // cookie expiration time
        })

        return res.json({
            success: true,
            user: {
                name: user.name,
                email: user.email,
            },
        });
    } catch (error) {
        console.error(error);
        res.json({
            success: false,
            message: error.message
        });
    }
}