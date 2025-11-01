import express from "express";
import bcrypt from "bcrypt";
import { AuthenticateToken, generateAuthToken } from "../../functions/token.js";
import { User } from "../../database/schema/user.js";
import { IUser } from "../../interfaces.js";
import { Status } from "../../constants.js";
import { Document } from "mongoose";

const loginRouter = express.Router();

// Login route
loginRouter.post("/", async (req, res): Promise<any> => {
  const { username, handle, password } = req.body;
  if ((!username && !handle) || !password) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  try {
    // Check if the user exists
    const user = await User.findOne<IUser & Document>({ $or: [{ username }, { handle }] });
    if (!user) {
      return res.status(401).json({ message: "Invalid username or handle" });
    }

    // Compare the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Generate or send the authentication token
    let token: string = user.token;
    if (!(await AuthenticateToken(user.token))) {
      token = await generateAuthToken(user.id, user.handle, password, user.password);
      user.token = token;
      user.save();
    }

    res.status(200).json({ token, message: "Logged in successfully" });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).json({ message: Status[500] });
  }
});

// Export the Login router
export default loginRouter;
