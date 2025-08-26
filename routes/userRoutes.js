const express = require("express");
const { Signup } = require("../models/Signup");
const { UserData } = require("../models/UserData");
const userRouter = express.Router();

userRouter.get("/", async (req, res) => {
  try {
    const email = req.query.email;
    console.log(email);
    const userData = await UserData.find({ email });

    res.json(userData);
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).send("Internal Server Error");
  }
});

userRouter.get("/findemail", async (req, res) => {
  const { email } = req.query;

  try {
    const newUser = await Signup.findOne({ email: email });
    if (!newUser) {
      return res.status(404).json({ message: "No user found with this email" });
    }
    return res
      .status(200)
      .json({ message: "User found", user: newUser, count: newUser.count });
  } catch (e) {
    console.error(e);
    return res.status(400).json({ error: e.message });
  }
});

userRouter.get("/getbalance", async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ error: "User ID is required" });
    }
    const user = await Signup.findOne({ email: userId });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user });
  } catch (error) {
    console.error("Error fetching balance:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = userRouter;
