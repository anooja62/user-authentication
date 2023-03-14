/** @format */

const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./model/usermodel");
const mongoose = require("mongoose");
const Cors = require("cors");
const fs = require("fs");
const dotenv = require("dotenv");
const app = express();
const port = 9000;
dotenv.config();
app.use(express.json());
app.use(Cors());

app.post("/signup", async (req, res) => {
  try {
    const publicKey = fs.readFileSync("public_key.pem", "utf-8");
    const encryptedEmail = crypto
      .publicEncrypt(publicKey, Buffer.from(req.body.email))
      .toString("base64");
    const encryptedMobileNumber = crypto
      .publicEncrypt(publicKey, Buffer.from(req.body.mobileNumber))
      .toString("base64");
    const encryptedFullName = crypto
      .publicEncrypt(publicKey, Buffer.from(req.body.fullName))
      .toString("base64");

    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    const newUser = new User({
      email: encryptedEmail,
      mobileNumber: encryptedMobileNumber,
      fullName: encryptedFullName,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Something went wrong" });
  }
});

app.post("/reset-password", async (req, res) => {
    try {
      const userId = req.user.id;
      const user = await User.findById(userId);
  
      // Check if the old password is correct
      const isMatch = await bcrypt.compare(req.body.oldPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: "Invalid old password" });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
  
      // Update the user's password in the database
      user.password = hashedPassword;
      await user.save();
  
      res.status(200).json({ message: "Password updated successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong" });
    }
  });
  app.post("/login", async (req, res) => {
    try {
      // Find the user by email
      const user = await User.findOne({ email: req.body.email });
  
      // Check if the user exists
      if (!user) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
  
      // Check if the password is correct
      const isMatch = await bcrypt.compare(req.body.password, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: "Invalid email or password" });
      }
  
      // Create a JWT with the user's ID, email, and mobile number as the payload
      const token = jwt.sign(
        { userId: user._id, email: user.email, mobileNumber: user.mobileNumber },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
  
      res.status(200).json({ token });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong" });
    }
  });
  app.put("/user/:id", async (req, res) => {
    try {
      const privateKey = fs.readFileSync("private_key.pem", "utf-8");
      const encryptedEmail = crypto
        .publicEncrypt(publicKey, Buffer.from(req.body.email))
        .toString("base64");
      const encryptedMobileNumber = crypto
        .publicEncrypt(publicKey, Buffer.from(req.body.mobileNumber))
        .toString("base64");
      const encryptedFullName = crypto
        .publicEncrypt(publicKey, Buffer.from(req.body.fullName))
        .toString("base64");
  
      const user = await User.findById(req.params.id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
  
      user.email = encryptedEmail;
      user.mobileNumber = encryptedMobileNumber;
      user.fullName = encryptedFullName;
  
      await user.save();
  
      res.json({ message: "User details updated successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "Something went wrong" });
    }
  });
      

app.listen(port, () => {
  console.log(`listening in : ${port}`);
});
