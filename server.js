require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/user.model");
const authenticateToken = require('./middlewares/auth')

const PORT = process.env.PORT || 3000;
const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database Connection
mongoose.connect(process.env.MONGO_URI);

// Register Route
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ status: "error", error: "Email already exists" });
    }

    
    const hashedPassword = await bcrypt.hash(password, 10);

    
    const newUser = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ status: "ok", user: newUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "error", error: "Server error" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ status: "error", error: "Invalid email or password" });
    }

   
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ status: "error", error: "Invalid email or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email, name: user.name }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ status: "ok", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "error", error: "Server error" });
  }
});


// Get Quote (Protected Route)
app.get("/quote", authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    res.json({ status: "ok", quote: user.quote });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "error", error: "Server error" });
  }
});


// Update Quote (Protected Route)
app.post("/quote", authenticateToken, async (req, res) => {
  try {
    await User.updateOne({ email: req.user.email }, { $set: { quote: req.body.quote } });
    res.json({ status: "ok" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: "error", error: "Server error" });
  }
});

app.listen(PORT, () => console.log(`Server Listening on Port ${PORT}...`));
