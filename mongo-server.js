require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');
const cors = require('cors');
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: 'https://cryptoprojectredux.netlify.app',
  credentials: true  
}));

app.use(express.json());
app.use(cookieParser());


mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      return res.status(400).json({ error: "All input is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials (email)" });
    }

    
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials (password)" });
    }

    // Generate token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_SECRET,
      { expiresIn: "6h" }
    );


    const { passwordHash, ...userData } = user.toObject();

    // Save the cookies
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,     // true just for HTTPS
      sameSite: "lax",   // or 'none' + secure: true for cross-site
      maxAge: 6 * 60 * 60 * 1000, // 6 h
      domain: "mongo-backend-rya4.onrender.com" 
    });

    res.status(200).json({ ...userData });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "Something went wrong" });
  }
});

app.post("/register", async(req, res) => {

  try {
    const { email, password } = req.body;

    if (!(email && password )) {
      res.status(400).send("All input is required");
    }

    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email: email.toLowerCase(),
      passwordHash: encryptedPassword,
    });

    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.get("/check-token", (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    res.json({ user: decoded });
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    }
    return res.status(401).json({ error: "Invalid token" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("token"); // deleted cookie
  res.json({ message: "Logged out" });
});

app.listen(PORT, () => console.log('Server is running on port 3001'));
