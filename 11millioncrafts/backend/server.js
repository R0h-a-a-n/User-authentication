const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const User = require('./models/User'); // Import User model

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: 'http://localhost:5174', // Allow requests from this frontend origin
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Allow these HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Allow these headers
    credentials: true, // Allow cookies or credentials
  })
);

// Handle preflight requests explicitly
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5174');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200); // Respond with HTTP 200 for OPTIONS requests
});

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Atlas Connected'))
  .catch((err) => console.error('MongoDB Connection Failed:', err));

// Register Endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'All fields are required!' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ message: 'Email already exists!' });
    } else {
      res.status(500).json({ message: 'Server error!' });
    }
  }
});

// Login Endpoint
// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'All fields are required!' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found!' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials!' });
    }

    // Add user role to the token
    const token = jwt.sign(
      { id: user._id, email: user.email, role: 'User' }, // Set default role for now
      process.env.SECRET_KEY,
      {
        expiresIn: '1h',
      }
    );

    res.status(200).json({ message: 'Login successful!', token, role: 'User' }); // Add role to response
  } catch (error) {
    res.status(500).json({ message: 'Server error!' });
  }
});


// Start Server
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
