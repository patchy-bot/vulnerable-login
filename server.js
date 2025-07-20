const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
app.use(express.json());

// Create a connection pool using environment variables
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Generate JWT token
function generateToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

// Middleware: Authenticate JWT
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}

// Middleware: Authorize specific roles
function authorizeRoles(allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.sendStatus(403);
    }
    next();
  };
}

// Input validation for registration and login
const userValidation = [
  body('username').isAlphanumeric().withMessage('Username must be alphanumeric'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
];

// Registration endpoint
app.post('/register', userValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);
    await pool.execute(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, 'user']
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// Login endpoint
app.post('/login', userValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { username, password } = req.body;
    // Use prepared statement
    const [rows] = await pool.execute(
      'SELECT id, username, password, role FROM users WHERE username = ?',
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.sendStatus(500);
  }
});

// Protected endpoint: only admin can view all users
app.get(
  '/users',
  authenticateToken,
  authorizeRoles(['admin']),
  async (req, res) => {
    try {
      const [users] = await pool.execute(
        'SELECT id, username, role FROM users'
      );
      res.json(users);
    } catch (err) {
      console.error(err);
      res.sendStatus(500);
    }
  }
);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});