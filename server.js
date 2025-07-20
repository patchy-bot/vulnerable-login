// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Load configuration from environment variables
const {
  DB_HOST,
  DB_USER,
  DB_PASSWORD,
  DB_NAME,
  JWT_SECRET,
  BCRYPT_SALT_ROUNDS = 12
} = process.env;

// Create a pool of connections
const pool = mysql.createPool({
  host: DB_HOST,
  user: DB_USER,
  password: DB_PASSWORD,
  database: DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Middleware: verify JWT token
async function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// Route: User registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  try {
    const hashed = await bcrypt.hash(password, Number(BCRYPT_SALT_ROUNDS)); // Hash password
    const sql = 'INSERT INTO users (username, password_hash) VALUES (?, ?)';
    const [result] = await pool.execute(sql, [username, hashed]); // Parameterized query
    res.status(201).json({ message: 'User registered', userId: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Route: User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }
  try {
    const sql = 'SELECT id, password_hash FROM users WHERE username = ?';
    const [rows] = await pool.execute(sql, [username]); // Parameterized query
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    // Sign JWT (no sensitive data)
    const token = jwt.sign({ userId: user.id, username }, JWT_SECRET, { expiresIn: '2h' });
    res.json({ message: 'Authentication successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected route: get user info by ID
app.get('/user/:id', authenticate, async (req, res) => {
  const requestedId = Number(req.params.id);
  // Authorization: users can only fetch their own data
  if (req.user.userId !== requestedId) {
    return res.status(403).json({ message: 'Forbidden: cannot access other user data' });
  }
  try {
    const sql = 'SELECT id, username, created_at FROM users WHERE id = ?';
    const [rows] = await pool.execute(sql, [requestedId]); // Parameterized query
    if (rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API running on port ${PORT}`));