const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('./db');
require('dotenv').config();
const mysql = require('mysql2/promise');
const path = require('path');

const app = express();

// ========== MIDDLEWARE ==========
app.use(cors());
app.use(express.json());
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use('/videos', express.static(path.join(__dirname, 'videos')));

// JWT secret from .env
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_dev_secret_change_me';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '24h';

// Auth middleware — verifies JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token.' });
    }
    req.user = decoded; // Attach decoded user data to request
    next();
  });
}

// ========== INITIALIZE DATABASE ==========
async function initDatabase() {
  try {
    // Create database if it doesn't exist
    const tempPool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
    });

    await tempPool.execute(`CREATE DATABASE IF NOT EXISTS \`${process.env.DB_NAME || 'streamvibe'}\``);
    await tempPool.end();

    // Create users table
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Create watchlist table (user's saved movies)
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS watchlist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        movie_id INT NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user_movie (user_id, movie_id),
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Create user_profiles table (Netflix-like profiles)
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS user_profiles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        profile_name VARCHAR(50) NOT NULL,
        avatar VARCHAR(255) DEFAULT NULL,
        is_kids TINYINT(1) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    console.log('Database tables initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err.message);
  }
}

// ========== ROUTES ==========

// ---- Health Check ----
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'StreamVibe API is running', timestamp: new Date().toISOString() });
});

// ---- REGISTER ----
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
    }
    if (name.trim().length < 2) {
      return res.status(400).json({ success: false, message: 'Name must be at least 2 characters.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
    }

    // Check if email already exists
    const [existing] = await pool.execute('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length > 0) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists.' });
    }

    // Hash the password with bcrypt (salt rounds = 12)
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert new user
    const [result] = await pool.execute(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name.trim(), email.toLowerCase(), hashedPassword]
    );

    // Create a default profile for the user
    await pool.execute(
      'INSERT INTO user_profiles (user_id, profile_name) VALUES (?, ?)',
      [result.insertId, name.trim()]
    );

    // Generate JWT token
    const token = jwt.sign(
      { id: result.insertId, name: name.trim(), email: email.toLowerCase() },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: {
        id: result.insertId,
        name: name.trim(),
        email: email.toLowerCase(),
      },
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
});

// ---- LOGIN ----
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    // Find user by email
    const [users] = await pool.execute('SELECT id, name, email, password FROM users WHERE email = ?', [email.toLowerCase()]);
    if (users.length === 0) {
      // Don't reveal whether email exists — use same message
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    const user = users[0];

    // Compare password with bcrypt hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      success: true,
      message: 'Login successful!',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, message: 'Server error during login.' });
  }
});

// ---- VERIFY TOKEN ----
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  // If middleware passed, token is valid
  res.json({
    success: true,
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
    },
  });
});

// ---- GET USER PROFILES ----
app.get('/api/profiles', authenticateToken, async (req, res) => {
  try {
    const [profiles] = await pool.execute(
      'SELECT id, profile_name, avatar, is_kids FROM user_profiles WHERE user_id = ?',
      [req.user.id]
    );
    res.json({ success: true, profiles });
  } catch (err) {
    console.error('Get profiles error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch profiles.' });
  }
});

// ---- WATCHLIST: Add movie ----
app.post('/api/watchlist', authenticateToken, async (req, res) => {
  try {
    const { movieId } = req.body;
    if (!movieId) return res.status(400).json({ success: false, message: 'movieId is required.' });

    await pool.execute(
      'INSERT IGNORE INTO watchlist (user_id, movie_id) VALUES (?, ?)',
      [req.user.id, movieId]
    );
    res.json({ success: true, message: 'Added to watchlist.' });
  } catch (err) {
    console.error('Watchlist add error:', err);
    res.status(500).json({ success: false, message: 'Failed to add to watchlist.' });
  }
});

// ---- WATCHLIST: Remove movie ----
app.delete('/api/watchlist/:movieId', authenticateToken, async (req, res) => {
  try {
    await pool.execute(
      'DELETE FROM watchlist WHERE user_id = ? AND movie_id = ?',
      [req.user.id, req.params.movieId]
    );
    res.json({ success: true, message: 'Removed from watchlist.' });
  } catch (err) {
    console.error('Watchlist remove error:', err);
    res.status(500).json({ success: false, message: 'Failed to remove from watchlist.' });
  }
});

// ---- WATCHLIST: Get all ----
app.get('/api/watchlist', authenticateToken, async (req, res) => {
  try {
    const [items] = await pool.execute(
      'SELECT movie_id, added_at FROM watchlist WHERE user_id = ? ORDER BY added_at DESC',
      [req.user.id]
    );
    res.json({ success: true, watchlist: items });
  } catch (err) {
    console.error('Watchlist get error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch watchlist.' });
  }
});

// ---- GET CURRENT USER ----
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [users] = await pool.execute(
      'SELECT id, name, email, created_at FROM users WHERE id = ?',
      [req.user.id]
    );
    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    res.json({ success: true, user: users[0] });
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch user data.' });
  }
});

// ========== START SERVER ==========
initDatabase().then(() => {
  app.listen(process.env.PORT || 3000, () => {
    console.log(`StreamVibe API running on http://localhost:${process.env.PORT || 3000}`);
    console.log('Available routes:');
    console.log('  POST   /api/auth/register   — Create account');
    console.log('  POST   /api/auth/login      — Login');
    console.log('  GET    /api/auth/verify      — Verify JWT token');
    console.log('  GET    /api/auth/me          — Get current user');
    console.log('  GET    /api/profiles          — Get user profiles');
    console.log('  POST   /api/watchlist         — Add to watchlist');
    console.log('  DELETE /api/watchlist/:id     — Remove from watchlist');
    console.log('  GET    /api/watchlist         — Get watchlist');
  });
});