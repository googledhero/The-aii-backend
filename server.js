// server.js - Backend Authentication Server
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Middleware
app.use(cors());
app.use(express.json());

// Initialize SQLite Database
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('✅ Database connected!');
        initDatabase();
    }
});

// Create tables
function initDatabase() {
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    `, (err) => {
        if (err) {
            console.error('Error creating table:', err);
        } else {
            console.log('✅ Users table ready!');
            createOwnerAccount();
        }
    });
}

// Create default owner account
function createOwnerAccount() {
    const ownerEmail = process.env.OWNER_EMAIL || 'owner@theaii.com';
    const ownerUsername = process.env.OWNER_USERNAME || 'Owner';
    const ownerPassword = process.env.OWNER_PASSWORD || 'Owner@123';

    db.get('SELECT * FROM users WHERE email = ?', [ownerEmail], async (err, user) => {
        if (!user) {
            const hashedPassword = await bcrypt.hash(ownerPassword, 10);
            db.run(
                'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                   [ownerUsername, ownerEmail, hashedPassword, 'owner'],
                   (err) => {
                       if (!err) {
                           console.log('👑 Owner account created!');
                           console.log('Email:', ownerEmail);
                           console.log('Password:', ownerPassword);
                       }
                   }
            );
        }
    });
}

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token.' });
        }
        req.user = user;
        next();
    });
}

// SIGNUP ENDPOINT
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required!' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters!' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (user) {
            return res.status(400).json({ error: 'This email is already registered!' });
        }

        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (user) {
                return res.status(400).json({ error: 'This username is already taken!' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            db.run(
                'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
                   [username, email, hashedPassword, 'user'],
                   function(err) {
                       if (err) {
                           return res.status(500).json({ error: 'Error creating account!' });
                       }

                       const token = jwt.sign(
                           { id: this.lastID, username, email, role: 'user' },
                           JWT_SECRET,
                           { expiresIn: '7d' }
                       );

                       res.json({
                           success: true,
                           message: 'Account created successfully!',
                           token,
                           user: { id: this.lastID, username, email, role: 'user' }
                       });
                   }
            );
        });
    });
});

// LOGIN ENDPOINT
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required!' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password!' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password!' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            success: true,
            message: 'Login successful!',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            }
        });
    });
});

// GET USER INFO
app.get('/api/user', authenticateToken, (req, res) => {
    db.get('SELECT id, username, email, role, created_at FROM users WHERE id = ?',
           [req.user.id],
           (err, user) => {
               if (err || !user) {
                   return res.status(404).json({ error: 'User not found!' });
               }
               res.json({ user });
           }
    );
});

// GET ALL USERS (Owner/Admin only)
app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'owner' && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied!' });
    }

    db.all('SELECT id, username, email, role, created_at FROM users', (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Error fetching users!' });
        }
        res.json({ users });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
