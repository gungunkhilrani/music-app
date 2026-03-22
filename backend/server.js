// backend/server.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // For password hashing
const sqlite3 = require('sqlite3').verbose(); // For SQLite database

const app = express();
const PORT = process.env.PORT || 3005;
const JWT_SECRET = 'your_very_secret_key_for_jwt_shhh_make_this_MUCH_stronger_in_prod_and_use_env_var';

// --- Database Setup ---
const DB_SOURCE = "musicapp.db"; // Database file will be created in this 'backend' folder

const db = new sqlite3.Database(DB_SOURCE, (err) => {
    if (err) {
        console.error("Error opening database:", err.message);
        throw err;
    } else {
        console.log('Connected to the SQLite database.');
        db.serialize(() => { // Ensures statements run in order
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )`, (err) => {
                if (err) console.error("Error creating users table:", err.message);
                else console.log("Users table is ready.");
            });

            db.run(`CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                song_id TEXT,
                title TEXT NOT NULL,
                artist TEXT,
                url TEXT,
                coverArt TEXT,
                played_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )`, (err) => {
                if (err) console.error("Error creating history table:", err.message);
                else console.log("History table is ready.");
            });
        });
    }
});

// Middleware
app.use(cors());
app.use(bodyParser.json());

// --- Authentication Middleware (to protect certain routes) ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ message: 'Authentication token is required.' });
    }

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(403).json({ message: 'Token is invalid or has expired.' });
        }
        req.user = userPayload; // Contains { userId, username }
        next();
    });
};

// --- Authentication Routes ---

// POST /api/auth/register - User Registration
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }
    if (password.length < 4) {
        return res.status(400).json({ message: 'Password must be at least 4 characters long.' });
    }

    const sqlCheckUser = "SELECT id FROM users WHERE username = ?";
    db.get(sqlCheckUser, [username], async (err, row) => {
        if (err) {
            console.error("DB Error (check user):", err.message);
            return res.status(500).json({ message: 'Server error during registration.' });
        }
        if (row) {
            return res.status(400).json({ message: 'Username already taken.' });
        }

        try {
            const saltRounds = 10;
            const password_hash = await bcrypt.hash(password, saltRounds);

            const sqlInsertUser = `INSERT INTO users (username, password_hash) VALUES (?, ?)`;
            db.run(sqlInsertUser, [username, password_hash], function(err) {
                if (err) {
                    console.error("DB Error (insert user):", err.message);
                    return res.status(500).json({ message: 'Server error during registration.' });
                }
                console.log(`User registered: ${username}, ID: ${this.lastID}`);
                res.status(201).json({ message: 'User registered successfully!', userId: this.lastID });
            });
        } catch (hashError) {
            console.error("Hashing Error:", hashError);
            return res.status(500).json({ message: 'Server error during registration processing.' });
        }
    });
});

// POST /api/auth/login - User Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required.' });
    }

    const sqlGetUser = "SELECT * FROM users WHERE username = ?";
    db.get(sqlGetUser, [username], async (err, user) => {
        if (err) {
            console.error("DB Error (get user for login):", err.message);
            return res.status(500).json({ message: 'Server error during login.' });
        }
        if (!user) {
            return res.status(400).json({ message: 'Invalid username or password.' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid username or password.' });
            }

            const accessToken = jwt.sign(
                { userId: user.id, username: user.username },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            console.log('User logged in:', { id: user.id, username: user.username });
            res.json({
                accessToken,
                user: { id: user.id, username: user.username }
            });
        } catch (compareError) {
            console.error("Password Compare Error:", compareError);
            return res.status(500).json({ message: 'Server error during login processing.' });
        }
    });
});

// GET /api/auth/me - Get current logged-in user's info
app.get('/api/auth/me', authenticateToken, (req, res) => {
    const sqlGetUser = "SELECT id, username FROM users WHERE id = ?";
    db.get(sqlGetUser, [req.user.userId], (err, user) => {
        if (err) {
            console.error("DB Error (get me):", err.message);
            return res.status(500).json({ message: 'Server error fetching user profile.' });
        }
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.json({ user });
    });
});


// --- Music History Routes (Protected by `authenticateToken`) ---

// GET /api/history - Get playback history for the logged-in user
app.get('/api/history', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const sqlGetHistory = `
        SELECT id, song_id, title, artist, url, coverArt, played_at 
        FROM history 
        WHERE user_id = ? 
        ORDER BY played_at DESC 
        LIMIT 50`; // Get latest 50 history items

    db.all(sqlGetHistory, [userId], (err, rows) => {
        if (err) {
            console.error("DB Error (get history):", err.message);
            return res.status(500).json({ message: 'Server error fetching history.' });
        }
        res.json(rows || []);
    });
});

// POST /api/history - Add a song to playback history for the logged-in user
app.post('/api/history', authenticateToken, (req, res) => {
    const userId = req.user.userId;
    const { id: song_id, title, artist, url, coverArt } = req.body.song; // Destructure song details

    if (!title) { // song_id might be optional if it's from an external source without a fixed ID
        return res.status(400).json({ message: 'Song title is required.' });
    }

    const played_at = new Date().toISOString();
    const sqlInsertHistory = `
        INSERT INTO history (user_id, song_id, title, artist, url, coverArt, played_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.run(sqlInsertHistory, [userId, song_id, title, artist, url, coverArt, played_at], function(err) {
        if (err) {
            console.error("DB Error (insert history):", err.message);
            return res.status(500).json({ message: 'Server error saving history.' });
        }
        console.log(`Song added to history for user ${userId}: ${title}, History ID: ${this.lastID}`);
        res.status(201).json({ message: 'Song added to history.', historyId: this.lastID });
    });
});


// --- Start the Server ---
app.listen(PORT, () => {
    console.log(`Backend server is up and running on http://localhost:${PORT}`);
    console.log("Data will now be stored in the musicapp.db SQLite file.");
});