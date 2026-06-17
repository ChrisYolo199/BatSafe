const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// 1. Initialize or open the local database file
const dbPath = path.join(__dirname, 'batsafe.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Database initialization failed:", err.message);
    } else {
        console.log("Connected successfully to secure batsafe.db file.");
    }
});

// 2. Build the database structure (Tables)
db.serialize(() => {
    // Table to keep track of user authentications
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            authHash TEXT NOT NULL
        )
    `);

    // Table to store local isolated encrypted vault records
    db.run(`
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY,
            email TEXT NOT NULL,
            label TEXT NOT NULL,
            iv TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            FOREIGN KEY(email) REFERENCES users(email)
        )
    `);
});

// Middleware configurations
app.use(cors());
app.use(express.json()); // Allows our server to read JSON sent by the frontend
app.use(express.static('public'));

// Simulated Database Array (Temporary storage in server memory)
const usersTable = [];

// --- SIGN UP ENDPOINT ---
app.post('/api/register', (req, res) => {
    const { email, authHash } = req.body;
    if (!email || !authHash) return res.status(400).json({ error: "Missing required fields." });

    // Normalize email to lowercase to prevent salt mismatches from typos
    const normalizedEmail = email.toLowerCase().trim();

    const sql = `INSERT INTO users (email, authHash) VALUES (?, ?)`;
    db.run(sql, [normalizedEmail, authHash], function(err) {
        if (err) {
            if (err.message.includes("UNIQUE constraint failed")) {
                return res.status(400).json({ error: "This account already exists." });
            }
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: "Registration successful!" });
    });
});

// --- SIGN IN ENDPOINT ---
app.post('/api/login', (req, res) => {
    const { email, authHash } = req.body;
    if (!email || !authHash) return res.status(400).json({ error: "Missing required fields." });

    const normalizedEmail = email.toLowerCase().trim();

    db.get(`SELECT * FROM users WHERE email = ?`, [normalizedEmail], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user || user.authHash !== authHash) {
            return res.status(401).json({ error: "Invalid email or master password." });
        }

        // Pull records cleanly
        db.all(`SELECT id, label, iv, ciphertext FROM vault_items WHERE email = ?`, [normalizedEmail], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Access granted. Synchronizing vault...", vault: rows });
        });
    });
});

// --- SYNCHRONIZE NEW ITEM ENDPOINT ---
app.post('/api/vault/add', (req, res) => {
    const { email, authHash, vaultItem } = req.body;
    if (!email || !authHash || !vaultItem) return res.status(400).json({ error: "Missing payload data." });

    const normalizedEmail = email.toLowerCase().trim();

    // Verify user credentials before modifying data
    db.get(`SELECT * FROM users WHERE email = ?`, [normalizedEmail], (err, user) => {
        if (err || !user || user.authHash !== authHash) {
            return res.status(401).json({ error: "Unauthorized sync request rejected." });
        }

        const sql = `INSERT INTO vault_items (id, email, label, iv, ciphertext) VALUES (?, ?, ?, ?, ?)`;
        
        // Ensure ID is passed cleanly as a number, and cryptographic strings remain untouched
        db.run(sql, [
            Number(vaultItem.id), 
            normalizedEmail, 
            vaultItem.label, 
            String(vaultItem.iv), 
            String(vaultItem.ciphertext)
        ], (err) => {
            if (err) {
                console.error("Database Write Error:", err.message);
                return res.status(500).json({ error: "Cloud sync database failure." });
            }
            res.json({ message: "Encrypted asset synchronized successfully." });
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server running securely at http://localhost:${PORT}`);
});