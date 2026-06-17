import 'dotenv/config'; 
import express from 'express';
import cors from 'cors';
import pkg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pkg;

// Recreate __dirname since it's not native to ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware configurations
app.use(cors());
app.use(express.json()); // Allows our server to read JSON sent by the frontend
app.use(express.static(path.join(__dirname, 'public')));

// Initialize connection pool to secure cloud Supabase instance
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for secure cloud hosting database connections
  }
});

// Verify connection on startup
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error("❌ Database connection failed:", err.message);
    } else {
        console.log("✅ Connected successfully to secure Supabase Cloud Database.");
    }
});

// --- SIGN UP ENDPOINT ---
app.post('/api/register', async (req, res) => {
    const { email, authHash } = req.body;
    if (!email || !authHash) return res.status(400).json({ error: "Missing required fields." });

    // Normalize email to lowercase to prevent salt mismatches from typos
    const normalizedEmail = email.toLowerCase().trim();

    try {
        const sql = `INSERT INTO users (email, auth_hash) VALUES ($1, $2)`;
        await pool.query(sql, [normalizedEmail, authHash]);
        res.json({ message: "Registration successful!" });
    } catch (err) {
        if (err.code === '23505') { // PostgreSQL unique constraint violation error code
            return res.status(400).json({ error: "This account already exists." });
        }
        return res.status(500).json({ error: err.message });
    }
});

// --- SIGN IN ENDPOINT ---
app.post('/api/login', async (req, res) => {
    const { email, authHash } = req.body;
    if (!email || !authHash) return res.status(400).json({ error: "Missing required fields." });

    const normalizedEmail = email.toLowerCase().trim();

    try {
        const userResult = await pool.query(`SELECT * FROM users WHERE email = $1`, [normalizedEmail]);
        const user = userResult.rows[0];

        if (!user || user.auth_hash !== authHash) {
            return res.status(401).json({ error: "Invalid email or master password." });
        }

        // Pull user records cleanly from cloud table matching profile email
        const vaultResult = await pool.query(
            `SELECT id, label, iv, ciphertext FROM vault_items WHERE user_email = $1`, 
            [normalizedEmail]
        );
        
        res.json({ message: "Access granted. Synchronizing vault...", vault: vaultResult.rows });
    } catch (err) {
        return res.status(500).json({ error: err.message });
    }
});

// --- SYNCHRONIZE NEW ITEM ENDPOINT ---
app.post('/api/vault/add', async (req, res) => {
    const { email, authHash, vaultItem } = req.body;
    if (!email || !authHash || !vaultItem) return res.status(400).json({ error: "Missing payload data." });

    const normalizedEmail = email.toLowerCase().trim();

    try {
        // Verify user credentials before modifying cloud storage data assets
        const userResult = await pool.query(`SELECT * FROM users WHERE email = $1`, [normalizedEmail]);
        const user = userResult.rows[0];

        if (!user || user.auth_hash !== authHash) {
            return res.status(401).json({ error: "Unauthorized sync request rejected." });
        }

        const sql = `INSERT INTO vault_items (id, user_email, label, iv, ciphertext) VALUES ($1, $2, $3, $4, $5)`;
        
        await pool.query(sql, [
            Number(vaultItem.id), 
            normalizedEmail, 
            vaultItem.label, 
            String(vaultItem.iv), 
            String(vaultItem.ciphertext)
        ]);

        res.json({ message: "Encrypted asset synchronized successfully." });
    } catch (err) {
        console.error("Database Write Error:", err.message);
        return res.status(500).json({ error: "Cloud sync database failure." });
    }
});

// Single unified app startup listener
app.listen(PORT, () => {
    console.log(`Server running securely at http://localhost:${PORT}`);
});