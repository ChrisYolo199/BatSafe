const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware configurations
app.use(cors());
app.use(express.json()); // Allows our server to read JSON sent by the frontend
app.use(express.static('public'));

// Simulated Database Array (Temporary storage in server memory)
const usersTable = [];

// --- API ENDPOINT 1: USER REGISTRATION ---
app.post('/api/register', (req, res) => {
    const { email, authHash } = req.body;

    if (!email || !authHash) {
        return res.status(400).json({ error: "Missing required fields." });
    }

    // Check if user already exists
    const userExists = usersTable.find(u => u.email === email);
    if (userExists) {
        return res.status(400).json({ error: "User already registered." });
    }

    // Store the credential profile
    const newProfile = {
        email: email,
        serverAuthHash: authHash, // The derived string sent over the network
        vaultItems: [] // Empty vault container initialized for the user
    };

    usersTable.push(newProfile);
    console.log(`[SERVER REGISTRATION] New user created: ${email}`);
    
    return res.status(201).json({ message: "Account successfully created!" });
});

// --- API ENDPOINT 2: USER LOGIN ---
app.post('/api/login', (req, res) => {
    const { email, authHash } = req.body;

    if (!email || !authHash) {
        return res.status(400).json({ error: "Missing fields." });
    }

    // Locate the user file record
    const userRecord = usersTable.find(u => u.email === email);
    if (!userRecord) {
        return res.status(401).json({ error: "Invalid email or master password." });
    }

    // Validate the incoming hash match against our recorded hash
    if (userRecord.serverAuthHash === authHash) {
        console.log(`[SERVER LOGIN] Authentication Successful for: ${email}`);
        return res.status(200).json({ 
            message: "Login successful!",
            vault: userRecord.vaultItems // Return their encrypted data back to them
        });
    } else {
        return res.status(401).json({ error: "Invalid email or master password." });
    }
});

// --- SYNC ENDPOINT: SAVE ENCRYPTED VAULT ITEM ---
app.post('/api/vault/add', (req, res) => {
    try {
        const { email, authHash, vaultItem } = req.body;

        if (!email || !authHash || !vaultItem) {
            return res.status(400).json({ error: "Missing synchronization details." });
        }

        // Locate user profile record
        const userRecord = usersTable.find(u => u.email === email);
        if (!userRecord || userRecord.serverAuthHash !== authHash) {
            return res.status(401).json({ error: "Authentication failed. Cannot sync data." });
        }

        // Push the client-side encrypted item safely into the user's vault database container
        userRecord.vaultItems.push(vaultItem);
        console.log(`[DATABASE SYNC] Added 1 encrypted item to vault for: ${email}`);
        
        return res.status(200).json({ message: "Item synchronized securely to backend database!" });

    } catch (error) {
        console.error("[SERVER ERROR IN VAULT ADD]:", error);
        return res.status(500).json({ error: "Internal Server Error during synchronization." });
    }
});

app.listen(PORT, () => {
    console.log(`Server running securely at http://localhost:${PORT}`);
});