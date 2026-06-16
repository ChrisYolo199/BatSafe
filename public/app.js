// --- CENTRAL SECURE STATE ---
// This object holds our keys strictly in volatile memory (RAM).
const appState = {
    userEmail: "",
    vaultKey: null,      // CryptoKey Object used for AES-GCM
    serverAuthHash: "",  // Hex string for login operations
    simulatedDatabase: [] // Temporary array representing database records
};

// --- CRYPTOGRAPHIC UTILITIES ---
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Derive both the vaultKey object and serverAuthHash from master password
async function deriveVaultCredentials(email, password) {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );

    // Derive raw 256-bit Vault Key material
    const rawVaultKeyBytes = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: encoder.encode(email), iterations: 600000, hash: "SHA-256" },
        baseKey, 256
    );

    // Turn raw bytes into a functional AES-GCM CryptoKey object
    appState.vaultKey = await window.crypto.subtle.importKey(
        "raw", rawVaultKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );

    // Derive the secondary Server Auth Hash
    const authBaseKey = await window.crypto.subtle.importKey(
        "raw", rawVaultKeyBytes, { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const rawAuthBytes = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: encoder.encode(email + "auth_purposes"), iterations: 1, hash: "SHA-256" },
        authBaseKey, 256
    );

    appState.serverAuthHash = bufferToHex(rawAuthBytes);
    appState.userEmail = email;
}

// --- INTERACTION LOGIC ---

// Handle Unlock / "Login or Register"
document.getElementById('btnUnlock').addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    const password = document.getElementById('masterPassword').value;
    const authScreen = document.getElementById('authScreen');
    const vaultScreen = document.getElementById('vaultScreen');

    if (!email || !password) return alert("Please fill out all fields.");

    try {
        // Step 1: Derive the local Vault Key and Server Auth Hash exactly like before
        await deriveVaultCredentials(email, password);

        // Step 2: Attempt to Log In by sending the auth hash over the network
        console.log("Sending login request to server...");
        let response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: appState.userEmail, authHash: appState.serverAuthHash })
        });

        let result = await response.json();

        // Step 3: If user doesn't exist yet, let's automatically register them for this demo!
        if (response.status === 401 && result.error === "Invalid email or master password.") {
            // Let's check if it's a completely new user profile configuration
            console.log("User not found. Registering new profile account...");
            
            let registerResponse = await fetch('/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: appState.userEmail, authHash: appState.serverAuthHash })
            });

            let registerResult = await registerResponse.json();
            
            if (!registerResponse.ok) {
                throw new Error(registerResult.error);
            }

            alert("Account created successfully! Click 'Unlock Local Vault' again to log into your new vault.");
            return;
        }

        if (!response.ok) {
            throw new Error(result.error);
        }

        // Step 4: Login successful! Load server vault data into client state
        alert(result.message); // Displays "Login successful!"
        
        // Populate our state cache array with whatever encrypted vault records the server sent back
        appState.simulatedDatabase = result.vault || [];
        renderVaultItems();

        // UI Transition
        authScreen.classList.add('hidden');
        vaultScreen.classList.remove('hidden');
        document.getElementById('masterPassword').value = "";

    } catch (error) {
        alert("Authentication Error: " + error.message);
    }
});

// Handle Adding, Encrypting, and Synchronizing a Vault Item
document.getElementById('btnAddItem').addEventListener('click', async () => {
    const label = document.getElementById('siteName').value;
    const username = document.getElementById('siteUsername').value;
    const password = document.getElementById('sitePassword').value;

    if (!label || !username || !password) return alert("Fill out all item fields.");

    try {
        const encoder = new TextEncoder();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Package target details together as a clean JSON packet text
        const plainPayload = JSON.stringify({ username, password });

        // Encrypt locally using our isolated Vault Key
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            appState.vaultKey,
            encoder.encode(plainPayload)
        );

        const ciphertextBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
        const base64Iv = btoa(String.fromCharCode(...iv));

        const databaseRecord = {
            id: Date.now(),
            label: label, 
            iv: base64Iv,
            ciphertext: ciphertextBase64
        };

        // NETWORK SYNC OPERATION: Send the encrypted record payload to the database
        console.log("Synchronizing encrypted record to cloud server database...");
        let response = await fetch('/api/vault/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: appState.userEmail,
                authHash: appState.serverAuthHash, // Authenticates request
                vaultItem: databaseRecord         // The encrypted data object
            })
        });

        let result = await response.json();

        if (!response.ok) {
            throw new Error(result.error);
        }

        // Push directly to our client-side display array and render
        appState.simulatedDatabase.push(databaseRecord);
        renderVaultItems();

        // Clear local UI inputs
        document.getElementById('siteName').value = "";
        document.getElementById('siteUsername').value = "";
        document.getElementById('sitePassword').value = "";

    } catch (e) {
        alert("Sync failed: " + e.message);
    }
});

// --- DECRYPTION HELPER UTILITY ---
function base64ToUint8Array(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// --- AUTOMATIC DECRYPTION RENDERING ENGINE ---
async function renderVaultItems() {
    const display = document.getElementById('encryptedVaultDisplay');
    display.innerHTML = ""; // Clear out stale interface elements

    if (appState.simulatedDatabase.length === 0) {
        display.innerText = "No credentials synchronized to this account yet.";
        return;
    }

    // Loop through every single encrypted record payload received from the server
    for (const item of appState.simulatedDatabase) {
        const itemBox = document.createElement('div');
        itemBox.className = "vault-item";

        try {
            // Step 1: Turn the stored Base64 strings back into raw cryptographic byte arrays
            const ciphertextBytes = base64ToUint8Array(item.ciphertext);
            const ivBytes = base64ToUint8Array(item.iv);

            // Step 2: Decrypt the credential payload client-side using the local vaultKey
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: ivBytes },
                appState.vaultKey,
                ciphertextBytes
            );

            // Step 3: Decode the decrypted binary array stream into a standard JSON string
            const decoder = new TextDecoder();
            const decryptedPayloadString = decoder.decode(decryptedBuffer);
            
            // Step 4: Parse the payload string back into a workable JavaScript Object
            const credentials = JSON.parse(decryptedPayloadString);

            // Step 5: Render the beautifully cleared plaintext info onto the user screen interface
            itemBox.innerHTML = `
                <strong style="color: #007acc; font-size: 1.1em;">Site: ${item.label}</strong>
                <div style="margin-top: 8px; font-family: monospace;">
                    <div><strong>User:</strong> ${credentials.username}</div>
                    <div><strong>Pass:</strong> <span style="color: #ffb300;">${credentials.password}</span></div>
                </div>
                <div style="margin-top: 10px; font-size: 0.75em; color: #666;">
                    Encrypted Server Payload ID: ${item.id}
                </div>
            `;

        } catch (error) {
            // Security fallback: If decryption fails for one specific item, shield the view gracefully
            console.error("Failed to decrypt item payload:", error);
            itemBox.style.borderLeft = "4px solid #d9534f";
            itemBox.innerHTML = `
                <strong>Site: ${item.label}</strong>
                <p style="color: #d9534f; font-size: 0.85em; margin: 5px 0 0 0;">
                    [Decryption Failure: Secure key mismatch or corrupted server payload]
                </p>
            `;
        }

        display.appendChild(itemBox);
    }
}

// Handle App Lock (Clearing secure state completely)
document.getElementById('btnLockApp').addEventListener('click', () => {
    // Wipe sensitive cryptographic material from active memory
    appState.vaultKey = null;
    appState.serverAuthHash = "";
    appState.userEmail = "";
    appState.simulatedDatabase = [];

    // Reset view
    document.getElementById('vaultScreen').classList.add('hidden');
    document.getElementById('authScreen').classList.remove('hidden');
    document.getElementById('encryptedVaultDisplay').innerText = "No items stored yet.";
});