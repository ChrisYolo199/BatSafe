// --- CENTRAL SECURE STATE ---
const appState = {
    userEmail: "",
    vaultKey: null,      
    serverAuthHash: "",  
    simulatedDatabase: []
};

window.addEventListener('load', () => {
    const inputs = ['email', 'masterPassword', 'regEmail', 'regMasterPassword', 'siteName', 'siteUsername', 'sitePassword'];
    inputs.forEach(id => {
        if (document.getElementById(id)) document.getElementById(id).value = "";
    });
});

// --- BASE64 & BINARY UTILITIES ---
function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToUint8Array(base64String) {
    const binaryString = window.atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Helper to convert array buffer to hexadecimal string
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- SECURE KEY DERIVATION ENGINE ---
async function deriveVaultCredentials(email, password) {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        "raw", encoder.encode(password), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );
    const rawVaultKeyBytes = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: encoder.encode(email), iterations: 600000, hash: "SHA-256" },
        baseKey, 256
    );
    appState.vaultKey = await window.crypto.subtle.importKey(
        "raw", rawVaultKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
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

// --- PANEL NAVIGATION ---
document.getElementById('linkCreateAccount').addEventListener('click', () => {
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('registerScreen').classList.remove('hidden');
});
document.getElementById('linkBackToLogin').addEventListener('click', () => {
    document.getElementById('registerScreen').classList.add('hidden');
    document.getElementById('authScreen').classList.remove('hidden');
});

// --- CORE FUNCTIONAL ACTIONS ---

// 1. UNLOCK APPLICATION
document.getElementById('btnUnlock').addEventListener('click', async () => {
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('masterPassword').value;
    if (!email || !password) return alert("Fill out all the fields");

    try {
        await deriveVaultCredentials(email, password);
        let response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: appState.userEmail, authHash: appState.serverAuthHash })
        });
        let result = await response.json();
        if (!response.ok) throw new Error(result.error);

        appState.simulatedDatabase = result.vault || [];
        await renderVaultItems();
        document.getElementById('authScreen').classList.add('hidden');
        document.getElementById('vaultScreen').classList.remove('hidden');
    } catch (e) { alert("Error: " + e.message); }
});

// 2. CREATE ACCOUNT REGISTER BUTTON
document.getElementById('btnRegisterSubmit').addEventListener('click', async () => {
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regMasterPassword').value;
    if (!email || !password) return alert("Fill out all the fields");

    try {
        await deriveVaultCredentials(email, password);
        let response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: appState.userEmail, authHash: appState.serverAuthHash })
        });
        let result = await response.json();
        if (!response.ok) throw new Error(result.error);

        alert("Account created!");
        document.getElementById('registerScreen').classList.add('hidden');
        document.getElementById('authScreen').classList.remove('hidden');
    } catch (e) { alert("Error: " + e.message); }
});

// 3. ADD NEW PASSWORD ITEM BUTTON
document.getElementById('btnAddItem').addEventListener('click', async () => {
    const label = document.getElementById('siteName').value.trim();
    const username = document.getElementById('siteUsername').value.trim();
    const password = document.getElementById('sitePassword').value;
    if (!label || !username || !password) return alert("Fill out all item fields.");

    try {
        const encoder = new TextEncoder();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv }, appState.vaultKey, encoder.encode(JSON.stringify({ username, password }))
        );

        const databaseRecord = {
            id: Date.now(),
            label: label, 
            iv: bufferToBase64(iv),
            ciphertext: bufferToBase64(encryptedBuffer)
        };

        let response = await fetch('/api/vault/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: appState.userEmail, authHash: appState.serverAuthHash, vaultItem: databaseRecord })
        });
        if (!response.ok) throw new Error("Sync failure.");

        appState.simulatedDatabase.push(databaseRecord);
        await renderVaultItems();
        
        document.getElementById('siteName').value = "";
        document.getElementById('siteUsername').value = "";
        document.getElementById('sitePassword').value = "";
    } catch (e) { alert(e.message); }
});

// 4. RENDERING VAULT ENGINE (SWAPPED TOGGLE COLOR LOGIC)
async function renderVaultItems() {
    const display = document.getElementById('encryptedVaultDisplay');
    display.innerHTML = ""; 

    if (appState.simulatedDatabase.length === 0) {
        display.innerHTML = `<div style="color:#80868b; font-size:0.95em;">No credentials stored.</div>`;
        return;
    }

    for (const item of appState.simulatedDatabase) {
        const itemBox = document.createElement('div');
        itemBox.className = "vault-item";

        itemBox.innerHTML = `
            <div class="vault-item-header">${item.label}</div>
            <div class="vault-item-fields">
                <div class="user-row">[User: <span class="user-span">***********</span>]</div>
                <div class="pass-row">[Pass: <span class="pass-span">***********</span>]</div>
            </div>
            <div class="card-action-row">
                <button class="btn-toggle-state btn-style-show" type="button">Show Password</button>
            </div>
            <div class="vault-item-id">Payload ID: ${item.id.toString(16).substring(0, 10)}</div>
        `;

        const userSpan = itemBox.querySelector('.user-span');
        const passSpan = itemBox.querySelector('.pass-span');
        const btnToggle = itemBox.querySelector('.btn-toggle-state');

        btnToggle.addEventListener('click', async () => {
            // IF CONCEALED -> DECRYPT AND SHOW (BUTTON MORPHS TO RED HIDE STATE)
            if (btnToggle.textContent === "Show Password") {
                try {
                    const ciphertextBytes = base64ToUint8Array(item.ciphertext);
                    const ivBytes = base64ToUint8Array(item.iv);

                    const decryptedBuffer = await window.crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: ivBytes }, appState.vaultKey, ciphertextBytes
                    );

                    const credentials = JSON.parse(new TextDecoder().decode(decryptedBuffer));
                    
                    userSpan.textContent = credentials.username;
                    passSpan.textContent = credentials.password;
                    passSpan.style.color = "#ffff8d"; 
                    
                    // Switch to Red "Hide Password" button state
                    btnToggle.textContent = "Hide Password";
                    btnToggle.classList.remove('btn-style-show');
                    btnToggle.classList.add('btn-style-hide');
                } catch (err) { 
                    alert("Decryption processing fault."); 
                }
            } 
            // IF EXPOSED -> CONCEAL AND COVER (BUTTON MORPHS TO YELLOW SHOW STATE)
            else {
                userSpan.textContent = "***********";
                passSpan.textContent = "***********";
                passSpan.style.color = "";
                
                // Switch back to Yellow "Show Password" button state
                btnToggle.textContent = "Show Password";
                btnToggle.classList.remove('btn-style-hide');
                btnToggle.classList.add('btn-style-show');
            }
        });

        display.appendChild(itemBox);
    }
}

// --- LOCK UTILITY ---
document.getElementById('btnLockApp').addEventListener('click', () => {
    appState.vaultKey = null;
    appState.serverAuthHash = "";
    appState.userEmail = "";
    appState.simulatedDatabase = [];

    document.getElementById('vaultScreen').classList.add('hidden');
    document.getElementById('authScreen').classList.remove('hidden');
    document.getElementById('encryptedVaultDisplay').innerText = "";
});