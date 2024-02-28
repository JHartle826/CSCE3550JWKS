const express = require('express');
const { generateKeyPairSync } = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 8080;

// Dictionary to store generated RSA keys
const keys = {};

// Dummy user database
const users = {
    "user1": "password1",
    "user2": "password2"
};

// Generate RSA key pair
function generateRSAKeyPair() 
{
    return generateKeyPairSync('rsa', 
                               {
                modulusLength: 2048,
                publicKeyEncoding: 
                {
                type: 'spki',
                format: 'pem'
        },
        privateKeyEncoding: 
        {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

// Generate JWT with a given private key
function generateJWT(privateKey) 
{
    const payload = { username: 'example_user' };
    return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

// Authentication endpoint
app.post('/auth', (req, res) => 
    {
    const { username, password } = req.body;
    if (!username || !password) 
    {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (!users[username] || users[username] !== password)
    {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Authentication successful, generate JWT
    const current_time = Math.floor(Date.now() / 1000);
    for (const [kid, { privateKey, expiry }] of Object.entries(keys)) 
    {
        if (expiry > current_time) 
        {
            const token = generateJWT(privateKey);
            return res.json({ token });
        }
    }
    return res.status(500).json({ error: 'No valid keys available' });
});

// Clean up expired keys
function cleanExpiredKeys() {
    const current_time = Math.floor(Date.now() / 1000);
    for (const [kid, { expiry }] of Object.entries(keys)) 
    {
        if (expiry <= current_time) 
        {
            delete keys[kid];
        }
    }
}

// JWKS endpoint
app.get('/jwks', (req, res) => 
{
    const current_time = Math.floor(Date.now() / 1000);
    const jwks_keys = Object.entries(keys).reduce((acc, [kid, { privateKey, expiry }]) => {
        if (expiry > current_time) {
            acc.push({
                kid,
                kty: 'RSA',
                alg: 'RS256',
                use: 'sig',
                n: privateKey.export({ type: 'spki', format: 'pem' }).toString('base64'),
                e: 'AQAB' // Public exponent
            });
        }
        return acc;
    }, []);
    res.json({ keys: jwks_keys });
});

// Generate initial RSA key pair and start server
function startServer() 
{
    const { privateKey, publicKey } = generateRSAKeyPair();
    keys['1'] = { privateKey, expiry: Math.floor(Date.now() / 1000) + 3600 }; // Expiry in 1 hour

    setInterval(cleanExpiredKeys, 60000); // Clean up expired keys every minute

    app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
}

startServer();
