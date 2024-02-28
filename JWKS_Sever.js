const express = require('express');
const { generateKeyPairSync } = require('crypto');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 8080;

// Dictionary to store generated RSA keys
const keys = {};

// Dummy user database
const Users = {
    "User1": "Password1",
    "User2": "Password2"
};

// Generate RSA key pair
function GenerateRSAKeyPair() 
{
    return generateKeyPairSync('rsa', 
                               {
                modulusLength: 2048,
                PublicKeyEncoding: 
                {
                type: 'spki',
                format: 'pem'
        },
        PrivateKeyEncoding: 
        {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}

// Generate JWT with a given private key
function GenerateJWT(PrivateKey) 
{
    const payload = { Username: 'example_user' };
    return jwt.sign(payload, PrivateKey, { algorithm: 'RS256' });
}

// Authentication endpoint
app.post('/auth', (req, res) => 
    {
    const { Username, password } = req.body;
    if (!Username || !password) 
    {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (!Users[Username] || Users[Username] !== password)
    {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Authentication successful, generate JWT
    const Current_Time = Math.floor(Date.now() / 1000);
    for (const [kid, { PrivateKey, expiry }] of Object.entries(keys)) 
    {
        if (expiry > Current_Time) 
        {
            const token = GenerateJWT(PrivateKey);
            return res.json({ token });
        }
    }
    return res.status(500).json({ error: 'No valid keys available' });
});

// Clean up expired keys
function CleanExpiredKeys() {
    const Current_Time = Math.floor(Date.now() / 1000);
    for (const [kid, { expiry }] of Object.entries(keys)) 
    {
        if (expiry <= Current_Time) 
        {
            delete keys[kid];
        }
    }
}

// JWKS endpoint
app.get('/jwks', (req, res) => 
{
    const Current_Time = Math.floor(Date.now() / 1000);
    const jwks_keys = Object.entries(keys).reduce((acc, [kid, { PrivateKey, expiry }]) => {
        if (expiry > Current_Time) {
            acc.push({
                kid,
                kty: 'RSA',
                alg: 'RS256',
                use: 'sig',
                n: PrivateKey.export({ type: 'spki', format: 'pem' }).toString('base64'),
                e: 'AQAB' // Public exponent
            });
        }
        return acc;
    }, []);
    res.json({ keys: jwks_keys });
});

// Generate initial RSA key pair and start server
function StartServer() 
{
    const { PrivateKey, PublicKey } = generateRSAKeyPair();
    keys['1'] = { PrivateKey, expiry: Math.floor(Date.now() / 1000) + 3600 }; // Expiry in 1 hour

    setInterval(cleanExpiredKeys, 60000); // Clean up expired keys every minute

    app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
}

StartServer();
