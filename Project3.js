const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const argon2 = require('argon2');

const app = express();
const port = 8080;

// Initialize SQLite database
const db = new sqlite3.Database('totally_not_my_privateKeys.db');

// AES encryption and decryption key from environment variable
const AES_KEY = process.env.NOT_MY_KEY;

// AES encryption and decryption functions
function encryptData(data, key) {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, crypto.randomBytes(16));
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptData(data, key) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, crypto.randomBytes(16));
  let decrypted = decipher.update(data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Generate secure password using UUIDv4
function generateSecurePassword() {
  return crypto.randomBytes(16).toString('hex');
}

// Middleware for rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 10000; // 10 seconds
const RATE_LIMIT_MAX_REQUESTS = 10;

function rateLimiter(req, res, next) {
  const ip = req.ip;
  const now = Date.now();
  const requests = rateLimitMap.get(ip) || [];

  // Remove requests that are older than the window
  const newRequests = requests.filter(time => now - time < RATE_LIMIT_WINDOW);
  if (newRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
    return res.status(429).send('Too Many Requests');
  }

  rateLimitMap.set(ip, [...newRequests, now]);
  next();
}

// Middleware to log authentication requests
function logAuthRequest(req, res, next) {
  const ip = req.ip;
  const user = req.body.username; // Assuming username is provided in request body
  const userId = getUserIdFromUsername(user); // You need to implement this function

  // Log the authentication request
  db.run('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', [ip, userId], (err) => {
    if (err) {
      console.error('Error logging authentication request:', err.message);
    }
  });

  next();
}

// Function to generate RSA key pairs and save them to the database
async function generateKeyPairs() {
  // Generate RSA key pairs
  const keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  // Save key pairs to the database
  saveKeyPairToDB(keyPair, Date.now() + 3600); // Expiry in 1 hour
  saveKeyPairToDB(expiredKeyPair, Date.now() - 3600); // Expiry in the past (expired)
}

// Function to save a key pair to the database
function saveKeyPairToDB(keyPair, exp) {
  const pemKey = keyPair.toPEM(true); // Serialize key to PEM format
  const encryptedKey = encryptData(pemKey, AES_KEY); // Encrypt private key
  // Insert encrypted key pair into the database
  db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [encryptedKey, exp], (err) => {
    if (err) {
      console.error('Error saving key to DB:', err.message);
    }
  });
}

// Function to retrieve a key pair from the database
function getKeyPairFromDB(expired) {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    const query = expired ? 'SELECT * FROM keys WHERE exp < ?' : 'SELECT * FROM keys WHERE exp > ?';
    // Execute the database query
    db.get(query, [now], (err, row) => {
      if (err) {
        reject(err);
      } else {
        if (!row) {
          reject(new Error(expired ? 'No expired keys found' : 'No valid keys found'));
        } else {
          const encryptedKey = row.key;
          const pemKey = decryptData(encryptedKey, AES_KEY); // Decrypt private key
          resolve(jose.JWK.asKey(pemKey)); // Resolve with the key pair
        }
      }
    });
  });
}

// Function to retrieve user ID from username (to be implemented)
function getUserIdFromUsername(username) {
  // Implementation to fetch user ID from database based on username
}

// Endpoint to retrieve JWKS (JSON Web Key Set)
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    // Retrieve all valid keys from the database
    const keys = await getAllValidKeysFromDB();
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys }); // Return keys in JWKS format
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to generate and return JWTs
app.post('/auth', rateLimiter, logAuthRequest, async (req, res) => {
  try {
    const expired = req.query.expired === 'true'; // Check if expired query parameter is true
    const privateKey = await getKeyPairFromDB(expired); // Retrieve private key from the database
    const payload = {
      user: 'sampleUser',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600 // Token expiry in 1 hour
    };
    const options = {
      algorithm: 'RS256',
      header: {
        typ: 'JWT',
        alg: 'RS256',
      }
    };
    const token = jwt.sign(payload, privateKey, options); // Sign JWT using private key
    res.send(token); // Send JWT as response
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Function to retrieve all valid keys from the database
async function getAllValidKeysFromDB() {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    // Query to retrieve keys with expiry greater than current time
    db.all('SELECT * FROM keys WHERE exp > ?', [now], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        // Deserialize keys and return
        const validKeys = rows.map(row => jose.JWK.asKey(decryptData(row.key, AES_KEY)));
        resolve(validKeys);
      }
    });
  });
}

// Initialize key generation, start server on specified port
generateKeyPairs().then(() => {
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
