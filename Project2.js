const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose(); // Import SQLite module

const app = express();
const port = 8080;

// Initialize SQLite database
const db = new sqlite3.Database('totally_not_my_privateKeys.db');

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
  // Insert key pair into the database
  db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [pemKey, exp], (err) => {
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
          resolve(row.key); // Resolve with the key pair
        }
      }
    });
  });
}

// Middleware to ensure only POST requests are allowed for /auth endpoint
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks endpoint
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

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
app.post('/auth', async (req, res) => {
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
        const validKeys = rows.map(row => jose.JWK.asKey(row.key));
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
