const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 8080;

const db = new sqlite3.Database('totally_not_my_privateKeys.db');

async function generateKeyPairs() {
  const keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  const expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

  // Save keys to the database
  saveKeyPairToDB(keyPair, Date.now() + 3600);
  saveKeyPairToDB(expiredKeyPair, Date.now() - 3600);
}

function saveKeyPairToDB(keyPair, exp) {
  const pemKey = keyPair.toPEM(true);
  db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [pemKey, exp], (err) => {
    if (err) {
      console.error('Error saving key to DB:', err.message);
    }
  });
}

function getKeyPairFromDB(expired) {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    const query = expired ? 'SELECT * FROM keys WHERE exp < ?' : 'SELECT * FROM keys WHERE exp > ?';
    db.get(query, [now], (err, row) => {
      if (err) {
        reject(err);
      } else {
        if (!row) {
          reject(new Error(expired ? 'No expired keys found' : 'No valid keys found'));
        } else {
          resolve(row.key);
        }
      }
    });
  });
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    const keys = await getAllValidKeysFromDB();
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth', async (req, res) => {
  try {
    const expired = req.query.expired === 'true';
    const privateKey = await getKeyPairFromDB(expired);
    const payload = {
      user: 'sampleUser',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600
    };
    const options = {
      algorithm: 'RS256',
      header: {
        typ: 'JWT',
        alg: 'RS256',
      }
    };
    const token = jwt.sign(payload, privateKey, options);
    res.send(token);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function getAllValidKeysFromDB() {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    db.all('SELECT * FROM keys WHERE exp > ?', [now], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        const validKeys = rows.map(row => jose.JWK.asKey(row.key));
        resolve(validKeys);
      }
    });
  });
}

generateKeyPairs().then(() => {
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
