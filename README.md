# CSCE3550JWKS
JWKS Server for UNT CSCE3550

# JWT Server with AES Encryption, User Registration, and Rate Limiting

This is a Node.js server application that provides JWT (JSON Web Token) generation, AES encryption of private keys, user registration functionality, logging of authentication requests, and optional rate limiting.

## Features

- **JWT Generation**: Provides an endpoint for generating JWTs signed with RSA private keys.
- **AES Encryption of Private Keys**: Private keys stored in the database are encrypted using AES encryption.
- **User Registration**: Allows users to register with a username and email, generating a secure password for them.
- **Logging of Authentication Requests**: Logs IP address, timestamp, and user ID for authentication requests.
- **Rate Limiting** (Optional): Limits the number of authentication requests per IP address within a specific time window.

## Prerequisites

- Node.js
- SQLite3
- `node-jose`
- `argon2`
- `crypto`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your/repository.git

2. Dependency Installation:
   npm install

3. Run the server:
  node server.js

 ## Configuration

 AES Key: Set the NOT_MY_KEY environment variable with a secure AES encryption key.
Rate Limiting: Adjust the RATE_LIMIT_WINDOW and RATE_LIMIT_MAX_REQUESTS constants in server.js for rate limiting configuration.
Endpoints
GET /.well-known/jwks.json: Retrieve JSON Web Key Set (JWKS) containing RSA public keys.
POST /auth: Generate and return JWTs. Optionally accepts a query parameter expired=true to retrieve an expired key.
POST /register: Register a new user with a username and email. Returns a generated secure password.

## Database Schema

keys Table
key: Encrypted private key.
exp: Expiry timestamp of the key.
users Table
id: Primary key, auto-incremented.
username: User's username (unique).
password_hash: Hashed password using Argon2.
email: User's email (unique).
date_registered: Timestamp of user registration.
last_login: Timestamp of user's last login.
auth_logs Table
id: Primary key, auto-incremented.
request_ip: IP address of the authentication request.
request_timestamp: Timestamp of the authentication request.
user_id: Foreign key referencing the id column in the users table.
