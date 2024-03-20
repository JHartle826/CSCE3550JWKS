# CSCE3550JWKS
JWKS Server for UNT CSCE3550

The code was 100% JavaScript which is a newer language for me so I had some concerns in debugging the code

Inatallation:
  To clone the repostitory:
  git clone https://github.com/yourusername/yourrepository.git
  cd "yourrepository"
  npm install

Usage:
  Ensure SQLite is installed on your system.
  Start the server:
    npm start
    The server will start listening on http://localhost:8080.

Endpoints
  GET /.well-known/jwks.json
    Retrieves all valid (non-expired) private keys from the database and returns a JWKS (JSON Web Key Set) response containing those keys.

  POST /auth
    Generates and signs a JWT using a private key retrieved from the database. If the query parameter expired=true is present, it uses an expired key for signing.
  
