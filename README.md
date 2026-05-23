CipherSphere — Secure Password Vault
CipherSphere is a full-stack password manager built with Python. It lets users securely store, manage, and retrieve credentials through an encrypted personal vault, protected by a master password that never leaves the device.
Tech Stack

Frontend — Streamlit
Backend — Flask (REST API)
Database — MySQL
Encryption — AES-256-GCM via PyCryptodome
Key Derivation — PBKDF2 (100,000 iterations)
Authentication — JWT (8-hour tokens)
Email — Gmail SMTP (TLS)

Features

User signup and login with strong password enforcement
Email OTP verification on account creation
Forgot password flow with OTP-based login password reset
Master password setup with optional memory hints
AES-256-GCM encrypted vault — master password never sent to server
Add, edit, copy, and delete individual vault entries
Delete entire vault or full account with double confirmation
Passphrase generator for strong master passwords
Auto-lock vault after configurable inactivity timeout
Real-time password strength checker
Sliding window rate limiting on all endpoints
JWT-based session management


Security Highlights

Master password is zero-knowledge — never stored or transmitted
Each vault entry encrypted with a unique random salt
Login passwords hashed with PBKDF2-SHA256 (260,000 iterations)
Constant-time comparison to prevent timing attacks
OTP expiry (5 minutes) with max attempt limiting
JWT tokens expire after 8 hours


Project Structure
ciphersphere/
├── frontend/
│   ├── app.py          # Streamlit UI
│   └── logo.png
├── backend/
│   └── server.py       # Flask API
├── .env                # Environment variables
└── requirements.txt

Environment Variables (.env)
JWT_SECRET_KEY=
DB_HOST=localhost
DB_PORT=3306
DB_USER=
DB_PASSWORD=
DB_NAME=
SMTP_USER=
GMAIL_APP_PASSWORD=

Setup
bash# Install dependencies
pip install streamlit flask flask-cors pycryptodome mysql-connector-python python-dotenv pyjwt

# Start backend
python server.py

# Start frontend
streamlit run app.py

