# 🔐 VaultX – AI-Powered Security Vault

A production-ready, full-featured password manager and security vault with AI-powered threat intelligence.

---

## ✨ Features

### Authentication & Access
- User registration with email OTP verification
- Secure login / logout with bcrypt password hashing
- Two-factor authentication (2FA) via OTP
- Auto logout on session inactivity (30 min)
- Brute-force protection with login attempt locking

### AI Security Intelligence
- AI Security Advisor (powered by Claude API)
- Real-time Vault Health Score
- Password risk analysis & strength checker
- Phishing URL detector
- Login threat detection
- Personalized security recommendations

### Password Vault
- Add / Edit / Delete passwords with encryption
- Password categories, tags, search & filter
- Password generator (standard, passphrase, memorable)
- Password strength checker
- Copy to clipboard with auto-clear
- Favourites system
- Password expiry warnings
- Recycle bin with restore

### Secure Storage
- Encrypted secure notes
- Encrypted file vault (upload & download)
- Encrypted backup export (.vxb format)
- Recycle bin for all item types

### Private Browser
- Sandboxed iframe browser
- No history storage
- Auto cookie clear on exit
- Session-only browsing
- Pre-loaded privacy-focused shortcuts

### Protection Features
- Stealth Mode (blur sensitive info)
- Panic Mode (instant logout)
- Honey Vault toggle
- Panic password configuration

### Security Monitoring
- Full audit log
- Login activity tracker with threat levels
- Breach alert system

### Customization
- 6 built-in themes (dark-cyber, ocean, red, purple, amber, light)
- Custom theme creator with color picker
- Sound control, cursor styles, animation levels
- Layout settings

---

## 🚀 Quick Start (Local)

### 1. Clone and setup

```bash
git clone https://github.com/yourusername/vaultx.git
cd vaultx
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings
```

### 3. Run

```bash
python app.py
```

Open: http://localhost:5000

---

## 🌐 Deploy to Render

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect your GitHub repo
4. Render auto-detects `render.yaml`
5. Add required environment variables:
   - `MAIL_USERNAME`, `MAIL_PASSWORD` (for OTP emails)
   - `ANTHROPIC_API_KEY` (for AI features, optional)
6. Deploy!

**Note:** Without mail config, OTP codes are shown directly in the flash message (dev mode). AI features degrade gracefully to built-in responses without an API key.

---

## ⚙️ Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key (auto-generated on Render) |
| `ENCRYPTION_KEY` | Yes | Fernet encryption key (auto-generated on Render) |
| `MAIL_USERNAME` | Optional | Gmail address for OTP emails |
| `MAIL_PASSWORD` | Optional | Gmail App Password |
| `ANTHROPIC_API_KEY` | Optional | For AI Security Advisor |
| `DATABASE_URL` | No | SQLite by default |

---

## 🛡 Security Architecture

- **Passwords**: Encrypted with Fernet (AES-128-CBC) before database storage
- **Notes**: Fernet encryption  
- **Files**: Fernet encryption, stored with randomized names
- **Master passwords**: bcrypt hashed with salt
- **Sessions**: Server-side with HTTPONLY cookies
- **2FA**: Time-limited OTP via email
- **Brute force**: Account lockout after 5 failed attempts

---

## 📁 Project Structure

```
vaultx/
├── app.py                  # Entry point
├── config.py               # Configuration
├── requirements.txt
├── render.yaml             # Render deployment
├── .env.example
├── app/
│   ├── __init__.py         # App factory
│   ├── models/             # Database models
│   ├── routes/             # Blueprint routes
│   └── services/           # Business logic
├── templates/              # Jinja2 templates
│   ├── base.html
│   ├── auth/
│   ├── dashboard/
│   ├── vault/
│   ├── ai/
│   └── browser/
└── static/
    ├── css/main.css
    ├── js/main.js
    └── icons/
```

---

## 🔧 Tech Stack

- **Backend**: Python 3.11, Flask 3.0, SQLAlchemy 2.0
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Encryption**: cryptography (Fernet/AES)
- **Auth**: Flask-Login, bcrypt, PyOTP
- **AI**: Anthropic Claude API
- **Frontend**: Vanilla JS, CSS custom properties
- **Server**: Gunicorn
- **Fonts**: Orbitron, JetBrains Mono, Space Grotesk

---

## 📝 License

MIT License — free to use and modify.
