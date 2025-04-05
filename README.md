# SSH WebSocket Server (AES Encrypted)

A secure WebSocket-based server for remote SSH access and command execution, built with Quart and AsyncSSH. This server allows encrypted SSH credential exchange via AES-CBC, providing a safe way to initiate SSH sessions and run commands remotely.

---

## Features

- Secure WebSocket communication for SSH sessions
- AES-CBC encrypted credentials from client to server
- Interactive bash session via PTY
- Real-time streaming of command output
- Support for Ctrl+C, file listing, and basic command execution

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/chatdevops/backend.git
cd backend
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration

### 1. Create `.env` File

Inside `/var/www/chatops/.env` or your project root, add:

```
ENCRYPTION_KEY=your_base64_encoded_256bit_key
```

You can generate a valid key using:

```bash
head -c 32 /dev/urandom | base64
```

---

## Running the Server

### 1. Start the Server (Development)

```bash
python app.py
```

### 2. Start with Hypercorn (Production-ready)

```bash
hypercorn app:app --bind 0.0.0.0:5000
```

---

## WebSocket API

### Connect and Authenticate

Send a JSON payload to `/ssh-stream` WebSocket endpoint:

```json
{
  "action": "CONNECT",
  "host": "<encrypted_base64>",
  "username": "<encrypted_base64>",
  "password": "<encrypted_base64>"
}
```

### Send a Command

```json
{
  "action": "RUN_COMMAND",
  "command": "uptime"
}
```

### Stop a Command

```json
{
  "action": "CTRL_C"
}
```

### List Directory Contents

```json
{
  "action": "LIST_FILES",
  "directory": "/home"
}
```

---

## Internal API

### Get Encryption Key (for development only)

```http
GET /get-key
```

Returns:

```json
{ "key": "your_base64_key" }
```

---

## Hosting Instructions (Self-Hosting Guide)

### 1. Setup Server (Ubuntu/Debian Example)

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip nginx
```

### 2. Create Project Directory

```bash
sudo mkdir -p /var/www/chatops
sudo chown $USER:$USER /var/www/chatops
cd /var/www/chatops
```

### 3. Deploy the App Code

Place your cloned `backend` code or copy project files into this folder.

### 4. Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Add `.env`

```bash
echo "ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)" > .env
```

### 6. Run with Hypercorn in Background

```bash
nohup hypercorn app:app --bind 0.0.0.0:5000 &
```

### 7. (Optional) Set Up Nginx Reverse Proxy

Configure a basic Nginx server block for HTTPS/WebSocket proxying.

### 8. Open Port (If Firewall Enabled)

```bash
sudo ufw allow 5000/tcp
```

---

## Notes

- Requires Python 3.10+
- Encryption key must decode to exactly 32 bytes for AES-256
- Interactive shell uses `bash -i` and PTY for full terminal capabilities
- Do not expose `/get-key` endpoint in production
- Consider SSL (WSS) if deploying to the internet

---

## License

MIT License. Feel free to use, modify, and distribute it. If it is useful, do give me a shoutout.

