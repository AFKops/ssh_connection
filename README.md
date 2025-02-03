# 🚀 SSH Connection API  

A lightweight **Flask-based API** for securely executing SSH commands on remote servers using **Paramiko**. This API allows remote command execution by sending SSH credentials and a command via HTTP POST requests.  

## ✨ Features  
✅ **Connect to remote servers** using SSH credentials  
✅ **Execute commands** on remote servers and return output  
✅ **Secure API** handling with structured JSON responses  
✅ **Built with Flask & Paramiko** for seamless SSH communication  

---

## 🛠️ Installation  

### 1️⃣ Clone the Repository  
```bash
git clone https://github.com/chatdevops/ssh_connection.git
cd ssh_connection
```

### 2️⃣ Install Dependencies  
Ensure you have Python installed, then run:  
```bash
pip install -r requirements.txt
```
(If `requirements.txt` doesn't exist, install manually: `pip install flask paramiko`)

---

## 🚀 Running the API  

### **Start the Flask Server**  
```bash
python ssh_server.py
```
✅ The API will now be available at:  
`http://0.0.0.0:5000` (accessible on all interfaces)  

✅ Or locally on:  
`http://127.0.0.1:5000`

---

## 🔌 API Usage  

### **1️⃣ Sending an SSH Command**  
Make a **POST request** to `/ssh` with the following **JSON payload**:

```json
{
  "host": "192.168.1.100",
  "username": "root",
  "password": "your_password",
  "command": "uptime"
}
```

### **2️⃣ Example Using cURL**  
```bash
curl -X POST http://192.168.1.100:5000/ssh \
     -H "Content-Type: application/json" \
     -d '{"host": "your_server_ip", "username": "root", "password": "your_password", "command": "uptime"}'
```

### **3️⃣ Example Python Request**  
```python
import requests

url = "http://192.168.1.100:5000/ssh"
data = {
    "host": "your_server_ip",
    "username": "root",
    "password": "your_password",
    "command": "uptime"
}

response = requests.post(url, json=data)
print(response.json())
```

---

## 🔒 Security Considerations  
⚠️ **DO NOT expose this API to the public internet** without proper authentication and security measures.  
⚠️ Consider using **SSH keys instead of passwords** for authentication.  
⚠️ Deploy with **gunicorn + Nginx** in production instead of Flask's built-in server.  

---

## 📌 Deploying on a Remote Server (DigitalOcean, AWS, etc.)  

### **Step 1: Run API in the Background**  
Use **screen** or **nohup** to keep it running:  
```bash
nohup python ssh_server.py &
```

### **Step 2: Allow External Traffic (If Needed)**  
Open port **5000** on your firewall:  
```bash
sudo ufw allow 5000/tcp
```

### **Step 3: Access API Remotely**  
Use your **server's public IP**:  
```bash
curl -X POST http://your_server_ip:5000/ssh \
     -H "Content-Type: application/json" \
     -d '{"host": "your_server_ip", "username": "root", "password": "your_password", "command": "uptime"}'
```

---

## 📜 License  
MIT License. Free to use, modify, and distribute.  

---

🚀 **Happy SSH-ing!** Let me know if you need any modifications! 😃