# 💬 ChatRoom — Real-time Chat App

A real-time chat app supporting both **1-on-1 and group chat** using Node.js, Express, and Socket.io.

## Features
- ✅ Join any room by name (works as group or 1-on-1)
- ✅ 24-hour chat history stored in server memory (auto-purged)
- ✅ "User is typing..." indicator
- ✅ Online user count + user list
- ✅ System join/leave messages
- ✅ Mobile-responsive dark UI
- ✅ Press Enter to send, Shift+Enter for new line

---

## Run Locally

```bash
npm install
npm run dev       # with auto-reload (nodemon)
# OR
npm start         # production
```

Open: http://localhost:3000

---

## Deploy to Render (Free)

### Step 1 — Push to GitHub
```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step 2 — Create Render Web Service
1. Go to https://render.com → Sign up / Log in
2. Click **"New"** → **"Web Service"**
3. Connect your GitHub account and select your repository
4. Fill in these settings:

| Setting | Value |
|---|---|
| Name | chatroom (or anything) |
| Environment | Node |
| Build Command | `npm install` |
| Start Command | `node server.js` |
| Instance Type | Free |

5. Click **"Create Web Service"**
6. Wait ~2 minutes for deployment
7. Your app will be live at: `https://your-app-name.onrender.com`

> ⚠️ Free Render instances spin down after 15 min of inactivity. First load may take ~30s.

---

## How Rooms Work

| Use case | How to do it |
|---|---|
| 1-on-1 chat | Both users enter the same unique room name (e.g. `alice-bob-private`) |
| Group chat | Share the room name with multiple people |
| Multiple rooms | Each room is completely isolated |

---

## Architecture

```
client (browser)
    │  WebSocket (Socket.io)
    ▼
server.js (Node.js + Express)
    │
    ├── rooms{}  ← in-memory store
    │     ├── room1: { messages[], users{} }
    │     └── room2: { messages[], users{} }
    │
    └── setInterval ← purges messages > 24h every 30min
```

No database needed. All messages are stored in RAM and automatically cleared after 24 hours.
