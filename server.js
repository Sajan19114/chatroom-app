const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// ─── In-Memory Store ─────────────────────────────────────────────────────────
// rooms[roomId] = { messages: [], users: {} }
const rooms = {};
const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

// Auto-purge messages older than 24 hours every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const roomId in rooms) {
    rooms[roomId].messages = rooms[roomId].messages.filter(
      (msg) => now - msg.timestamp < TWENTY_FOUR_HOURS
    );
    // Clean up empty rooms with no connected users
    if (
      rooms[roomId].messages.length === 0 &&
      Object.keys(rooms[roomId].users).length === 0
    ) {
      delete rooms[roomId];
    }
  }
  console.log(`[CLEANUP] Active rooms: ${Object.keys(rooms).length}`);
}, 30 * 60 * 1000);

// ─── Helper ───────────────────────────────────────────────────────────────────
function ensureRoom(roomId) {
  if (!rooms[roomId]) {
    rooms[roomId] = { messages: [], users: {} };
  }
  return rooms[roomId];
}

function getRecentMessages(roomId) {
  const now = Date.now();
  const room = rooms[roomId];
  if (!room) return [];
  return room.messages.filter((msg) => now - msg.timestamp < TWENTY_FOUR_HOURS);
}

// ─── Static Files ─────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// Health check endpoint (Render requires this)
app.get("/health", (req, res) => res.json({ status: "ok", rooms: Object.keys(rooms).length }));

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on("connection", (socket) => {
  console.log(`[CONNECT] ${socket.id}`);

  // Join a room
  socket.on("join_room", ({ roomId, username }) => {
    if (!roomId || !username) return;

    const room = ensureRoom(roomId);

    socket.join(roomId);
    socket.data.roomId = roomId;
    socket.data.username = username;

    // Track user in room
    room.users[socket.id] = username;

    // Send chat history to the new joiner
    const history = getRecentMessages(roomId);
    socket.emit("chat_history", history);

    // Notify everyone in the room
    const userList = Object.values(room.users);
    io.to(roomId).emit("room_update", {
      userCount: userList.length,
      users: userList,
    });

    // System message
    const sysMsg = {
      id: `sys_${Date.now()}`,
      type: "system",
      text: `${username} joined the room`,
      timestamp: Date.now(),
    };
    room.messages.push(sysMsg);
    io.to(roomId).emit("new_message", sysMsg);

    console.log(`[JOIN] ${username} → room:${roomId} (${userList.length} users)`);
  });

  // Send a message
  socket.on("send_message", ({ roomId, text }) => {
    if (!roomId || !text?.trim()) return;

    const room = rooms[roomId];
    if (!room) return;

    const message = {
      id: `msg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      type: "user",
      senderId: socket.id,
      username: socket.data.username,
      text: text.trim(),
      timestamp: Date.now(),
    };

    room.messages.push(message);

    // Broadcast to everyone in the room (including sender)
    io.to(roomId).emit("new_message", message);
  });

  // Typing indicators
  socket.on("typing_start", ({ roomId }) => {
    socket.to(roomId).emit("user_typing", { username: socket.data.username });
  });

  socket.on("typing_stop", ({ roomId }) => {
    socket.to(roomId).emit("user_stop_typing", { username: socket.data.username });
  });

  // Disconnect
  socket.on("disconnect", () => {
    const { roomId, username } = socket.data;
    if (!roomId || !rooms[roomId]) return;

    const room = rooms[roomId];
    delete room.users[socket.id];

    const userList = Object.values(room.users);
    io.to(roomId).emit("room_update", {
      userCount: userList.length,
      users: userList,
    });

    const sysMsg = {
      id: `sys_${Date.now()}`,
      type: "system",
      text: `${username} left the room`,
      timestamp: Date.now(),
    };
    room.messages.push(sysMsg);
    io.to(roomId).emit("new_message", sysMsg);

    console.log(`[DISCONNECT] ${username} left room:${roomId}`);
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n🚀 Chat server running on http://localhost:${PORT}\n`);
});
