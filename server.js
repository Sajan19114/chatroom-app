require("dotenv").config();
const express     = require("express");
const http        = require("http");
const { Server }  = require("socket.io");
const mongoose    = require("mongoose");
const jwt         = require("jsonwebtoken");
const cookieParser= require("cookie-parser");
const path        = require("path");
const { User, Message } = require("./models");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_in_production";
const PORT       = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB error:", err); process.exit(1); });

// ─── Helpers ──────────────────────────────────────────────────────────────────
const AVATAR_COLORS = ["#6366f1","#ec4899","#10b981","#f59e0b","#3b82f6","#8b5cf6","#ef4444","#14b8a6"];

function getInitials(name) {
  return name.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2);
}

function getAvatarColor(userId) {
  const idx = parseInt(userId.toString().slice(-2), 16) % AVATAR_COLORS.length;
  return AVATAR_COLORS[idx];
}

function signToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "30d" });
}

function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

// Auth middleware for REST routes
function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: "Unauthorized" });
  req.userId = payload.id;
  next();
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name, mobile, password, age, gender } = req.body;
    if (!name || !mobile || !password || !age || !gender)
      return res.status(400).json({ error: "All fields are required" });

    if (!/^\d{10}$/.test(mobile))
      return res.status(400).json({ error: "Mobile must be 10 digits" });

    if (password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });

    const existing = await User.findOne({ mobile });
    if (existing)
      return res.status(409).json({ error: "Mobile number already registered" });

    const user = await User.create({ name, mobile, password, age: Number(age), gender });
    const token = signToken(user._id);

    res.cookie("token", token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile || !password)
      return res.status(400).json({ error: "Mobile and password required" });

    const user = await User.findOne({ mobile });
    if (!user || !(await user.comparePassword(password)))
      return res.status(401).json({ error: "Invalid mobile or password" });

    const token = signToken(user._id);
    res.cookie("token", token, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: "lax" });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

// Get current user (auto-login check)
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ user: safeUser(user) });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Update profile
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { name, age, gender } = req.body;
    const user = await User.findByIdAndUpdate(
      req.userId,
      { name, age: Number(age), gender },
      { new: true, runValidators: true }
    ).select("-password");
    res.json({ success: true, user: safeUser(user) });
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

// Get room history for user
app.get("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("rooms");
    res.json({ rooms: user.rooms || [] });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

// Health check
app.get("/health", (req, res) => res.json({ status: "ok" }));

function safeUser(user) {
  return {
    id: user._id,
    name: user.name,
    mobile: user.mobile,
    age: user.age,
    gender: user.gender,
    initials: getInitials(user.name),
    avatarColor: getAvatarColor(user._id),
    rooms: user.rooms || [],
  };
}

// ─── Socket.io Auth ───────────────────────────────────────────────────────────
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.cookie
    ?.split(";").find(c => c.trim().startsWith("token="))?.split("=")[1];

  const payload = verifyToken(token);
  if (!payload) return next(new Error("Unauthorized"));

  const user = await User.findById(payload.id).select("-password");
  if (!user) return next(new Error("User not found"));

  socket.user = { ...safeUser(user), _id: user._id };
  next();
});

// Track who's online: roomId -> Set of socket ids
const onlineRooms = {};

io.on("connection", (socket) => {
  console.log(`[CONNECT] ${socket.user.name} (${socket.id})`);

  // Join room
  socket.on("join_room", async ({ roomId }) => {
    if (!roomId) return;

    socket.join(roomId);
    socket.data.roomId = roomId;

    // Track online
    if (!onlineRooms[roomId]) onlineRooms[roomId] = new Set();
    onlineRooms[roomId].add(socket.id);

    // Save room to user's history
    await User.findByIdAndUpdate(socket.user._id, { $addToSet: { rooms: roomId } });

    // Send last 24h messages from MongoDB
    const history = await Message.find({ roomId })
      .sort({ timestamp: 1 })
      .limit(100)
      .lean();
    socket.emit("chat_history", history);

    // Broadcast online users
    emitRoomUsers(roomId);

    // System message
    await broadcastSystem(roomId, `${socket.user.name} joined the room`);

    console.log(`[JOIN] ${socket.user.name} → room:${roomId}`);
  });

  // Send message
  socket.on("send_message", async ({ roomId, text }) => {
    if (!roomId || !text?.trim()) return;

    const msg = await Message.create({
      roomId,
      type: "user",
      senderId: socket.user._id,
      username: socket.user.name,
      initials: socket.user.initials,
      avatarColor: socket.user.avatarColor,
      text: text.trim(),
    });

    io.to(roomId).emit("new_message", msg);
  });

  // Typing
  socket.on("typing_start", ({ roomId }) => {
    socket.to(roomId).emit("user_typing", { username: socket.user.name });
  });
  socket.on("typing_stop", ({ roomId }) => {
    socket.to(roomId).emit("user_stop_typing", { username: socket.user.name });
  });

  // Disconnect
  socket.on("disconnect", async () => {
    const roomId = socket.data.roomId;
    if (!roomId) return;

    if (onlineRooms[roomId]) {
      onlineRooms[roomId].delete(socket.id);
      if (onlineRooms[roomId].size === 0) delete onlineRooms[roomId];
    }

    emitRoomUsers(roomId);
    await broadcastSystem(roomId, `${socket.user.name} left the room`);
    console.log(`[DISCONNECT] ${socket.user.name}`);
  });

  // ── Helpers ────────────────────────────────────────────────────────────────
  async function broadcastSystem(roomId, text) {
    const msg = await Message.create({ roomId, type: "system", text });
    io.to(roomId).emit("new_message", msg);
  }

  function emitRoomUsers(roomId) {
    const sockets = onlineRooms[roomId] ? [...onlineRooms[roomId]] : [];
    const users = sockets.map(sid => {
      const s = io.sockets.sockets.get(sid);
      return s ? { name: s.user.name, initials: s.user.initials, avatarColor: s.user.avatarColor } : null;
    }).filter(Boolean);

    io.to(roomId).emit("room_update", { userCount: users.length, users });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
