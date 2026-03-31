require("dotenv").config();
const express      = require("express");
const http         = require("http");
const { Server }   = require("socket.io");
const mongoose     = require("mongoose");
const jwt          = require("jsonwebtoken");
const bcrypt       = require("bcryptjs");
const cookieParser = require("cookie-parser");
const path         = require("path");
const { User, Room, Message, Activity } = require("./models");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: "*" } });

const JWT_SECRET     = process.env.JWT_SECRET     || "dev_secret_change_in_prod";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME  || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD  || "admin123";
const PORT           = process.env.PORT            || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB error:", err); process.exit(1); });

// ─── Helpers ──────────────────────────────────────────────────────────────────
const AVATAR_COLORS = ["#6366f1","#ec4899","#10b981","#f59e0b","#3b82f6","#8b5cf6","#ef4444","#14b8a6","#f97316","#06b6d4"];

function getInitials(name) { return name.split(" ").map(w=>w[0]).join("").toUpperCase().slice(0,2); }
function getAvatarColor(userId) { return AVATAR_COLORS[parseInt(userId.toString().slice(-2),16) % AVATAR_COLORS.length]; }
function signToken(userId, role="user") { return jwt.sign({ id: userId, role }, JWT_SECRET, { expiresIn: "30d" }); }
function signAdminToken() { return jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "8h" }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }

function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
  const payload = verifyToken(token);
  if (!payload || payload.role === "admin") return res.status(401).json({ error: "Unauthorized" });
  req.userId = payload.id;
  next();
}
function adminMiddleware(req, res, next) {
  const token = req.cookies?.adminToken || req.headers.authorization?.split(" ")[1];
  const payload = verifyToken(token);
  if (!payload || payload.role !== "admin") return res.status(403).json({ error: "Admin access required" });
  next();
}

function generateRoomCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

function safeUser(user) {
  return {
    id: user._id, name: user.name, mobile: user.mobile,
    age: user.age, gender: user.gender, banned: user.banned,
    initials: getInitials(user.name), avatarColor: getAvatarColor(user._id),
  };
}
function safeRoom(room, userId) {
  return {
    id: room._id, roomCode: room.roomCode, name: room.name,
    isOwner: room.owner.toString() === userId.toString(),
    memberCount: room.members.length,
    pinnedMessage: room.pinnedMessage,
    createdAt: room.createdAt,
    plainPassword: room.owner.toString() === userId.toString() ? room.plainPassword : undefined,
  };
}

async function logActivity(action, targetId, targetName, detail) {
  try { await Activity.create({ action, targetId: String(targetId), targetName, detail }); }
  catch (e) { console.error("Activity log error:", e); }
}

// ─── Online tracking (shared between user + admin) ────────────────────────────
const onlineRooms = {}; // roomCode -> Set<socketId>

// ════════════════════════════════════════════════════════════════════════════
// USER AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════
app.post("/api/register", async (req, res) => {
  try {
    const { name, mobile, password, age, gender } = req.body;
    if (!name || !mobile || !password || !age || !gender)
      return res.status(400).json({ error: "All fields are required" });
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error: "Mobile must be 10 digits" });
    if (password.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
    if (await User.findOne({ mobile })) return res.status(409).json({ error: "Mobile number already registered" });
    const user = await User.create({ name, mobile, password, age: Number(age), gender });
    const token = signToken(user._id);
    res.cookie("token", token, { httpOnly: true, maxAge: 30*24*60*60*1000, sameSite: "lax" });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/login", async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile || !password) return res.status(400).json({ error: "Mobile and password required" });
    const user = await User.findOne({ mobile });
    if (!user || !(await user.comparePassword(password)))
      return res.status(401).json({ error: "Invalid mobile or password" });
    if (user.banned) return res.status(403).json({ error: `Account banned. Reason: ${user.banReason || "Violation of terms"}` });
    const token = signToken(user._id);
    res.cookie("token", token, { httpOnly: true, maxAge: 30*24*60*60*1000, sameSite: "lax" });
    res.json({ success: true, user: safeUser(user) });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token"); res.json({ success: true }); });

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Not found" });
    if (user.banned) { res.clearCookie("token"); return res.status(403).json({ error: `Account banned: ${user.banReason}` }); }
    res.json({ user: safeUser(user) });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { name, age, gender } = req.body;
    const user = await User.findByIdAndUpdate(req.userId, { name, age: Number(age), gender }, { new: true, runValidators: true });
    res.json({ success: true, user: safeUser(user) });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Room Routes ──────────────────────────────────────────────────────────────
app.post("/api/rooms/create", authMiddleware, async (req, res) => {
  try {
    const { name, password } = req.body;
    if (!name || !password) return res.status(400).json({ error: "Room name and password required" });
    if (password.length < 4) return res.status(400).json({ error: "Password must be at least 4 characters" });
    let roomCode, exists = true;
    while (exists) { roomCode = generateRoomCode(); exists = await Room.findOne({ roomCode }); }
    const passwordHash = await bcrypt.hash(password, 10);
    const room = await Room.create({ roomCode, name, passwordHash, plainPassword: password, owner: req.userId, members: [req.userId] });
    res.json({ success: true, room: safeRoom(room, req.userId) });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/rooms/join", authMiddleware, async (req, res) => {
  try {
    const { roomCode, password } = req.body;
    if (!roomCode || !password) return res.status(400).json({ error: "Room code and password required" });
    const room = await Room.findOne({ roomCode });
    if (!room) return res.status(404).json({ error: "Room not found. Check the room code." });
    if (!(await room.comparePassword(password))) return res.status(401).json({ error: "Wrong room password" });
    if (!room.members.map(m=>m.toString()).includes(req.userId.toString())) {
      room.members.push(req.userId); await room.save();
    }
    res.json({ success: true, room: safeRoom(room, req.userId) });
  } catch (err) { console.error(err); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const rooms = await Room.find({ members: req.userId }).sort({ createdAt: -1 });
    res.json({ rooms: rooms.map(r => safeRoom(r, req.userId)) });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.get("/api/rooms/:roomCode", authMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode: req.params.roomCode }).populate("members", "name");
    if (!room) return res.status(404).json({ error: "Room not found" });
    const msgCount = await Message.countDocuments({ roomId: req.params.roomCode, type: "user" });
    const pinnedMsg = room.pinnedMessage ? await Message.findById(room.pinnedMessage) : null;
    res.json({
      room: safeRoom(room, req.userId),
      members: room.members.map(m => ({ id: m._id, name: m.name, initials: getInitials(m.name), avatarColor: getAvatarColor(m._id) })),
      messageCount: msgCount,
      pinnedMessage: pinnedMsg && !pinnedMsg.deleted ? pinnedMsg : null,
    });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/rooms/:roomCode", authMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode: req.params.roomCode });
    if (!room) return res.status(404).json({ error: "Room not found" });
    if (room.owner.toString() !== req.userId.toString()) return res.status(403).json({ error: "Only the owner can delete" });
    await Message.deleteMany({ roomId: req.params.roomCode });
    await Room.deleteOne({ roomCode: req.params.roomCode });
    io.to(req.params.roomCode).emit("room_deleted", { roomCode: req.params.roomCode });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/rooms/:roomCode/pin", authMiddleware, async (req, res) => {
  try {
    const { messageId } = req.body;
    const room = await Room.findOne({ roomCode: req.params.roomCode });
    if (!room) return res.status(404).json({ error: "Room not found" });
    if (room.owner.toString() !== req.userId.toString()) return res.status(403).json({ error: "Only owner can pin" });
    if (room.pinnedMessage?.toString() === messageId) {
      room.pinnedMessage = null;
      await Message.findByIdAndUpdate(messageId, { pinned: false });
    } else {
      if (room.pinnedMessage) await Message.findByIdAndUpdate(room.pinnedMessage, { pinned: false });
      room.pinnedMessage = messageId;
      await Message.findByIdAndUpdate(messageId, { pinned: true });
    }
    await room.save();
    const pinnedMsg = room.pinnedMessage ? await Message.findById(room.pinnedMessage) : null;
    io.to(req.params.roomCode).emit("pin_updated", { pinnedMessage: pinnedMsg });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ════════════════════════════════════════════════════════════════════════════
// ADMIN AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD)
    return res.status(401).json({ error: "Invalid admin credentials" });
  const token = signAdminToken();
  res.cookie("adminToken", token, { httpOnly: true, maxAge: 8*60*60*1000, sameSite: "lax" });
  res.json({ success: true });
});

app.post("/api/admin/logout", (req, res) => { res.clearCookie("adminToken"); res.json({ success: true }); });

app.get("/api/admin/verify", adminMiddleware, (req, res) => res.json({ ok: true }));

// ─── Admin Dashboard Stats ────────────────────────────────────────────────────
app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  try {
    const [totalUsers, totalRooms, totalMessages, bannedUsers] = await Promise.all([
      User.countDocuments(),
      Room.countDocuments(),
      Message.countDocuments({ type: "user" }),
      User.countDocuments({ banned: true }),
    ]);
    // Count total online users across all rooms
    let onlineCount = 0;
    for (const roomCode in onlineRooms) onlineCount += onlineRooms[roomCode].size;
    res.json({ totalUsers, totalRooms, totalMessages, bannedUsers, onlineNow: onlineCount });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: All Users ─────────────────────────────────────────────────────────
app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    const query = search ? { $or: [{ name: new RegExp(search, "i") }, { mobile: new RegExp(search, "i") }] } : {};
    const users = await User.find(query).select("-password").sort({ createdAt: -1 }).limit(100);
    res.json({ users });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: Ban / Unban User ──────────────────────────────────────────────────
app.post("/api/admin/users/:userId/ban", adminMiddleware, async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(req.params.userId, { banned: true, banReason: reason || "Admin action" }, { new: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    await logActivity("BAN_USER", user._id, user.name, `Reason: ${reason || "Admin action"}`);
    // Force disconnect any active socket for this user
    io.sockets.sockets.forEach(s => { if (s.user?._id?.toString() === user._id.toString()) s.disconnect(true); });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.post("/api/admin/users/:userId/unban", adminMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.userId, { banned: false, banReason: "" }, { new: true });
    if (!user) return res.status(404).json({ error: "User not found" });
    await logActivity("UNBAN_USER", user._id, user.name, "User unbanned");
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: Delete User ────────────────────────────────────────────────────────
app.delete("/api/admin/users/:userId", adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    await User.deleteOne({ _id: user._id });
    await logActivity("DELETE_USER", user._id, user.name, "User account deleted");
    io.sockets.sockets.forEach(s => { if (s.user?._id?.toString() === user._id.toString()) s.disconnect(true); });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: All Rooms ─────────────────────────────────────────────────────────
app.get("/api/admin/rooms", adminMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    const query = search ? { $or: [{ name: new RegExp(search, "i") }, { roomCode: new RegExp(search, "i") }] } : {};
    const rooms = await Room.find(query).populate("owner", "name mobile").sort({ createdAt: -1 }).limit(100);
    const result = await Promise.all(rooms.map(async r => {
      const msgCount = await Message.countDocuments({ roomId: r.roomCode, type: "user" });
      const online = onlineRooms[r.roomCode]?.size || 0;
      return {
        id: r._id, roomCode: r.roomCode, name: r.name,
        owner: r.owner ? { name: r.owner.name, mobile: r.owner.mobile } : null,
        memberCount: r.members.length, messageCount: msgCount,
        onlineNow: online, createdAt: r.createdAt,
        plainPassword: r.plainPassword,
      };
    }));
    res.json({ rooms: result });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: Delete Room ────────────────────────────────────────────────────────
app.delete("/api/admin/rooms/:roomCode", adminMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode: req.params.roomCode });
    if (!room) return res.status(404).json({ error: "Room not found" });
    await Message.deleteMany({ roomId: req.params.roomCode });
    await Room.deleteOne({ roomCode: req.params.roomCode });
    io.to(req.params.roomCode).emit("room_deleted", { roomCode: req.params.roomCode });
    await logActivity("DELETE_ROOM", room._id, room.name, `Code: ${room.roomCode}`);
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: Read Room Messages ────────────────────────────────────────────────
app.get("/api/admin/rooms/:roomCode/messages", adminMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({ roomId: req.params.roomCode }).sort({ timestamp: 1 }).limit(500).lean();
    res.json({ messages });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ─── Admin: Activity Log ──────────────────────────────────────────────────────
app.get("/api/admin/activity", adminMiddleware, async (req, res) => {
  try {
    const logs = await Activity.find().sort({ timestamp: -1 }).limit(100);
    res.json({ logs });
  } catch { res.status(500).json({ error: "Server error" }); }
});

app.get("/health", (req, res) => res.json({ status: "ok" }));

// Serve admin page
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/admin/*", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

// ════════════════════════════════════════════════════════════════════════════
// SOCKET.IO
// ════════════════════════════════════════════════════════════════════════════
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token ||
    socket.handshake.headers?.cookie?.split(";").find(c => c.trim().startsWith("token="))?.split("=")[1];
  const payload = verifyToken(token);
  if (!payload || payload.role === "admin") return next(new Error("Unauthorized"));
  const user = await User.findById(payload.id);
  if (!user) return next(new Error("User not found"));
  if (user.banned) return next(new Error("Account banned"));
  socket.user = { ...safeUser(user), _id: user._id };
  next();
});

io.on("connection", (socket) => {
  console.log(`[CONNECT] ${socket.user.name}`);

  socket.on("join_room", async ({ roomCode }) => {
    if (!roomCode) return;
    const room = await Room.findOne({ roomCode });
    if (!room) return socket.emit("error_msg", "Room not found");
    if (!room.members.map(m=>m.toString()).includes(socket.user._id.toString()))
      return socket.emit("error_msg", "You are not a member of this room");

    socket.join(roomCode);
    socket.data.roomCode = roomCode;
    if (!onlineRooms[roomCode]) onlineRooms[roomCode] = new Set();
    onlineRooms[roomCode].add(socket.id);

    const history = await Message.find({ roomId: roomCode }).sort({ timestamp: 1 }).limit(200).lean();
    socket.emit("chat_history", history);

    if (room.pinnedMessage) {
      const pinned = await Message.findById(room.pinnedMessage);
      if (pinned && !pinned.deleted) socket.emit("pin_updated", { pinnedMessage: pinned });
    }

    emitRoomUsers(roomCode);
    const sysMsg = await Message.create({ roomId: roomCode, type: "system", text: `${socket.user.name} joined the room` });
    io.to(roomCode).emit("new_message", sysMsg);
  });

  socket.on("send_message", async ({ roomCode, text }) => {
    if (!roomCode || !text?.trim()) return;
    const msg = await Message.create({
      roomId: roomCode, type: "user",
      senderId: socket.user._id, username: socket.user.name,
      initials: socket.user.initials, avatarColor: socket.user.avatarColor,
      text: text.trim(),
    });
    io.to(roomCode).emit("new_message", msg);
  });

  socket.on("delete_message", async ({ messageId, roomCode }) => {
    const msg = await Message.findById(messageId);
    if (!msg) return;
    if (msg.senderId.toString() !== socket.user._id.toString())
      return socket.emit("error_msg", "You can only delete your own messages");
    if (Date.now() - new Date(msg.timestamp).getTime() > 5 * 60 * 1000)
      return socket.emit("error_msg", "Messages can only be deleted within 5 minutes");
    await Message.findByIdAndDelete(messageId);
    const room = await Room.findOne({ roomCode });
    if (room?.pinnedMessage?.toString() === messageId) {
      room.pinnedMessage = null; await room.save();
      io.to(roomCode).emit("pin_updated", { pinnedMessage: null });
    }
    io.to(roomCode).emit("message_deleted", { messageId });
  });

  socket.on("typing_start", ({ roomCode }) => socket.to(roomCode).emit("user_typing", { username: socket.user.name }));
  socket.on("typing_stop",  ({ roomCode }) => socket.to(roomCode).emit("user_stop_typing", { username: socket.user.name }));

  socket.on("disconnect", async () => {
    const roomCode = socket.data.roomCode;
    if (!roomCode) return;
    if (onlineRooms[roomCode]) {
      onlineRooms[roomCode].delete(socket.id);
      if (onlineRooms[roomCode].size === 0) delete onlineRooms[roomCode];
    }
    emitRoomUsers(roomCode);
    const sysMsg = await Message.create({ roomId: roomCode, type: "system", text: `${socket.user.name} left the room` });
    io.to(roomCode).emit("new_message", sysMsg);
  });

  function emitRoomUsers(roomCode) {
    const sids = onlineRooms[roomCode] ? [...onlineRooms[roomCode]] : [];
    const users = sids.map(sid => {
      const s = io.sockets.sockets.get(sid);
      return s ? { name: s.user.name, initials: s.user.initials, avatarColor: s.user.avatarColor } : null;
    }).filter(Boolean);
    io.to(roomCode).emit("room_update", { userCount: users.length, users });
  }
});

server.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
