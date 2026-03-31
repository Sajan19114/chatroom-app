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

const JWT_SECRET     = process.env.JWT_SECRET     || "dev_secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME  || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD  || "admin123";
const PORT           = process.env.PORT            || 3000;

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// ─── MongoDB ──────────────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB error:", err); process.exit(1); });

// ─── Helpers ──────────────────────────────────────────────────────────────────
const AVATAR_COLORS = ["#6366f1","#ec4899","#10b981","#f59e0b","#3b82f6","#8b5cf6","#ef4444","#14b8a6","#f97316","#06b6d4"];
const CATEGORY_EMOJI = { general:"💬", study:"📚", work:"💼", friends:"👫", gaming:"🎮", other:"🏷️" };

function getInitials(name) { return name.split(" ").map(w=>w[0]).join("").toUpperCase().slice(0,2); }
function getAvatarColor(userId) { return AVATAR_COLORS[parseInt(userId.toString().slice(-2),16) % AVATAR_COLORS.length]; }
function signToken(userId) { return jwt.sign({ id: userId, role:"user" }, JWT_SECRET, { expiresIn:"30d" }); }
function signAdminToken() { return jwt.sign({ role:"admin" }, JWT_SECRET, { expiresIn:"8h" }); }
function verifyToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }

function authMiddleware(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
  const p = verifyToken(token);
  if (!p || p.role === "admin") return res.status(401).json({ error: "Unauthorized" });
  req.userId = p.id;
  next();
}
function adminMiddleware(req, res, next) {
  const token = req.cookies?.adminToken || req.headers.authorization?.split(" ")[1];
  const p = verifyToken(token);
  if (!p || p.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}
function generateRoomCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

function safeUser(user) {
  return {
    id: user._id, name: user.name, mobile: user.mobile,
    age: user.age, gender: user.gender, banned: user.banned,
    status: user.status, statusText: user.statusText,
    lastSeen: user.lastSeen, mutedRooms: user.mutedRooms || [],
    initials: getInitials(user.name), avatarColor: getAvatarColor(user._id),
  };
}
function safeRoom(room, userId) {
  const isOwner = room.owner.toString() === userId.toString();
  return {
    id: room._id, roomCode: room.roomCode, name: room.name,
    isOwner, memberCount: room.members.length,
    pinnedMessage: room.pinnedMessage, createdAt: room.createdAt,
    announcement: room.announcement, category: room.category,
    plainPassword: isOwner ? room.plainPassword : undefined,
  };
}
async function logActivity(action, targetId, targetName, detail) {
  try { await Activity.create({ action, targetId: String(targetId), targetName, detail }); } catch {}
}

// ─── Online tracking ──────────────────────────────────────────────────────────
const onlineRooms = {}; // roomCode -> Set<socketId>

// ════════════════════════════════════════════════════════════════
// USER ROUTES
// ════════════════════════════════════════════════════════════════
app.post("/api/register", async (req, res) => {
  try {
    const { name, mobile, password, age, gender } = req.body;
    if (!name||!mobile||!password||!age||!gender) return res.status(400).json({ error:"All fields required" });
    if (!/^\d{10}$/.test(mobile)) return res.status(400).json({ error:"Mobile must be 10 digits" });
    if (password.length < 6) return res.status(400).json({ error:"Password min 6 chars" });
    if (await User.findOne({ mobile })) return res.status(409).json({ error:"Mobile already registered" });
    const user = await User.create({ name, mobile, password, age:Number(age), gender });
    const token = signToken(user._id);
    res.cookie("token", token, { httpOnly:true, maxAge:30*24*60*60*1000, sameSite:"lax" });
    res.json({ success:true, user:safeUser(user) });
  } catch(err) { console.error(err); res.status(500).json({ error:"Server error" }); }
});

app.post("/api/login", async (req, res) => {
  try {
    const { mobile, password } = req.body;
    if (!mobile||!password) return res.status(400).json({ error:"Mobile and password required" });
    const user = await User.findOne({ mobile });
    if (!user||!(await user.comparePassword(password))) return res.status(401).json({ error:"Invalid credentials" });
    if (user.banned) return res.status(403).json({ error:`Account banned: ${user.banReason||"Contact support"}` });
    const token = signToken(user._id);
    res.cookie("token", token, { httpOnly:true, maxAge:30*24*60*60*1000, sameSite:"lax" });
    res.json({ success:true, user:safeUser(user) });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token"); res.json({ success:true }); });

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error:"Not found" });
    if (user.banned) { res.clearCookie("token"); return res.status(403).json({ error:`Banned: ${user.banReason}` }); }
    res.json({ user:safeUser(user) });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { name, age, gender, statusText, status } = req.body;
    const user = await User.findByIdAndUpdate(req.userId,
      { name, age:Number(age), gender, statusText:statusText||"", status:status||"online" },
      { new:true, runValidators:true });
    // Broadcast status change to all rooms this user is in
    io.sockets.sockets.forEach(s => {
      if (s.user?._id?.toString() === req.userId.toString()) {
        s.user.status = status;
        s.user.statusText = statusText;
        if (s.data.roomCode) io.to(s.data.roomCode).emit("user_status_changed", { userId:req.userId, status, statusText, name });
      }
    });
    res.json({ success:true, user:safeUser(user) });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// Push notification subscription
app.post("/api/push/subscribe", authMiddleware, async (req, res) => {
  try {
    const { subscription } = req.body;
    if (!subscription) return res.status(400).json({ error:"No subscription" });
    const subStr = JSON.stringify(subscription);
    await User.findByIdAndUpdate(req.userId, { $addToSet: { pushTokens: subStr } });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// Mute/unmute room
app.post("/api/rooms/:roomCode/mute", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const muted = user.mutedRooms || [];
    const idx = muted.indexOf(req.params.roomCode);
    if (idx === -1) { muted.push(req.params.roomCode); } else { muted.splice(idx,1); }
    user.mutedRooms = muted;
    await user.save();
    res.json({ success:true, muted: idx === -1 });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// ─── Room Routes ──────────────────────────────────────────────────────────────
app.post("/api/rooms/create", authMiddleware, async (req, res) => {
  try {
    const { name, password, category } = req.body;
    if (!name||!password) return res.status(400).json({ error:"Name and password required" });
    if (password.length < 4) return res.status(400).json({ error:"Password min 4 chars" });
    let roomCode, exists = true;
    while (exists) { roomCode = generateRoomCode(); exists = await Room.findOne({ roomCode }); }
    const passwordHash = await bcrypt.hash(password, 10);
    const room = await Room.create({ roomCode, name, passwordHash, plainPassword:password, owner:req.userId, members:[req.userId], category:category||"general" });
    res.json({ success:true, room:safeRoom(room, req.userId) });
  } catch(err) { console.error(err); res.status(500).json({ error:"Server error" }); }
});

app.post("/api/rooms/join", authMiddleware, async (req, res) => {
  try {
    const { roomCode, password } = req.body;
    if (!roomCode||!password) return res.status(400).json({ error:"Code and password required" });
    const room = await Room.findOne({ roomCode });
    if (!room) return res.status(404).json({ error:"Room not found" });
    if (!(await room.comparePassword(password))) return res.status(401).json({ error:"Wrong password" });
    if (!room.members.map(m=>m.toString()).includes(req.userId.toString())) { room.members.push(req.userId); await room.save(); }
    res.json({ success:true, room:safeRoom(room, req.userId) });
  } catch(err) { console.error(err); res.status(500).json({ error:"Server error" }); }
});

// Join via invite link
app.get("/api/rooms/invite/:roomCode", authMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode: req.params.roomCode });
    if (!room) return res.status(404).json({ error:"Room not found" });
    res.json({ name: room.name, roomCode: room.roomCode, category: room.category, memberCount: room.members.length });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const rooms = await Room.find({ members:req.userId }).sort({ createdAt:-1 });
    res.json({ rooms: rooms.map(r=>safeRoom(r,req.userId)) });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/rooms/:roomCode", authMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode:req.params.roomCode }).populate("members","name");
    if (!room) return res.status(404).json({ error:"Room not found" });
    const msgCount = await Message.countDocuments({ roomId:req.params.roomCode, type:"user" });
    const pinnedMsg = room.pinnedMessage ? await Message.findById(room.pinnedMessage) : null;
    res.json({
      room: safeRoom(room, req.userId),
      members: room.members.map(m=>({ id:m._id, name:m.name, initials:getInitials(m.name), avatarColor:getAvatarColor(m._id) })),
      messageCount: msgCount,
      pinnedMessage: pinnedMsg&&!pinnedMsg.deleted ? pinnedMsg : null,
    });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.delete("/api/rooms/:roomCode", authMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({ roomCode:req.params.roomCode });
    if (!room) return res.status(404).json({ error:"Not found" });
    if (room.owner.toString() !== req.userId.toString()) return res.status(403).json({ error:"Owner only" });
    await Message.deleteMany({ roomId:req.params.roomCode });
    await Room.deleteOne({ roomCode:req.params.roomCode });
    io.to(req.params.roomCode).emit("room_deleted", { roomCode:req.params.roomCode });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.post("/api/rooms/:roomCode/pin", authMiddleware, async (req, res) => {
  try {
    const { messageId } = req.body;
    const room = await Room.findOne({ roomCode:req.params.roomCode });
    if (!room||room.owner.toString()!==req.userId.toString()) return res.status(403).json({ error:"Owner only" });
    if (room.pinnedMessage?.toString()===messageId) {
      room.pinnedMessage=null; await Message.findByIdAndUpdate(messageId,{pinned:false});
    } else {
      if (room.pinnedMessage) await Message.findByIdAndUpdate(room.pinnedMessage,{pinned:false});
      room.pinnedMessage=messageId; await Message.findByIdAndUpdate(messageId,{pinned:true});
    }
    await room.save();
    const pinnedMsg = room.pinnedMessage ? await Message.findById(room.pinnedMessage) : null;
    io.to(req.params.roomCode).emit("pin_updated",{pinnedMessage:pinnedMsg});
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// Set room announcement
app.post("/api/rooms/:roomCode/announcement", authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    const room = await Room.findOne({ roomCode:req.params.roomCode });
    if (!room||room.owner.toString()!==req.userId.toString()) return res.status(403).json({ error:"Owner only" });
    room.announcement = text||""; await room.save();
    io.to(req.params.roomCode).emit("announcement_updated",{ text:room.announcement });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// Search messages in room
app.get("/api/rooms/:roomCode/search", authMiddleware, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q||q.length<2) return res.json({ messages:[] });
    const messages = await Message.find({
      roomId:req.params.roomCode, type:"user",
      text: { $regex: q, $options:"i" }
    }).sort({ timestamp:-1 }).limit(30).lean();
    res.json({ messages });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// Mark messages as read
app.post("/api/rooms/:roomCode/read", authMiddleware, async (req, res) => {
  try {
    await Message.updateMany(
      { roomId:req.params.roomCode, readBy:{ $ne:req.userId }, type:"user" },
      { $addToSet:{ readBy:req.userId } }
    );
    io.to(req.params.roomCode).emit("messages_read",{ userId:req.userId, roomCode:req.params.roomCode });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (username!==ADMIN_USERNAME||password!==ADMIN_PASSWORD) return res.status(401).json({ error:"Invalid credentials" });
  const token = signAdminToken();
  res.cookie("adminToken", token, { httpOnly:true, maxAge:8*60*60*1000, sameSite:"lax" });
  res.json({ success:true });
});
app.post("/api/admin/logout", (req, res) => { res.clearCookie("adminToken"); res.json({ success:true }); });
app.get("/api/admin/verify", adminMiddleware, (req, res) => res.json({ ok:true }));

app.get("/api/admin/stats", adminMiddleware, async (req, res) => {
  try {
    const [totalUsers,totalRooms,totalMessages,bannedUsers] = await Promise.all([
      User.countDocuments(), Room.countDocuments(),
      Message.countDocuments({type:"user"}), User.countDocuments({banned:true})
    ]);
    let onlineCount=0;
    for (const r in onlineRooms) onlineCount += onlineRooms[r].size;
    res.json({ totalUsers,totalRooms,totalMessages,bannedUsers,onlineNow:onlineCount });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/admin/users", adminMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    const query = search ? { $or:[{name:new RegExp(search,"i")},{mobile:new RegExp(search,"i")}] } : {};
    const users = await User.find(query).select("-password").sort({createdAt:-1}).limit(100);
    res.json({ users });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.post("/api/admin/users/:userId/ban", adminMiddleware, async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(req.params.userId,{banned:true,banReason:reason||"Admin action"},{new:true});
    if (!user) return res.status(404).json({ error:"Not found" });
    await logActivity("BAN_USER",user._id,user.name,`Reason: ${reason||"Admin action"}`);
    io.sockets.sockets.forEach(s=>{ if(s.user?._id?.toString()===user._id.toString()) s.disconnect(true); });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.post("/api/admin/users/:userId/unban", adminMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.userId,{banned:false,banReason:""},{new:true});
    if (!user) return res.status(404).json({ error:"Not found" });
    await logActivity("UNBAN_USER",user._id,user.name,"Unbanned");
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.delete("/api/admin/users/:userId", adminMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return res.status(404).json({ error:"Not found" });
    await User.deleteOne({_id:user._id});
    await logActivity("DELETE_USER",user._id,user.name,"Deleted");
    io.sockets.sockets.forEach(s=>{ if(s.user?._id?.toString()===user._id.toString()) s.disconnect(true); });
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/admin/rooms", adminMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    const query = search ? { $or:[{name:new RegExp(search,"i")},{roomCode:new RegExp(search,"i")}] } : {};
    const rooms = await Room.find(query).populate("owner","name mobile").sort({createdAt:-1}).limit(100);
    const result = await Promise.all(rooms.map(async r=>{
      const msgCount = await Message.countDocuments({roomId:r.roomCode,type:"user"});
      return { id:r._id, roomCode:r.roomCode, name:r.name, category:r.category,
        owner:r.owner?{name:r.owner.name,mobile:r.owner.mobile}:null,
        memberCount:r.members.length, messageCount:msgCount,
        onlineNow:onlineRooms[r.roomCode]?.size||0,
        createdAt:r.createdAt, plainPassword:r.plainPassword };
    }));
    res.json({ rooms:result });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.delete("/api/admin/rooms/:roomCode", adminMiddleware, async (req, res) => {
  try {
    const room = await Room.findOne({roomCode:req.params.roomCode});
    if (!room) return res.status(404).json({ error:"Not found" });
    await Message.deleteMany({roomId:req.params.roomCode});
    await Room.deleteOne({roomCode:req.params.roomCode});
    io.to(req.params.roomCode).emit("room_deleted",{roomCode:req.params.roomCode});
    await logActivity("DELETE_ROOM",room._id,room.name,`Code:${room.roomCode}`);
    res.json({ success:true });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/admin/rooms/:roomCode/messages", adminMiddleware, async (req, res) => {
  try {
    const messages = await Message.find({roomId:req.params.roomCode}).sort({timestamp:1}).limit(500).lean();
    res.json({ messages });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/api/admin/activity", adminMiddleware, async (req, res) => {
  try {
    const logs = await Activity.find().sort({timestamp:-1}).limit(100);
    res.json({ logs });
  } catch { res.status(500).json({ error:"Server error" }); }
});

app.get("/health", (req, res) => res.json({ status:"ok" }));
app.get("/admin", (req, res) => res.sendFile(path.join(__dirname,"public","admin.html")));
app.get("/join/:roomCode", (req, res) => res.sendFile(path.join(__dirname,"public","index.html")));

// ════════════════════════════════════════════════════════════════
// SOCKET.IO
// ════════════════════════════════════════════════════════════════
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token ||
    socket.handshake.headers?.cookie?.split(";").find(c=>c.trim().startsWith("token="))?.split("=")[1];
  const payload = verifyToken(token);
  if (!payload||payload.role==="admin") return next(new Error("Unauthorized"));
  const user = await User.findById(payload.id);
  if (!user) return next(new Error("Not found"));
  if (user.banned) return next(new Error("Banned"));
  socket.user = { ...safeUser(user), _id:user._id };
  next();
});

io.on("connection", async (socket) => {
  console.log(`[CONNECT] ${socket.user.name}`);
  // Mark online
  await User.findByIdAndUpdate(socket.user._id, { status:"online", lastSeen:new Date() });

  socket.on("join_room", async ({ roomCode }) => {
    if (!roomCode) return;
    const room = await Room.findOne({ roomCode });
    if (!room) return socket.emit("error_msg","Room not found");
    if (!room.members.map(m=>m.toString()).includes(socket.user._id.toString()))
      return socket.emit("error_msg","Not a member");

    socket.join(roomCode);
    socket.data.roomCode = roomCode;
    if (!onlineRooms[roomCode]) onlineRooms[roomCode] = new Set();
    onlineRooms[roomCode].add(socket.id);

    const history = await Message.find({ roomId:roomCode }).sort({timestamp:1}).limit(200).lean();
    socket.emit("chat_history", history);

    // Send announcement if exists
    if (room.announcement) socket.emit("announcement_updated",{ text:room.announcement });

    if (room.pinnedMessage) {
      const pinned = await Message.findById(room.pinnedMessage);
      if (pinned&&!pinned.deleted) socket.emit("pin_updated",{ pinnedMessage:pinned });
    }

    emitRoomUsers(roomCode);
    const sysMsg = await Message.create({ roomId:roomCode, type:"system", text:`${socket.user.name} joined` });
    io.to(roomCode).emit("new_message", sysMsg);
  });

  socket.on("send_message", async ({ roomCode, text, replyTo }) => {
    if (!roomCode||!text?.trim()) return;
    const msgData = {
      roomId:roomCode, type:"user",
      senderId:socket.user._id, username:socket.user.name,
      initials:socket.user.initials, avatarColor:socket.user.avatarColor,
      text:text.trim(),
    };
    if (replyTo?.messageId) {
      msgData.replyTo = { messageId:replyTo.messageId, username:replyTo.username, text:replyTo.text };
    }
    const msg = await Message.create(msgData);
    io.to(roomCode).emit("new_message", msg);
  });

  socket.on("delete_message", async ({ messageId, roomCode }) => {
    const msg = await Message.findById(messageId);
    if (!msg) return;
    if (msg.senderId.toString()!==socket.user._id.toString()) return socket.emit("error_msg","Own messages only");
    if (Date.now()-new Date(msg.timestamp).getTime() > 5*60*1000) return socket.emit("error_msg","5 min limit passed");
    await Message.findByIdAndDelete(messageId);
    const room = await Room.findOne({ roomCode });
    if (room?.pinnedMessage?.toString()===messageId) {
      room.pinnedMessage=null; await room.save();
      io.to(roomCode).emit("pin_updated",{ pinnedMessage:null });
    }
    io.to(roomCode).emit("message_deleted",{ messageId });
  });

  // Reactions
  socket.on("toggle_reaction", async ({ messageId, roomCode, emoji }) => {
    const msg = await Message.findById(messageId);
    if (!msg) return;
    const existing = msg.reactions.findIndex(r=>r.userId===socket.user._id.toString()&&r.emoji===emoji);
    if (existing>-1) { msg.reactions.splice(existing,1); }
    else { msg.reactions.push({ emoji, userId:socket.user._id.toString(), username:socket.user.name }); }
    await msg.save();
    io.to(roomCode).emit("reaction_updated",{ messageId, reactions:msg.reactions });
  });

  // Read receipts
  socket.on("mark_read", async ({ roomCode }) => {
    await Message.updateMany(
      { roomId:roomCode, readBy:{ $ne:socket.user._id }, type:"user" },
      { $addToSet:{ readBy:socket.user._id } }
    );
    io.to(roomCode).emit("messages_read",{ userId:socket.user._id.toString(), roomCode });
  });

  // Status change
  socket.on("set_status", async ({ status, statusText }) => {
    await User.findByIdAndUpdate(socket.user._id, { status, statusText:statusText||"", lastSeen:new Date() });
    socket.user.status = status;
    if (socket.data.roomCode) {
      io.to(socket.data.roomCode).emit("user_status_changed",{
        userId:socket.user._id.toString(), status, statusText, name:socket.user.name
      });
    }
  });

  socket.on("typing_start", ({ roomCode }) => socket.to(roomCode).emit("user_typing",{ username:socket.user.name }));
  socket.on("typing_stop",  ({ roomCode }) => socket.to(roomCode).emit("user_stop_typing",{ username:socket.user.name }));

  socket.on("disconnect", async () => {
    const roomCode = socket.data.roomCode;
    await User.findByIdAndUpdate(socket.user._id, { status:"offline", lastSeen:new Date() });
    if (!roomCode) return;
    if (onlineRooms[roomCode]) {
      onlineRooms[roomCode].delete(socket.id);
      if (onlineRooms[roomCode].size===0) delete onlineRooms[roomCode];
    }
    emitRoomUsers(roomCode);
    const sysMsg = await Message.create({ roomId:roomCode, type:"system", text:`${socket.user.name} left` });
    io.to(roomCode).emit("new_message", sysMsg);
  });

  function emitRoomUsers(roomCode) {
    const sids = onlineRooms[roomCode] ? [...onlineRooms[roomCode]] : [];
    const users = sids.map(sid=>{
      const s = io.sockets.sockets.get(sid);
      return s ? { name:s.user.name, initials:s.user.initials, avatarColor:s.user.avatarColor, status:s.user.status||"online" } : null;
    }).filter(Boolean);
    io.to(roomCode).emit("room_update",{ userCount:users.length, users });
  }
});

server.listen(PORT, () => console.log(`🚀 Server on http://localhost:${PORT}`));
