const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// ─── User ─────────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true, maxlength: 40 },
  mobile:    { type: String, required: true, unique: true, trim: true },
  password:  { type: String, required: true },
  age:       { type: Number, required: true, min: 10, max: 120 },
  gender:    { type: String, required: true, enum: ["male", "female", "other"] },
  banned:    { type: Boolean, default: false },
  banReason: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
userSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

// ─── Room ─────────────────────────────────────────────────────────────────────
const roomSchema = new mongoose.Schema({
  roomCode:      { type: String, required: true, unique: true },
  name:          { type: String, required: true, trim: true, maxlength: 40 },
  passwordHash:  { type: String, required: true },
  plainPassword: { type: String, required: true },
  owner:         { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  members:       [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  pinnedMessage: { type: mongoose.Schema.Types.ObjectId, ref: "Message", default: null },
  createdAt:     { type: Date, default: Date.now }
});
roomSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

// ─── Message ──────────────────────────────────────────────────────────────────
const messageSchema = new mongoose.Schema({
  roomId:      { type: String, required: true, index: true },
  type:        { type: String, enum: ["user", "system"], default: "user" },
  senderId:    { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  username:    { type: String },
  initials:    { type: String },
  avatarColor: { type: String },
  text:        { type: String, required: true, maxlength: 2000 },
  deleted:     { type: Boolean, default: false },
  pinned:      { type: Boolean, default: false },
  timestamp:   { type: Date, default: Date.now }
});

// ─── Admin Activity Log ───────────────────────────────────────────────────────
const activitySchema = new mongoose.Schema({
  action:    { type: String, required: true },  // e.g. "DELETE_ROOM", "BAN_USER"
  targetId:  { type: String },
  targetName:{ type: String },
  detail:    { type: String },
  timestamp: { type: Date, default: Date.now }
});

const User     = mongoose.model("User", userSchema);
const Room     = mongoose.model("Room", roomSchema);
const Message  = mongoose.model("Message", messageSchema);
const Activity = mongoose.model("Activity", activitySchema);

module.exports = { User, Room, Message, Activity };
