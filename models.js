const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// ─── User Model ───────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true, maxlength: 40 },
  mobile:   { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  age:      { type: Number, required: true, min: 10, max: 120 },
  gender:   { type: String, required: true, enum: ["male", "female", "other"] },
  avatar:   { type: String, default: "" }, // initials color hex
  rooms:    [{ type: String }],            // room names user has joined
  createdAt:{ type: Date, default: Date.now }
});

// Hash password before save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = function (plain) {
  return bcrypt.compare(plain, this.password);
};

// ─── Message Model ────────────────────────────────────────────────────────────
const messageSchema = new mongoose.Schema({
  roomId:    { type: String, required: true, index: true },
  type:      { type: String, enum: ["user", "system"], default: "user" },
  senderId:  { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  username:  { type: String },
  initials:  { type: String },
  avatarColor:{ type: String },
  text:      { type: String, required: true, maxlength: 2000 },
  timestamp: { type: Date, default: Date.now } // kept forever
});

const User    = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

module.exports = { User, Message };
