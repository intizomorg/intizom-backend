const mongoose = require("mongoose");
const sanitizeHtml = require("sanitize-html");

const MessageSchema = new mongoose.Schema({
  from: {
    type: String,
    required: true,
    index: true
  },
  to: {
    type: String,
    required: true,
    index: true
  },
  text: {
    type: String,
    required: true,
    trim: true,
    maxlength: 2000
  },

  // ✅ client yuborgan tempId (idempotency uchun)
  clientMsgId: {
    type: String,
    default: null,
    index: true
  },

  // ✅ edit bo‘lganda
  editedAt: {
    type: Date,
    default: null,
    index: true
  },

  // ✅ xabar qachon o‘qilganini saqlaydi
  readAt: {
    type: Date,
    default: null,
    index: true
  },

  // ✅ Reply (quote) — qaysi message ga javob
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Message",
    default: null,
    index: true
  },

  // ✅ Delivered status (✔✔) — receiver socketiga yetib kelganda
  deliveredAt: {
    type: Date,
    default: null,
    index: true
  },

  // ✅ Reactions — emoji -> usernamelar
  reactions: {
    type: Map,
    of: [String], // ["ali", "vali"]
    default: {}
  },

  createdAt: {
    type: Date,
    default: Date.now
  }
});

// 🔍 Mavjud indexlar
MessageSchema.index({ from: 1, to: 1, createdAt: -1 });
MessageSchema.index({ to: 1, from: 1, readAt: 1, createdAt: -1 });

// ✅ Yangi indexlar (tezlik uchun)
MessageSchema.index({ to: 1, deliveredAt: 1, createdAt: -1 });
MessageSchema.index({ to: 1, readAt: 1, createdAt: -1 });

// ✅ idempotency: bitta user bir tempId ni qayta yuborsa duplicate bo‘lmaydi
MessageSchema.index(
  { from: 1, clientMsgId: 1 },
  { unique: true, sparse: true }
);

// 🧼 XSS sanitization
MessageSchema.pre("save", function () {
  this.text = sanitizeHtml(String(this.text || ""), {
    allowedTags: [],
    allowedAttributes: {}
  }).trim();
});

module.exports = mongoose.model("Message", MessageSchema);