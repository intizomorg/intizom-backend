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
  createdAt: {
    type: Date,
    default: Date.now
  }
});

MessageSchema.index({ from: 1, to: 1, createdAt: -1 });

MessageSchema.pre("save", function () {
  this.text = sanitizeHtml(String(this.text || ""), {
    allowedTags: [],
    allowedAttributes: {}
  }).trim();
});

module.exports = mongoose.model("Message", MessageSchema);
