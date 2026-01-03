const mongoose = require("mongoose");

const CommentSchema = new mongoose.Schema({
  postId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Post",
    required: true,
    index: true
  },
  user: {
    type: String,
    required: true,
    index: true
  },
  text: {
    type: String,
    required: true,
    maxlength: 1000
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
});

// MUHIM: agar model allaqachon mavjud bo‘lsa, qayta yaratmasin
module.exports = mongoose.models.Comment || mongoose.model("Comment", CommentSchema);
