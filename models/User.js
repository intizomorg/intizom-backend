// models/User.js
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 10;

// ✅ Profession variantlari
const PROFESSION_ENUM = [
  "",               // ✅ bo‘sh holatga ruxsat (Tanlang...)
  "Developer",
  "Designer",
  "SMM",
  "Photographer",
  "Videographer",
  "Teacher",
  "Doctor",
  "Engineer",
  "Student",
  "Entrepreneur",
  "Lawyer",         // ✅ frontend’da bor edi
  "Other"
];

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 30,
      match: [
        /^[a-z0-9\-_]+$/,
        "Username may contain only lowercase letters, numbers, hyphen and underscore."
      ]
    },

    password: {
      type: String,
      required: true,
      select: false,
      minlength: 8
    },

    avatar: { type: String, default: null },

    bio: { type: String, default: "", maxlength: 300 },

    website: {
      type: String,
      default: "",
      trim: true,
      set: (v) => {
        if (!v) return "";
        const val = v.trim();
        if (!val) return "";
        if (!/^https?:\/\//i.test(val)) return "https://" + val;
        return val;
      }
    },

    profession: {
      type: String,
      enum: PROFESSION_ENUM,
      default: "" // ✅ endi enum ichida bor
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    tokenVersion: {
      type: Number,
      default: 0,
      select: false
    }
  },
  { timestamps: true }
);

function transform(doc, ret) {
  ret.id = ret._id?.toString();
  delete ret._id;
  delete ret.__v;
  delete ret.password;
  return ret;
}

UserSchema.set("toJSON", { virtuals: true, transform });
UserSchema.set("toObject", { virtuals: true, transform });

UserSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
});

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};
module.exports = mongoose.model("User", UserSchema);
