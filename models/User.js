// models/User.js
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 10; // adjust to 12+ in stronger production environments if CPU allows

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

    // password is never returned in queries by default
    password: {
      type: String,
      required: true,
      select: false,
      minlength: 8
    },

    avatar: {
      type: String,
      default: null
    },

    bio: {
      type: String,
      default: "",
      maxlength: 300
    },

    website: {
      type: String,
      default: "",
      trim: true,
      set: (v) => {
        if (!v) return "";
        const val = v.trim();
        if (!/^https?:\/\//i.test(val)) return "https://" + val;
        return val;
      }
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },

    // ✅ QO‘SHILDI: token versioning (JWT invalidation uchun)
    tokenVersion: {
      type: Number,
      default: 0,
      select: false
    }
  },
  { timestamps: true }
);

/**
 * toJSON / toObject transform:
 * - remove internal fields (password is already select:false, but remove defensively)
 * - convert _id to id
 * - remove __v
 */
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
  const hash = await bcrypt.hash(this.password, SALT_ROUNDS);
  this.password = hash;
});

/**
 * Instance method to compare password.
 * Note: when querying user for authentication, include password with `.select('+password')`.
 */
UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model("User", UserSchema);
