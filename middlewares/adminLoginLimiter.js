const rateLimit = require("express-rate-limit");

module.exports = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const ip = req.ip || "unknown";
    const username = (req.body && req.body.username) || "";
    return `${ip}:${username}`;
  },
  message: { msg: "Too many admin login attempts. Try again later." }
});
