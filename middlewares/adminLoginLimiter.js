const rateLimit = require("express-rate-limit");

module.exports = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  message: { msg: "Too many admin login attempts" },
  standardHeaders: true,
  legacyHeaders: false,
});
