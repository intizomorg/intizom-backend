module.exports = function adminIpOnly(req, res, next) {
  const allowed = (process.env.ADMIN_ALLOWED_IPS || "")
    .split(",")
    .map(ip => ip.trim())
    .filter(Boolean);

  if (!allowed.length) return next();

  const raw =
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"] ||
    req.headers["x-real-ip"] ||
    req.socket.remoteAddress ||
    "";

  const ip = raw.split(",")[0].replace("::ffff:", "").trim();

  if (!allowed.includes(ip)) {
    console.log("ADMIN IP BLOCKED:", ip);
    return res.status(403).json({ msg: "Admin IP restricted" });
  }

  next();
};
