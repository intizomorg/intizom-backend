module.exports = function adminIpOnly(req, res, next) {
  const allowed = (process.env.ADMIN_ALLOWED_IPS || "")
    .split(",")
    .map(ip => ip.trim())
    .filter(Boolean);

  if (!allowed.length) return next();

  const ip = (req.ip || "").replace("::ffff:", "").trim();

  if (!allowed.includes(ip)) {
    console.log("ADMIN IP BLOCKED:", ip);
    return res.status(403).json({ msg: "Admin IP restricted" });
  }

  next();
};
