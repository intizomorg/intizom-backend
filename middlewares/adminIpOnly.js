module.exports = function adminIpOnly(req, res, next) {
  const allowed = (process.env.ADMIN_ALLOWED_IPS || '')
    .split(',')
    .map(ip => ip.trim())
    .filter(Boolean);

  if (!allowed.length) return next();

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0]
    .trim();

  if (!allowed.includes(ip)) {
    return res.status(403).json({ msg: 'Admin access blocked from this IP' });
  }

  next();
};
