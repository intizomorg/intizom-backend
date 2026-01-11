module.exports = function adminDomainOnly(req, res, next) {
  const host = (req.headers.host || "").toLowerCase();

  const allowed = [
    "admin-api.intizom.org",
    "api.intizom.org" // PRODUCTION uchun majburiy
  ];

  if (!allowed.includes(host)) {
    console.log("ADMIN DOMAIN BLOCKED:", host);
    return res.status(403).json({ msg: "Admin endpoint blocked by domain policy" });
  }

  next();
};
