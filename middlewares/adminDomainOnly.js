module.exports = function adminDomainOnly(req, res, next) {
  const origin = (req.headers.origin || "").toLowerCase();
  const referer = (req.headers.referer || "").toLowerCase();

  const allowed = [
    "https://intizom.org",
    "https://www.intizom.org"
  ];

  const ok =
    allowed.some(d => origin.startsWith(d)) ||
    allowed.some(d => referer.startsWith(d));

  if (!ok) {
    return res.status(403).json({ msg: "Admin endpoint blocked" });
  }

  next();
};
