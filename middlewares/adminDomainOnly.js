module.exports = function adminDomainOnly(req, res, next) {
  const host = req.headers.host;

  if (host !== 'admin-api.intizom.org') {
    return res.status(403).json({
      msg: 'Admin endpoints are accessible only via admin-api.intizom.org'
    });
  }

  next();
};
