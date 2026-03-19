function requireAuth(req, res, next) {
  if (!req.session?.user) {
    res.redirect("/login");
    return;
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user) {
    res.redirect("/login");
    return;
  }
  if (req.session.user.role !== "admin") {
    res.status(403).send("Forbidden");
    return;
  }
  next();
}

module.exports = {
  requireAuth,
  requireAdmin,
};
