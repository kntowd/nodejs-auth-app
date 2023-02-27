const jwt = require("jsonwebtoken");

const tokenValidate = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    res.cookie("redirect", req.path);
    return res.redirect("/login");
  }

  try {
    jwt.verify(token, "secret");
  } catch (err) {
    res.cookie("redirect", "/test");
    return res.redirect("/login");
  }
  next();
};

module.exports = tokenValidate;
