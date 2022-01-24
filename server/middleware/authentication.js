const {isTokenValid, attachCookiesToResponse} = require("../utils/index");
const Token = require('../models/Token');

const authenticateUser = async (req, res, next) => {
  const {refreshToken, accessToken} = req.signedCookies;

  try {
    if (accessToken) {
      const payload = isTokenValid(accessToken);
      req.user = payload.user;
      return next();
    }
    const payload = isTokenValid(refreshToken);

    const existingToken = await Token.findOne({
      user: payload.user.userId,
      refreshToken: payload.refreshToken,
    });

    if (!existingToken || !existingToken.isValid) {
      req.flash("error_msg", "Authentication invalid");
      return res.redirect("/");
    }

    attachCookiesToResponse({
      res,
      user: payload.user,
      refreshToken: existingToken.refreshToken,
    });

    req.user = payload.user;
    next();
  } catch (error) {
    req.flash("error_msg", "Authentication invalid");
    return res.redirect("/");
  }
};

const authorizePermissions = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      req.flash("error_msg", "You are not authorized to access this route.");
      return res.redirect("/");
    }
    next();
  };
};

module.exports = {authenticateUser, authorizePermissions};
