const CustomError = require('../errors/index');
const {isTokenValid} = require('../utils/jwt');

const authenticateUser = async (req, res, next) => {
  let token;

  // Check header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer')) {
    token = authHeader.split(' ')[1];
  }
  // Check cookies
  else if (req.cookies.token) {
    token = req.cookies.token;
  }

  if (!token) {
    req.flash("error_msg", "Authentication invalid");
    return res.redirect("/");
  }
  try {
    const payload = isTokenValid(token);

    // Attach the user and his permissions to the req object
    req.user = {
      userId: payload.user.userId,
      role: payload.user.role,
    };

    next();
  } catch (error) {
    req.flash("error_msg", "Authentication invalid");
    return res.redirect("/");
  }
};

const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      req.flash("error_msg", "You are not authorized to access this route.");
      return res.redirect("/");
    }
    next();
  };
};

module.exports = {authenticateUser, authorizeRoles};
