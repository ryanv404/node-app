const checkPermissions = (requestUser, resourceUserId) => {
  if (requestUser.role === 'admin') return;
  if (requestUser.userId === resourceUserId.toString()) return;
  
  // If the user is both not an admin and not the author of a resource, then throw unauthorized error
  req.flash("error_msg", "You are not authorized to access this route.");
  return res.redirect("/");
};

module.exports = checkPermissions;
