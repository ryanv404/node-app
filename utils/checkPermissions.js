const CustomError = require('../errors');

const checkPermissions = (requestUser, resourceUserId) => {
  if (requestUser.role === 'admin') return;
  if (requestUser.userId === resourceUserId.toString()) return;
  
  // If the user is both not an admin and not the author of a resource, then throw unauthorized error
  throw new CustomError.UnauthorizedError('Not authorized to access this route.');
};

module.exports = checkPermissions;
