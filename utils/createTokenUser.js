const createTokenUser = (user) => {
  return {name: user.first_name, userId: user._id, role: user.role};
};

module.exports = createTokenUser;
