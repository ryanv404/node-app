const LocalStrategy = require("passport-local").Strategy;
const User = require("../models/User");

module.exports = (passport) => {
  passport.use(new LocalStrategy({usernameField: "email"}, 
    async (email, password, done) => {
      // Match user by email
      const user = await User.findOne({email});
      if (!user) {
        return done(null, false, {message: 'That email address is not registered.'});
      }

      // Check if provided password matches user's stored password
      const isMatch = await user.comparePassword(password);
      if (isMatch) return done(null, user);
      return done(null, false, {message: "Your password was incorrect."});
    }
  ));

  passport.serializeUser((user, done) => {
    return done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      return done(err, user);
    });
  });
};
