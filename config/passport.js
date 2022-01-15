const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");

// Load User model
const User = require("../models/User");

module.exports = (passport) => {
  passport.use(
    new LocalStrategy((username, password, done) => {

      // Match user by username
      User.findOne({username: username})
        .then((user) => {
          if (!user) {
            return done(null, false,
              {message: `The username "${username}" is not registered.`});
          };
          
          // Match password
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (isMatch) return done(null, user);
            return done(null, false, {message: "Incorrect password."});
          });
        });
    })
  );

  passport.serializeUser((user, done) => {
    return done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
      return done(err, user);
    });
  });
};
