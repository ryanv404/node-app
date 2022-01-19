const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const {ensureAuthenticated} = require("../controllers/authController");
const User = require("../models/User");

// Register user
router.post("/register", (req, res) => {
  const {fname, lname, email, username, password, confirm_pw} = req.body;
  let errors = [];

  if (!fname || !lname || !email || !username || !password || !confirm_pw) {
    errors.push({msg: "Please enter all fields."});
  }

  if (password !== confirm_pw) {
    errors.push({msg: "Passwords do not match."});
  }

  if (password.length < 6) {
    errors.push({msg: "Password must be at least 6 characters."});
  }

  if (errors.length > 0) {
    res.render("home", {title: "Home", errors});
  } else {
    User.findOne({username: username})
      .then((user) => {
        if (user) {
          errors.push({msg: "Username already exists."});
          res.render("home", {
            title: "Home",
            errors
          });
        } else {
          const newUser = new User({
            firstName: fname,
            lastName: lname,
            email: email,
            username: username,
            password: password
          });

          bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(newUser.password, salt, (err, hash) => {
              if (err) throw err;
              newUser.password = hash;
              newUser
                .save()
                .then((user) => {
                  req.flash("success_msg", "You are now registered and can log in.");
                  res.redirect("/");
                })
                .catch((err) => console.log(err));
            });
          });
        }
      })
      .catch((err) => console.log(err));
  }
});

// Password reset form
router.get("/reset", (req, res) => {
  res.render("reset", {
    title: "Reset Password"
  });
});

// Reset password
router.post("/reset", async (req, res) => {
  const {username, password, new_pass, confirm_pass} = req.body;
  let errors = [];

  if (!username || !password || !new_pass || !confirm_pass) {
    errors.push({msg: "Please enter all fields."});
  }

  if (new_pass !== confirm_pass) {
    errors.push({msg: "New passwords do not match."});
  }

  if (new_pass.length < 6) {
    errors.push({msg: "Passwords must be at least 6 characters."});
  }

  // Find user by username
  const user = await User.findOne({username: username});
  
  // Check if user exists in the db
  if (!user) {
    errors.push({msg: `The username "${username}" is not registered.`});
  } else {
    // Verify by matching current password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) console.log(err);
      if (!isMatch) errors.push({msg: "Incorrect password."});
    });
  }
  if (errors.length > 0) {
    res.render("reset", {
      title: "Reset Password",
      errors
    });
  } else {
    // Hash new password and store it
    bcrypt.genSalt(10, (err, salt) => {
      bcrypt.hash(new_pass, salt, (err, hash) => {
        if (err) throw err;
        User.findOneAndUpdate({username: username}, {$set: {password: hash}}, (err, user) => {
          if (err) throw err;
          if (user) {
            req.flash("success_msg", "Your password has been updated!");
            res.redirect("/");
          }
        });
      });
    });
  }
});

// User's profile
router.get("/profile", ensureAuthenticated, async (req, res) => {
  const user = await User.findOne({username: req.user.username});
  res.render("profile", {
    user: user,
    title: "Profile"
  });
});

// TODO: Update profile
router.put("/profile", ensureAuthenticated, async (req, res) => {
  let updateObj = {};
  try {
    const user = await User.findOne(req.params.username);
    if (req.body.modified_firstName !== user.firstName) {
      updateObj.firstName = req.body.modified_firstName;
    }
    if (req.body.modified_lastName !== user.lastName) {
      updateObj.lastName = req.body.modified_lastName;
    }
    if (updateObj && (req.user.username === req.params.username)) {
      await User.findByIdAndUpdate(user._id, {$set: updateObj});
    }
  } catch (err) {
    console.log(err);
  }
  res.redirect("/profile");
});

// TODO: Delete profile
router.delete("/profile", ensureAuthenticated, async (req, res) => {
  try {
    await User.findOne(req.params.username);
  } catch (err) {
    console.log(err);
  }
  res.redirect("/logout");
});

module.exports = router;
