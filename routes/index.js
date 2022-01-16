require("dotenv").config();
const express = require('express');
const router = express.Router();
const passport = require("passport");
const {
  rememberMeMiddleware, ensureAuthenticated,
  forwardAuthenticated,
} = require("../config/auth");

// Welcome page
router.get('/', forwardAuthenticated, (req, res) => {
  const loggedIn = req.isAuthenticated();
  res.render('home', {title: "Welcome", loggedIn});
});

// User's dashboard
router.get('/dashboard', ensureAuthenticated, (req, res) => {
  const loggedIn = req.isAuthenticated();
  const firstname = req.user.firstName;
  res.render("dashboard", {
    user: firstname,
    title: "Dashboard",
    loggedIn
  });
});

// Log in user
router.post("/login", rememberMeMiddleware, passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/",
    failureFlash: true,
  })
);

// Log out user
router.get("/logout", (req, res) => {
  req.logout();
  req.flash("success_msg", "You are logged out.");
  res.redirect("/");
});

module.exports = router;
