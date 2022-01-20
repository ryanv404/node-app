require("dotenv").config();
const express = require('express');
const router = express.Router();
const passport = require("passport");
const {rememberMeMiddleware, ensureAuthenticated, forwardAuthenticated} = require("../controllers/authController");

// Welcome page
router.get('/', forwardAuthenticated, (req, res) => {
  res.render('home', {title: "Welcome"});
});

// User's dashboard
router.get('/dashboard', ensureAuthenticated, (req, res) => {
  const firstname = req.user.firstName;
  res.render("dashboard", {
    user: firstname,
    title: "Dashboard"
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
  req.flash("success_msg", "You are now logged out.");
  res.redirect("/");
});

module.exports = router;
