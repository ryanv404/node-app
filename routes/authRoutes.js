const express = require('express');
const router = express.Router();
const {authenticateUser} = require('../middleware/authentication');
const {
  homepage,
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  forgotPasswordPage,
  resetPassword,
  resetPasswordPage,
  userDashboard
} = require("../controllers/authController");

router.get('/', homepage)
router.get('/dashboard', userDashboard)
router.post('/register', register);
router.post('/login', login);
router.delete('/logout', authenticateUser, logout);
router.get('/verify-email', verifyEmail);
router.route('/reset-password').get(resetPasswordPage).post(resetPassword);
router.route('/forgot-password').get(forgotPasswordPage).post(forgotPassword);

module.exports = router;
