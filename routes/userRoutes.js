const express = require('express');
const router = express.Router();
const {
  authenticateUser, 
  authorizePermissions} = require('../middleware/authentication');
const {
  getAllUsers,
  getSingleUser,
  showCurrentUser,
  updateUser,
  updateUserPassword
} = require('../controllers/userController');

router.route('/').get(authenticateUser, authorizePermissions('admin'), getAllUsers);
router.route('/me').get(authenticateUser, showCurrentUser);
router.route('/:id').get(authenticateUser, getSingleUser);
router.route('/updateUser').patch(authenticateUser, updateUser);
router.route('/updateUserPassword').patch(authenticateUser, updateUserPassword);

module.exports = router;
