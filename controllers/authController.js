const User = require('../models/User');
const Token = require('../models/Token');
const {StatusCodes} = require('http-status-codes');
const CustomError = require('../errors');
const crypto = require('crypto');
const {
  attachCookiesToResponse,
  createTokenUser,
  sendVerificationEmail,
  sendResetPasswordEmail,
  createHash,
} = require('../utils/index');

const homepage = (req, res) => {
  res.render('home', {title: "Welcome"});
};

const register = async (req, res) => {
  const {first_name, last_name, email, password, confirm_pw} = req.body;

  // Check if email address is already in DB
  const alreadyExists = await User.findOne({email});
  if (alreadyExists) {
    throw new CustomError.BadRequestError('Email already exists. Please log in.');
  }

  // Check if confirmation password === password
  if (password !== confirm_pw) {
    throw new CustomError.BadRequestError("Passwords do not match.");
  }

  // First registered user is set to be an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    first_name,
    last_name,
    email,
    password,
    role,
    verificationToken
  });

  // Send verification email to user
  const origin = process.env.BASE_URL;
  
  await sendVerificationEmail({
    name: user.first_name || "there",
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });

  res.status(StatusCodes.CREATED).json({msg: 'Success! Please check your email to verify your account.'});
};

const verifyEmail = async (req, res) => {
  const {token, email} = req.query;
  const user = await User.findOne({email});

  // Ensure that user exists and that verification token matches
  if (!user || (user.verificationToken !== token)) {
    throw new CustomError.UnauthenticatedError('Verification failed');
  }

  // Verify user in the DB
  user.isVerified = true;
  user.verifiedOn = Date.now();
  user.verificationToken = '';
  await user.save();

  res.status(StatusCodes.OK).json({msg: 'Email verified'});
};

const login = async (req, res) => {
  const {email, password} = req.body;
  // Ensure user provided both an email and password
  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide an email and password.');
  }

  // Ensure the user is registered and password is correct
  const user = await User.findOne({email});
  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Password is incorrect.');
  }

  // Ensure user has a verified email address
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Please verify your email address.');
  }

  const tokenUser = createTokenUser(user);

  // Create refresh token
  let refreshToken = '';

  // Check for existing token
  const existingToken = await Token.findOne({user: user._id});

  if (existingToken) {
    const {isValid} = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid credentials');
    }
    refreshToken = existingToken.refreshToken;
    attachCookiesToResponse({res, user: tokenUser, refreshToken});

    res.status(StatusCodes.OK).json({user: tokenUser});
    return;
  }

  // Create and store a new token
  refreshToken = crypto.randomBytes(40).toString('hex');
  const userAgent = req.headers['user-agent'];
  const ip = req.ip;
  const userToken = {
    refreshToken, 
    ip, 
    userAgent, 
    user: user._id
  };

  await Token.create(userToken);

  attachCookiesToResponse({res, user: tokenUser, refreshToken});

  res.status(StatusCodes.OK).json({user: tokenUser});
};

const logout = async (req, res) => {
  // Delete the user's token
  await Token.findOneAndDelete({user: req.user.userId});

  // Set accessToken & refreshToken to 'logout' and expiration to now
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.cookie('refreshToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.status(StatusCodes.OK).json({msg: 'User has been logged out!'});
};

const forgotPasswordPage = (req, res) => {
  res.render("forgot_pass", {title: "Forgot Password"});
};

const forgotPassword = async (req, res) => {
  const {email} = req.body;
  if (!email) {
    throw new CustomError.BadRequestError('Please provide a valid email.');
  }

  // Look up the user if one exists
  const user = await User.findOne({email});
  
  // If the user exists, send a password reset email
  if (user) {
    const passwordToken = crypto.randomBytes(70).toString('hex');
    
    // Send email
    const origin = process.env.BASE_URL;
    await sendResetPasswordEmail({
      name: user.first_name || "there",
      email: user.email,
      token: passwordToken,
      origin,
    });

    // User has 10 minutes to reset the password
    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
    
    req.flash("success_msg", "Please check your email for the password reset link.");
    res.redirect("/");
  } else {
    throw new CustomError.BadRequestError("Could not find a user with that email address.");
  }
};

const resetPasswordPage = (req, res) => {
  const {token, email} = req.query;
  res.render('reset_pass', {title: "Reset Password", token, email})
}

const resetPassword = async (req, res) => {
  const {token, email, password, confirm_pw} = req.body;

  // Ensure that the user's token, email, and password were provided
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError("Please provide all values.");
  }

  // Check if new password === retyped password
  if (password !== confirm_pw) {
    throw new CustomError.BadRequestError("Passwords do not match.");
  }

  const user = await User.findOne({email});

  // If user exists, update password in the DB and clear the password token
  if (user) {
    const currentDate = new Date();

    // Check if stored password token is the same as the provided token and if the token is expired
    if (
      user.passwordToken === createHash(token) &&
      user.passwordTokenExpirationDate > currentDate
    ) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();

      req.flash("success_msg", "Your password has been reset.");
      res.redirect("/");
    } else {
      throw new CustomError.BadRequestError("Password could not be reset.");
    }
  } else {
    throw new CustomError.BadRequestError(
      "Could not find a user with that email address."
    );
  }
};

const ensureAuthenticated = (req, res, next) => {
  // Protect routes that require log in
  if (req.isAuthenticated()) return next();
  req.flash('error_msg', 'Please log in to view this page.');
  res.redirect('/');
};

const forwardAuthenticated = (req, res, next) => {
  // Forward user to dashboard if already logged in
  if (!req.isAuthenticated()) return next();
  res.redirect('/dashboard');      
};

const rememberMeMiddleware = (req, res, next) => {
  if (req.body.remember_me) {
    // Set max age of cookie to 1 day if remember me was checked
    const oneDay = 1000 * 60 * 60 * 24;
    req.session.cookie.originalMaxAge = oneDay;
  } else {
    req.session.cookie.expires = false;
  }
  next();
};

module.exports = {
  homepage,
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  forgotPasswordPage,
  resetPassword,
  resetPasswordPage,
  ensureAuthenticated,
  forwardAuthenticated,
  rememberMeMiddleware
};
