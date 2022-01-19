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
} = require('../utils');

const register = async (req, res) => {
  const {email, name, password} = req.body;

  // Check if email address is already in DB
  const emailAlreadyExists = await User.findOne({email});
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists.');
  }

  // First registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';

  const verificationToken = crypto.randomBytes(40).toString('hex');

  const user = await User.create({
    name,
    email,
    password,
    role,
    verificationToken
  });

  // Send verification email to user
  const origin = 'http://localhost:3000';
  
  await sendVerificationEmail({
    name: user.name,
    email: user.email,
    verificationToken: user.verificationToken,
    origin,
  });

  res.status(StatusCodes.CREATED).json({
    msg: 'Success! Please check your email to verify your account.',
  });
};

const verifyEmail = async (req, res) => {
  const {verificationToken, email} = req.body;
  const user = await User.findOne({email});

  if (!user) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  if (user.verificationToken !== verificationToken) {
    throw new CustomError.UnauthenticatedError('Verification Failed');
  }

  // Verify user in the DB
  user.isVerified = true;
  user.verified = Date.now();
  user.verificationToken = '';
  await user.save();

  res.status(StatusCodes.OK).json({msg: 'Email Verified'});
};

const login = async (req, res) => {
  const {email, password} = req.body;
  // Ensure user provided both an email and password
  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide an email and password.');
  }

  const user = await User.findOne({email});
  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  // Check if provided password matches user's saved password
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  // Ensure user has a verified account
  if (!user.isVerified) {
    throw new CustomError.UnauthenticatedError('Please verify your account.');
  }

  const tokenUser = createTokenUser(user);

  // Create refresh token
  let refreshToken = '';

  // Check for existing token
  const existingToken = await Token.findOne({user: user._id});

  if (existingToken) {
    const {isValid} = existingToken;
    if (!isValid) {
      throw new CustomError.UnauthenticatedError('Invalid Credentials');
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
    const origin = 'http://localhost:3000';
    await sendResetPasswordEmail({
      name: user.name,
      email: user.email,
      token: passwordToken,
      origin
    });

    // User has 10 minutes to reset the password
    const tenMinutes = 1000 * 60 * 10;
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes);

    user.passwordToken = createHash(passwordToken);
    user.passwordTokenExpirationDate = passwordTokenExpirationDate;
    await user.save();
    
    res.status(StatusCodes.OK).json({msg: 'Please check your email for the password reset link.'});
  } else {
    throw new CustomError.BadRequestError("Could not find a user with that email address.");
  }
};

const resetPassword = async (req, res) => {
  const {token, email, password} = req.body;

  // Ensure that the user's token, email, and password were provided 
  if (!token || !email || !password) {
    throw new CustomError.BadRequestError('Please provide all values.');
  }

  const user = await User.findOne({email});

  // If user exists, update password in the DB and clear the password token
  if (user) {
    const currentDate = new Date();

    // Check if stored password token is the same as the provided token and if the token is expired
    if (user.passwordToken === createHash(token) &&
        user.passwordTokenExpirationDate > currentDate) {
      user.password = password;
      user.passwordToken = null;
      user.passwordTokenExpirationDate = null;
      await user.save();

      res.send("Password has been reset.");
    } else {
      throw new CustomError.BadRequestError("Password could not be reset.");
    }
  } else {
    throw new CustomError.BadRequestError("Could not find a user with that email address.");
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
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  ensureAuthenticated,
  forwardAuthenticated,
  rememberMeMiddleware
};
