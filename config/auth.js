module.exports = {
  ensureAuthenticated: (req, res, next) => {
    // Protect routes that require log in
    if (req.isAuthenticated()) return next();

    req.flash('error_msg', 'Please log in to view this page.');
    res.redirect('/');
  },
  forwardAuthenticated: (req, res, next) => {
    // Forward user to dashboard if already logged in
    if (!req.isAuthenticated()) return next();
    
    res.redirect('/dashboard');      
  },
  rememberMeMiddleware: (req, res, next) => {
    if (req.body.remember_me) {
      const oneDay = 1000 * 60 * 60 * 24;
      req.session.cookie.originalMaxAge = oneDay;
    } else {
      req.session.cookie.expires = false;
    }
    next();
  }
};
