const {StatusCodes} = require('http-status-codes');

const errorHandlerMiddleware = (err, req, res, next) => {
  let customError = {
    // Set default error
    statusCode: err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR,
    msg: err.message || 'Something went wrong. Please try again.',
  };
  if (err.name === 'ValidationError') {
    customError.msg = Object.values(err.errors)
      .map((item) => item.message)
      .join(',');
    customError.statusCode = 400;
  }
  if (err.code && err.code === 11000) {
    customError.msg = `Duplicate value entered for the ${Object.keys(err.keyValue)} field. Please choose another value.`;
    customError.statusCode = 400;
  }
  if (err.name === 'CastError') {
    customError.msg = `No item found with id: ${err.value}.`;
    customError.statusCode = 404;
  }
  return res.status(customError.statusCode).render("error", {
    title: "Error",
    msg: customError.msg,
  });
};

module.exports = errorHandlerMiddleware;
