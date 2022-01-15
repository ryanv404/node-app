const errorHandlerMiddleware = (err, req, res, next) => {
  console.log(err);
  return res.status(500).render("error", {
      title: "Error",
      msg: "Something went wrong. Please try again."
    });
};

module.exports = errorHandlerMiddleware;
