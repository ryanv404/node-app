const notFound = (req, res) => {
  return res.status(404).render("error", {
    title: "Error", 
    msg: "Could not find that page."
  });
};

module.exports = notFound;
