const express = require("express");
const router = express.Router();
const moment = require("moment");
const Review = require("../models/Review"); 

// Get all reviews
router.get("/", async (req, res) => {
  try {
    const reviews = await Review.find().sort("-createdAt -updatedAt");
    res.render("reviews", {
      title: "Reviews",
      reviews,
      moment,
    });
  } catch (error) {
    console.log(error);
  }
});

// Get one review
router.get("/:reviewID", async (req, res) => {
  try {
    const review = await Review.findById(req.params.reviewID);
    res.json(review);
  } catch (error) {
    console.log(error);
  }
});

// Create a review
router.post("/", async (req, res) => {
  try {
    const alreadyExists = await Review.findOne({
      reviewTitle: req.body.reviewTitle
    });
    
    if (alreadyExists) {
      console.log("Review with that title already exists.");
      return res.redirect("/reviews");
    }
    const newReview = new Review({
      reviewTitle: req.body.reviewTitle,
      movieName: req.body.movieName,
      reviewBody: req.body.reviewBody,
      reviewRating: req.body.reviewRating
    });

    const successful = await Review.create(newReview);
    if (successful){
      req.flash("success_msg", "Review successfully created.");
    }
  } catch (error) {
    console.log(error);
  }
  res.redirect("/reviews");
});

// Update a review
router.put("/:reviewID", async (req, res) => {
  try {
    let {movieTitle, reviewTitle, reviewContent, reviewRating} = req.body;
    
    reviewRating = Number(reviewRating);
    const successful = await Review.findByIdAndUpdate(req.params.reviewID, {
      reviewTitle: reviewTitle,
      movieName: movieTitle,
      reviewBody: reviewContent,
      reviewRating: reviewRating
    });
    if (successful) {
      req.flash("success_msg", "Review successfully updated.");
    }
  } catch (error) {
    console.log(error);
  }
  res.redirect("/reviews");
});

// Delete a review
router.delete("/:reviewID", async (req, res) => {
  try {
    const successful = await Review.findOneAndDelete(req.params.reviewID);
    if (successful) {
      req.flash("success_msg", "Review successfully deleted.");
    }
  } catch (error) {
    console.log(error);
  }
  res.redirect("/reviews");
});

module.exports = router;