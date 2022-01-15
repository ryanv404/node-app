const mongoose = require("mongoose");

// Define the schema
const reviewSchema = new mongoose.Schema({
  reviewTitle: {
    type: String,
    maxlength: [100, "Title is too long (max 100 characters)."],
    required: [true, "Title cannot be empty."],
    unique: true
  },
  movieName: {
    type: String,
    maxlength: [100, "Movie name is too long (max 200 characters)."],
    required: [true, "Movie name cannot be empty."],
  },
  reviewBody: {
    type: String,
    maxlength: [1000, "Review body is too long (max 1000 characters)."],
    required: [true, "Review body cannot be empty."],
  },
  reviewRating: {
    type: Number,
    default: 0,
  },
}, {timestamps: true});

// Define mongoose model
const Review = mongoose.model("Review", reviewSchema);

module.exports = Review;
