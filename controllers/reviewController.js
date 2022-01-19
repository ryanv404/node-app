const Review = require('../models/Review');
const Product = require('../models/Product');
const {StatusCodes} = require('http-status-codes');
const CustomError = require('../errors');
const {checkPermissions} = require('../utils');

const createReview = async (req, res) => {
  const {product: productId} = req.body;

  // Check if the product ID exists
  const isValidProduct = await Product.findOne({_id: productId});
  if (!isValidProduct) {
    throw new CustomError.NotFoundError(`No product with id: ${productId}.`);
  }

  // Check if the user has already submitted a review for this product
  const alreadySubmitted = await Review.findOne({
    product: productId,
    user: req.user.userId
  });
  if (alreadySubmitted) {
    throw new CustomError.BadRequestError('You have already submitted a review for this product.');
  }

  // Include 'user: userId' in the req.body object and then create a new review
  req.body.user = req.user.userId;
  const review = await Review.create(req.body);

  res.status(StatusCodes.CREATED).json({review});
};

const getAllReviews = async (req, res) => {
  // Populate the Review.product field with the product's Product.name, Product.company, and Product.price
  const reviews = await Review.find({}).populate({
    path: "product",
    select: "name company price"
  });

  res.status(StatusCodes.OK).json({reviews, count: reviews.length});
};

const getSingleReview = async (req, res) => {
  const {id: reviewId} = req.params;

  const review = await Review.findOne({_id: reviewId});

  if (!review) {
    throw new CustomError.NotFoundError(`No review with id: ${reviewId}.`);
  }

  res.status(StatusCodes.OK).json({review});
};

const updateReview = async (req, res) => {
  const {id: reviewId} = req.params;
  const {rating, title, comment} = req.body;

  const review = await Review.findOne({_id: reviewId});

  if (!review) {
    throw new CustomError.NotFoundError(`No review with id: ${reviewId}.`);
  }

  // Ensure the current user is either the review's original author or is an admin
  checkPermissions(req.user, review.user);

  // Save new review fields in the DB
  review.rating = rating;
  review.title = title;
  review.comment = comment;
  await review.save();

  res.status(StatusCodes.OK).json({review});
};

const deleteReview = async (req, res) => {
  const {id: reviewId} = req.params;

  const review = await Review.findOne({_id: reviewId});

  if (!review) {
    throw new CustomError.NotFoundError(`No review with id: ${reviewId}.`);
  }

  // Ensure the current user is either the review's original author or is an admin
  checkPermissions(req.user, review.user);

  // Delete the review from the DB
  await review.remove();

  res.status(StatusCodes.OK).json({msg: "Success! Review removed."});
};

const getSingleProductReviews = async (req, res) => {
  const {id: productId} = req.params;

  const reviews = await Review.find({product: productId});
  
  res.status(StatusCodes.OK).json({reviews, count: reviews.length});
};

module.exports = {
  createReview,
  getAllReviews,
  getSingleReview,
  updateReview,
  deleteReview,
  getSingleProductReviews
};
