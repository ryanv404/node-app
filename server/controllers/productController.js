const Product = require('../models/Product');
const {StatusCodes} = require('http-status-codes');
const CustomError = require('../errors');
const path = require('path');

const createProduct = async (req, res) => {
  // Include 'user: userId' in the req.body object and then create a new product
  req.body.user = req.user.userId;
  const product = await Product.create(req.body);

  res.status(StatusCodes.CREATED).json({product});
};

const getAllProducts = async (req, res) => {
  const products = await Product.find({});

  res.status(StatusCodes.OK).json({products, count: products.length});
};

const getSingleProduct = async (req, res) => {
  const {id: productId} = req.params;

  // Populate the Product.reviews field with the fields from the referenced Review document
  const product = await Product.findOne({_id: productId}).populate('reviews');

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id: ${productId}.`);
  }

  res.status(StatusCodes.OK).json({product});
};

const updateProduct = async (req, res) => {
  const {id: productId} = req.params;

  const product = await Product.findOneAndUpdate({_id: productId}, req.body, {
    new: true,
    runValidators: true
  });

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id: ${productId}.`);
  }

  res.status(StatusCodes.OK).json({product});
};

const deleteProduct = async (req, res) => {
  const {id: productId} = req.params;

  const product = await Product.findOne({_id: productId});

  if (!product) {
    throw new CustomError.NotFoundError(`No product with id: ${productId}.`);
  }

  await product.remove();

  res.status(StatusCodes.OK).json({msg: 'Success! Product removed.'});
};

const uploadImage = async (req, res) => {
  if (!req.files) {
    throw new CustomError.BadRequestError('No file uploaded.');
  }
  const productImage = req.files.image;

  if (!productImage.mimetype.startsWith('image')) {
    throw new CustomError.BadRequestError('Please upload an image.');
  }

  // Max image size of 1MB
  const maxSize = 1024 * 1024;
  if (productImage.size > maxSize) {
    throw new CustomError.BadRequestError('Please upload an image smaller than 1MB.');
  }

  const imagePath = path.join(__dirname, '../public/uploads/' + `${productImage.name}`);
  await productImage.mv(imagePath);
  
  res.status(StatusCodes.OK).json({image: `/uploads/${productImage.name}`});
};

module.exports = {
  createProduct,
  getAllProducts,
  getSingleProduct,
  updateProduct,
  deleteProduct,
  uploadImage
};
