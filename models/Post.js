const mongoose = require("mongoose");

// Define the schema
const postSchema = new mongoose.Schema(
  {
    postTitle: {
      type: String,
      trim: true,
      minlength: [2, "Title is too short (min 2 characters)."],
      maxlength: [100, "Title is too long (max 100 characters)."],
      required: [true, "Title cannot be empty."],
    },
    postContent: {
      type: String,
      trim: true,
      minlength: [2, "Post body is too short (min 2 characters)."],
      maxlength: [200, "Post body is too long (max 200 characters)."],
      required: [true, "Post body cannot be empty."],
    },
    postOwner: {
      type: mongoose.Schema.ObjectId,
      ref: "User",
      required: [true, "Post owner cannot be empty."],
    },
  },
  {timestamps: true}
);

// Define mongoose model
const Post = mongoose.model("Post", postSchema);

module.exports = Post;
