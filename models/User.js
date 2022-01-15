const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");

// Define the user schema
const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      lowercase: true,
      trim: true,
      minlength: [2, "First name is too short (min 2 characters)."],
      maxlength: [25, "First name is too long (max 25 characters)."],
      required: [true, "First name cannot be empty."],
    },
    lastName: {
      type: String,
      lowercase: true,
      trim: true,
      minlength: [2, "Last name is too short (min 2 characters)."],
      maxlength: [25, "Last name is too long (max 25 characters)."],
      required: [true, "Last name cannot be empty."],
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
      unique: true,
      required: [true, "Email cannot be empty."],
      validate: {
        validator: validator.isEmail,
        message: "Please provide a valid email.",
      },
    },
    username: {
      type: String,
      lowercase: true,
      trim: true,
      unique: true,
      required: [true, "Username cannot be empty."],
    },
    password: {
      type: String,
      required: [true, "Password cannot be empty."],
      minlength: 6,
    },
    role: {
      type: String,
      enum: ["admin", "user"],
      default: "user",
    },
    verificationToken: String,
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationDate: Date,
    passwordToken: String,
    passwordTokenExpirationDate: Date,
  }, {timestamps: true}
);

// Hash password prior to save
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Define password comparison method
userSchema.methods.comparePassword = async function (candidatePassword) {
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  return isMatch;
};

module.exports = mongoose.model("User", userSchema);
