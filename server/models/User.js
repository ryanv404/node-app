const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");

const UserSchema = new mongoose.Schema(
  {
    first_name: {
      type: String,
      maxlength: 50,
      default: null,
    },
    last_name: {
      type: String,
      maxlength: 50,
      default: null,
    },
    email: {
      type: String,
      unique: true,
      required: [true, "Please provide an email."],
      validate: {
        validator: validator.isEmail,
        message: "Please provide a valid email.",
      },
    },
    password: {
      type: String,
      required: [true, "Please provide a password."],
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
    verifiedOn: Date,
    passwordToken: {
      type: String,
    },
    passwordTokenExpirationDate: {
      type: Date,
    },
  },
  {timestamps: true}
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = async function (canditatePassword) {
  const isMatch = await bcrypt.compare(canditatePassword, this.password);
  return isMatch;
};

module.exports = mongoose.model("User", UserSchema);
