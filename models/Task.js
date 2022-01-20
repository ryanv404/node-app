const mongoose = require("mongoose");

// Define the schema
const taskSchema = new mongoose.Schema(
  {
    taskName: {
      type: String,
      trim: true,
      minlength: [2, "First name is too short."],
      maxlength: [100, "Task is too long (max 100 characters)."],
      required: [true, "Task cannot be empty."],
      unique: true,
    },
    taskOwner: {
      type: mongoose.Schema.ObjectId,
      ref: "User",
      required: [true, "Task owner must not be empty."],
    },
    taskStatus: {
      type: String,
      default: "brainstorming",
      required: [true, "Task status must not be empty."],
    },
    isCompleted: {
      type: Boolean,
      default: "false",
    },
  },
  {timestamps: true}
);

// Define mongoose model
const Task = mongoose.model("Task", taskSchema);

module.exports = Task;
