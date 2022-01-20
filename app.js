require("dotenv").config();
require("express-async-errors");

const path = require("path");
const methodOverride = require("method-override");
const connectDB = require("./db/connect");
const MongoStore = require("connect-mongo");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const fileUpload = require("express-fileupload");
const rateLimiter = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss-clean");
const cors = require("cors");
const mongoSanitize = require("express-mongo-sanitize");

// Express
const express = require("express");
const app = express();

// Passport Config
const passport = require("passport");
require("./config/passport")(passport);

// Trust one reverse proxy for deployment
app.set("trust proxy", 1);
app.use(
  rateLimiter({
    // Limit each IP to a max of 60 requests per 15 minutes
    windowMs: 15 * 60 * 1000,
    max: 60,
  })
);

// EJS configuration
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Express body parsers
app.use(express.urlencoded({extended: false}));
app.use(express.json());

// Redirect POST request to DELETE or PUT with:
// "?_method=DELETE" or "?_method=PUT"
app.use(methodOverride("_method"));

// Middleware
if (process.env.NODE_ENV === "development") {
  // Load logger in dev mode only
  const logger = require("morgan");
  app.use(logger("dev"));
}
// Set content security policies
app.use(
  helmet({
    contentSecurityPolicy: require("./config/csp")
  })
);
app.use(cors());
// Sanitize data in req.body, req.query, and req.params
app.use(xss());
// Remove keys beginning with '$' to prevent query selector injection attacks
app.use(mongoSanitize());

app.use(cookieParser(process.env.JWT_SECRET));
app.use("/public", express.static(path.join(__dirname, "public")));

// Attach file objects from input fields onto req.files
app.use(fileUpload());

// Express session
app.use(
  session({
    name: "rv",
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
    }),
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Connect flash
const flash = require("connect-flash");
app.use(flash());

// Global variables
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  next();
});

// Routes
app.use("/", require("./routes/index.js"));
app.use("/users", require("./routes/users.js"));
app.use("/tasks", require("./routes/tasks.js"));
app.use("/posts", require("./routes/posts.js"));
app.use("/reviews", require("./routes/reviews.js"));

// Error handlers
app.use(require("./middleware/not-found"));
app.use(require("./middleware/error-handler"));

// Start server
const PORT = process.env.PORT || 3000;
const start_server = async () => {
  try {
    // Connect to MongoDB
    await connectDB(process.env.MONGO_URI);
    // Start server
    app.listen(PORT, () => console.log(`Server listening on port: ${PORT}.`));
  } catch (error) {
    console.log(error);
  }
};

start_server();

module.exports = app;
