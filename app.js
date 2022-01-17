require("dotenv").config();

const path = require("path");
const methodOverride = require("method-override");
const favicon = require("serve-favicon");
const connectDB = require("./db/connect");
const MongoStore = require("connect-mongo");
const session = require("express-session");

const express = require("express");
const app = express();

// Passport Config
const passport = require("passport");
require('./config/passport')(passport);

// Connect to MongoDB
connectDB(process.env.MONGO_URI)
  .then(() => console.log("Connected to database!"))
  .catch(err => console.log(err));

// EJS configuration
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Express body parser
app.use(express.urlencoded({extended: false}));
app.use(express.json());

// Redirect POST request to DELETE or PUT with:
// "?_method=DELETE" or "?_method=PUT"
app.use(methodOverride('_method'));

// Middleware
if (process.env.NODE_ENV === "development") {
  const logger = require("morgan");
  app.use(logger("dev"));
}
app.use(express.static(path.join(__dirname, "public")));

// Express session
app.use(
  session({
    name: "AppInProgress",
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions"
    })
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
  res.locals.success_msg = req.flash('success_msg');
  res.locals.error_msg = req.flash('error_msg');
  res.locals.error = req.flash('error');
  next();
});

// Routes
app.use('/', require('./routes/index.js'));
app.use('/users', require('./routes/users.js'));
app.use('/tasks', require('./routes/tasks.js'));
app.use('/posts', require('./routes/posts.js'));
app.use("/reviews", require("./routes/reviews.js"));

// Error handlers
app.use(require("./middleware/error-handler"));
app.use(require("./middleware/not-found"));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on http://localhost:${PORT}`));

module.exports = app;