const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");
const helmet = require("helmet"); // Helmet helps set secure HTTP headers
const db = require("../db"); // Assuming db.js initializes and exports a MySQL connection pool

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({ secret: "very-secret-key", resave: true, saveUninitialized: true })
);

// Security Headers using Helmet
app.use(
  helmet({
    xframeOptions: { action: 'deny' },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"], // Restrict content to the same origin
        scriptSrc: ["'self'"], // Allow scripts only from the same origin
        styleSrc: ["'self'", "https://fonts.googleapis.com"], // Allow styles from the same origin and Google Fonts
        imgSrc: ["'self'", "https://images.example.com"], // Allow images from the same origin and a trusted domain
        connectSrc: ["'self'"], // Restrict connections to the same origin
        objectSrc: ["'none'"], // Block embedding objects
        frameAncestors: ["'none'"], // Prevent clickjacking by disallowing framing
        upgradeInsecureRequests: [], // Enforce HTTPS for all requests
      },
    },
    frameguard: { action: "deny" }, // Prevent the site from being loaded in an iframe (anti-clickjacking)
  })
);

// Routes
app.get("/", (req, res) => {
  res.send(`<h1>Security Misconfiguration</h1>`);
});

// Start Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log("Security Misconfiguration: /");
});
