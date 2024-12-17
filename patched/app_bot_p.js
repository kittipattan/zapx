const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const multer = require("multer");
const fs = require("fs");
const http = require("http");
const path = require("path");
const db = require("../db"); // Assuming db.js initializes and exports a MySQL connection pool

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // Serve static files
app.use(
  session({ secret: "very-secret-key", resave: true, saveUninitialized: true })
);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Base Routes
app.get("/", (req, res) => {
  res.send(`<h1>Hello World!</h1>
    <a href="/no-bot-defense-1"></a>
    <a href="/no-bot-defense-2"></a>
    <a href="/no-bot-defense-3"></a>
    <a href="/no-bot-defense-4">no-bot-defense-4</a>
  `);
});

// Secure Bot Defense 1
const captcha = require("express-recaptcha").RecaptchaV2;
const recaptcha = new captcha("SITE_KEY", "SECRET_KEY");

app.get("/no-bot-defense-1", recaptcha.middleware.render, (req, res) => {
  res.send(`
    <h1>Bot Defense with Captcha</h1>
    <form action="/validate-captcha" method="POST">
      <div>${res.recaptcha}</div>
      <button type="submit">Submit</button>
    </form>
  `);
});

// Secure Bot Defense 2
const rateLimit = require("express-rate-limit");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: "Too many requests from this IP, please try again later.",
});

app.get("/no-bot-defense-2", limiter, (req, res) => {
  res.send("<h1>Bot Defense with Rate Limiting</h1><p>Attackers, beware!</p>");
});

// Secure Bot Defense 3
app.get("/no-bot-defense-3", recaptcha.middleware.render, (req, res) => {
  res.send(`
    <h1>Bot Defense with Invisible Captcha</h1>
    <form action="/validate-invisible-captcha" method="POST">
      <button type="submit">Submit</button>
      ${res.recaptcha}
    </form>
  `);
});

// Secure Bot Defense 4
app.get("/no-bot-defense-4", (req, res) => {
  const referrer = req.headers["referer"];
  console.log(referrer);
  if (!referrer || referrer !== "http://localhost:3002/") {
    res.status(403).send("Access denied: Invalid referrer.");
    return;
  }
  res.send("<h1>Bot Defense with Referrer Validation</h1>");
});

// Start Server
app.listen(PORT, () => {
  console.log(`Running vulnerable server at http://localhost:${PORT}`);
  console.log("\n===========================================");
  console.log("              Available Endpoints");
  console.log("===========================================\n");

  // No Bot Defense
  console.log("Secure Bot Defense - Example of site with bot defenses:");
  console.log(`    - GET http://localhost:${PORT}/no-bot-defense-n\n`);
});
