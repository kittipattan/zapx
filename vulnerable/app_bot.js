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
    <a href="/no-bot-defense"></a>
  `);
});

// No Bot Defense
app.get("/no-bot-defense", (req, res) => {
  res.send("<h1>No bot defense here!</h1><p>Automated attacks welcome!</p>");
});

// Start Server
app.listen(PORT, () => {
  console.log(`Running vulnerable server at http://localhost:${PORT}`);
  console.log("\n===========================================");
  console.log("              Available Endpoints");
  console.log("===========================================\n");

  // No Bot Defense
  console.log("No Bot Defense - Example of site without bot defenses:");
  console.log(`    - GET http://localhost:${PORT}/no-bot-defense\n`);
});