const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const http = require("http");
const path = require("path");
const db = require("../db"); // Assuming db.js initializes and exports a MySQL connection pool

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({ secret: "very-secret-key", resave: true, saveUninitialized: true })
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
