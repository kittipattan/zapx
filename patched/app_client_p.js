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
    <a href="/client-storage-1"></a>
    <a href="/client-storage-2"></a>
    <a href="/client-storage-3"></a>
    <a href="/client-storage-4"></a>
    <a href="/client-storage-5"></a>
    <a href="/client-storage-6"></a>
    <a href="/client-storage-7"></a>
    <a href="/client-storage-8"></a>
    <a href="/client-storage-9"></a>
    <a href="/client-storage-10"></a>
    <a href="/sensitive-info-1"></a>
    <a href="/sensitive-info-2"></a>
    <a href="/sensitive-info-3"></a>
    <a href="/sensitive-info-4"></a>
    <a href="/sensitive-info-5"></a>
    <a href="/sensitive-info-6"></a>
    <a href="/sensitive-info-7"></a>
    <a href="/sensitive-info-8"></a>
    <a href="/sensitive-info-9"></a>
    <a href="/sensitive-info-10"></a>
  `);
});

// Secure Client-side 1
app.get("/client-storage-1", (req, res) => {
  res.send(`
    <h1>Client-side Storage</h1>
    <script>
      console.log("No sensitive data is stored on the client side.");
    </script>
  `);
});

// Secure Client-side 2
app.get("/client-storage-2", (req, res) => {
  res.send(`
    <h1>Dynamic Client-side Storage</h1>
    <script>
      console.log("No sensitive information stored or processed.");
    </script>
  `);
});

// Secure Client-side 3
app.get("/client-storage-3", (req, res) => {
  res.send(`
    <h1>Secure Object Storage</h1>
    <script>
      console.log("No sensitive data stored in localStorage.");
    </script>
  `);
});

// Secure Client-side 4
app.get("/client-storage-4", (req, res) => {
  res.send(`
    <h1>Plain Text Storage</h1>
    <script>
      console.log("No sensitive data stored in localStorage.");
    </script>
  `);
});

// Secure Client-side 5
app.get("/client-storage-5", (req, res) => {
  res.send(`
    <h1>Session Storage</h1>
    <script>
      console.log("No sensitive session data stored.");
    </script>
  `);
});

// Secure Client-side 6
app.get("/client-storage-6", (req, res) => {
  res.send(`
    <h1>Hardcoded User Information</h1>
    <script>
      console.log("No sensitive data exposed.");
    </script>
  `);
});

// Secure Client-side 7
app.get("/client-storage-7", (req, res) => {
  res.send(`
    <h1>Base64 Encoded Data</h1>
    <script>
      console.log("No sensitive data processed or stored.");
    </script>
  `);
});

// Secure Client-side 8
app.get("/client-storage-8", (req, res) => {
  res.send(`
    <h1>Inline Credentials</h1>
    <script>
      console.log("No sensitive data stored in localStorage.");
    </script>
  `);
});

// Secure Client-side 9
app.get("/client-storage-9", (req, res) => {
  res.send(`
    <h1>Obfuscated Storage</h1>
    <script>
      console.log("No sensitive data obfuscated or stored.");
    </script>
  `);
});

// Secure Client-side 10
app.get("/client-storage-10", (req, res) => {
  res.send(`
    <h1>Session Storage</h1>
    <script>
      console.log("No sensitive session data stored.");
    </script>
  `);
});

// Secure Sensitive Info 1
app.get("/sensitive-info-1", (req, res) => {
  res.send(`
    <h1>Secure Info</h1>
    <script>
      console.log("Sensitive information is not exposed.");
    </script>
  `);
});

// Secure Sensitive Info 2
app.get("/sensitive-info-2", (req, res) => {
  res.send(`
    <h1>Secure Info</h1>
    <script>
      console.log("No sensitive data is exposed here.");
    </script>
  `);
});

// Secure Sensitive Info 3
app.get("/sensitive-info-3", (req, res) => {
  res.send(`
    <h1>Global Variables</h1>
    <script>
      console.log("No sensitive data stored in globals.");
    </script>
  `);
});

// Secure Sensitive Info 4
app.get("/sensitive-info-4", (req, res) => {
  res.send(`
    <h1>Hardcoded Credentials</h1>
    <script>
      console.log("No credentials are hardcoded.");
    </script>
  `);
});

// Secure Sensitive Info 5
app.get("/sensitive-info-5", (req, res) => {
  res.send(`
    <h1>Secure JWT Storage</h1>
    <script>
      console.log("No JWT tokens are stored client-side.");
    </script>
  `);
});

// Secure Sensitive Info 6
app.get("/sensitive-info-6", (req, res) => {
  res.send(`
    <h1>Payment Information</h1>
    <script>
      console.log("No payment information is exposed.");
    </script>
  `);
});

// Secure Sensitive Info 7
app.get("/sensitive-info-7", (req, res) => {
  res.send(`
    <h1>Analytics Key</h1>
    <script>
      console.log("No analytics keys are exposed.");
    </script>
  `);
});

// Secure Sensitive Info 8
app.get("/sensitive-info-8", (req, res) => {
  res.send(`
    <h1>Debug Info</h1>
    <script>
      console.log("Debug information does not contain sensitive data.");
    </script>
  `);
});

// Secure Sensitive Info 9
app.get("/sensitive-info-9", (req, res) => {
  res.send(`
    <h1>Private Key</h1>
    <script>
      console.log("No private keys are exposed.");
    </script>
  `);
});

// Secure Sensitive Info 10
app.get("/sensitive-info-10", (req, res) => {
  res.send(`
    <h1>Authentication Details</h1>
    <script>
      console.log("No sensitive authentication details are exposed.");
    </script>
  `);
});

// Start Server
app.listen(PORT, () => {
  console.log(`Running vulnerable server at http://localhost:${PORT}`);
  console.log("\n===========================================");
  console.log("              Available Endpoints");
  console.log("===========================================\n");

  // Insecure Client-Side Storage
  console.log("Secure Client-Side Storage :");
  console.log(`   - GET http://localhost:${PORT}/client-storage-n\n`);

  // Exposed Sensitive Information
  console.log("Not exposed Sensitive Information:");
  console.log(`   - GET http://localhost:${PORT}/sensitive-info-n\n`);
});