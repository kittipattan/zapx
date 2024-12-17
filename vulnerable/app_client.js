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

// Insecure Client-side 1
app.get("/client-storage-1", (req, res) => {
  res.send(`
    <h1>Insecure Client-side Storage</h1>
    <script>
      localStorage.setItem("apiKey", "12345-secret-api-key");
      sessionStorage.setItem("password", "super-secret-password");
    </script>
  `);
});

// Insecure Client-side 2
app.get("/client-storage-2", (req, res) => {
  res.send(`
    <h1>Dynamic Client-side Storage</h1>
    <script>
      const partial1 = "12345"; 
      const partial2 = "-secret-api-key";
      const apiKey = partial1 + partial2;
      localStorage.setItem("config", apiKey);

      const passPart1 = "super-";
      const passPart2 = "secret-password";
      const password = passPart1 + passPart2;
      sessionStorage.setItem("auth", password);
    </script>
  `);
});

// Insecure Client-side 3
app.get("/client-storage-3", (req, res) => {
  res.send(`
    <h1>Insecure Object Storage</h1>
    <script>
      const userData = {
        apiKey: "12345-secret-api-key",
        sessionToken: "session-secret-token",
        password: "super-secret-password"
      };

      localStorage.setItem("userData", JSON.stringify(userData));
    </script>
  `);
});

// Insecure Client-side 4
app.get("/client-storage-4", (req, res) => {
  res.send(`
    <h1>Plain Text API Key</h1>
    <script>
      localStorage.setItem("plainTextApiKey", "67890-another-secret-key");
    </script>
  `);
});

// Insecure Client-side 5
app.get("/client-storage-5", (req, res) => {
  res.send(`
    <h1>Session Storage with Sensitive Data</h1>
    <script>
      sessionStorage.setItem("userToken", "user-secret-token");
    </script>
  `);
});

// Insecure Client-side 6
app.get("/client-storage-6", (req, res) => {
  res.send(`
    <h1>Hardcoded User Information</h1>
    <script>
      const userInfo = {
        username: "admin",
        password: "admin-password",
        apiKey: "admin-api-key"
      };
      localStorage.setItem("userInfo", JSON.stringify(userInfo));
    </script>
  `);
});

// Medium-to-detect Client-side 7
app.get("/client-storage-7", (req, res) => {
  res.send(`
    <h1>Base64 Encoded Key</h1>
    <script>
      const encodedKey = btoa("encoded-secret-key");
      localStorage.setItem("encodedApiKey", encodedKey);
    </script>
  `);
});

// Insecure Client-side 8
app.get("/client-storage-8", (req, res) => {
  res.send(`
    <h1>Inline Credentials</h1>
    <script>
      const credentials = "username:admin;password:admin123";
      localStorage.setItem("credentials", credentials);
    </script>
  `);
});

// Medium-to-detect Client-side 9
app.get("/client-storage-9", (req, res) => {
  res.send(`
    <h1>Reversible Obfuscation</h1>
    <script>
      const key = "obf123".split("").reverse().join("") + "-key";
      localStorage.setItem("obfuscatedKey", key);
    </script>
  `);
});

// Insecure Client-side 10
app.get("/client-storage-10", (req, res) => {
  res.send(`
    <h1>Unencrypted Session Storage</h1>
    <script>
      sessionStorage.setItem("sessionId", "abc123-unsecured-session-id");
    </script>
  `);
});

// Sensitive Information 1
app.get("/sensitive-info-1", (req, res) => {
  res.send(`
    <h1>Exposed Sensitive Info</h1>
    <!-- TODO: Remove this before production -->
    <!-- API Key: 12345-secret-key -->
    <script>
      console.log("Admin password: admin123");
    </script>
  `);
});

// Sensitive Information 2
app.get("/sensitive-info-2", (req, res) => {
  res.send(`
    <h1>Exposed Sensitive Info</h1>
    <script>
      // Database Credentials: user=root, pass=super-secret-password
      // API Endpoint: https://api.example.com/secret
      console.log("Sensitive API endpoint: https://api.example.com");
    </script>
  `);
});

// Sensitive Information 3
app.get("/sensitive-info-3", (req, res) => {
  res.send(`
    <h1>Exposed Sensitive Info in Globals</h1>
    <script>
      // Configuration stored in global variable
      window.config = {
        apiKey: "12345-super-secret-api-key",
        adminPassword: "admin123",
      };
      console.log(window.config.apiKey);
    </script>
  `);
});

// Sensitive Information 4
app.get("/sensitive-info-4", (req, res) => {
  res.send(`
    <h1>Exposed Hardcoded Credentials</h1>
    <script>
      const credentials = {
        username: "admin",
        password: "password123",
      };
      console.log("Credentials:", credentials);
    </script>
  `);
});

// Sensitive Information 5
app.get("/sensitive-info-5", (req, res) => {
  res.send(`
    <h1>Exposed JWT Token</h1>
    <script>
      const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.12345.super-secret-signature";
      localStorage.setItem("jwt", jwtToken);
    </script>
  `);
});

// Sensitive Information 6
app.get("/sensitive-info-6", (req, res) => {
  res.send(`
    <h1>Exposed Payment Information</h1>
    <script>
      const paymentDetails = {
        cardNumber: "4111111111111111",
        expiry: "12/25",
        cvv: "123",
      };
      localStorage.setItem("paymentDetails", JSON.stringify(paymentDetails));
    </script>
  `);
});

// Sensitive Information 7
app.get("/sensitive-info-7", (req, res) => {
  res.send(`
    <h1>Exposed Analytics Key</h1>
    <!-- TODO: Remove this in production -->
    <!-- Analytics Key: UA-123456-78 -->
    <script>
      localStorage.setItem("analyticsKey", "UA-123456-78");
      console.log("Analytics Key:", localStorage.getItem("analyticsKey"));
    </script>
  `);
});

// Sensitive Information 8
app.get("/sensitive-info-8", (req, res) => {
  res.send(`
    <h1>Debugging Info in Comments</h1>
    <!-- Debug Info -->
    <!-- User Email: user@example.com -->
    <!-- Secret Key: abcdefgh123456 -->
    <script>
      console.log("Debug mode enabled");
    </script>
  `);
});

// Sensitive Information 9
app.get("/sensitive-info-9", (req, res) => {
  res.send(`
    <h1>Exposed Private Key</h1>
    <script>
      const privateKey = "-----BEGIN PRIVATE KEY-----\\nMIICdwIBADANBg...\\n-----END PRIVATE KEY-----";
      console.log(privateKey);
    </script>
  `);
});

// Sensitive Information 10
app.get("/sensitive-info-10", (req, res) => {
  res.send(`
    <h1>Exposed Authentication Details</h1>
    <script>
      const authDetails = {
        token: "Bearer abc123-super-secret-token",
        refreshToken: "refresh123456",
      };
      sessionStorage.setItem("authDetails", JSON.stringify(authDetails));
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
  console.log(
    "Insecure Client-Side Storage - Example of storing sensitive data in localStorage or sessionStorage:"
  );
  console.log(`   - GET http://localhost:${PORT}/client-storage-n\n`);

  // Exposed Sensitive Information
  console.log(
    "Exposed Sensitive Information - Example of exposed sensitive information:"
  );
  console.log(`   - GET http://localhost:${PORT}/sensitive-info-n\n`);
});
