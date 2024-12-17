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

// File upload setup
const upload = multer({ dest: "uploads/" });

// User authentication middleware
// function authenticate(req, res, next) {
//   if (req.session.user) {
//     return next();
//   }
//   res.redirect("/login");
// }

// Routes
app.get("/", (req, res) => {
  res.send(`<h1>Hello World!</h1>
    <a href="/xss-reflected?input="></a>
    <a href="/xss-stored"></a>
    <a href="/xss-dom?input="></a>
    <a href="/sqli?username="></a>
    <a href="/idor?userId="></a>
    <a href="/csrf"></a>
    <a href="/ssrf?url="></a>
    <a href="/client-storage"></a>
    <a href="/sensitive-info"></a>
    <a href="/no-bot-defense"></a>
  `);
});

// 1. XSS
// Reflected XSS
app.get("/xss-reflected", (req, res) => {
  const query = req.query.input || "";
  res.send(
    `<h1>Reflected XSS</h1><p>Input: ${query}</p><a href="/xss-reflected?input=">Try Again</a>`
  );
});

// Stored XSS with messages
app.get("/xss-stored", async (req, res) => {
  try {
    const [rows] = await db.promise().query("SELECT * FROM comments");
    const messages = rows.map((msg) => `<div>${msg.content}</div>`).join("");
    res.send(`
      <h1>Stored XSS</h1>
      <form method="POST" action="/xss-stored">
        <textarea name="message"></textarea><button type="submit">Submit</button>
      </form>
      <div>${messages}</div>
    `);
  } catch (err) {
    res.status(500).send("Database error!");
  }
});

app.post("/xss-stored", async (req, res) => {
  const { message } = req.body;

  // Vulnerable to XSS
  const query = `INSERT INTO comments (content) VALUES ('${message}')`;

  try {
    await db.promise().query(query);
    res.send("Comment saved!");
  } catch (err) {
    res.status(500).send("Database error!");
  }
});

// DOM-based XSS
app.get("/xss-dom", (req, res) => {
  res.send(`
    <h1>DOM-based XSS</h1>
    <script>
      const query = new URLSearchParams(window.location.search).get('input');
      if (query) {
        document.write("<p>" + query + "</p>");
      }
    </script>
  `);
});

// 2. SQL Injection
app.get("/sqli", async (req, res) => {
  const { username } = req.query;

  // SQL Injection Vulnerability: Directly concatenate user input
  const query = `SELECT * FROM users WHERE username = '${username}'`;

  try {
    const [rows] = await db.promise().query(query);
    res.send(rows);
  } catch (err) {
    res.status(500).send("Database error!");
  }
});

// 3. IDOR
app.get("/idor", async (req, res) => {
  const userId = req.query.userId;
  try {
    const [rows] = await db
      .promise()
      .query(`SELECT * FROM users WHERE id = ${userId}`);
    if (rows.length === 0) {
      return res.send("User not found.");
    }
    res.send(rows[0]);
  } catch (err) {
    res.status(500).send("Error");
  }
});

// 4. CSRF
app.get("/csrf", (req, res) => {
  res.send(`
    <h1>CSRF</h1>
    <form method="POST" action="/csrf-transfer">
      <input type="text" name="account" placeholder="Account Number">
      <input type="text" name="amount" placeholder="Amount">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Transfer</button>
    </form>
  `);
});

app.post("/csrf-transfer", (req, res) => {
  res.send("Transfer successful.");
});

// 5. SSRF
app.get("/ssrf", (req, res) => {
  const target = req.query.url;
  if (target) {
    try {
      http.get(target, (response) => {
        response.pipe(res);
      });
    } catch (error) {

    }
  } else {
    res.send("Provide a URL parameter.");
  }
});

// 6. Insecure Client-side Storage
app.get("/client-storage", (req, res) => {
  res.send(`
    <h1>Insecure Client-side Storage</h1>
    <script>
      localStorage.setItem("apiKey", "12345-secret-api-key");
      sessionStorage.setItem("password", "super-secret-password");
    </script>
  `);
});

// 7. Exposed Sensitive Information
app.get("/sensitive-info", (req, res) => {
  // res.send(`
  //   <h1>Exposed Sensitive Info</h1>
  //   <!-- TODO: Remove this before production -->
  //   <!-- API Key: 12345-secret-key -->
  //   <script>
  //     console.log("Admin password: admin123");
  //   </script>
  // `);
  res.send(`
    <h1>Exposed Sensitive Info</h1>
    <!-- TODO: Remove this before production -->
    <!-- API Key: 12345-secret-key -->
  `);
});

// 8. No Bot Defense
app.get("/no-bot-defense", (req, res) => {
  res.send("<h1>No bot defense here!</h1><p>Automated attacks welcome!</p>");
});

// Start Server
app.listen(PORT, () => {
  console.log(`Running vulnerable server at http://localhost:${PORT}`);
  console.log("\n===========================================");
  console.log("              Available Endpoints");
  console.log("===========================================\n");

  // XSS - Reflected
  console.log("1.1 XSS Reflected - Reflected XSS vulnerability example:");
  console.log(
    `   - GET http://localhost:${PORT}/xss-reflected?input=<user_input>\n`
  );

  // XSS - Stored
  console.log("1.2 XSS Stored - Stored XSS vulnerability example:");
  console.log(`   - GET http://localhost:${PORT}/xss-stored (View Comments)`);
  console.log(`   - POST http://localhost:${PORT}/xss-stored (Submit Comment)\n`);

  // DOM-based XSS
  console.log("1.3 DOM-based XSS - DOM-based XSS vulnerability example:");
  console.log(`   - GET http://localhost:${PORT}/xss-dom?input=<user_input>\n`);

  // SQL Injection
  console.log("2. SQL Injection - Basic SQL injection vulnerability example:");
  console.log(`   - GET http://localhost:${PORT}/sqli?username=<username>\n`);

  // IDOR (Insecure Direct Object Reference)
  console.log("3. IDOR - Example of Insecure Direct Object Reference:");
  console.log(`   - GET http://localhost:${PORT}/idor?userId=<user_id>\n`);

  // CSRF (Cross-Site Request Forgery)
  console.log("4. CSRF - Example of CSRF vulnerability:");
  console.log(`   - GET http://localhost:${PORT}/csrf (Form to transfer funds)`);
  console.log(
    `   - POST http://localhost:${PORT}/csrf-transfer (Perform Transfer)\n`
  );

  // SSRF (Server-Side Request Forgery)
  console.log("5. SSRF - Example of SSRF vulnerability:");
  console.log(`   - GET http://localhost:${PORT}/ssrf?url=<target_url>\n`);

  // Insecure Client-Side Storage
  console.log(
    "6. Insecure Client-Side Storage - Example of storing sensitive data in localStorage or sessionStorage:"
  );
  console.log(`   - GET http://localhost:${PORT}/client-storage\n`);

  // Exposed Sensitive Information
  console.log(
    "7. Exposed Sensitive Information - Example of exposed sensitive information:"
  );
  console.log(`    - GET http://localhost:${PORT}/sensitive-info\n`);

  // No Bot Defense
  console.log("8. No Bot Defense - Example of site without bot defenses:");
  console.log(`    - GET http://localhost:${PORT}/no-bot-defense\n`);
});

