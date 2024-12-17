const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const multer = require("multer");
const fs = require("fs");
const http = require("http");
const path = require("path");
const db = require("../db");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public")); // Serve static files
app.use(
  session({ secret: "very-secret-key", resave: true, saveUninitialized: true })
);
app.set("view engine", "ejs");
app.set("views", path.join("../views"));

// File upload setup
const upload = multer({ dest: "uploads/" });

// User authentication middleware
function authenticate(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

// Login and Register
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

  try {
    const [rows] = await db.promise().query(query, [username, password]);

    if (rows.length > 0) {
      // Save user info and role in session
      req.session.user = {
        id: rows[0].id,
        username: rows[0].username,
        role: rows[0].role,
      };
      res.redirect("/");
    } else {
      res.send("Invalid username or password");
    }
  } catch (err) {
    console.error("Error executing query:", err);
    res.status(500).send("Database error");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
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
app.get("/xss-stored", authenticate, async (req, res) => {
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

app.get("/sqli-advanced", async (req, res) => {
  const id = req.query.id || "0";

  const query = `SELECT id, username FROM users WHERE id = ${id}`;

  try {
    const [rows] = await db.promise().query(query);
    res.send(rows.length > 0 ? rows : "No users found.");
  } catch (err) {
    console.error(err);
    res.status(500).send("Error");
  }
});

// 3. IDOR
app.get("/idor", authenticate, async (req, res) => {
  const userId = req.query.userId || req.session.user.id;
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
app.get("/csrf", authenticate, (req, res) => {
  res.send(`
    <h1>Fund Transfer</h1>
    <form method="POST" action="/csrf-transfer">
      <label>Recipient:</label>
      <input type="text" name="recipient" value="user123"><br>
      <label>Amount:</label>
      <input type="text" name="amount" value="100"><br>
      <button type="submit">Transfer</button>
    </form>
  `);
});

app.post("/csrf-transfer", authenticate, (req, res) => {
  const { recipient, amount } = req.body;
  res.send(`
    <h1>Transfer Successful</h1>
    <p>${amount} has been transferred to ${recipient}.</p>
  `);
});

// 5. SSRF
app.get("/ssrf", (req, res) => {
  const target = req.query.url;
  if (target) {
    http.get(target, (response) => {
      response.pipe(res);
    });
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
      alert("API Key and Password stored in localStorage and sessionStorage");
    </script>
  `);
});

// 7. Exposed Sensitive Information
app.get("/sensitive-info", (req, res) => {
  res.send(`
    <h1>Exposed Sensitive Info</h1>
    <!-- TODO: Remove this before production -->
    <!-- API Key: 12345-secret-key -->
    <script>
      console.log("Admin password: admin123");
    </script>
  `);
});

// 8. No Bot Defense
app.get("/no-bot-defense", (req, res) => {
  res.send("<h1>No bot defense here!</h1><p>Automated attacks welcome!</p>");
});

// 9. Broken Access Control
app.get("/admin", authenticate, (req, res) => {
  // Simulated vulnerability: No role-based access control
  res.send(`
    <h1>Admin Dashboard</h1>
    <p>Welcome, ${req.session.user.username}!</p>
    <p>This page should be accessible only if you are admin.</p>
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="/logout">Logout</a></li>
    </ul>
  `);
});

// Start Server
app.listen(PORT, () => {
  console.log(`Running vulnerable server at http://localhost:${PORT}`);
  console.log("\n===========================================");
  console.log("              Available Endpoints");
  console.log("===========================================\n");

  // XSS - Reflected
  console.log("1. XSS Reflected - Reflected XSS vulnerability example:");
  console.log(
    "   - GET http://localhost:3000/xss-reflected?input=<user_input>\n"
  );

  // XSS - Stored
  console.log("2. XSS Stored - Stored XSS vulnerability example:");
  console.log("   - GET http://localhost:3000/xss-stored (View Comments)");
  console.log("   - POST http://localhost:3000/xss-stored (Submit Comment)\n");

  // DOM-based XSS
  console.log("3. DOM-based XSS - DOM-based XSS vulnerability example:");
  console.log("   - GET http://localhost:3000/xss-dom?input=<user_input>\n");

  // SQL Injection (Basic)
  console.log("4. SQL Injection - Basic SQL injection vulnerability example:");
  console.log("   - GET http://localhost:3000/sqli?username=<username>\n");

  // SQL Injection (Advanced)
  console.log(
    "5. SQL Injection Advanced - Advanced SQL injection vulnerability example:"
  );
  console.log("   - GET http://localhost:3000/sqli-advanced?id=<id>\n");

  // IDOR (Insecure Direct Object Reference)
  console.log("6. IDOR - Example of Insecure Direct Object Reference:");
  console.log("   - GET http://localhost:3000/idor?userId=<user_id>\n");

  // CSRF (Cross-Site Request Forgery)
  console.log("7. CSRF - Example of CSRF vulnerability:");
  console.log("   - GET http://localhost:3000/csrf (Form to transfer funds)");
  console.log(
    "   - POST http://localhost:3000/csrf-transfer (Perform Transfer)\n"
  );

  // SSRF (Server-Side Request Forgery)
  console.log("8. SSRF - Example of SSRF vulnerability:");
  console.log("   - GET http://localhost:3000/ssrf?url=<target_url>\n");

  // Insecure Client-Side Storage
  console.log(
    "9. Insecure Client-Side Storage - Example of storing sensitive data in localStorage or sessionStorage:"
  );
  console.log("   - GET http://localhost:3000/client-storage\n");

  // Exposed Sensitive Information
  console.log(
    "10. Exposed Sensitive Information - Example of exposed sensitive information:"
  );
  console.log("    - GET http://localhost:3000/sensitive-info\n");

  // No Bot Defense
  console.log("11. No Bot Defense - Example of site without bot defenses:");
  console.log("    - GET http://localhost:3000/no-bot-defense\n");

  // Login and Logout
  console.log("12. Login - Access the login page:");
  console.log("    - GET http://localhost:3000/login\n");
  console.log("13. Logout - Log out and destroy session:");
  console.log("    - GET http://localhost:3000/logout\n");
});
