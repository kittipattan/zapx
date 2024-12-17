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
  session({
    secret: "very-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, sameSite: "strict" }, // Use secure: true in production with HTTPS
  })
);
app.set("view engine", "ejs");
app.set("views", path.join("../views"));

// File upload setup
const upload = multer({ dest: "uploads/" });

// Middleware to authenticate user
function authenticate(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect("/login");
}

// Middleware to enforce role-based access control
function enforceRole(requiredRole) {
  return async (req, res, next) => {
    try {
      const [rows] = await db
        .promise()
        .query("SELECT role FROM users WHERE id = ?", [req.session.user.id]);
      if (rows.length > 0 && rows[0].role === requiredRole) {
        return next();
      }
      res.status(403).send("Forbidden: You do not have access to this resource.");
    } catch (err) {
      console.error("Error verifying role:", err);
      res.status(500).send("Server error");
    }
  };
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

  // Should store hashed password instead
  // This is for simplicity during experiment and evaluation only
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
    res.status(500).send("Something went wrong. Please try again.");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

const escapeHTML = (str) =>
  str.replace(/[&<>"'/]/g, (match) => {
    const escapeMap = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#x27;",
      "/": "&#x2F;",
    };
    return escapeMap[match];
  });

// 1. XSS
// Reflected XSS
app.get("/xss-reflected", (req, res) => {
  const query = req.query.input || "";
  res.send(
    `<h1>Reflected XSS</h1><p>Input: ${escapeHTML(
      query
    )}</p><a href="/xss-reflected?input=">Try Again</a>`
  );
});

// Stored XSS with messages
const sanitize = require("sanitize-html");

app.post("/xss-stored", async (req, res) => {
  const { message } = req.body;
  const sanitizedMessage = sanitize(message);
  const query = `INSERT INTO comments (content) VALUES (?)`;

  try {
    await db.promise().query(query, [sanitizedMessage]);
    res.send("Comment saved!");
  } catch (err) {
    res.status(500).send("Something went wrong. Please try again.");
  }
});

app.get("/xss-stored", async (req, res) => {
  try {
    const [rows] = await db.promise().query("SELECT * FROM comments");
    const messages = rows
      .map((msg) => `<div>${escapeHTML(msg.content)}</div>`)
      .join("");
    res.send(`
      <h1>Stored XSS</h1>
      <form method="POST" action="/xss-stored">
        <textarea name="message"></textarea><button type="submit">Submit</button>
      </form>
      <div>${messages}</div>
    `);
  } catch (err) {
    res.status(500).send("Something went wrong. Please try again.");
  }
});

// DOM-based XSS
app.get("/xss-dom", (req, res) => {
  res.send(`
    <h1>DOM-based XSS</h1>
    <script>
      const query = new URLSearchParams(window.location.search).get('input');
      if (query) {
        const safeOutput = document.createElement("p");
        safeOutput.textContent = query;
        document.body.appendChild(safeOutput);
      }
    </script>
  `);
});

// 2. SQL Injection
app.get("/sqli", async (req, res) => {
  const { username } = req.query;
  const query = "SELECT * FROM users WHERE username = ?";

  try {
    const [rows] = await db.promise().query(query, [username]);
    res.send(rows);
  } catch (err) {
    res.status(500).send("Something went wrong. Please try again.");
  }
});

// 3. IDOR
app.get("/idor", authenticate, async (req, res) => {
  const authenticatedUserId = req.session.user.id;

  try {
    const [rows] = await db
      .promise()
      .query("SELECT secret FROM users WHERE id = ?", [authenticatedUserId]);
    if (rows.length === 0) {
      return res.send("User not found.");
    }
    res.send(rows[0]);
  } catch (err) {
    res.status(500).send("Something went wrong. Please try again.");
  }
});

// 4. CSRF
// const csrf = require("csurf");
// const csrfProtection = csrf({ cookie: true });

// app.get("/csrf", csrfProtection, (req, res) => {
//   res.send(`
//     <h1>CSRF</h1>
//     <form method="POST" action="/csrf-transfer">
//       <input type="hidden" name="_csrf" value="${req.csrfToken()}">
//       <input type="text" name="amount" placeholder="Amount">
//       <button type="submit">Transfer</button>
//     </form>
//   `);
// });

// app.post("/csrf-transfer", csrfProtection, (req, res) => {
//   res.send("Transfer successful.");
// });

// 5. SSRF
app.get("/ssrf", (req, res) => {
  const target = req.query.url;

  if (
    !/^https?:\/\/(trusted\.domain\.com|another\.safe\.domain)/.test(target)
  ) {
    return res.status(400).send("Invalid URL");
  }

  http.get(target, (response) => {
    response.pipe(res);
  });
});

// 6. Insecure Client-side Storage
app.get("/client-storage", (req, res) => {
  res.send(`<h1>Secure Client-side Storage</h1>`);
});

// 7. Exposed Sensitive Information
app.get("/sensitive-info", (req, res) => {
  res.send(`<h1>Exposed Sensitive Info</h1>`);
});

// 8. No Bot Defense
const rateLimit = require("express-rate-limit");
const { strict } = require("assert");

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});

app.use("/no-bot-defense", limiter);

app.get("/no-bot-defense", (req, res) => {
  res.send("<h1>Bot defense implemented!</h1>");
});

// 9. Broken Access Control
app.get(
  "/admin",
  authenticate,
  enforceRole("admin"),
  (req, res) => {
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
  }
);

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
  console.log(
    `   - POST http://localhost:${PORT}/xss-stored (Submit Comment)\n`
  );

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
  console.log(
    `   - GET http://localhost:${PORT}/csrf (Form to transfer funds)`
  );
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
