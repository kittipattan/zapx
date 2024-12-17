const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "vulnerable_user",
  password: "password",
  database: "vulnerable_app",
});

const resetDatabase = async () => {
  const dropTables = `
    DROP TABLE IF EXISTS access_logs, messages, comments, users;
  `;

  const userTable = `
    CREATE TABLE users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      secret VARCHAR(255),
      role VARCHAR(50) NOT NULL DEFAULT 'user'
    );
  `;

  const commentsTable = `
    CREATE TABLE comments (
      id INT AUTO_INCREMENT PRIMARY KEY,
      content TEXT NOT NULL
    );
  `;

  const messagesTable = `
    CREATE TABLE messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      content TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `;

  const accessLogsTable = `
    CREATE TABLE access_logs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      action VARCHAR(255) NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `;

  const seedUsers = `
    INSERT INTO users (username, password, secret, role)
    VALUES
      ('admin', 'admin', 'admin-secret', 'admin'),
      ('user1', 'password1', 'secret1', 'user'),
      ('user2', 'password2', 'secret2', 'user'),
      ('user3', 'password3', 'secret3', 'user'),
      ('user4', 'password4', 'secret4', 'user'),
      ('user5', 'password5', 'secret5', 'user');
  `;

  const seedComments = `
    INSERT INTO comments (content)
    VALUES
      ('This is the first comment.'),
      ('Here is another comment for testing.'),
      ('Comments can be long or short.'),
      ('Final comment for testing.');
  `;

  const seedMessages = `
    INSERT INTO messages (user_id, content)
    VALUES
      (1, 'Hello, this is admin message.'),
      (2, 'User1 has sent this message.'),
      (3, 'Message from user2, hello there!'),
      (4, 'User3 just joined and sent this message.'),
      (5, 'Testing messages from user4.');
  `;

  const seedAccessLogs = `
    INSERT INTO access_logs (user_id, action)
    VALUES
      (1, 'Logged in as admin'),
      (2, 'User1 accessed a restricted page'),
      (3, 'User2 posted a comment'),
      (4, 'User3 viewed messages'),
      (5, 'User4 tried to access admin page');
  `;

  try {
    console.log("Resetting database...");

    await db.promise().query(dropTables);
    console.log("Dropped existing tables.");

    await db.promise().query(userTable);
    await db.promise().query(commentsTable);
    await db.promise().query(messagesTable);
    await db.promise().query(accessLogsTable);
    console.log("Created new tables.");

    await db.promise().query(seedUsers);
    await db.promise().query(seedComments);
    await db.promise().query(seedMessages);
    await db.promise().query(seedAccessLogs);
    console.log("Seeded initial data.");
  } catch (err) {
    console.error("Error resetting database:", err);
  }
};

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err.message);
    process.exit(1);
  }

  console.log("Connected to the MySQL database.");

  resetDatabase().then(() => {
    console.log("Database setup completed.");
  });
});

module.exports = db;


// const mysql = require("mysql2");

// const db = mysql.createConnection({
//   host: "localhost",
//   user: "vulnerable_user",
//   password: "password",
//   database: "vulnerable_app",
// });

// const userTable = `
//     CREATE TABLE IF NOT EXISTS users (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       username VARCHAR(255) NOT NULL,
//       password VARCHAR(255) NOT NULL,
//       secret VARCHAR(255)
//     );
//   `;

// const commentsTable = `
//     CREATE TABLE IF NOT EXISTS comments (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       user_id INT,
//       content TEXT
//     );
//   `;

// const messagesTable = `
//     CREATE TABLE IF NOT EXISTS messages (
//       id INT AUTO_INCREMENT PRIMARY KEY,
//       user_id INT,
//       content TEXT
//     );
//   `;

// db.connect((err) => {
//   if (err) {
//     console.error("Database connection failed:", err.message);
//     process.exit(1);
//   }

//   console.log("Connected to the MySQL database.");

//   const setup = async () => {
//     try {
//       await db.promise().query(userTable);
//       await db.promise().query(commentsTable);
//       await db.promise().query(messagesTable);

//       console.error("Set up the database successfully.");
//     } catch (err) {
//       console.error("Error setting up the database:", err);
//     }
//   };

//   setup();
// });

// module.exports = db;
