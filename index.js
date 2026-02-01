require("dotenv").config();
const path = require("path");
const bcrypt = require("bcrypt");

const express = require("express");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const mysql = require("mysql2/promise");

const app = express();
const PORT = process.env.PORT || 3000;
const crypto = require("crypto");
const { encrypt, decrypt } = require("./utils/encrypt");


/* =======================
   MIDDLEWARE
======================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set("view engine", "ejs");
app.use(express.static("public"));
app.set("views", path.join(__dirname, "views"));

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* =======================
   DATABASE
======================= */
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});


(async () => {
  try {
    const conn = await pool.getConnection();
    console.log("✅ Connected to MySQL database");
    conn.release();
  } catch (err) {
    console.error("❌ MySQL connection failed:", err.message);
    process.exit(1);
  }
})();

/* =======================
   SESSION
======================= */
const sessionStore = new MySQLStore({}, pool);

app.use(
  session({
    name: "evault_session",
    secret: process.env.SESSION_SECRET || "supersecretkey",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

/* =======================
   AUTH MIDDLEWARE
======================= */
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

/* =======================
   ROUTES
======================= */

// Home
app.get("/", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  res.render("home");
});

function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

app.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  const [users] = await pool.query(
    "SELECT * FROM users WHERE email = ?",
    [email]
  );

  if (users.length === 0) {
    return res.send("Email not registered");
  }

  const otp = generateOTP();
  const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  await pool.query(
    "UPDATE users SET reset_otp=?, reset_otp_expiry=? WHERE email=?",
    [otp, expiry, email]
  );

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "E-Vaulto Password Reset OTP",
    text: `Your OTP is ${otp}. Valid for 10 minutes.`
  });

  res.redirect("/verify-otp?email=" + email);
});

app.get("/verify-otp", (req, res) => {
  res.render("verify-otp", { email: req.query.email });
});

app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  const [users] = await pool.query(
    "SELECT * FROM users WHERE email=? AND reset_otp=? AND reset_otp_expiry > NOW()",
    [email, otp]
  );

  if (users.length === 0) {
    return res.send("Invalid or expired OTP");
  }

  res.redirect("/reset-password?email=" + email);
});

app.get("/reset-password", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.redirect("/forgot-password");
  }

  res.render("reset-password", { email });
});


app.post("/reset-password", async (req, res) => {
  const { email, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);

  await pool.query(
    `UPDATE users 
     SET password_hash=?, reset_otp=NULL, reset_otp_expiry=NULL 
     WHERE email=?`,
    [hashed, email]
  );

  res.redirect("/login");
});


// Signup
app.get("/signup", (req, res) => {
  res.render("signup", { error: null });
});

app.post("/signup", async (req, res) => {
  const { first_name, last_name, username, email, gender, age, password } = req.body;

  if (!first_name || !last_name || !username || !email || !gender || !age || !password) {
    return res.render("signup", { error: "All fields are required" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO users 
      (first_name, last_name, username, email, gender, age, password_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [first_name, last_name, username, email, gender, age, hashedPassword]
    );

    res.redirect("/login");
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.render("signup", { error: "Username or email already exists" });
    }
    res.render("signup", { error: "Database error" });
  }
});

// Login
app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.render("login", { error: "All fields required" });
  }

  const q = identifier.includes("@")
    ? "SELECT * FROM users WHERE email = ?"
    : "SELECT * FROM users WHERE username = ?";

  const [rows] = await pool.query(q, [identifier]);

  if (rows.length === 0) {
    return res.render("login", { error: "User not found" });
  }

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);

  if (!match) {
    return res.render("login", { error: "Incorrect password" });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name
  };

  res.redirect("/dashboard");
});

// Dashboard
app.get("/dashboard", requireLogin, (req, res) => {
  res.render("dashboard", { user: req.session.user });
});

// Profile edit
app.get("/profile/edit", requireLogin, (req, res) => {
  res.render("edit-profile", { user: req.session.user, error: null });
});

app.post("/profile/edit", requireLogin, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.render("edit-profile", { user: req.session.user, error: "Username required" });
  }

  try {
    await pool.query("UPDATE users SET username = ? WHERE id = ?", [
      username,
      req.session.user.id
    ]);

    req.session.user.username = username;
    res.redirect("/dashboard");
  } catch (err) {
    res.render("edit-profile", { user: req.session.user, error: "Username already taken" });
  }
});

// Delete account
app.get("/account/delete", requireLogin, (req, res) => {
  res.render("delete-account");
});

app.post("/account/delete", requireLogin, async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.render("delete-account", {
      error: "Password is required"
    });
  }

  const userId = req.session.user.id;

  const [rows] = await pool.query(
    "SELECT password_hash FROM users WHERE id = ?",
    [userId]
  );

  if (rows.length === 0) {
    return res.redirect("/login");
  }

  const match = await bcrypt.compare(password, rows[0].password_hash);

  if (!match) {
    return res.render("delete-account", {
      error: "Incorrect password"
    });
  }

  // ✅ Password correct → delete account
  await pool.query("DELETE FROM users WHERE id = ?", [userId]);

  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/passwords", requireLogin, async (req, res) => {
  const userId = req.session.user.id;

  const [rows] = await pool.query(
    "SELECT * FROM passwords WHERE user_id = ?",
    [userId]
  );

  const passwords = rows.map(p => ({
    ...p,
    password: decrypt(p.password_encrypted)
  }));

  res.render("passwords", { passwords });
});

app.post("/passwords/add", requireLogin, async (req, res) => {
  const { site_name, login_identifier, password } = req.body;
  const userId = req.session.user.id;

  const encryptedPassword = encrypt(password);

  await pool.query(
    `INSERT INTO passwords 
     (user_id, site_name, login_identifier, password_encrypted)
     VALUES (?, ?, ?, ?)`,
    [userId, site_name, login_identifier, encryptedPassword]
  );

  res.redirect("/passwords");
});

app.get("/passwords/delete/:id", requireLogin, async (req, res) => {
  const userId = req.session.user.id;

  await pool.query(
    "DELETE FROM passwords WHERE id = ? AND user_id = ?",
    [req.params.id, userId]
  );

  res.redirect("/passwords");
});
;

// Vault sections

// =======================
// GAMES VAULT
// =======================

app.get("/games", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;

    const [games] = await pool.query(
      "SELECT * FROM games WHERE user_id = ? ORDER BY created_at DESC",
      [userId]
    );

    res.render("games", { games });
  } catch (err) {
    console.error(err);
    res.redirect("/");
  }
});

app.post("/games/add", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { gameName, launcher, gameId, gamePassword } = req.body;

    await pool.query(
      `INSERT INTO games 
       (user_id, game_name, launcher, game_id, game_password)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, gameName, launcher, gameId, gamePassword]
    );

    res.redirect("/games");
  } catch (err) {
    console.error(err);
    res.redirect("/games");
  }
});

app.post("/games/delete/:id", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const gameId = req.params.id;

    await pool.query(
      "DELETE FROM games WHERE id = ? AND user_id = ?",
      [gameId, userId]
    );

    res.redirect("/games");
  } catch (err) {
    console.error(err);
    res.redirect("/games");
  }
});


// =======================
// EXPENSES (E-VAULTO)
// =======================
 
app.get("/expenses", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;

    /* Expense List */
    const [expenses] = await pool.query(
      `
      SELECT * FROM ev_expenses
      WHERE user_id = ?
      ORDER BY expense_date DESC
      `,
      [userId]
    );

    /* Monthly Spending (Money vs Months) — excludes savings */
    const [monthlyData] = await pool.query(
      `
      SELECT 
        MONTH(expense_date) AS month,
        SUM(amount) AS total
      FROM ev_expenses
      WHERE user_id = ?
        AND YEAR(expense_date) = YEAR(CURDATE())
        AND category NOT IN ('Savings', 'Saving')
      GROUP BY MONTH(expense_date)
      ORDER BY MONTH(expense_date)
      `,
      [userId]
    );

    /* Pie Chart Data — excludes savings */
    const [pieData] = await pool.query(
      `
      SELECT category, SUM(amount) AS total
      FROM ev_expenses
      WHERE user_id = ?
        AND category NOT IN ('Savings', 'Saving')
      GROUP BY category
      `,
      [userId]
    );

    /* Savings Box */
    const [[savingsBox]] = await pool.query(
      `
      SELECT IFNULL(SUM(amount), 0) AS total
      FROM ev_expenses
      WHERE user_id = ?
        AND category IN ('Savings', 'Saving')
      `,
      [userId]
    );

    res.render("ev-expenses", {
      expenses,
      monthlyData,
      pieData,
      savingsTotal: savingsBox.total
    });

  } catch (err) {
    console.error(err);
    res.redirect("/dashboard");
  }
});

/* ➕ Add Expense (auto-detects today) */
app.post("/expenses/add", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { title, amount, category } = req.body;

    await pool.query(
      `
      INSERT INTO ev_expenses
      (user_id, title, amount, category, expense_date)
      VALUES (?, ?, ?, ?, CURDATE())
      `,
      [userId, title, amount, category]
    );

    res.redirect("/expenses");
  } catch (err) {
    console.error(err);
    res.redirect("/expenses");
  }
});

/* ❌ Delete Expense */
app.post("/expenses/delete/:id", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const expenseId = req.params.id;

    await pool.query(
      `
      DELETE FROM ev_expenses
      WHERE id = ? AND user_id = ?
      `,
      [expenseId, userId]
    );

    res.redirect("/expenses");
  } catch (err) {
    console.error(err);
    res.redirect("/expenses");
  }
});


// =======================
// NOTES (E-VAULTO)
// =======================

// View notes
app.get("/notes", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;

    const [notes] = await pool.query(
      `
      SELECT * FROM ev_notes
      WHERE user_id = ?
      ORDER BY created_at DESC
      `,
      [userId]
    );

    res.render("ev-notes", { notes });
  } catch (err) {
    console.error(err);
    res.redirect("/dashboard");
  }
});

// Add note
app.post("/notes/add", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { title, content } = req.body;

    await pool.query(
      `
      INSERT INTO ev_notes (user_id, title, content)
      VALUES (?, ?, ?)
      `,
      [userId, title, content]
    );

    res.redirect("/notes");
  } catch (err) {
    console.error(err);
    res.redirect("/notes");
  }
});

// Delete note
app.post("/notes/delete/:id", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const noteId = req.params.id;

    await pool.query(
      `
      DELETE FROM ev_notes
      WHERE id = ? AND user_id = ?
      `,
      [noteId, userId]
    );

    res.redirect("/notes");
  } catch (err) {
    console.error(err);
    res.redirect("/notes");
  }
});

// Update note
app.post("/notes/edit/:id", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const noteId = req.params.id;
    const { title, content } = req.body;

    await pool.query(
      `
      UPDATE ev_notes
      SET title = ?, content = ?
      WHERE id = ? AND user_id = ?
      `,
      [title, content, noteId, userId]
    );

    res.redirect("/notes");
  } catch (err) {
    console.error(err);
    res.redirect("/notes");
  }
});

/* =======================
   START SERVER
======================= */
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
