const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database("cheapdata.db");

// Users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT NOT NULL,
    password TEXT NOT NULL
  )
`);

// Add wallet balance to existing users table
try {
  db.exec(`
    ALTER TABLE users
    ADD COLUMN wallet_balance REAL NOT NULL DEFAULT 0
  `);
} catch (error) {
  // Column already exists
}

// Transactions table
db.exec(`
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    reference TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`);

app.use(express.json());

// Website
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../Index.html"));
});

// Test API
app.get("/api", (req, res) => {
  res.json({
    message: "Backend is working!",
    status: "success"
  });
});

// Get wallet balance
app.get("/api/wallet/:userId", (req, res) => {
  const userId = Number(req.params.userId);

  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({
      message: "Invalid user ID"
    });
  }

  const user = db
    .prepare(`
      SELECT id, name, wallet_balance
      FROM users
      WHERE id = ?
    `)
    .get(userId);

  if (!user) {
    return res.status(404).json({
      message: "User not found"
    });
  }

  res.json({
    status: "success",
    wallet: {
      userId: user.id,
      name: user.name,
      balance: user.wallet_balance
    }
  });
});

// Get transaction history
app.get("/api/transactions/:userId", (req, res) => {
  const userId = Number(req.params.userId);

  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(400).json({
      message: "Invalid user ID"
    });
  }

  const transactions = db
    .prepare(`
      SELECT id, type, amount, status, reference, created_at
      FROM transactions
      WHERE user_id = ?
      ORDER BY id DESC
    `)
    .all(userId);

  res.json({
    status: "success",
    transactions
  });
});
// Process data order
app.post("/api/order", (req, res) => {
  const { network, bundle, price, phone } = req.body;

  if (!network || !bundle || !price || !phone) {
    return res.status(400).json({
      status: "error",
      message: "Missing order details"
    });
  }

  if (!/^[0-9]{11}$/.test(phone)) {
    return res.status(400).json({
      status: "error",
      message: "Invalid phone number"
    });
  }

  console.log("New order:", {
    network,
    bundle,
    price,
    phone
  });

  res.json({
    status: "success",
    message: "Your order has been received successfully!"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});

