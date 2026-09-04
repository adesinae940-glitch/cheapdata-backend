const express = require("express");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const axios = require("axios");
const app = express();

app.use(express.json());

const dbPath = path.join(__dirname, "cheapdata.db");

let db;

async function startServer() {
  const SQL = await initSqlJs();

  // Load existing database
  if (fs.existsSync(dbPath)) {
    const file = fs.readFileSync(dbPath);
    db = new SQL.Database(file);
  } else {
    db = new SQL.Database();
  }

  // =========================
  // USERS TABLE
  // =========================

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      password TEXT NOT NULL,
      wallet_balance REAL NOT NULL DEFAULT 0
    )
  `);

  // Add wallet column to an existing users table
  try {
    db.run(`
      ALTER TABLE users
      ADD COLUMN wallet_balance REAL NOT NULL DEFAULT 0
    `);
  } catch (error) {
    // Column already exists
  }

  // =========================
  // ORDERS TABLE
  // =========================

  db.run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      network TEXT NOT NULL,
      data TEXT NOT NULL,
      price INTEGER NOT NULL,
      phone TEXT NOT NULL,
      status TEXT DEFAULT "pending",
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // =========================
  // WALLET TRANSACTIONS TABLE
  // =========================

  db.run(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      amount REAL NOT NULL,
      status TEXT NOT NULL,
      reference TEXT UNIQUE NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // Save database
  fs.writeFileSync(
    dbPath,
    Buffer.from(db.export())
  );

  // =========================
  // SIGN UP
  // =========================

  app.post("/api/signup", async (req, res) => {
    try {
      const { name, email, phone, password } = req.body;

      if (!name || !email || !phone || !password) {
        return res.status(400).json({
          message: "All fields are required"
        });
      }

      const existing = db.exec(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );

      if (existing.length > 0 && existing[0].values.length > 0) {
        return res.status(409).json({
          message: "Email already registered"
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      db.run(
        `INSERT INTO users
        (name, email, phone, password, wallet_balance)
        VALUES (?, ?, ?, ?, 0)`,
        [name, email, phone, hashedPassword]
      );

      fs.writeFileSync(
        dbPath,
        Buffer.from(db.export())
      );

      res.status(201).json({
        message: "Account created successfully"
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  // LOGIN
  // =========================

  app.post("/api/login", async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          message: "Email and password are required"
        });
      }

      const result = db.exec(
        `SELECT id, name, email, phone, password
         FROM users
         WHERE email = ?`,
        [email]
      );

      if (result.length === 0 || result[0].values.length === 0) {
        return res.status(401).json({
          message: "Invalid email or password"
        });
      }

      const user = result[0].values[0];

      const passwordMatch = await bcrypt.compare(
        password,
        user[4]
      );

      if (!passwordMatch) {
        return res.status(401).json({
          message: "Invalid email or password"
        });
      }

      res.json({
        message: "Login successful",
        user: {
          id: user[0],
          name: user[1],
          email: user[2],
          phone: user[3]
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  // GET WALLET BALANCE
  // =========================

  app.get("/api/wallet/:user_id", (req, res) => {
    try {
      const userId = Number(req.params.user_id);

      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({
          message: "Invalid user ID"
        });
      }

      const result = db.exec(
        `SELECT id, name, wallet_balance
         FROM users
         WHERE id = ?`,
        [userId]
      );

      if (result.length === 0 || result[0].values.length === 0) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      const user = result[0].values[0];

      res.json({
        status: "success",
        wallet: {
          userId: user[0],
          name: user[1],
          balance: user[2]
        }
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  // WALLET TRANSACTIONS
  // =========================

  app.get("/api/wallet/transactions/:user_id", (req, res) => {
    try {
      const userId = Number(req.params.user_id);

      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({
          message: "Invalid user ID"
        });
      }

      const result = db.exec(
        `SELECT id, type, amount, status, reference, created_at
         FROM wallet_transactions
         WHERE user_id = ?
         ORDER BY id DESC`,
        [userId]
      );

      const transactions = [];

      if (result.length > 0) {
        result[0].values.forEach(row => {
          transactions.push({
            id: row[0],
            type: row[1],
            amount: row[2],
            status: row[3],
            reference: row[4],
            date: row[5]
          });
        });
      }

      res.json({
        status: "success",
        transactions
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  // CREATE ORDER
  // =========================

  app.post("/api/orders", (req, res) => {
    try {
      const {
        user_id,
        network,
        data,
        price,
        phone
      } = req.body;

      if (
        !user_id ||
        !network ||
        !data ||
        !price ||
        !phone
      ) {
        return res.status(400).json({
          message: "All order fields are required"
        });
      }

      db.run(
        `INSERT INTO orders
        (user_id, network, data, price, phone)
        VALUES (?, ?, ?, ?, ?)`,
        [user_id, network, data, price, phone]
      );

      fs.writeFileSync(
        dbPath,
        Buffer.from(db.export())
      );

      res.status(201).json({
        message: "Order created successfully"
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  // GET ORDERS
  // =========================

  app.get("/api/orders/:user_id", (req, res) => {
    try {
      const userId = Number(req.params.user_id);

      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({
          message: "Invalid user ID"
        });
      }

      const result = db.exec(
        `SELECT id, network, data, price, phone, status, created_at
         FROM orders
         WHERE user_id = ?
         ORDER BY id DESC`,
        [userId]
      );

      const orders = [];

      if (result.length > 0) {
        result[0].values.forEach(row => {
          orders.push({
            id: row[0],
            network: row[1],
            data: row[2],
            price: row[3],
            phone: row[4],
            status: row[5],
            date: row[6]
          });
        });
      }

      res.json({
        orders
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  // =========================
  
  // =========================
  // INITIALIZE PAYSTACK PAYMENT
  // =========================

  app.post("/api/wallet/fund", async (req, res) => {
    try {
      const { user_id, amount } = req.body;

      if (!user_id || !amount) {
        return res.status(400).json({
          message: "User ID and amount are required"
        });
      }

      if (Number(amount) < 100) {
        return res.status(400).json({
          message: "Minimum funding amount is ₦100"
        });
      }

      const result = db.exec(
        `SELECT email FROM users WHERE id = ?`,
        [user_id]
      );

      if (
        result.length === 0 ||
        result[0].values.length === 0
      ) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      const email = result[0].values[0][0];

      const response = await axios.post(
        "https://api.paystack.co/transaction/initialize",
        {
          email: email,
          amount: Math.round(Number(amount) * 100),
          metadata: {
            user_id: Number(user_id)
          }
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
            "Content-Type": "application/json"
          }
        }
      );

      const payment = response.data.data;

      // Save pending transaction
      db.run(
        `INSERT INTO wallet_transactions
        (user_id, type, amount, status, reference)
        VALUES (?, ?, ?, ?, ?)`,
        [
          user_id,
          "credit",
          Number(amount),
          "pending",
          payment.reference
        ]
      );

      fs.writeFileSync(
        dbPath,
        Buffer.from(db.export())
      );

      res.json({
        status: "success",
        authorization_url: payment.authorization_url,
        reference: payment.reference
      });

    } catch (error) {
      console.error(error.response?.data || error.message);

      res.status(500).json({
        message: "Unable to initialize payment"
      });
    }
  });// WEBSITE
  // =========================

  app.get("/", (req, res) => {
    res.sendFile(
      path.join(__dirname, "../Index.html")
    );
  });

  // =========================
  // TEST API
  // =========================

  app.get("/api", (req, res) => {
    res.json({
      message: "Backend is working!",
      status: "success"
    });
  });

  // =========================
  // START SERVER
  // =========================

  app.listen(
    process.env.PORT || 3000,
    "0.0.0.0",
    () => {
      console.log(
        "Server running on http://localhost:3000"
      );
    }
  );
}

startServer();

