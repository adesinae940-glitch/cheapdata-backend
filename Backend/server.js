
const express = require("express");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();

app.use(express.json());

const dbPath = path.join(__dirname, "cheapdata.db");

let db;

async function startServer() {
  const SQL = await initSqlJs();

  if (fs.existsSync(dbPath)) {
    const file = fs.readFileSync(dbPath);
    db = new SQL.Database(file);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);

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

  fs.writeFileSync(
    dbPath,
    Buffer.from(db.export())
  );

  
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
        "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
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

  app.post("/api/login", async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          message: "Email and password are required"
        });
      }

      const result = db.exec(
        "SELECT id, name, email, phone, password FROM users WHERE email = ?",
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

  app.post("/api/orders", (req, res) => {
    try {
      const { user_id, network, data, price, phone } = req.body;

      if (!user_id || !network || !data || !price || !phone) {
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

  app.get("/api/orders/:user_id", (req, res) => {
    try {
      const userId = Number(req.params.user_id);

      if (!userId) {
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

      res.json({ orders });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        message: "Server error"
      });
    }
  });

  app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../Index.html"));
  });

  app.get("/api", (req, res) => {   res.json({
      message: "Backend is working!",
      status: "success"
    });
  });

  app.listen(process.env.PORT || 3000, "0.0.0.0", () => {
    console.log("Server running on http://localhost:3000");
  });
}

startServer();
