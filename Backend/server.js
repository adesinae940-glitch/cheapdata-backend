const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const axios = require("axios");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const dbPath = path.join(__dirname, "cheapdata.db");

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ERICODATA_API_KEY = process.env.ERICODATA_API_KEY;
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET;

function createAdminToken(userId) {
  const payload = `${userId}.${Date.now()}`;

  const signature = crypto
    .createHmac("sha256", ADMIN_TOKEN_SECRET)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function verifyAdminToken(token) {
  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const [userId, timestamp, signature] = parts;

    const payload = `${userId}.${timestamp}`;

    const expectedSignature = crypto
      .createHmac("sha256", ADMIN_TOKEN_SECRET)
      .update(payload)
      .digest("hex");

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      )
    ) {
      return null;
    }

    const age = Date.now() - Number(timestamp);

    if (age > 24 * 60 * 60 * 1000) {
      return null;
    }

    return Number(userId);

  } catch (error) {
    return null;
  }
}
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

  try {
    db.run(`
      ALTER TABLE users
      ADD COLUMN wallet_balance REAL NOT NULL DEFAULT 0
    `);
  } catch (error) {
    // Column already exists
  }
  try {
    db.run(`
      ALTER TABLE users
      ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0
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
  // WALLET TRANSACTIONS
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

  saveDatabase();

  // =========================
  // SIGN UP
  // =========================

  app.post("/api/signup", async (req, res) => {
    try {
      const { name, email, phone, password } = req.body;

      if (!name || !email || !phone || !password) {
        return res.status(400).json({
          status: "error",
          message: "All fields are required"
        });
      }

      const existing = db.exec(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );

      if (existing.length > 0 && existing[0].values.length > 0) {
        return res.status(409).json({
          status: "error",
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

      saveDatabase();

      const result = db.exec(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );

      const userId = result[0].values[0][0];

      res.status(201).json({
        status: "success",
        message: "Registration successful",
        userId
      });

    } catch (error) {
      console.error("Signup error:", error);

      res.status(500).json({
        status: "error",
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
          status: "error",
          message: "Email and password are required"
        });
      }

const result = db.exec(
  `SELECT id, name, email, phone, password, wallet_balance, is_admin
   FROM users
   WHERE email = ?`,
  [email]
);
      if (
        result.length === 0 ||
        result[0].values.length === 0
      ) {
        return res.status(401).json({
          status: "error",
          message: "Invalid email or password"
        });
      }

      const user = result[0].values[0];
console.log("LOGIN DEBUG:", {
  email,
  userId: user[0],
  passwordMatch: await bcrypt.compare(password, user[4])
});
      const passwordMatch = await bcrypt.compare(
        password,
        user[4]
      );

      if (!passwordMatch) {
        return res.status(401).json({
          status: "error",
          message: "Invalid email or password"
        });
      }

res.json({
  status: "success",
  message: "Login successful",
  user: {
    id: user[0],
    name: user[1],
    email: user[2],
    phone: user[3],
    wallet: user[5],
    is_admin: user[6]
  },
  adminToken: Number(user[6]) === 1
    ? createAdminToken(user[0])
    : null
});
    } catch (error) {
      console.error("Login error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  });

  // =========================
  // =========================
  // ADMIN AUTHORIZATION
  // =========================
  function requireAdmin(req, res, next) {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          status: "error",
          message: "Admin login required"
        });
      }

      const token = authHeader.substring(7);
      const userId = verifyAdminToken(token);

      if (!userId) {
        return res.status(401).json({
          status: "error",
          message: "Invalid or expired admin token"
        });
      }

      const result = db.exec(
        `SELECT is_admin
         FROM users
         WHERE id = ?`,
        [userId]
      );

      if (
        result.length === 0 ||
        result[0].values.length === 0 ||
        Number(result[0].values[0][0]) !== 1
      ) {
        return res.status(403).json({
          status: "error",
          message: "Admin access denied"
        });
      }

      req.adminUserId = userId;

      next();

    } catch (error) {
      console.error("Admin authorization error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  }
 // GET WALLET
  // =========================

  app.get("/api/wallet/:user_id", (req, res) => {
    try {
      const userId = Number(req.params.user_id);

      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({
          status: "error",
          message: "Invalid user ID"
        });
      }

      const result = db.exec(
        `SELECT id, name, wallet_balance
         FROM users
         WHERE id = ?`,
        [userId]
      );

      if (
        result.length === 0 ||
        result[0].values.length === 0
      ) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
   	     });
      }

      const user = result[0].values[0];
res.json({
  status: "success",
  wallet: user[2]
});
    } catch (error) {
      console.error("Wallet error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  });

  // =========================
  // WALLET TRANSACTIONS
  // =========================

  app.get(
    "/api/wallet/transactions/:user_id",
    (req, res) => {
      try {
        const userId = Number(req.params.user_id);

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
        console.error("Transactions error:", error);

        res.status(500).json({
          status: "error",
          message: "Server error"
        });
      }
    }
  );

  // =========================
  // PAYSTACK FUND WALLET
  // =========================

  app.post("/api/wallet/fund", async (req, res) => {
    try {
      const { user_id, amount } = req.body;

      if (!user_id || !amount) {
        return res.status(400).json({
          status: "error",
          message: "User ID and amount are required"
        });
      }

      if (Number(amount) < 100) {
        return res.status(400).json({
          status: "error",
          message: "Minimum funding amount is ₦100"
        });
      }

      if (!PAYSTACK_SECRET_KEY) {
        console.error("PAYSTACK_SECRET_KEY is missing");

        return res.status(500).json({
          status: "error",
          message: "Paystack secret key is not configured"
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
          status: "error",
          message: "User not found"
        });
      }

      const email = result[0].values[0][0];

      const response = await axios.post(
        "https://api.paystack.co/transaction/initialize",
        {
          email,
          amount: Math.round(Number(amount) * 100),
callback_url: "https://cheapdata-backend.onrender.com/",
          metadata: {
            user_id: Number(user_id)
          }
        },
        {
          headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
            "Content-Type": "application/json"
          }
        }
      );

      const payment = response.data.data;

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

      saveDatabase();

      res.json({
        status: "success",
        authorization_url: payment.authorization_url,
        reference: payment.reference
      });

    } catch (error) {
      console.error(
        "Paystack error:",
        error.response?.data || error.message
      );

      res.status(500).json({
        status: "error",
        message:
          error.response?.data?.message ||
          "Unable to initialize payment"
      });
    }
  });

  // =========================
  // VERIFY PAYSTACK PAYMENT
  // =========================

  app.get(
    "/api/wallet/verify/:reference",
    async (req, res) => {
      try {
        const reference = req.params.reference;

        const transactionResult = db.exec(
          `SELECT id, user_id, amount, status
           FROM wallet_transactions
           WHERE reference = ?`,
          [reference]
        );

        if (
          transactionResult.length === 0 ||
          transactionResult[0].values.length === 0
        ) {
          return res.status(404).json({
            status: "error",
            message: "Transaction not found"
          });
        }

        const transaction =
          transactionResult[0].values[0];

        const transactionId = transaction[0];
        const userId = transaction[1];
        const expectedAmount = Number(transaction[2]);
        const currentStatus = transaction[3];

        if (currentStatus === "success") {
          return res.json({
            status: "success",
            message: "Transaction already verified"
          });
        }

        if (!PAYSTACK_SECRET_KEY) {
          return res.status(500).json({
            status: "error",
            message: "Paystack secret key is not configured"
          });
        }

        const response = await axios.get(
          `https://api.paystack.co/transaction/verify/${reference}`,
          {
            headers: {
              Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`
            }
          }
        );

        const payment = response.data.data;

        if (payment.status !== "success") {
          return res.status(400).json({
            status: "error",
            message: "Payment was not successful"
          });
        }

        const paidAmount =
          Number(payment.amount) / 100;

        if (paidAmount !== expectedAmount) {
          return res.status(400).json({
            status: "error",
            message: "Payment amount does not match"
          });
        }

        db.run(
          `UPDATE users
           SET wallet_balance = wallet_balance + ?
           WHERE id = ?`,
          [expectedAmount, userId]
        );

        db.run(
          `UPDATE wallet_transactions
           SET status = "success"
           WHERE id = ?`,
          [transactionId]
        );

        saveDatabase();

        const userResult = db.exec(
          `SELECT wallet_balance
           FROM users
           WHERE id = ?`,
          [userId]
        );

        const newBalance =
          userResult[0].values[0][0];

        res.json({
          status: "success",
          message: "Wallet funded successfully",
          balance: newBalance
        });

      } catch (error) {
        console.error(
          "Payment verification error:",
          error.response?.data || error.message
        );

        res.status(500).json({
          status: "error",
          message:
            error.response?.data?.message ||
            "Unable to verify payment"
        });
      }
    }
  );

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
          status: "error",
          message: "All order fields are required"
        });
      }

      const userResult = db.exec(
        `SELECT wallet_balance
         FROM users
         WHERE id = ?`,
        [user_id]
      );

      if (
        userResult.length === 0 ||
        userResult[0].values.length === 0
      ) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
        });
      }

      const balance =
        Number(userResult[0].values[0][0]);

      const orderPrice = Number(price);

      if (balance < orderPrice) {
        return res.status(400).json({
          status: "error",
          message: "Insufficient wallet balance"
        });
      }

      db.run(
        `UPDATE users
         SET wallet_balance = wallet_balance - ?
         WHERE id = ?`,
        [orderPrice, user_id]
      );

      db.run(
        `INSERT INTO orders
        (user_id, network, data, price, phone, status)
        VALUES (?, ?, ?, ?, ?, ?)`,
        [
          user_id,
          network,
          data,
          orderPrice,
          phone,
          "pending"
        ]
      );

      saveDatabase();

      res.status(201).json({
        status: "success",
        message: "Order created successfully"
      });

    } catch (error) {
      console.error("Order error:", error);

      res.status(500).json({
        status: "error",
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
        status: "success",
        orders
      });

    } catch (error) {
      console.error("Get orders error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  });
  // =========================
  // ADMIN ORDERS
  // =========================

  app.get("/api/admin/orders", requireAdmin, (req, res) => {
    try {
      const result = db.exec(`
        SELECT
          orders.id,
          orders.user_id,
          users.name,
          users.email,
          orders.network,
          orders.data,
          orders.price,
          orders.phone,
          orders.status,
          orders.created_at
        FROM orders
        JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC
      `);

      const orders = [];

      if (result.length > 0) {
        result[0].values.forEach(row => {
          orders.push({
            id: row[0],
            user_id: row[1],
            customer: row[2],
            email: row[3],
            network: row[4],
            data: row[5],
            price: row[6],
            phone: row[7],
            status: row[8],
            date: row[9]
          });
        });
      }

      res.json({
        status: "success",
        orders
      });

    } catch (error) {
      console.error("Admin orders error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  });
  // =========================
  app.put("/api/admin/orders/:id/status", requireAdmin, (req, res) => {
    try {
      const orderId = Number(req.params.id);
      const { status } = req.body;

      const allowedStatuses = [
        "pending",
        "processing",
        "successful",
        "failed"
      ];

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid order status"
        });
      }

      db.run(
        `UPDATE orders
         SET status = ?
         WHERE id = ?`,
        [status, orderId]
      );

      saveDatabase();

      res.json({
        status: "success",
        message: "Order status updated"
      });

    } catch (error) {
      console.error("Admin status update error:", error);

      res.status(500).json({
        status: "error",
        message: "Server error"
      });
    }
  });  
// WEBSITE
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
      status: "success",
      message: "CheapData backend is working!"
    });
  });
app.get("/api/ericodata-test", (req, res) => {
  res.json({
    ericodata_key_configured: !!ERICODATA_API_KEY
  });
});

  // =========================
  // START SERVER
  // =========================

// =========================
// ERICODATA PLANS TEST
// =========================

app.get("/api/ericodata-plans-test", async (req, res) => {
  try {
    const response = await axios.get(
      "https://ericodata.com.ng/wp-json/ericodata/v1/plans",
      {
        headers: {
          "X-Agent-Key": ERICODATA_API_KEY
        }
      }
    );

    res.json({
      status: "success",
      plans: response.data
    });

  } catch (error) {
    console.error(
      "Ericodata plans error:",
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      status: "error",
      message:
        error.response?.data ||
        "Unable to fetch Ericodata plans"
    });
  }
});
// =========================
// ERICODATA NETWORK PLANS TEST
// =========================
app.get("/api/ericodata-network-plans-test", async (req, res) => {
  try {
    const network = req.query.network;

    const response = await axios.get(
      "https://ericodata.com.ng/wp-json/ericodata/v1/plans",
      {
        params: network ? { network } : {},
        headers: {
          "X-Agent-Key": ERICODATA_API_KEY
        }
      }
    );

    res.json({
      status: "success",
      network: network || "all",
      plans: response.data
    });

  } catch (error) {
    console.error(
      "Ericodata network plans error:",
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      status: "error",
      message:
        error.response?.data ||
        "Unable to fetch Ericodata plans"
    });
  }
});
// =========================  
// =========================
// ERICODATA TRANSACTIONS TEST
// =========================
app.get("/api/ericodata-transactions-test", async (req, res) => {
  try {
    const response = await axios.get(
      "https://ericodata.com.ng/wp-json/ericodata/v1/transactions",
      {
        headers: {
          "X-Agent-Key": ERICODATA_API_KEY
        }
      }
    );

    res.json({
      status: "success",
      transactions: response.data
    });

  } catch (error) {
    console.error(
      "Ericodata transactions error:",
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      status: "error",
      message:
        error.response?.data ||
        "Unable to fetch Ericodata transactions"
    });
  }
});
// ERICODATA ORDER FORMAT TEST
// =========================
app.post("/api/ericodata-order-test", async (req, res) => {
  try {
const response = await axios.post(
  "https://ericodata.com.ng/wp-json/ericodata/v1/order",
  req.body,
  {
    headers: {
      "Content-Type": "application/json",
      "X-Agent-Key": ERICODATA_API_KEY
    }
  }
);
    res.json({
      status: "success",
      response: response.data
    });

  } catch (error) {
    console.error(
      "Ericodata order test:",
      error.response?.data || error.message
    );
    res.status(error.response?.status || 500).json({
      status: "error",
      message: error.response?.data || error.message
    });
  }
});
// =========================
// ERICODATA BALANCE TEST
// =========================
app.get("/api/ericodata-balance-test", async (req, res) => {
  try {
    const response = await axios.get(
      "https://ericodata.com.ng/wp-json/ericodata/v1/balance",
      {
        headers: {
          "X-Agent-Key": ERICODATA_API_KEY
        }
      }
    );

    res.json({
      status: "success",
      balance: response.data
    });

  } catch (error) {
    console.error(
      "Ericodata balance error:",
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      status: "error",
      message: error.response?.data || error.message
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "CheapData server running on port " + PORT
  );
});
}

function saveDatabase() {
  fs.writeFileSync(
    dbPath,
    Buffer.from(db.export())
  );
}

startServer();
