// CheapDataNG backend - Airtel 600MB price fix
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const axios = require("axios");
const { Pool } = require("pg");

const pgPool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const dbPath = path.join(__dirname, "cheapdata.db");

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ERICODATA_API_KEY = process.env.ERICODATA_API_KEY;
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET;
const USER_TOKEN_SECRET = process.env.USER_TOKEN_SECRET;


// =========================
// ERICODATA PLAN MAPPING
// =========================
const ERICODATA_PLANS = {
  MTN: {
    "500MB": 528,
    "1GB": 861,
    "2GB": 473
  },
  Airtel: {
    "600MB": 478,
    "1GB": 625,
    "2GB": 617
  },
  Glo: {
    "500MB": 810,
    "1GB": 811,
    "2.5GB": 493
  }
};


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
    if (!token || typeof token !== "string") {
      return null;
    }

    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const [userId, timestamp, signature] = parts;

    if (!/^\d+$/.test(userId) || !/^\d+$/.test(timestamp)) {
      return null;
    }

    if (!/^[0-9a-f]+$/.test(signature)) {
      return null;
    }

    const payload = `${userId}.${timestamp}`;

    const expectedSignature = crypto
      .createHmac("sha256", ADMIN_TOKEN_SECRET)
      .update(payload)
      .digest("hex");

    if (
      signature.length !== expectedSignature.length ||
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      )
    ) {
      return null;
    }

    const userIdNumber = Number(userId);
    const timestampNumber = Number(timestamp);

    if (!Number.isSafeInteger(userIdNumber) || userIdNumber <= 0) {
      return null;
    }

    if (!Number.isFinite(timestampNumber)) {
      return null;
    }

    const age = Date.now() - timestampNumber;

    if (age < 0 || age > 24 * 60 * 60 * 1000) {
      return null;
    }

    return userIdNumber;

  } catch (error) {
    return null;
  }
}

function createUserToken(userId) {
  const payload = `${userId}.${Date.now()}`;

  const signature = crypto
    .createHmac("sha256", USER_TOKEN_SECRET)
    .update(payload)
    .digest("hex");

  return `${payload}.${signature}`;
}

function verifyUserToken(token) {
  try {
    const parts = String(token || "").split(".");

    if (parts.length !== 3) {
      return null;
    }

    const [userId, timestamp, signature] = parts;
    const payload = `${userId}.${timestamp}`;

    const expectedSignature = crypto
      .createHmac("sha256", USER_TOKEN_SECRET)
      .update(payload)
      .digest("hex");

    if (
      signature.length !== expectedSignature.length ||
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
      )
    ) {
      return null;
    }

    const numericUserId = Number(userId);
    const numericTimestamp = Number(timestamp);

    if (!Number.isInteger(numericUserId) || numericUserId <= 0) {
      return null;
    }

    if (!Number.isFinite(numericTimestamp)) {
      return null;
    }

    const age = Date.now() - numericTimestamp;

    if (age < 0 || age > 24 * 60 * 60 * 1000) {
      return null;
    }

    return numericUserId;
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
  // ADMIN PASSWORD MIGRATION
  // =========================

  if (process.env.ADMIN_PASSWORD_HASH) {
    const admin = db.exec(
      `SELECT id FROM users WHERE id = ? AND is_admin = 1`,
      [5]
    );

    if (admin.length > 0 && admin[0].values.length > 0) {
      db.run(
        `UPDATE users SET password = ? WHERE id = ?`,
        [process.env.ADMIN_PASSWORD_HASH, 5]
      );
      saveDatabase();
      console.log("Admin password migration applied");
    }
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

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const existing = await pgPool.query(
        "SELECT id FROM users WHERE email = $1",
        [email]
      );

      if (existing.rows.length > 0) {
        return res.status(409).json({
          status: "error",
          message: "Email already registered"
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await pgPool.query(
        `INSERT INTO users
        (name, email, phone, password, wallet_balance, is_admin)
        VALUES ($1, $2, $3, $4, 0, 0)
        RETURNING id`,
        [name, email, phone, hashedPassword]
      );

      const userId = result.rows[0].id;

      res.status(201).json({
        status: "success",
        message: "Registration successful",
        userId
      });
    } catch (error) {
      console.error("Signup PostgreSQL error:", error);

      if (error.code === "23505") {
        return res.status(409).json({
          status: "error",
          message: "Email already registered"
        });
      }

      res.status(500).json({
        status: "error",
        message: "Registration failed"
      });
    }
  });

  app.post("/api/login", async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({
          status: "error",
          message: "Email and password are required"
        });
      }

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const result = await pgPool.query(
        `SELECT id, name, email, phone, password, wallet_balance, is_admin
         FROM users
         WHERE email = $1`,
        [email]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          status: "error",
          message: "Invalid email or password"
        });
      }

      const user = result.rows[0];

      const passwordMatch = await bcrypt.compare(
        password,
        user.password
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
          id: user.id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          wallet: Number(user.wallet_balance),
          is_admin: user.is_admin
        },
        adminToken: Number(user.is_admin) === 1
          ? createAdminToken(user.id)
          : null,
        userToken: createUserToken(user.id)
      });
    } catch (error) {
      console.error("Login PostgreSQL error:", error);

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
  async function requireUser(req, res, next) {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ status: "error", message: "Login required" });
      }
      const userId = verifyUserToken(authHeader.substring(7));
      if (!userId) {
        return res.status(401).json({ status: "error", message: "Invalid or expired login token" });
      }
      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const result = await pgPool.query(
        "SELECT id FROM users WHERE id = $1",
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(401).json({
          status: "error",
          message: "User account not found"
        });
      }

      req.userId = userId;
      next();
    } catch (error) {
      console.error("User authorization error:", error);
      return res.status(500).json({ status: "error", message: "Server error" });
    }
  }

 // GET WALLET
  // =========================

  app.get("/api/wallet", requireUser, async (req, res) => {
    try {
      const userId = req.userId;

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const result = await pgPool.query(
        `SELECT id, name, wallet_balance
         FROM users
         WHERE id = $1`,
        [userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
        });
      }

      const user = result.rows[0];

      res.json({
        status: "success",
        wallet: Number(user.wallet_balance)
      });
    } catch (error) {
      console.error("Wallet PostgreSQL error:", error);

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
    "/api/wallet/transactions",
    requireUser,
    async (req, res) => {
      try {
        const userId = req.userId;

        if (!pgPool) {
          return res.status(500).json({
            status: "error",
            message: "PostgreSQL is not configured"
          });
        }

        const result = await pgPool.query(
          `SELECT id, type, amount, status, reference, created_at
           FROM wallet_transactions
           WHERE user_id = $1
           ORDER BY id DESC`,
          [userId]
        );

        const transactions = result.rows.map(row => ({
          id: row.id,
          type: row.type,
          amount: Number(row.amount),
          status: row.status,
          reference: row.reference,
          date: row.created_at
        }));

        res.json({
          status: "success",
          transactions
        });

      } catch (error) {
        console.error("Transactions PostgreSQL error:", error);

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

  app.post("/api/wallet/fund", requireUser, async (req, res) => {
    try {
      const userId = req.userId;
      const { amount } = req.body;

      if (!amount) {
        return res.status(400).json({
          status: "error",
          message: "Amount is required"
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

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const userResult = await pgPool.query(
        "SELECT email FROM users WHERE id = $1",
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
        });
      }

      const email = userResult.rows[0].email;

      const response = await axios.post(
        "https://api.paystack.co/transaction/initialize",
        {
          email,
          amount: Math.round(Number(amount) * 100),
          callback_url: "https://cheapdata-backend.onrender.com/",
          metadata: {
            user_id: Number(userId)
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

      await pgPool.query(
        `INSERT INTO wallet_transactions
        (user_id, type, amount, status, reference)
        VALUES ($1, $2, $3, $4, $5)`,
        [
          userId,
          "credit",
          Number(amount),
          "pending",
          payment.reference
        ]
      );

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

        if (!pgPool) {
          return res.status(500).json({
            status: "error",
            message: "PostgreSQL is not configured"
          });
        }

        const transactionResult = await pgPool.query(
          `SELECT id, user_id, amount, status
           FROM wallet_transactions
           WHERE reference = $1`,
          [reference]
        );

        if (transactionResult.rows.length === 0) {
          return res.status(404).json({
            status: "error",
            message: "Transaction not found"
          });
        }

        const transaction = transactionResult.rows[0];

        const transactionId = transaction.id;
        const userId = transaction.user_id;
        const expectedAmount = Number(transaction.amount);
        const currentStatus = transaction.status;

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

        const paidAmount = Number(payment.amount) / 100;

        if (paidAmount !== expectedAmount) {
          return res.status(400).json({
            status: "error",
            message: "Payment amount does not match"
          });
        }

        const client = await pgPool.connect();

        try {
          await client.query("BEGIN");

          const lockResult = await client.query(
            `SELECT status
             FROM wallet_transactions
             WHERE id = $1
             FOR UPDATE`,
            [transactionId]
          );

          if (lockResult.rows.length === 0) {
            await client.query("ROLLBACK");
            return res.status(404).json({
              status: "error",
              message: "Transaction not found"
            });
          }

          if (lockResult.rows[0].status === "success") {
            await client.query("COMMIT");
            return res.json({
              status: "success",
              message: "Transaction already verified"
            });
          }

          await client.query(
            `UPDATE users
             SET wallet_balance = wallet_balance + $1
             WHERE id = $2`,
            [expectedAmount, userId]
          );

          await client.query(
            `UPDATE wallet_transactions
             SET status = $1
             WHERE id = $2`,
            ["success", transactionId]
          );

          await client.query("COMMIT");
        } catch (dbError) {
          await client.query("ROLLBACK");
          throw dbError;
        } finally {
          client.release();
        }

        const userResult = await pgPool.query(
          `SELECT wallet_balance
           FROM users
           WHERE id = $1`,
          [userId]
        );

        if (userResult.rows.length === 0) {
          return res.status(404).json({
            status: "error",
            message: "User not found"
          });
        }

        const newBalance = Number(userResult.rows[0].wallet_balance);

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

  app.get("/api/ericodata/plans", async (req, res) => {
  try {
    const network = String(req.query.network || "").trim().toLowerCase();

    if (!["mtn", "airtel", "glo"].includes(network)) {
      return res.status(400).json({
        status: "error",
        message: "Network must be mtn, airtel, or glo"
      });
    }

    if (!ERICODATA_API_KEY) {
      return res.status(500).json({
        status: "error",
        message: "Ericodata API key is not configured"
      });
    }

    const response = await axios.get(
      "https://ericodata.com.ng/wp-json/ericodata/v1/plans",
      {
        params: { network },
        headers: {
          "X-Agent-Key": ERICODATA_API_KEY
        }
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error(
      "Ericodata plans error:",
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json(
      error.response?.data || {
        status: "error",
        message: "Unable to fetch Ericodata plans"
      }
    );
  }
});

app.post("/api/orders", requireUser, async (req, res) => {
    try {
      const {
        network,
        data,
        phone
      } = req.body;

      const userId = req.userId;

      if (!network || !data || !phone) {
        return res.status(400).json({
          status: "error",
          message: "All order fields are required"
        });
      }

      const cleanPhone = String(phone).trim();

      if (!/^\d{11}$/.test(cleanPhone)) {
        return res.status(400).json({
          status: "error",
          message: "Phone number must be exactly 11 digits"
        });
      }

      const productKey =
        `${String(network).trim().toLowerCase()}|${String(data).trim().toUpperCase()}`;

      const PRODUCTS = {
        "mtn|500MB": {
          network: "mtn",
          data: "500MB",
          price: 350,
          plan_id: 471
        },
        "mtn|1GB": {
          network: "mtn",
          data: "1GB",
          price: 500,
          plan_id: 861
        },
        "mtn|2GB": {
          network: "mtn",
          data: "2GB",
          price: 900,
          plan_id: 473
        },

        "airtel|1GB": {
          network: "airtel",
          data: "1GB",
          price: 450,
          plan_id: 625
        },
        "airtel|2GB": {
          network: "airtel",
          data: "2GB",
          price: 700,
          plan_id: 617

        },
        "glo|1GB": {
          network: "glo",
          data: "1GB",
          price: 300,
          plan_id: 862
        },
        "glo|2.5GB": {
          network: "glo",
          data: "2.5GB",
          price: 600,
          plan_id: 493
        }
      };

      const product = PRODUCTS[productKey];

      if (!product) {
        return res.status(400).json({
          status: "error",
          message: "This data plan is currently unavailable"
        });
      }

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const userResult = await pgPool.query(
        `SELECT wallet_balance
         FROM users
         WHERE id = $1`,
        [userId]
      );

      if (userResult.rows.length === 0) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
        });
      }

      const balance = Number(userResult.rows[0].wallet_balance);

      if (balance < product.price) {
        return res.status(400).json({
          status: "error",
          message: "Insufficient wallet balance"
        });
      }

      const client = await pgPool.connect();
      let orderId;

      try {
        await client.query("BEGIN");

        const lockedUser = await client.query(
          `SELECT wallet_balance
           FROM users
           WHERE id = $1
           FOR UPDATE`,
          [userId]
        );

        if (lockedUser.rows.length === 0) {
          await client.query("ROLLBACK");
          return res.status(404).json({
            status: "error",
            message: "User not found"
          });
        }

        const lockedBalance = Number(lockedUser.rows[0].wallet_balance);

        if (lockedBalance < product.price) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            status: "error",
            message: "Insufficient wallet balance"
          });
        }

        const orderResult = await client.query(
          `INSERT INTO orders
          (user_id, network, data, price, phone, status)
          VALUES ($1, $2, $3, $4, $5, $6)
          RETURNING id`,
          [
            userId,
            product.network,
            product.data,
            product.price,
            cleanPhone,
            "pending"
          ]
        );

        orderId = orderResult.rows[0].id;

        await client.query(
          `UPDATE users
           SET wallet_balance = wallet_balance - $1
           WHERE id = $2`,
          [product.price, userId]
        );

        await client.query("COMMIT");
      } catch (dbError) {
        await client.query("ROLLBACK");
        throw dbError;
      } finally {
        client.release();
      }

      try {
        const supplierResponse = await axios.post(
          "https://ericodata.com.ng/wp-json/ericodata/v1/order",
          {
            service: "data",
            network: product.network,
            phone: cleanPhone,
            plan_id: product.plan_id
          },
          {
            headers: {
              "Content-Type": "application/json",
              "X-Agent-Key": ERICODATA_API_KEY
            }
          }
        );

        const supplierData = supplierResponse.data;

        if (
          !supplierData ||
          supplierData.success !== true ||
          String(supplierData.Status || "").toLowerCase() !== "successful"
        ) {
          throw new Error(
            supplierData?.message ||
            "Ericodata did not confirm the order as successful"
          );
        }

        await pgPool.query(
          `UPDATE orders
           SET status = $1
           WHERE id = $2`,
          ["successful", orderId]
        );

        return res.status(201).json({
          status: "success",
          message: "Order successful",
          order_id: orderId
        });

      } catch (supplierError) {

        console.error(
          "Ericodata order error:",
          supplierError.response?.data ||
          supplierError.message
        );

        const refundClient = await pgPool.connect();

        try {
          await refundClient.query("BEGIN");

          await refundClient.query(
            `UPDATE users
             SET wallet_balance = wallet_balance + $1
             WHERE id = $2`,
            [product.price, userId]
          );

          await refundClient.query(
            `UPDATE orders
             SET status = $1
             WHERE id = $2`,
            ["failed", orderId]
          );

          await refundClient.query("COMMIT");
        } catch (refundError) {
          await refundClient.query("ROLLBACK");
          console.error("Order refund error:", refundError);
        } finally {
          refundClient.release();
        }

        return res.status(502).json({
          status: "error",
          message:
            supplierError.response?.data?.message ||
            "Data supplier order failed. Your wallet has been refunded.",
          order_id: orderId
        });
      }

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

  app.get("/api/orders", requireUser, async (req, res) => {
    try {
      const userId = req.userId;

      const result = await pgPool.query(
        `SELECT id, network, data, price, phone, status, created_at
         FROM orders
         WHERE user_id = $1
         ORDER BY id DESC`,
        [userId]
      );

      const orders = result.rows.map(row => ({
        id: row.id,
        network: row.network,
        data: row.data,
        price: Number(row.price),
        phone: row.phone,
        status: row.status,
        date: row.created_at
      }));

      res.json({
        status: "success",
        orders
      });

    } catch (error) {
      console.error("Get orders PostgreSQL error:", error);

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

  // =========================
  // START SERVER
  // =========================

// =========================  
// =========================
// ERICODATA TRANSACTIONS TEST
// =========================
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

