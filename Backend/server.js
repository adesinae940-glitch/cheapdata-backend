// CheapDataNG backend - Airtel 600MB price fix
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const axios = require("axios");
let pgPool = null;
const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ERICODATA_API_KEY = process.env.ERICODATA_API_KEY;
const MELE_API_KEY = process.env.MELE_API_KEY;
const TEETECH_API_KEY = process.env.TEETECH_API_KEY;
const BBK_API_KEY = process.env.BBK_API_KEY;
const NATA_API_KEY = process.env.NATA_API_KEY;
const NATA_BASE_URL = "https://api.nata.ng/api";
const VTUSHARE_BASE_URL = "https://vtushare.com.ng/api";
const VTUSHARE_EMAIL = process.env.VTUSHARE_EMAIL;
const VTUSHARE_PASSWORD = process.env.VTUSHARE_PASSWORD;
const MELE_BASE_URL = "https://meledata.ng/api/v1/developer";
const OPLUG_API_KEY = process.env.OPLUG_API_KEY;
const OPLUG_BASE_URL = "https://www.oplug.com.ng/api/v1";
const ADMIN_TOKEN_SECRET = process.env.ADMIN_TOKEN_SECRET;
const USER_TOKEN_SECRET = process.env.USER_TOKEN_SECRET;

// VTUShare Basic Authentication
function getVTUShareAuth() {
  if (!VTUSHARE_EMAIL || !VTUSHARE_PASSWORD) {
    throw new Error("VTUShare credentials are not configured");
  }

  return Buffer
    .from(`${VTUSHARE_EMAIL}:${VTUSHARE_PASSWORD}`)
    .toString("base64");
}


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

async function startServer() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is not set");
  }

  pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5
  });

  await pgPool.query("SELECT 1");

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT NOT NULL,
      password TEXT NOT NULL,
      wallet_balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      is_admin INTEGER NOT NULL DEFAULT 0,
      transaction_pin TEXT
    )
  `);
  await pgPool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS wallet_balance NUMERIC(12,2) NOT NULL DEFAULT 0");
  await pgPool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER NOT NULL DEFAULT 0");
  await pgPool.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS transaction_pin TEXT");

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      network TEXT NOT NULL,
      data TEXT NOT NULL,
      price INTEGER NOT NULL,
      phone TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pgPool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_cost NUMERIC(12,2)");

  await pgPool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_name TEXT");
  await pgPool.query("ALTER TABLE orders ADD COLUMN IF NOT EXISTS supplier_reference TEXT");

  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      status TEXT NOT NULL,
      reference TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `);

  if (process.env.ADMIN_PASSWORD_HASH) {
    const admin = await pgPool.query(
      "SELECT id FROM users WHERE id = $1 AND is_admin = 1",
      [5]
    );
    if (admin.rowCount > 0) {
      await pgPool.query(
        "UPDATE users SET password = $1 WHERE id = $2",
        [process.env.ADMIN_PASSWORD_HASH, 5]
      );
      console.log("Admin password migration applied");
    }
  }

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

  app.get("/api/transaction-pin/status", requireUser, async (req, res) => {
    try {
      const result = await pgPool.query(
        "SELECT transaction_pin FROM users WHERE id = $1",
        [req.userId]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          status: "error",
          message: "User not found"
        });
      }

      res.json({
        status: "success",
        has_pin: !!result.rows[0].transaction_pin
      });
    } catch (error) {
      console.error("Transaction PIN status error:", error);
      res.status(500).json({
        status: "error",
        message: "Unable to check transaction PIN"
      });
    }
  });

  app.post("/api/transaction-pin/set", requireUser, async (req, res) => {
    try {
      const pin = String(req.body.pin || "").trim();

      if (!/^\d{4,6}$/.test(pin)) {
        return res.status(400).json({
          status: "error",
          message: "Transaction PIN must contain 4 to 6 digits"
        });
      }

      const hashedPin = await bcrypt.hash(pin, 10);

      await pgPool.query(
        "UPDATE users SET transaction_pin = $1 WHERE id = $2",
        [hashedPin, req.userId]
      );

      res.json({
        status: "success",
        message: "Transaction PIN created successfully"
      });
    } catch (error) {
      console.error("Transaction PIN set error:", error);
      res.status(500).json({
        status: "error",
        message: "Unable to create transaction PIN"
      });
    }
  });

  // =========================
  // ADMIN AUTHORIZATION
  // =========================
  async function requireAdmin(req, res, next) {
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

      if (!pgPool) {
        return res.status(500).json({
          status: "error",
          message: "PostgreSQL is not configured"
        });
      }

      const result = await pgPool.query(
        `SELECT is_admin
         FROM users
         WHERE id = $1`,
        [userId]
      );

      if (
        result.rows.length === 0 ||
        Number(result.rows[0].is_admin) !== 1
      ) {
        return res.status(403).json({
          status: "error",
          message: "Admin access denied"
        });
      }

      req.adminUserId = Number(userId);

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

      const validAmount =
        (typeof amount === "number" && Number.isSafeInteger(amount)) ||
        (typeof amount === "string" && /^\d+$/.test(amount.trim()));

      const fundingAmount = Number(amount);

      if (
        !validAmount ||
        !Number.isSafeInteger(fundingAmount) ||
        !Number.isSafeInteger(fundingAmount * 100) ||
        fundingAmount < 100
      ) {
        return res.status(400).json({
          status: "error",
          message: "Enter a valid whole-naira amount of at least ₦100"
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
          amount: fundingAmount * 100,
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
          fundingAmount,
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
    "/api/wallet/verify/:reference", requireUser,
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
           WHERE reference = $1
             AND user_id = $2`,
          [reference, req.userId]
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

          if (lockResult.rows[0].status !== "pending") {
            await client.query("ROLLBACK");
            return res.status(409).json({
              status: "error",
              message: "Transaction is not pending and cannot be credited again"
            });
          }

          const walletUpdate = await client.query(
            `UPDATE users
             SET wallet_balance = wallet_balance + $1
             WHERE id = $2`,
            [expectedAmount, userId]
          );

          if (walletUpdate.rowCount !== 1) {
            throw new Error("Wallet credit failed: user row was not updated");
          }

          const paymentUpdate = await client.query(
            `UPDATE wallet_transactions
             SET status = $1
             WHERE id = $2`,
            ["success", transactionId]
          );

          if (paymentUpdate.rowCount !== 1) {
            throw new Error("Payment status update failed");
          }

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
      const transactionPin = String(req.body.transaction_pin || "").trim();

      if (!/^\d{11}$/.test(cleanPhone)) {
        return res.status(400).json({
          status: "error",
          message: "Phone number must be exactly 11 digits"
        });
      }

      if (!/^\d{4,6}$/.test(transactionPin)) {
        return res.status(400).json({
          status: "error",
          message: "A 4 to 6 digit transaction PIN is required"
        });
      }

      const pinResult = await pgPool.query(
        "SELECT transaction_pin FROM users WHERE id = $1",
        [userId]
      );

      if (
        pinResult.rows.length === 0 ||
        !pinResult.rows[0].transaction_pin
      ) {
        return res.status(400).json({
          status: "error",
          message: "Transaction PIN has not been created yet"
        });
      }

      const pinMatch = await bcrypt.compare(
        transactionPin,
        pinResult.rows[0].transaction_pin
      );

      if (!pinMatch) {
        return res.status(401).json({
          status: "error",
          message: "Incorrect transaction PIN"
        });
      }

      const productKey =
        `${String(network).trim().toLowerCase()}|${String(data).trim().toUpperCase()}`;

      const PRODUCTS = {
        "mtn|1GB": { network: "mtn", data: "1GB", price: 450, plan_id: "OPL_9", supplier_cost: 395, supplier_network: 1 },
        "mtn|2GB": { network: "mtn", data: "2GB", price: 800, plan_id: "OPL_8", supplier_cost: 700, supplier_network: 1 },
        "mtn|3GB": { network: "mtn", data: "3GB", price: 1100, plan_id: "OPL_13", supplier_cost: 1040, supplier_network: 1 },
        "airtel|1GB": { network: "airtel", data: "1GB", price: 450, plan_id: "oplug_special_74", supplier_cost: 335, supplier_network: 4 },
        "airtel|8GB": { network: "airtel", data: "8GB", price: 2500, plan_id: "OPL_358", supplier_cost: 2468, supplier_network: 4 },
        "airtel|10GB": { network: "airtel", data: "10GB", price: 2950, plan_id: "oplug_special_93", supplier_cost: 2897, supplier_network: 4 },
        "glo|1GB": { network: "glo", data: "1GB", price: 350, plan_id: "OPL_528", supplier_cost: 296, supplier_network: 2 },
        "glo|3GB (1 DAY)": { network: "glo", data: "3GB (1 Day)", price: 900, plan_id: "OPL_583", supplier_cost: 490, supplier_network: 2 },
        "glo|5GB": { network: "glo", data: "5.2GB (30 Days)", price: 1560, plan_id: "OPL_532", supplier_cost: 1410, supplier_network: 2 },
        "glo|10GB": { network: "glo", data: "10GB", price: 2900, plan_id: "OPL_113", supplier_cost: 1850, supplier_network: 2 }
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

      // OPLUG CONFIGURATION CHECK
      if (!OPLUG_API_KEY) {
        return res.status(503).json({
          status: "error",
          message: "Data supplier is not configured"
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

        const walletDeduction = await client.query(
          `UPDATE users
           SET wallet_balance = wallet_balance - $1
           WHERE id = $2`,
          [product.price, userId]
        );

        if (walletDeduction.rowCount !== 1) {
          throw new Error("Wallet deduction did not update exactly one user");
        }

        await client.query("COMMIT");
      } catch (dbError) {
        await client.query("ROLLBACK");
        throw dbError;
      } finally {
        client.release();
      }

      let oplugPurchaseAttempted = false;

      try {
        const supplierName = "Oplug";
        const supplierCost = product.supplier_cost;
        const requestId = `CDNG-${orderId}-${crypto.randomUUID()}`;

        const savedSupplier = await pgPool.query(
          `UPDATE orders
           SET supplier_name = $1, supplier_cost = $2,
               supplier_reference = $3
           WHERE id = $4 AND status IN ('pending', 'processing')`,
          [supplierName, supplierCost, requestId, orderId]
        );

        if (savedSupplier.rowCount !== 1) {
          throw new Error("Could not save Oplug order details");
        }

        oplugPurchaseAttempted = true;

        const oplugResponse = await axios.post(
          `${OPLUG_BASE_URL}/data`,
          {
            network: product.supplier_network,
            phone: cleanPhone,
            data_plan: product.plan_id,
            bypass: false,
            "request-id": requestId
          },
          {
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Token ${OPLUG_API_KEY}`
            },
            timeout: 20000
          }
        );

        const supplierData = oplugResponse.data;
        const supplierStatus = String(
          supplierData?.transaction_status || ""
        ).toUpperCase();

        console.info("Oplug purchase response:", {
          orderId,
          requestId,
          transactionStatus: supplierStatus
        });

        if (supplierStatus === "SUCCESS" || supplierStatus === "SUCCESSFUL") {
          const successUpdate = await pgPool.query(
            `UPDATE orders
             SET status = 'successful'
             WHERE id = $1 AND status IN ('pending', 'processing')`,
            [orderId]
          );

          if (successUpdate.rowCount !== 1) {
            const e = new Error("Could not confirm order status in database");
            e.orderPending = true;
            throw e;
          }

          return res.status(201).json({
            status: "success",
            message: "Order successful",
            order_id: orderId,
            supplier: supplierName
          });
        }

        const e = new Error(
          supplierData?.message || "Oplug has not confirmed this order"
        );

        if (supplierStatus === "FAILED") {
          e.confirmedFailure = true;
        } else {
          e.orderPending = true;
        }

        throw e;

      } catch (supplierError) {

        const responseBody = supplierError.response?.data;
        const redactSensitive = (value) => {
          let safe = String(value ?? "").slice(0, 200);
          if (cleanPhone) safe = safe.split(cleanPhone).join("[redacted-phone]");
          if (OPLUG_API_KEY) safe = safe.split(OPLUG_API_KEY).join("[redacted-key]");
          return safe
            .replace(/\b(?:\+?234|0)[789]\d{9}\b/g, "[redacted-phone]")
            .replace(/[\r\n]+/g, " ");
        };

        const safeSupplierResponse = {};
        if (responseBody && typeof responseBody === "object" && !Array.isArray(responseBody)) {
          for (const key of ["message", "error", "detail", "code", "transaction_status", "status"]) {
            if (["string", "number", "boolean"].includes(typeof responseBody[key])) {
              safeSupplierResponse[key] = redactSensitive(responseBody[key]);
            }
          }
        } else if (typeof responseBody === "string") {
          safeSupplierResponse.text = redactSensitive(responseBody);
        }

        console.error("Oplug order error:", {
          orderId,
          requestId,
          httpStatus: supplierError.response?.status || null,
          errorCode: supplierError.code || null,
          errorName: supplierError.name || null,
          supplierResponse: safeSupplierResponse,
          supplierMessage: redactSensitive(supplierError.message || "")
        });

        if (supplierError.orderPending || (oplugPurchaseAttempted && !supplierError.confirmedFailure)) {
          await pgPool.query(
            "UPDATE orders SET status = $1 WHERE id = $2 AND status IN ('pending', 'processing')",
            ["pending", orderId]
          );

          return res.status(202).json({
            status: "pending",
            message: "Supplier confirmation is pending. Do not repeat this purchase yet.",
            order_id: orderId,
            supplier: "Oplug"
          });
        }

        const refundClient = await pgPool.connect();
        let refundSucceeded = false;

        try {
          await refundClient.query("BEGIN");

          const refundWallet = await refundClient.query(
            `UPDATE users
             SET wallet_balance = wallet_balance + $1
             WHERE id = $2`,
            [product.price, userId]
          );

          if (refundWallet.rowCount !== 1) {
            throw new Error("Refund failed: customer wallet was not updated");
          }

          const failedOrder = await refundClient.query(
            `UPDATE orders
             SET status = $1
             WHERE id = $2 AND status IN ('pending', 'processing')`,
            ["failed", orderId]
          );

          if (failedOrder.rowCount !== 1) {
            throw new Error("Refund failed: order was not marked failed exactly once");
          }

          await refundClient.query("COMMIT");
          refundSucceeded = true;
        } catch (refundError) {
          try {
            await refundClient.query("ROLLBACK");
          } catch (rollbackError) {
            console.error("Refund rollback error:", rollbackError);
          }
          console.error("Order refund error:", refundError);
        } finally {
          refundClient.release();
        }

        if (!refundSucceeded) {
          return res.status(500).json({
            status: "error",
            message: "Supplier failed, but refund could not be confirmed. Contact support with this order ID.",
            order_id: orderId
          });
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


  // VERIFY OPLUG ORDER
  app.get("/api/orders/:id/verify", requireUser, async (req, res) => {
    try {
      const userId = req.userId;
      const orderId = Number(req.params.id);

      if (!Number.isInteger(orderId) || orderId < 1) {
        return res.status(400).json({ status: "error", message: "Invalid order ID" });
      }

      if (!OPLUG_API_KEY) {
        return res.status(503).json({ status: "error", message: "Data supplier is not configured" });
      }

      const found = await pgPool.query(
        `SELECT id, status, supplier_name, supplier_reference, price
         FROM orders WHERE id = $1 AND user_id = $2`,
        [orderId, userId]
      );

      if (found.rowCount !== 1) {
        return res.status(404).json({ status: "error", message: "Order not found" });
      }

      const order = found.rows[0];

      if (order.status !== "pending" && order.status !== "processing") {
        return res.json({ status: order.status, order_id: orderId });
      }

      if (order.supplier_name !== "Oplug" || !order.supplier_reference) {
        return res.status(400).json({ status: "error", message: "Oplug reference not found" });
      }

      const verifyResponse = await axios.get(
        `${OPLUG_BASE_URL}/verify-transaction`,
        {
          params: { "request-id": order.supplier_reference },
          headers: { "Authorization": `Token ${OPLUG_API_KEY}` },
          timeout: 20000
        }
      );

      const supplierStatus = String(verifyResponse.data?.transaction_status || "").toUpperCase();

      console.info("Oplug verification response:", {
        orderId,
        requestReference: order.supplier_reference,
        transactionStatus: supplierStatus
      });

      if (supplierStatus === "SUCCESS" || supplierStatus === "SUCCESSFUL") {
        await pgPool.query(
          `UPDATE orders SET status = 'successful'
           WHERE id = $1 AND user_id = $2
           AND status IN ('pending', 'processing')`,
          [orderId, userId]
        );

        return res.json({ status: "successful", order_id: orderId });
      }

      if (supplierStatus !== "FAILED") {
        return res.json({ status: "pending", order_id: orderId,
          message: "Supplier confirmation is still pending." });
      }

      const client = await pgPool.connect();
      let finalStatus = "pending";

      try {
        await client.query("BEGIN");

        const locked = await client.query(
          `SELECT status, price FROM orders
           WHERE id = $1 AND user_id = $2 FOR UPDATE`,
          [orderId, userId]
        );

        if (locked.rowCount !== 1) {
          throw new Error("Order not found during refund");
        }

        if (locked.rows[0].status === "pending" ||
            locked.rows[0].status === "processing") {
          const refund = await client.query(
            `UPDATE users SET wallet_balance = wallet_balance + $1
             WHERE id = $2`,
            [Number(locked.rows[0].price), userId]
          );

          if (refund.rowCount !== 1) {
            throw new Error("Wallet refund failed");
          }

          const failedUpdate = await client.query(
            `UPDATE orders SET status = 'failed'
             WHERE id = $1 AND user_id = $2`,
            [orderId, userId]
          );

          if (failedUpdate.rowCount !== 1) {
            throw new Error("Order status update failed during refund");
          }

          finalStatus = "failed";
        } else {
          finalStatus = locked.rows[0].status;
        }

        await client.query("COMMIT");
      } catch (refundError) {
        await client.query("ROLLBACK");
        throw refundError;
      } finally {
        client.release();
      }

      return res.json({
        status: finalStatus,
        order_id: orderId,
        message: finalStatus === "failed"
          ? "Supplier confirmed failure. Your wallet has been refunded."
          : "Order status updated."
      });

    } catch (error) {
      console.error("Oplug verification error:", {
        orderId,
        httpStatus: error.response?.status || null,
        errorCode: error.code || null,
        errorName: error.name || null
      });
      return res.status(502).json({
        status: "pending",
        message: "Could not confirm the order yet. Please check again later."
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


  app.get("/api/admin/oplug-balance", requireAdmin, async (req, res) => {
    try {
      if (!OPLUG_API_KEY) {
        return res.status(503).json({
          status: "error",
          message: "Oplug is not configured"
        });
      }

      const response = await axios.get(`${OPLUG_BASE_URL}/balance`, {
        headers: { Authorization: `Token ${OPLUG_API_KEY}` },
        timeout: 15000
      });

      return res.json({
        status: "success",
        supplier: "Oplug",
        balance: response.data?.balance,
        currency: response.data?.currency || "NGN",
        account_status: response.data?.user?.status || "unknown"
      });
    } catch (error) {
      console.error("Oplug balance check failed:", error.response?.status || error.message);
      return res.status(502).json({
        status: "error",
        message: "Could not check Oplug balance"
      });
    }
  });

  app.get("/api/admin/users", requireAdmin, async (req, res) => {
    try {
      const result = await pgPool.query(`
        SELECT id, name, email, phone, wallet_balance, is_admin
        FROM users
        ORDER BY id DESC
      `);

      const users = result.rows.map(row => ({
        id: row.id,
        name: row.name,
        email: row.email,
        phone: row.phone,
        wallet_balance: Number(row.wallet_balance || 0),
        is_admin: Number(row.is_admin) === 1
      }));

      res.json({
        status: "success",
        total: users.length,
        users
      });
    } catch (error) {
      console.error("Admin users PostgreSQL error:", error);
      res.status(500).json({
        status: "error",
        message: "Unable to load users"
      });
    }
  });


  // ADMIN PROFIT REPORT
  app.get("/api/admin/profit", requireAdmin, async (req, res) => {
    try {
      const result = await pgPool.query(`
        SELECT
          COUNT(*) FILTER (WHERE status = 'successful') AS successful_orders,
          COALESCE(SUM(price) FILTER (WHERE status = 'successful'), 0) AS total_sales,
          COUNT(*) FILTER (
            WHERE status = 'successful' AND supplier_cost IS NOT NULL
          ) AS orders_with_recorded_cost,
          COUNT(*) FILTER (
            WHERE status = 'successful' AND supplier_cost IS NULL
          ) AS orders_missing_supplier_cost,
          COALESCE(SUM(supplier_cost) FILTER (
            WHERE status = 'successful' AND supplier_cost IS NOT NULL
          ), 0) AS recorded_supplier_cost,
          COALESCE(SUM(price - supplier_cost) FILTER (
            WHERE status = 'successful' AND supplier_cost IS NOT NULL
          ), 0) AS profit_on_orders_with_recorded_cost
        FROM orders
      `);

      const row = result.rows[0];
      res.json({
        status: "success",
        report: {
          successful_orders: Number(row.successful_orders || 0),
          total_sales: Number(row.total_sales || 0),
          orders_with_recorded_cost: Number(row.orders_with_recorded_cost || 0),
          orders_missing_supplier_cost: Number(row.orders_missing_supplier_cost || 0),
          recorded_supplier_cost: Number(row.recorded_supplier_cost || 0),
          profit_on_orders_with_recorded_cost: Number(row.profit_on_orders_with_recorded_cost || 0),
          note: "Profit covers only successful orders with a recorded supplier cost. Missing costs must be recorded before total actual profit can be known."
        }
      });
    } catch (error) {
      console.error("Admin profit report error:", error);
      res.status(500).json({
        status: "error",
        message: "Unable to load profit report"
      });
    }
  });

  app.get("/api/admin/orders", requireAdmin, async (req, res) => {
    try {
      const result = await pgPool.query(`
        SELECT orders.id, orders.user_id, users.name, users.email,
               orders.network, orders.data, orders.price, orders.phone,
               orders.status, orders.created_at,
               orders.supplier_cost, orders.supplier_name,
               orders.supplier_reference
        FROM orders
        JOIN users ON users.id = orders.user_id
        ORDER BY orders.id DESC
      `);
      const orders = result.rows.map(row => ({
        id: row.id,
        user_id: row.user_id,
        customer: row.name,
        email: row.email,
        network: row.network,
        data: row.data,
        price: Number(row.price),
        supplier_cost: row.supplier_cost === null ? null : Number(row.supplier_cost),
        supplier_name: row.supplier_name,
        supplier_reference: row.supplier_reference,
        phone: row.phone,
        status: row.status,
        date: row.created_at
      }));
      res.json({ status: "success", orders });
    } catch (error) {
      console.error("Admin orders PostgreSQL error:", error);
      res.status(500).json({ status: "error", message: "Server error" });
    }
  });

  app.put("/api/admin/orders/:id/status", requireAdmin, async (req, res) => {
    try {
      const orderId = Number(req.params.id);
      const { status } = req.body;

      if (!Number.isSafeInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
          status: "error",
          message: "Invalid order ID"
        });
      }

      if (status === "successful" || status === "failed") {
        return res.status(409).json({
          status: "error",
          message: "Manual final status changes are disabled. Pending orders must be reviewed against confirmed supplier results."
        });
      }

      if (status !== "pending" && status !== "processing") {
        return res.status(400).json({
          status: "error",
          message: "Invalid order status"
        });
      }

      const result = await pgPool.query(
        `UPDATE orders SET status = $1
         WHERE id = $2 AND status IN ('pending', 'processing')`,
        [status, orderId]
      );

      if (result.rowCount === 0) {
        const existing = await pgPool.query(
          "SELECT id, status FROM orders WHERE id = $1",
          [orderId]
        );

        if (existing.rowCount === 0) {
          return res.status(404).json({
            status: "error",
            message: "Order not found"
          });
        }

        return res.status(409).json({
          status: "error",
          message: "Only pending or processing orders can be adjusted manually",
          order_status: existing.rows[0].status
        });
      }

      return res.json({
        status: "success",
        message: "Non-final order status updated"
      });
    } catch (error) {
      console.error("Admin status PostgreSQL error:", error);
      return res.status(500).json({
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
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    "CheapData server running on port " + PORT
  );
});
}

startServer().catch(error => {
  console.error("CheapData startup failed:", error.message);
  process.exit(1);
});
