const express = require("express");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = "users.json";

app.use("/api/paystack/webhook", express.raw({ type: "application/json" }));
app.use(express.json());
let users = fs.existsSync(DATA_FILE)
  ? JSON.parse(fs.readFileSync(DATA_FILE))
  : [];

function saveUsers() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

app.get("/api", (req, res) => {
  res.json({
    status: "success",
    message: "CheapData backend is working!"
  });
});

app.post("/api/signup", async (req, res) => {
  const { name, email, phone, password } = req.body;

  if (!name || !email || !phone || !password) {
    return res.status(400).json({
      status: "error",
      message: "All fields are required"
    });
  }

  if (users.find(u => u.email === email)) {
    return res.status(400).json({
      status: "error",
      message: "Email already registered"
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = {
    id: users.length + 1,
    name,
    email,
    phone,
    password: hashedPassword,
    wallet: 0,
    transactions: []
  };

  users.push(user);
  saveUsers();

  res.json({
    status: "success",
    message: "Registration successful",
    userId: user.id
  });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
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
      wallet: user.wallet
    }
  });
});
app.get("/api/wallet/:userId", (req, res) => {
  const user = users.find(u => u.id == req.params.userId);

  if (!user) {
    return res.status(404).json({
      status: "error",
      message: "User not found"
    });
  }

  res.json({
    status: "success",
    wallet: user.wallet
  });
});
const axios = require("axios");

app.post("/api/wallet/fund", async (req, res) => {
  const { user_id, amount } = req.body;

  const user = users.find(u => u.id == user_id);

  if (!user) {
    return res.status(404).json({
      status: "error",
      message: "User not found"
    });
  }

  if (!amount || amount < 100) {
    return res.status(400).json({
      status: "error",
      message: "Minimum funding amount is ₦100"
    });
  }

  try {
    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      {
        email: user.email,
        amount: Math.round(amount * 100),
        callback_url: "https://cheapdata-backend.onrender.com/api/payment/callback"
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    res.json({
      status: "success",
      authorization_url: response.data.data.authorization_url,
      reference: response.data.data.reference
    });
  } catch (error) {
    console.error("Paystack error:", error.response?.data || error.message);

    res.status(500).json({
      status: "error",
      message: "Unable to initialize payment"
    });
  }
});
app.get("/api/payment/callback", async (req, res) => {
  const { reference } = req.query;

  if (!reference) {
    return res.status(400).send("Payment reference missing");
  }

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    const payment = response.data.data;

    if (payment.status !== "success") {
      return res.status(400).send("Payment was not successful");
    }

    const user = users.find(u => u.email === payment.customer.email);

    if (!user) {
      return res.status(404).send("User not found");
    }

    const alreadyCredited = user.transactions?.find(
      t => t.reference === reference
    );

    if (alreadyCredited) {
      return res.send("Payment already credited");
    }

    const amount = payment.amount / 100;

    user.wallet += amount;

    if (!user.transactions) {
      user.transactions = [];
    }

    user.transactions.push({
      type: "wallet_funding",
      amount,
      reference,
      status: "success",
      date: new Date().toISOString()
    });

    saveUsers();

    res.send("Payment successful. Wallet credited.");
  } catch (error) {
    console.error(
      "Payment verification error:",
      error.response?.data || error.message
    );

    res.status(500).send("Unable to verify payment");
  }
});
const crypto = require("crypto");
app.post("/api/paystack/webhook", (req, res) => {
  try {
    const hash = crypto
      .createHmac("sha512", process.env.PAYSTACK_SECRET_KEY)
      .update(req.body)
      .digest("hex");

    if (hash !== req.headers["x-paystack-signature"]) {
      return res.status(401).send("Invalid signature");
    }

    const event = JSON.parse(req.body.toString());

    if (event.event !== "charge.success") {
      return res.sendStatus(200);
    }

    const payment = event.data;

    if (payment.status !== "success" || payment.currency !== "NGN") {
      return res.sendStatus(200);
    }

    const reference = payment.reference;
    const amount = payment.amount / 100;
    const email = payment.customer.email;

    const user = users.find(u => u.email === email);

    if (!user) {
      console.log("User not found:", email);
      return res.sendStatus(200);
    }

    if (!user.transactions) {
      user.transactions = [];
    }

    const alreadyCredited = user.transactions.find(
      t => t.reference === reference
    );

    if (alreadyCredited) {
      console.log("Payment already credited:", reference);
      return res.sendStatus(200);
    }

    user.wallet += amount;

    user.transactions.push({
      type: "wallet_funding",
      amount: amount,
      reference: reference,
      status: "success",
      date: new Date().toISOString()
    });

    saveUsers();

    console.log(`Wallet credited: ${email} +₦${amount}`);

    res.sendStatus(200);

  } catch (error) {
    console.error("Webhook error:", error);
    res.sendStatus(500);
  }
});
app.post("/api/orders", (req, res) => {
  const { user_id, network, data, price, phone } = req.body;

  if (!user_id || !network || !data || !price || !phone) {
    return res.status(400).json({
      status: "error",
      message: "All order fields are required"
    });
  }

  const user = users.find(u => u.id == user_id);

  if (!user) {
    return res.status(404).json({
      status: "error",
      message: "User not found"
    });
  }

  if (user.wallet < price) {
    return res.status(400).json({
      status: "error",
      message: "Insufficient wallet balance"
    });
  }

  user.wallet -= Number(price);

  if (!user.transactions) {
    user.transactions = [];
  }

  user.transactions.push({
    type: "data_purchase",
    network,
    data,
    phone,
    amount: Number(price),
    status: "pending",
    date: new Date().toISOString()
  });

  saveUsers();

  res.json({
    status: "success",
    message: "Order successful",
    order: {
      network,
      data,
      phone,
      price: Number(price),
      status: "pending"
    }
  });
});
app.listen(PORT, "0.0.0.0", () => {
  console.log("CheapData server running on port " + PORT);
});

