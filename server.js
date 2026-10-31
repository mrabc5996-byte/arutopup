const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "100kb" }));
app.use(express.static(__dirname));
const SETTINGS_FILE = path.join(__dirname, "settings.json");
const DEPOSITS_FILE = path.join(__dirname, "deposits.json");
const WALLETS_FILE = path.join(__dirname, "wallets.json");

function readDeposits() {
  return readJSON(DEPOSITS_FILE);
}

function readWallets() {
  return readJSON(WALLETS_FILE, {});
}
}
const ADMIN_PASSWORD = "Aru330#?";
const SECRET ="ARU_TOPUP_SECRET_2026";

const ORDERS_FILE = path.join(__dirname, "orders.json");
const PRODUCTS_FILE = path.join(__dirname, "products.json");

function readJSON(file, fallback = []) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function readOrders() {
  return readJSON(ORDERS_FILE);
}

function readProducts() {
  return readJSON(PRODUCTS_FILE);
}

// ADMIN TOKEN
function createToken() {
  const payload = Buffer.from(JSON.stringify({
    exp: Date.now() + 86400000
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace(/^Bearer\s+/i, "");

  const parts = token.split(".");

  if (!SECRET || parts.length !== 2) {
    return res.status(401).json({ message: "Login required" });
  }

  const expected = crypto
    .createHmac("sha256", SECRET)
    .update(parts[0])
    .digest("base64url");

  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ message: "Invalid token" });
  }

  try {
    const data = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (data.exp < Date.now()) {
      return res.status(401).json({ message: "Session expired" });
    }
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }

  next();
}

// ADMIN LOGIN
app.post("/api/admin/login", (req, res) => {
  if (!ADMIN_PASSWORD || !SECRET) {
    return res.status(503).json({
      message: "Admin settings missing"
    });
  }

  if (req.body.password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      message: "Incorrect password"
    });
  }

  res.json({
    success: true,
    token: createToken()
  });
});
// ===============================
// BKASH PAYMENT SETTINGS
// ===============================

// PUBLIC: Website payment settings
app.get("/api/payment-settings", (req, res) => {
  const settings = readSettings();

  res.json({
    paymentMethod: "bKash",
    bkashNumber: settings.bkashNumber
  });
});

// ADMIN: Get payment settings
app.get("/api/admin/payment-settings", verifyToken, (req, res) => {
  res.json(readSettings());
});

// ADMIN: Update bKash number
app.put("/api/admin/payment-settings", verifyToken, (req, res) => {
  const number = String(req.body.bkashNumber || "").trim();

  if (!/^01[3-9]\d{8}$/.test(number)) {
    return res.status(400).json({
      success: false,
      message: "Valid Bangladesh mobile number required"
    });
  }

  const settings = {
    paymentMethod: "bKash",
    bkashNumber: number
  };

  saveJSON(SETTINGS_FILE, settings);

  res.json({
    success: true,
    message: "bKash number updated",
    settings
  });
});
// PUBLIC PRODUCT LIST
app.get("/api/products", (req, res) => {
  res.json(readProducts().filter(p => p.active !== false));
});

// ADMIN PRODUCT LIST
app.get("/api/admin/products", verifyToken, (req, res) => {
  res.json(readProducts());
});

// ADD PRODUCT
app.post("/api/admin/products", verifyToken, (req, res) => {
  const { name, price, category } = req.body || {};

  const productName = String(name || "").trim();
  const productCategory = String(category || "").trim();
  const productPrice = Number(price);

  if (
    !productName ||
    !productCategory ||
    !Number.isFinite(productPrice) ||
    productPrice < 0
  ) {
    return res.status(400).json({
      message: "Valid name, category and price required"
    });
  }

  const products = readProducts();

  const product = {
    id: crypto.randomUUID(),
    name: productName,
    price: productPrice,
    category: productCategory,
    active: true
  };

  products.push(product);
  saveJSON(PRODUCTS_FILE, products);

  res.status(201).json({
    success: true,
    product
  });
});

// UPDATE PRODUCT
app.patch("/api/admin/products/:id", verifyToken, (req, res) => {
  const products = readProducts();

  const product = products.find(
    p => p.id === req.params.id
  );

  if (!product) {
    return res.status(404).json({
      message: "Product not found"
    });
  }

  if (req.body.name !== undefined) {
    const name = String(req.body.name).trim();

    if (!name) {
      return res.status(400).json({
        message: "Product name required"
      });
    }

    product.name = name;
  }

  if (req.body.price !== undefined) {
    const price = Number(req.body.price);

    if (!Number.isFinite(price) || price < 0) {
      return res.status(400).json({
        message: "Invalid price"
      });
    }

    product.price = price;
  }

  if (req.body.category !== undefined) {
    product.category = String(req.body.category).trim();
  }

  if (req.body.active !== undefined) {
    product.active = Boolean(req.body.active);
  }

  saveJSON(PRODUCTS_FILE, products);

  res.json({
    success: true,
    product
  });
});

// DELETE PRODUCT
app.delete("/api/admin/products/:id", verifyToken, (req, res) => {
  const products = readProducts();

  const updated = products.filter(
    p => p.id !== req.params.id
  );

  if (updated.length === products.length) {
    return res.status(404).json({
      message: "Product not found"
    });
  }

  saveJSON(PRODUCTS_FILE, updated);

  res.json({ success: true });
});
// ===================================
// ARU TOPUP - ADD MONEY & WALLET API
// ===================================

// CUSTOMER: Submit Add Money Request
app.post("/api/add-money", (req, res) => {
  const { uid, amount, senderNumber, transactionId } = req.body || {};

  const customerUID = String(uid || "").trim();
  const sender = String(senderNumber || "").trim();
  const trx = String(transactionId || "").trim();
  const money = Number(amount);

  if (!customerUID || !sender || !trx) {
    return res.status(400).json({
      success: false,
      message: "All information required"
    });
  }

  if (!Number.isFinite(money) || money < 10 || money > 50000) {
    return res.status(400).json({
      success: false,
      message: "Amount must be between 10 and 50000"
    });
  }

  if (!/^01[3-9]\d{8}$/.test(sender)) {
    return res.status(400).json({
      success: false,
      message: "Invalid sender number"
    });
  }

  const deposits = readDeposits();

  const duplicate = deposits.some(
    d => d.transactionId.toLowerCase() === trx.toLowerCase()
  );

  if (duplicate) {
    return res.status(409).json({
      success: false,
      message: "Transaction ID already submitted"
    });
  }

  const deposit = {
    id: crypto.randomUUID(),
    uid: customerUID,
    amount: money,
    senderNumber: sender,
    transactionId: trx,
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  deposits.unshift(deposit);
  saveJSON(DEPOSITS_FILE, deposits);

  res.status(201).json({
    success: true,
    message: "Request submitted. Waiting for admin verification.",
    deposit
  });
});


// ADMIN: View Add Money Requests
app.get("/api/admin/deposits", verifyToken, (req, res) => {
  res.json(readDeposits());
});


// ADMIN: Approve or Reject Request
app.patch("/api/admin/deposits/:id", verifyToken, (req, res) => {
  const { status } = req.body || {};

  if (!["Approved", "Rejected"].includes(status)) {
    return res.status(400).json({
      success: false,
      message: "Invalid status"
    });
  }

  const deposits = readDeposits();

  const deposit = deposits.find(
    d => d.id === req.params.id
  );

  if (!deposit) {
    return res.status(404).json({
      success: false,
      message: "Request not found"
    });
  }

  if (deposit.status !== "Pending") {
    return res.status(409).json({
      success: false,
      message: "Request already processed"
    });
  }

  if (status === "Approved") {
    const wallets = readWallets();

    const uid = deposit.uid;

    wallets[uid] = Number(wallets[uid] || 0) + deposit.amount;

    saveJSON(WALLETS_FILE, wallets);
  }

  deposit.status = status;
  deposit.updatedAt = new Date().toISOString();

  saveJSON(DEPOSITS_FILE, deposits);

  res.json({
    success: true,
    message: status === "Approved"
      ? "Money added to wallet"
      : "Request rejected",
    deposit
  });
});


// ADMIN: View Wallet Balances
app.get("/api/admin/wallets", verifyToken, (req, res) => {
  res.json(readWallets());
});
// CREATE ORDER
app.post("/api/orders", (req, res) => {
  const {
    uid,
    playerName,
    package: pack,
    price,
    transactionId
  } = req.body || {};

  if (!uid || !pack || !transactionId) {
    return res.status(400).json({
      success: false,
      message: "Required information missing"
    });
  }

  const orders = readOrders();

  const order = {
    id: Date.now().toString(),
    uid: String(uid),
    playerName: String(playerName || ""),
    package: String(pack),
    price: Number(price) || 0,
    transactionId: String(transactionId),
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  orders.unshift(order);
  saveJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    order
  });
});

// ADMIN ORDERS
app.get("/api/admin/orders", verifyToken, (req, res) => {
  res.json(readOrders());
});

// UPDATE ORDER STATUS
app.patch("/api/admin/orders/:id", verifyToken, (req, res) => {
  const orders = readOrders();

  const order = orders.find(
    o => o.id === req.params.id
  );

  if (!order) {
    return res.status(404).json({
      message: "Order not found"
    });
  }

  if (!["Pending", "Completed", "Cancelled"].includes(req.body.status)) {
    return res.status(400).json({
      message: "Invalid status"
    });
  }

  order.status = req.body.status;
  saveJSON(ORDERS_FILE, orders);

  res.json({
    success: true,
    order
  });
});

// PAGES
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "FFX.html"));
});

app.listen(PORT, () => {
  console.log("ARU TOPUP running on port " + PORT);
});
