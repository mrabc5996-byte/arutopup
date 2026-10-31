const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Aru123#?";
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const DATA_FILE = path.join(__dirname, "orders.json");

function readOrders() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return [];
  }
}

function saveOrders(orders) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(orders, null, 2));
}

// Simple signed admin token
function createToken() {
  const payload = Buffer.from(
    JSON.stringify({ exp: Date.now() + 24 * 60 * 60 * 1000 })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SECRET)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const parts = token.split(".");

  if (parts.length !== 2) {
    return res.status(401).json({ message: "Please login first" });
  }

  const expected = crypto
    .createHmac("sha256", SECRET)
    .update(parts[0])
    .digest("base64url");

  if (parts[1] !== expected) {
    return res.status(401).json({ message: "Invalid session" });
  }

  try {
    const payload = JSON.parse(
      Buffer.from(parts[0], "base64url").toString()
    );

    if (payload.exp < Date.now()) {
      return res.status(401).json({ message: "Session expired" });
    }
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }

  next();
}

// Admin login
app.post("/api/admin/login", (req, res) => {
  const password = req.body.password;

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      success: false,
      message: "Incorrect password"
    });
  }

  res.json({
    success: true,
    token: createToken()
  });
});

// Create customer order
app.post("/api/orders", (req, res) => {
  const { uid, playerName, package: pack, price, transactionId } = req.body;

  if (!uid || !pack || !transactionId) {
    return res.status(400).json({
      success: false,
      message: "UID, package and transaction ID required"
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
  saveOrders(orders);

  res.json({ success: true, order });
});

// Protected: all orders
app.get("/api/admin/orders", verifyToken, (req, res) => {
  res.json(readOrders());
});

// Protected: update order status
app.patch("/api/admin/orders/:id", verifyToken, (req, res) => {
  const orders = readOrders();
  const order = orders.find(o => o.id === req.params.id);

  if (!order) {
    return res.status(404).json({ message: "Order not found" });
  }

  const allowed = ["Pending", "Completed", "Cancelled"];

  if (!allowed.includes(req.body.status)) {
    return res.status(400).json({ message: "Invalid status" });
  }

  order.status = req.body.status;
  saveOrders(orders);

  res.json({ success: true, order });
});

// Admin page
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Home page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "FFX.html"));
});

app.listen(PORT, () => {
  console.log("ARU TOPUP running on port " + PORT);
});
