const express = require("express");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(__dirname));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change_this_password";

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

// Admin login
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      success: false,
      message: "Incorrect password"
    });
  }

  res.json({
    success: true,
    message: "Login successful"
  });
});

// Create new order
app.post("/api/orders", (req, res) => {
  const orders = readOrders();

  const order = {
    id: Date.now().toString(),
    uid: req.body.uid || "",
    playerName: req.body.playerName || "",
    package: req.body.package || "",
    price: req.body.price || 0,
    transactionId: req.body.transactionId || "",
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  orders.unshift(order);
  saveOrders(orders);

  res.json({
    success: true,
    message: "Order submitted",
    order
  });
});

// Get all orders
app.get("/api/admin/orders", (req, res) => {
  res.json(readOrders());
});

// Update order status
app.patch("/api/admin/orders/:id", (req, res) => {
  const orders = readOrders();
  const order = orders.find(o => o.id === req.params.id);

  if (!order) {
    return res.status(404).json({
      success: false,
      message: "Order not found"
    });
  }

  const allowed = ["Pending", "Completed", "Cancelled"];

  if (!allowed.includes(req.body.status)) {
    return res.status(400).json({
      success: false,
      message: "Invalid status"
    });
  }

  order.status = req.body.status;
  saveOrders(orders);

  res.json({
    success: true,
    order
  });
});

// Admin page
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

// Main website
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "FFX.html"));
});

app.listen(PORT, () => {
  console.log("ARU TOPUP server running on port " + PORT);
});
