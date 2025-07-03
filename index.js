require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const app = express();
const PORT = process.env.PORT || 8080;
const MONGO = process.env.MONGOURL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!MONGO || !JWT_SECRET) {
  console.error("Missing MONGOURL or JWT_SECRET in environment");
  process.exit(1);
}

app.use(express.json());
app.use(cors({ origin: "*" }));

mongoose
  .connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
  text: { type: String, required: true },
  status: { type: String, default: "pending" },
  priority: { type: String, default: "normal" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});
const Task = mongoose.model("Task", taskSchema);

const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password required" });

  const exists = await User.findOne({ username });
  if (exists)
    return res.status(400).json({ message: "Username already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.json({ message: "User registered successfully" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Username and password required" });

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

app.get("/tasks", authMiddleware, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId });
  res.json(tasks);
});

app.post("/tasks", authMiddleware, async (req, res) => {
  const { text, status, priority } = req.body;
  if (!text) return res.status(400).json({ message: "Task text is required" });

  const task = new Task({
    text,
    status: status || "pending",
    priority: priority || "normal",
    userId: req.userId,
  });

  await task.save();
  res.json(task);
});

app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  await Task.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  res.json({ message: "Task deleted" });
});

app.patch("/tasks/:id/status", authMiddleware, async (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ message: "Status is required" });

  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { status },
    { new: true }
  );

  if (!task) return res.status(404).json({ message: "Task not found" });
  res.json(task);
});

app.patch("/tasks/:id/priority", authMiddleware, async (req, res) => {
  const { priority } = req.body;
  if (!priority)
    return res.status(400).json({ message: "Priority is required" });

  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { priority },
    { new: true }
  );

  if (!task) return res.status(404).json({ message: "Task not found" });
  res.json(task);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
