const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_CODE = process.env.ADMIN_CODE;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "history.json");

if (!ADMIN_CODE || !SESSION_SECRET) {
  console.error("Set ADMIN_CODE and SESSION_SECRET environment variables before starting.");
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]", "utf8");

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  name: "trustcheck.sid",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", maxAge: 8 * 60 * 60 * 1000 }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: "draft-7", legacyHeaders: false });
const readHistory = () => {
  try { return JSON.parse(fs.readFileSync(DB_FILE, "utf8")); }
  catch { return []; }
};
const writeHistory = (items) => fs.writeFileSync(DB_FILE, JSON.stringify(items.slice(0, 100), null, 2), "utf8");
const requireAuth = (req, res, next) => req.session && req.session.authorized ? next() : res.status(401).json({ error: "Unauthorized" });

app.post("/api/auth", loginLimiter, (req, res) => {
  const supplied = String(req.body?.code || "");
  if (supplied.length > 100 || supplied !== ADMIN_CODE) return res.status(401).json({ error: "Invalid code" });
  req.session.authorized = true;
  res.json({ ok: true });
});
app.get("/api/history", requireAuth, (req, res) => res.json(readHistory()));
app.post("/api/history", requireAuth, (req, res) => {
  const r = req.body || {};
  if (typeof r.your !== "string" || typeof r.friend !== "string" ||
      !Array.isArray(r.answers) || r.answers.length !== 20 ||
      typeof r.score !== "number" || !Number.isFinite(r.score)) {
    return res.status(400).json({ error: "Invalid result" });
  }
  const safe = {
    id: Date.now(), your: r.your.slice(0, 30), friend: r.friend.slice(0, 30),
    score: Math.max(0, Math.min(10, r.score)),
    date: new Date().toLocaleString("ru-RU"),
    answers: r.answers.slice(0, 20).map(a => ({
      index: Number.isInteger(a.index) ? Math.max(0, Math.min(4, a.index)) : 0,
      label: String(a.label || "").slice(0, 30),
      custom: String(a.custom || "").slice(0, 180)
    }))
  };
  const history = readHistory();
  history.unshift(safe);
  writeHistory(history);
  res.json({ ok: true });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`TRUST CHECK listening on ${PORT}`));
