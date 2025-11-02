import express from "express";
import cors from "cors";
import path from "path";
import fs from "fs";
import multer from "multer";
import nodemailer from "nodemailer";
import session from "express-session";
import bcrypt from "bcryptjs";
import sharp from "sharp";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
    import sgMail from "@sendgrid/mail";
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);

dotenv.config();
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// ✅ Allow your frontend domain


app.use(
  cors({
    origin: ["https://jtslogistics.net", "https://www.jtslogistics.net"],
    methods: ["GET", "POST", "PUT"],
    allowedHeaders: ["Content-Type"],
    credentials: true, // ✅ важно за cookie session
  })
);
// ✅ Explicitly allow credentials header in all responses
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});



const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONTENT_FILE = path.join(DATA_DIR, "content.json");
const MSG_FILE = path.join(DATA_DIR, "messages.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Helpers
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8") || "null");
  } catch (e) {
    return null;
  }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

// Default users
if (!fs.existsSync(USERS_FILE)) {
  const users = [
    { username: "admin", passwordHash: bcrypt.hashSync("1234", 10), role: "admin" },
    { username: "user", passwordHash: bcrypt.hashSync("7890", 10), role: "limited" },
  ];
  writeJSON(USERS_FILE, users);
}

// Default content
if (!fs.existsSync(CONTENT_FILE)) {
  const defaultContent = {
    hero: {
      title: "JTS Logistics INC — Truck Dispatch",
      subtitle: "Loading...",
      bullets: ["Top load sourcing", "Paperwork handled"],
    },
    services: [],
    process: [],
    pricing: [],
    tops: [
      { rank: "Winner", name: "—", route: "Route A → B", km: "0", image: "", video: "" },
      { rank: "Silver", name: "—", route: "Route A → B", km: "0", image: "", video: "" },
      { rank: "Bronze", name: "—", route: "Route A → B", km: "0", image: "", video: "" },
    ],
    contact: { phone: "", email: "", location: "" },
    footer: { brandText: "JTS Logistics INC" },
    updatedAt: new Date().toISOString(),
  };
  writeJSON(CONTENT_FILE, defaultContent);
}
if (!fs.existsSync(MSG_FILE)) writeJSON(MSG_FILE, []);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "none", // ✅ важно за cross-domain (Render ↔ Net)
      secure: true,     // ✅ cookie ќе оди само преку HTTPS
    },
  })
);

app.use(express.static(path.join(__dirname, "public")));

// Auth helpers
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ ok: false, error: "Unauthorized" });
}
function isLimited(req) {
  return req.session?.user?.role === "limited";
}

// 🟢 LOGIN
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE) || [];
  const u = users.find((x) => x.username === username);
  if (!u) return res.json({ ok: false });
  if (!bcrypt.compareSync(password, u.passwordHash)) return res.json({ ok: false });
  req.session.user = { username: u.username, role: u.role };
  res.json({ ok: true, role: u.role });
});

// 🟢 LOGOUT
app.post("/api/admin/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

// 🟢 SESSION
app.get("/api/admin/me", (req, res) => {
  if (req.session && req.session.user) return res.json({ ok: true, user: req.session.user });
  res.status(401).json({ ok: false });
});

// 🟢 CONTENT (public + admin)
app.get("/api/content", (_req, res) => res.json(readJSON(CONTENT_FILE)));
app.get("/api/admin/content", requireAuth, (_req, res) => res.json(readJSON(CONTENT_FILE)));

app.put("/api/admin/content", requireAuth, (req, res) => {
  const incoming = req.body || {};
  const existing = readJSON(CONTENT_FILE) || {};
  let next;

  if (isLimited(req)) {
    next = { ...existing, tops: incoming.tops || existing.tops };
  } else {
    next = { ...existing, ...incoming };
  }

  next.updatedAt = new Date().toISOString();
  writeJSON(CONTENT_FILE, next);
  res.json({ ok: true, content: next });
});

// 🟢 CONTACT + EMAIL
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) =>
    cb(null, Date.now() + "_" + file.originalname.replace(/[^a-z0-9.\-_]+/gi, "_")),
});
const upload = multer({ storage });

// 🟢 DRIVER APPLICATION FORM
app.post("/api/apply", upload.single("attachment"), async (req, res) => {
  try {
    const data = req.body;
    const file = req.file ? `/uploads/${req.file.filename}` : null;

    const htmlBody = `
      <h3>🧾 New Driver Employment Application</h3>
      <table border="1" cellspacing="0" cellpadding="5" style="border-collapse:collapse;">
        ${Object.entries(data)
          .map(([key, val]) => `<tr><td><b>${key}</b></td><td>${val || ""}</td></tr>`)
          .join("")}
      </table>
      ${file ? `<p><b>Attachment:</b> ${file}</p>` : ""}
    `;

    // ✅ SENDGRID API METHOD

    const msg = {
      to: ["recruiting@jtslogistics.net", process.env.NOTIFY_TO],
      from: "websolution.mn@gmail.com", // истиот што е верифициран во SendGrid
      subject: `New Driver Application – ${data["First Name"] || "No name"}`,
      html: htmlBody,
    };

    // ако има прикачен фајл
    if (file) {
      const filePath = path.join(__dirname, "public", file);
      const fileContent = fs.readFileSync(filePath).toString("base64");
      msg.attachments = [
        {
          content: fileContent,
          filename: path.basename(filePath),
          type: "application/octet-stream",
          disposition: "attachment",
        },
      ];
    }

    await sgMail.send({
  to: ["recruiting@jtslogistics.net", process.env.NOTIFY_TO],
  from: "websolution.mn@gmail.com",
  subject: `New Driver Application – ${data["First Name"] || "No name"}`,
  html: htmlBody,
});


    // снимаме локално
    const msgs = readJSON(MSG_FILE) || [];
    msgs.push({ ...data, attachment: file, createdAt: new Date().toISOString() });
    writeJSON(MSG_FILE, msgs);

    res.json({ ok: true });
  } catch (err) {
    console.error("❌ Driver application error:", err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// 🟢 INBOX MESSAGES (for admin panel)
app.get("/api/admin/messages", requireAuth, (req, res) => {
  const msgs = readJSON(MSG_FILE) || [];
  res.json(msgs);
});


//app.get("*", (_req, res) =>
//  res.sendFile(path.join(__dirname, "public", "index.html"))
//);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
