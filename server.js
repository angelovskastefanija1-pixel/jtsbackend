import express from "express";
import path from "path";
import fs from "fs";
import multer from "multer";
import session from "express-session";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/* -------------------- CORS -------------------- */
app.set("trust proxy", 1);

app.use((req, res, next) => {
  const allowedOrigins = [
    "https://jtslogistics.net",
    "https://www.jtslogistics.net",
    "http://localhost:3000",
    "http://127.0.0.1:3000"
  ];

  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Vary", "Origin");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

/* -------------------- MIDDLEWARE -------------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "none",
      secure: true
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "public", "uploads")));

/* -------------------- FILE PATHS -------------------- */
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONTENT_FILE = path.join(DATA_DIR, "content.json");
const MSG_FILE = path.join(DATA_DIR, "messages.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

/* -------------------- HELPERS -------------------- */
function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* -------------------- DEFAULT FILES -------------------- */
if (!fs.existsSync(USERS_FILE)) {
  writeJSON(USERS_FILE, [
    {
      username: "admin",
      passwordHash: bcrypt.hashSync("1234", 10),
      role: "admin"
    },
    {
      username: "user",
      passwordHash: bcrypt.hashSync("7890", 10),
      role: "limited"
    }
  ]);
}

if (!fs.existsSync(CONTENT_FILE)) {
  writeJSON(CONTENT_FILE, {
    hero: {
      title: "JTS Logistics INC — Truck Dispatch",
      subtitle: "Loading...",
      bullets: []
    },
    services: [],
    process: [],
    pricing: [],
    tops: [],
    contact: {},
    footer: {},
    updatedAt: new Date().toISOString()
  });
}

if (!fs.existsSync(MSG_FILE)) {
  writeJSON(MSG_FILE, []);
}

/* -------------------- AUTH -------------------- */
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

function isLimited(req) {
  return req.session?.user?.role === "limited";
}

/* -------------------- LOGIN -------------------- */
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE) || [];
  const user = users.find((x) => x.username === username);

  if (!user) return res.json({ ok: false });

  if (!bcrypt.compareSync(password, user.passwordHash)) {
    return res.json({ ok: false });
  }

  req.session.user = {
    username: user.username,
    role: user.role
  };

  res.json({ ok: true, role: user.role });
});

/* -------------------- LOGOUT -------------------- */
app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

/* -------------------- SESSION -------------------- */
app.get("/api/admin/me", (req, res) => {
  if (req.session?.user) {
    return res.json({ ok: true, user: req.session.user });
  }

  return res.status(401).json({ ok: false });
});

/* -------------------- CONTENT -------------------- */
app.get("/api/content", (_req, res) => {
  res.json(readJSON(CONTENT_FILE));
});

app.get("/api/admin/content", requireAuth, (_req, res) => {
  res.json(readJSON(CONTENT_FILE));
});

app.put("/api/admin/content", requireAuth, (req, res) => {
  const incoming = req.body || {};
  const existing = readJSON(CONTENT_FILE) || {};

  const next = isLimited(req)
    ? { ...existing, tops: incoming.tops || existing.tops }
    : { ...existing, ...incoming };

  next.updatedAt = new Date().toISOString();

  writeJSON(CONTENT_FILE, next);

  res.json({ ok: true, content: next });
});

/* -------------------- UPLOAD ENGINE -------------------- */
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOADS_DIR);
  },
  filename: (_req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-z0-9.\-_]+/gi, "_");
    cb(null, Date.now() + "_" + safeName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 15 * 1024 * 1024
  }
});

const multiUpload = upload.fields([
  { name: "license", maxCount: 1 },
  { name: "medcard", maxCount: 1 },
  { name: "extra", maxCount: 10 }
]);

/* -------------------- BREVO API EMAIL -------------------- */
async function sendBrevoEmail({ subject, html, attachments }) {
  if (!process.env.BREVO_API_KEY) {
    throw new Error("Missing BREVO_API_KEY in Render Environment");
  }

  if (!process.env.MAIL_FROM) {
    throw new Error("Missing MAIL_FROM in Render Environment");
  }

  if (!process.env.MAIL_TO) {
    throw new Error("Missing MAIL_TO in Render Environment");
  }

  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: {
      accept: "application/json",
      "api-key": process.env.BREVO_API_KEY,
      "content-type": "application/json"
    },
    body: JSON.stringify({
      sender: {
        name: "JTS Logistics",
        email: process.env.MAIL_FROM
      },
      to: [
        {
          email: process.env.MAIL_TO
        }
      ],
      subject,
      htmlContent: html,
      attachment: attachments
    })
  });

  const result = await response.json().catch(() => ({}));

  if (!response.ok) {
    console.error("Brevo API error:", result);
    throw new Error(result.message || "Brevo email failed");
  }

  return result;
}

/* -------------------- DRIVER APPLICATION FORM -------------------- */
app.post("/api/apply", multiUpload, async (req, res) => {
  try {
    const data = req.body || {};
    const files = req.files || {};

    console.log("BODY:", data);
    console.log("FILES:", Object.keys(files));

    if (!files.license || !files.medcard) {
      return res.status(400).json({
        ok: false,
        error: "Missing required documents",
        receivedFiles: Object.keys(files)
      });
    }

    const htmlBody = `
      <h3>New Driver Employment Application</h3>

      <table border="1" cellspacing="0" cellpadding="6">
        ${Object.entries(data)
          .map(
            ([key, value]) =>
              `<tr>
                <td><b>${escapeHTML(key)}</b></td>
                <td>${escapeHTML(value)}</td>
              </tr>`
          )
          .join("")}
      </table>
    `;

    const attachments = [];

    Object.keys(files).forEach((key) => {
      files[key].forEach((file) => {
        attachments.push({
          name: file.originalname,
          content: fs.readFileSync(file.path).toString("base64")
        });
      });
    });

    const subject = `New Driver Application - ${
      data["First Name"] || "Unknown"
    } ${data["Last Name"] || ""}`;

    await sendBrevoEmail({
      subject,
      html: htmlBody,
      attachments
    });

    const messages = readJSON(MSG_FILE) || [];

    messages.push({
      ...data,
      documents: Object.keys(files),
      createdAt: new Date().toISOString()
    });

    writeJSON(MSG_FILE, messages);

    res.json({
      ok: true,
      message: "Application sent successfully"
    });
  } catch (err) {
    console.error("Driver application error:", err.message);
    console.error("Full error:", err);

    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

/* -------------------- INBOX -------------------- */
app.get("/api/admin/messages", requireAuth, (_req, res) => {
  res.json(readJSON(MSG_FILE) || []);
});

/* -------------------- HEALTH CHECK -------------------- */
app.get("/", (_req, res) => {
  res.send("JTS Backend is running");
});

/* -------------------- START SERVER -------------------- */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});