// src/index.ts
import "dotenv/config";

import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import { z } from "zod";

import { pool } from "./db.js";
import { signToken, requireAuth, requireAdmin } from "./auth.js";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT ?? 4000);

/* -------------------- helpers -------------------- */

async function ensureTables() {
  // Creates the users table if it doesn't exist
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      email TEXT UNIQUE,
      username TEXT UNIQUE,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Helpful indexes (safe if run multiple times)
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`);
}

type DbUser = {
  id: string;
  role: "ADMIN" | "USER";
  email: string | null;
  username: string | null;
  password_hash: string;
  full_name: string | null;
  is_active: boolean;
};

function publicUser(u: DbUser) {
  return {
    id: u.id,
    role: u.role,
    email: u.email,
    username: u.username,
    fullName: u.full_name,
    isActive: u.is_active,
  };
}

/* -------------------- routes -------------------- */

// Health check
app.get("/", async (_req, res) => {
  res.json({ ok: true, app: "StockPilot Backend" });
});

// DB check
app.get("/db", async (_req, res) => {
  try {
    const r = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: r.rows[0] });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message ?? "db error" });
  }
});

/**
 * POST /auth/register-admin
 * Body: { email, password, fullName? }
 */
app.post("/auth/register-admin", async (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { email, password, fullName } = parsed.data;

  // Check if email already used
  const existing = await pool.query<DbUser>(
    `SELECT * FROM users WHERE email = $1 LIMIT 1`,
    [email]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const created = await pool.query<DbUser>(
    `INSERT INTO users (role, email, password_hash, full_name)
     VALUES ('ADMIN', $1, $2, $3)
     RETURNING *`,
    [email, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, admin: publicUser(created.rows[0]) });
});

/**
 * POST /auth/login
 * Admin: { email, password }
 * User:  { username, password }
 */
app.post("/auth/login", async (req, res) => {
  const schema = z.object({
    email: z.string().email().optional(),
    username: z.string().min(2).optional(),
    password: z.string().min(8),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { email, username, password } = parsed.data;

  if (!email && !username) {
    return res.status(400).json({ error: "Provide email (admin) or username (user)" });
  }

  const q = email
    ? { text: `SELECT * FROM users WHERE email = $1 LIMIT 1`, values: [email] }
    : { text: `SELECT * FROM users WHERE username = $1 LIMIT 1`, values: [username] };

  const result = await pool.query<DbUser>(q.text, q.values);
  const user = result.rows[0];

  if (!user || !user.is_active) return res.status(401).json({ error: "Invalid login" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid login" });

  const token = signToken({ userId: user.id, role: user.role });

  res.json({
    ok: true,
    token,
    user: publicUser(user),
  });
});

// Example protected route
app.get("/me", requireAuth, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string };

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
    [jwtUser.userId]
  );
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ ok: true, user: publicUser(user) });
});

/**
 * POST /admin/create-user
 * Admin only. Creates a USER with username + password.
 * Body: { username, password, fullName? }
 */
app.post("/admin/create-user", requireAuth, requireAdmin, async (req, res) => {
  const schema = z.object({
    username: z.string().min(2),
    password: z.string().min(8),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { username, password, fullName } = parsed.data;

  const existing = await pool.query<DbUser>(
    `SELECT * FROM users WHERE username = $1 LIMIT 1`,
    [username]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Username already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const created = await pool.query<DbUser>(
    `INSERT INTO users (role, username, password_hash, full_name)
     VALUES ('USER', $1, $2, $3)
     RETURNING *`,
    [username, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, user: publicUser(created.rows[0]) });
});

/* -------------------- start -------------------- */

async function start() {
  try {
    // Needed for gen_random_uuid()
    await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

    await ensureTables();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`✅ Running on port ${PORT}`);
    });
  } catch (e) {
    console.error("❌ Startup error (raw):", e);
    if (e instanceof Error) console.error(e.stack);
    process.exit(1);
  }
}

start();
