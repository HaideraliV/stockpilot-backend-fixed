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
  // Needed for gen_random_uuid()
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

  // Businesses table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Users table (now includes business_id)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,

      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      email TEXT,
      username TEXT,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Unique per business (email/username)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_business_email_uq
    ON users(business_id, email)
    WHERE email IS NOT NULL;
  `);

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_business_username_uq
    ON users(business_id, username)
    WHERE username IS NOT NULL;
  `);

  // Helpful indexes
  await pool.query(`
    CREATE INDEX IF NOT EXISTS users_business_idx ON users(business_id);
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(
    `CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`
  );
}

type DbUser = {
  id: string;
  business_id: string;
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
    businessId: u.business_id,
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
 * Creates a new Business + an ADMIN in that business
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

  // Create business first (name = fullName or email prefix)
  const bizName = fullName?.trim() || email.split("@")[0] || "My Business";
  const biz = await pool.query<{ id: string }>(
    `INSERT INTO businesses (name) VALUES ($1) RETURNING id`,
    [bizName]
  );
  const businessId = biz.rows[0].id;

  // Check if email already used in THIS business (usually won't happen, but safe)
  const existing = await pool.query<DbUser>(
    `SELECT * FROM users WHERE business_id = $1 AND email = $2 LIMIT 1`,
    [businessId, email]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const created = await pool.query<DbUser>(
    `INSERT INTO users (business_id, role, email, password_hash, full_name)
     VALUES ($1, 'ADMIN', $2, $3, $4)
     RETURNING *`,
    [businessId, email, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, admin: publicUser(created.rows[0]) });
});

/**
 * POST /auth/login
 * Admin: { email, password }
 * User:  { username, password }
 * Returns JWT token with businessId
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
    return res
      .status(400)
      .json({ error: "Provide email (admin) or username (user)" });
  }

  // ⚠️ With business separation, we need to find the user.
  // For now: login by global email OR global username is okay,
  // because the UI uses email for admin and username for user.
  // If you later allow the same username across businesses, you'll need a business selector.
  const q = email
    ? { text: `SELECT * FROM users WHERE email = $1 LIMIT 1`, values: [email] }
    : {
        text: `SELECT * FROM users WHERE username = $1 LIMIT 1`,
        values: [username],
      };

  const result = await pool.query<DbUser>(q.text, q.values);
  const user = result.rows[0];

  if (!user || !user.is_active) return res.status(401).json({ error: "Invalid login" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Invalid login" });

  const token = signToken({
    userId: user.id,
    role: user.role,
    businessId: user.business_id,
  });

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
 * Admin only. Creates a USER with username + password inside the SAME business.
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

  const jwtUser = (req as any).user as { businessId: string };

  // Check username inside THIS business only
  const existing = await pool.query<DbUser>(
    `SELECT * FROM users WHERE business_id = $1 AND username = $2 LIMIT 1`,
    [jwtUser.businessId, username]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Username already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  const created = await pool.query<DbUser>(
    `INSERT INTO users (business_id, role, username, password_hash, full_name)
     VALUES ($1, 'USER', $2, $3, $4)
     RETURNING *`,
    [jwtUser.businessId, username, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, user: publicUser(created.rows[0]) });
});

/* -------------------- start -------------------- */

async function start() {
  try {
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
