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

const PORT = Number(process.env.PORT ?? 8080);

/* -------------------- basic routes -------------------- */

app.get("/", (_req, res) => {
  res.status(200).send("StockPilot backend is running ✅");
});

app.get("/db", async (_req, res) => {
  try {
    const r = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: r.rows[0] });
  } catch (e: any) {
    res.status(500).json({ ok: false, error: e?.message ?? "db error" });
  }
});

/* -------------------- helpers -------------------- */

type DbUser = {
  id: string;
  role: "ADMIN" | "USER";
  business_id: string;
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
    businessId: u.business_id,
    email: u.email,
    username: u.username,
    fullName: u.full_name,
    isActive: u.is_active,
  };
}

async function ensureTables() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      email TEXT,
      username TEXT,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Ensure business_id exists
  const colCheck = await pool.query<{ exists: boolean }>(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'users'
        AND column_name = 'business_id'
    ) AS exists;
  `);

  if (!colCheck.rows[0].exists) {
    await pool.query(`ALTER TABLE users ADD COLUMN business_id UUID;`);
  }

  // Ensure a default business exists (for old rows)
  await pool.query(`
    INSERT INTO businesses (name)
    VALUES ('Default Business')
    ON CONFLICT DO NOTHING;
  `);

  const defaultBiz = await pool.query<{ id: string }>(
    `SELECT id FROM businesses WHERE name = 'Default Business' LIMIT 1`
  );
  const defaultBusinessId = defaultBiz.rows[0].id;

  // Backfill existing users
  await pool.query(
    `UPDATE users SET business_id = $1 WHERE business_id IS NULL`,
    [defaultBusinessId]
  );

  // Make business_id required
  await pool.query(`ALTER TABLE users ALTER COLUMN business_id SET NOT NULL;`);

  // FK constraint (only if missing)
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_business_fk'
      ) THEN
        ALTER TABLE users
        ADD CONSTRAINT users_business_fk
        FOREIGN KEY (business_id) REFERENCES businesses(id)
        ON DELETE CASCADE;
      END IF;
    END $$;
  `);

  // Unique per business
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

  // ✅ CRITICAL RULE: Admin email must be unique globally (across ALL businesses)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS admins_email_global_uq
    ON users(email)
    WHERE role = 'ADMIN' AND email IS NOT NULL;
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS users_business_idx ON users(business_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`);
}

/* -------------------- auth routes -------------------- */

/**
 * POST /auth/admin/register
 * Body: { businessName, email, password }
 * Creates a BUSINESS + an ADMIN tied to that business.
 */
app.post("/auth/admin/register", async (req, res) => {
  const schema = z.object({
    businessName: z.string().min(2),
    email: z.string().email(),
    password: z.string().min(8),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid input", errors: parsed.error.flatten() });
  }

  const { businessName, email, password } = parsed.data;

  try {
    // ✅ If admin email already exists anywhere, block it
    const existingAdmin = await pool.query(
      `SELECT 1 FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`,
      [email]
    );
    if (existingAdmin.rows.length > 0) {
      return res.status(409).json({ message: "Email already in use" });
    }

    // Create business
    const biz = await pool.query<{ id: string }>(
      `INSERT INTO businesses (name) VALUES ($1) RETURNING id`,
      [businessName]
    );
    const businessId = biz.rows[0].id;

    // Create admin user
    const passwordHash = await bcrypt.hash(password, 10);

    const created = await pool.query<DbUser>(
      `INSERT INTO users (role, business_id, email, password_hash)
       VALUES ('ADMIN', $1, $2, $3)
       RETURNING *`,
      [businessId, email, passwordHash]
    );

    const token = signToken({
      userId: created.rows[0].id,
      role: "ADMIN",
      businessId,
    });

    return res.json({
      ok: true,
      message: "Admin created",
      token,
      user: publicUser(created.rows[0]),
    });
  } catch (e: any) {
    const msg = e?.message ?? "Register failed";
    // Postgres unique violation usually contains "duplicate key value"
    if (msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "Email already in use" });
    }
    return res.status(500).json({ message: msg });
  }
});

/**
 * POST /auth/login
 * Admin: { role:"admin", email, password }
 * User:  { role:"user", username, password }
 */
app.post("/auth/login", async (req, res) => {
  const schema = z.object({
    role: z.enum(["admin", "user"]),
    email: z.string().email().optional(),
    username: z.string().min(2).optional(),
    password: z.string().min(8),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid input", errors: parsed.error.flatten() });
  }

  const { role, email, username, password } = parsed.data;

  try {
    const q =
      role === "admin"
        ? { text: `SELECT * FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`, values: [email ?? ""] }
        : { text: `SELECT * FROM users WHERE role='USER' AND username=$1 LIMIT 1`, values: [username ?? ""] };

    const result = await pool.query<DbUser>(q.text, q.values);
    const user = result.rows[0];

    if (!user || !user.is_active) {
      return res.status(401).json({ message: "Invalid login" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid login" });

    const token = signToken({
      userId: user.id,
      role: user.role,
      businessId: user.business_id,
    });

    return res.json({ ok: true, token, user: publicUser(user) });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Login failed" });
  }
});

/* -------------------- protected routes -------------------- */

app.get("/me", requireAuth, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string };

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
    [jwtUser.userId]
  );
  const user = result.rows[0];

  // ✅ If account was deleted, token becomes useless
  if (!user || !user.is_active) {
    return res.status(401).json({ message: "Account no longer exists" });
  }

  res.json({ ok: true, user: publicUser(user) });
});

/**
 * POST /admin/create-user
 * Admin only.
 * Body: { username, password, fullName? }
 */
app.post("/admin/create-user", requireAuth, requireAdmin, async (req, res) => {
  const schema = z.object({
    username: z.string().min(2),
    password: z.string().min(8),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid input", errors: parsed.error.flatten() });
  }

  const { username, password, fullName } = parsed.data;
  const jwt = (req as any).user as { businessId: string };

  try {
    const existing = await pool.query(
      `SELECT 1 FROM users WHERE business_id = $1 AND username = $2 LIMIT 1`,
      [jwt.businessId, username]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Username already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const created = await pool.query<DbUser>(
      `INSERT INTO users (role, business_id, username, password_hash, full_name)
       VALUES ('USER', $1, $2, $3, $4)
       RETURNING *`,
      [jwt.businessId, username, passwordHash, fullName ?? null]
    );

    return res.json({ ok: true, user: publicUser(created.rows[0]) });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Create user failed" });
  }
});

/**
 * ✅ DELETE /admin/delete-account
 * Admin only.
 * Deletes the BUSINESS row → cascades and deletes ALL users of that business.
 * After this, login with same email WILL FAIL.
 */
app.delete("/admin/delete-account", requireAuth, requireAdmin, async (req, res) => {
  const jwt = (req as any).user as { businessId: string; userId: string };

  try {
    // Extra safety: ensure the requesting admin still exists
    const admin = await pool.query(
      `SELECT 1 FROM users WHERE id=$1 AND role='ADMIN' AND business_id=$2 LIMIT 1`,
      [jwt.userId, jwt.businessId]
    );
    if (admin.rows.length === 0) {
      return res.status(401).json({ message: "Account no longer exists" });
    }

    // Delete business -> cascades users
    await pool.query(`DELETE FROM businesses WHERE id=$1`, [jwt.businessId]);

    return res.json({ ok: true, message: "Account deleted" });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Delete failed" });
  }
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
