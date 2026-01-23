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
  // Creates the businesses table if it doesn't exist
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      code3 TEXT NOT NULL UNIQUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Creates the users table if it doesn't exist
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      business_id UUID REFERENCES businesses(id),
      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      email TEXT,
      username TEXT,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Ensure business_id exists for legacy tables
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS business_id UUID REFERENCES businesses(id);`
  );

  // Legacy cleanup: remove global unique constraint if it exists
  await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;`);
  await pool.query(`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;`);

  // Helpful indexes (safe if run multiple times)
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`);
  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS users_business_username_key
     ON users(business_id, username)
     WHERE business_id IS NOT NULL AND username IS NOT NULL;`
  );
  await pool.query(
    `CREATE UNIQUE INDEX IF NOT EXISTS users_business_email_key
     ON users(business_id, email)
     WHERE business_id IS NOT NULL AND email IS NOT NULL;`
  );
}

type DbUser = {
  id: string;
  business_id: string | null;
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

async function generateBusinessCode3() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 5000; attempt += 1) {
    let code = "";
    for (let i = 0; i < 3; i += 1) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    const existing = await pool.query(
      `SELECT 1 FROM businesses WHERE code3 = $1 LIMIT 1`,
      [code]
    );
    if (existing.rows.length === 0) return code;
  }
  const ms = Date.now().toString();
  return ms.slice(-3);
}

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
 * POST /auth/admin/register
 * Body: { businessName, email, password, fullName? }
 */
const registerAdminHandler = async (req: any, res: any) => {
  const schema = z.object({
    businessName: z.string().min(1),
    email: z.string().email(),
    password: z.string().min(8),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { businessName, email, password, fullName } = parsed.data;

  const existing = await pool.query<DbUser>(
    `SELECT 1 FROM users WHERE email = $1 LIMIT 1`,
    [email]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Email already in use" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const code3 = await generateBusinessCode3();

  const biz = await pool.query(
    `INSERT INTO businesses (name, code3) VALUES ($1, $2) RETURNING *`,
    [businessName, code3]
  );
  const business = biz.rows[0];

  const created = await pool.query<DbUser>(
    `INSERT INTO users (business_id, role, email, password_hash, full_name)
     VALUES ($1, 'ADMIN', $2, $3, $4)
     RETURNING *`,
    [business.id, email, passwordHash, fullName ?? null]
  );

  const token = signToken({
    userId: created.rows[0].id,
    role: "ADMIN",
    businessId: business.id,
    adminId: created.rows[0].id,
  });

  res.json({
    ok: true,
    token,
    businessId: business.id,
    businessCode3: business.code3,
    admin: publicUser(created.rows[0]),
  });
};
app.post("/auth/register-admin", registerAdminHandler);
app.post("/auth/admin/register", registerAdminHandler);

/**
 * POST /auth/login
 * Admin: { email, password }
 * User:  { businessCode, username, password }
 */
app.post("/auth/login", async (req, res) => {
  const schema = z.object({
    role: z.enum(["admin", "user"]).optional(),
    email: z.string().email().optional(),
    username: z.string().min(2).optional(),
    businessCode: z.string().min(3).max(3).optional(),
    businessCode3: z.string().min(3).max(3).optional(),
    password: z.string().min(6),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { role, email, username, password, businessCode, businessCode3 } = parsed.data;

  if (!email && !username) {
    return res
      .status(400)
      .json({ error: "Provide email (admin) or username (user)" });
  }

  if (email) {
    const result = await pool.query<DbUser>(
      `SELECT * FROM users WHERE email = $1 AND role = 'ADMIN' LIMIT 1`,
      [email]
    );
    const user = result.rows[0];

    if (!user || !user.is_active) return res.status(401).json({ error: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid login" });

    // Backfill business for legacy admin (no business_id)
    let businessId = user.business_id;
    let businessCode3: string | undefined;
    if (!businessId) {
      const code3 = await generateBusinessCode3();
      const biz = await pool.query(
        `INSERT INTO businesses (name, code3) VALUES ($1, $2) RETURNING *`,
        [user.email ?? "Business", code3]
      );
      businessId = biz.rows[0].id;
      businessCode3 = biz.rows[0].code3;
      await pool.query(`UPDATE users SET business_id = $1 WHERE id = $2`, [
        businessId,
        user.id,
      ]);
    } else {
      const biz = await pool.query(
        `SELECT code3 FROM businesses WHERE id = $1 LIMIT 1`,
        [businessId]
      );
      businessCode3 = biz.rows[0]?.code3;
    }

    if (!businessId) return res.status(401).json({ error: "Invalid login" });

    const token = signToken({
      userId: user.id,
      role: user.role,
      businessId,
      adminId: user.id,
    });

    return res.json({
      ok: true,
      token,
      businessId,
      businessCode3,
      user: publicUser({ ...user, business_id: businessId }),
    });
  }

  const codeInput = (businessCode3 ?? businessCode ?? "").trim();
  if (!codeInput) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const normalizedCode = codeInput.toUpperCase();

  const biz = await pool.query(
    `SELECT * FROM businesses WHERE code3 = $1 LIMIT 1`,
    [normalizedCode]
  );
  const business = biz.rows[0];
  if (!business) return res.status(401).json({ error: "Invalid credentials" });

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE business_id = $1 AND username = $2 AND role = 'USER' LIMIT 1`,
    [business.id, username]
  );
  const user = result.rows[0];

  if (!user || !user.is_active) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const supplied = password.trim();
  let passwordPart = supplied;
  if (supplied.includes("-")) {
    const idx = supplied.indexOf("-");
    const prefix = supplied.slice(0, idx).toUpperCase();
    const suffix = supplied.slice(idx + 1);
    if (prefix === normalizedCode && suffix.trim().length > 0) {
      passwordPart = suffix;
    }
  }

  let ok = await bcrypt.compare(passwordPart, user.password_hash);
  if (!ok) {
    const legacy = `${normalizedCode}-${passwordPart}`;
    ok = await bcrypt.compare(legacy, user.password_hash);
  }
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const userBusinessId = user.business_id ?? business.id;
  const token = signToken({
    userId: user.id,
    role: user.role,
    businessId: userBusinessId,
    username: user.username ?? undefined,
  });

  return res.json({ ok: true, token, businessId: userBusinessId, user: publicUser(user) });
});

// Example protected route
app.get("/me", requireAuth, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string; businessId: string };

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE id = $1 AND business_id = $2 LIMIT 1`,
    [jwtUser.userId, jwtUser.businessId]
  );
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ ok: true, user: publicUser(user) });
});

/**
 * POST /admin/create-user
 * POST /admin/users
 * Admin only. Creates a USER with username + password.
 * Body: { username, password, fullName? }
 */
const createUserHandler = async (req: any, res: any) => {
  const schema = z.object({
    username: z.string().min(2),
    password: z.string().min(6),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { username, password, fullName } = parsed.data;

  const jwtUser = (req as any).user as { businessId: string };
  const businessId = jwtUser.businessId;

  const existing = await pool.query<DbUser>(
    `SELECT 1 FROM users WHERE business_id = $1 AND username = $2 LIMIT 1`,
    [businessId, username]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Username already in use" });
  }

  const bizCodeRes = await pool.query<{ code3: string }>(
    `SELECT code3 FROM businesses WHERE id = $1 LIMIT 1`,
    [businessId]
  );
  const bizCode3 = (bizCodeRes.rows[0]?.code3 ?? "").toString().trim().toUpperCase();

  let passwordPart = password.trim();
  if (bizCode3 && passwordPart.includes("-")) {
    const idx = passwordPart.indexOf("-");
    const prefix = passwordPart.slice(0, idx).toUpperCase();
    const suffix = passwordPart.slice(idx + 1);
    if (prefix === bizCode3 && suffix.trim().length > 0) {
      passwordPart = suffix;
    }
  }

  const passwordHash = await bcrypt.hash(passwordPart, 10);

  const created = await pool.query<DbUser>(
    `INSERT INTO users (business_id, role, username, password_hash, full_name)
     VALUES ($1, 'USER', $2, $3, $4)
     RETURNING *`,
    [businessId, username, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, user: publicUser(created.rows[0]) });
};
app.post("/admin/create-user", requireAuth, requireAdmin, createUserHandler);
app.post("/admin/users", requireAuth, requireAdmin, createUserHandler);

/**
 * GET /admin/users
 * Admin only. Lists users for this business.
 */
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const jwtUser = (req as any).user as { businessId: string };
  const businessId = jwtUser.businessId;

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE business_id = $1 AND role = 'USER' ORDER BY created_at DESC`,
    [businessId]
  );

  res.json({ ok: true, users: result.rows.map(publicUser) });
});

/**
 * DELETE /admin/users/:username
 * Admin only. Deletes a user for this business.
 */
app.delete("/admin/users/:username", requireAuth, requireAdmin, async (req, res) => {
  const username = (req.params.username ?? "").toString();
  if (!username.trim()) return res.status(400).json({ error: "Missing username" });

  const jwtUser = (req as any).user as { businessId: string };
  const businessId = jwtUser.businessId;

  const result = await pool.query<DbUser>(
    `DELETE FROM users WHERE business_id = $1 AND username = $2 AND role = 'USER' RETURNING *`,
    [businessId, username]
  );

  const deleted = result.rows[0];
  if (!deleted) return res.status(404).json({ error: "User not found" });

  res.json({ ok: true, user: publicUser(deleted) });
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
