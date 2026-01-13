// src/index.ts
import "dotenv/config";

import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import { z } from "zod";

import { pool } from "./db.js";
import { signToken, requireAuth, requireAdmin, type JwtUser } from "./auth.js";

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

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function normalizeUsername(username: string) {
  return username.trim();
}

function isValidCode3(code3: string) {
  return /^[A-Z0-9]{3}$/.test(code3.trim().toUpperCase());
}

async function generateUniqueCode3(): Promise<string> {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 5000; attempt++) {
    let code = "";
    for (let i = 0; i < 3; i++) {
      code += chars[Math.floor(Math.random() * chars.length)];
    }
    code = code.toUpperCase();

    const exists = await pool.query(
      `SELECT 1 FROM businesses WHERE code3 = $1 LIMIT 1`,
      [code]
    );
    if (exists.rows.length === 0) return code;
  }

  // fallback
  const ms = Date.now().toString();
  const last3 = ms.slice(-3).replace(/[^0-9]/g, "9");
  return last3.padEnd(3, "9").slice(0, 3);
}

async function ensureTables() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

  // Businesses table (now includes code3)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      code3 TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Users table
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

  // Ensure code3 exists
  const code3Check = await pool.query<{ exists: boolean }>(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'businesses'
        AND column_name = 'code3'
    ) AS exists;
  `);

  if (!code3Check.rows[0].exists) {
    await pool.query(`ALTER TABLE businesses ADD COLUMN code3 TEXT;`);
  }

  // Ensure a default business exists (for old rows)
  await pool.query(`
    INSERT INTO businesses (name)
    SELECT 'Default Business'
    WHERE NOT EXISTS (SELECT 1 FROM businesses WHERE name = 'Default Business');
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

  // ✅ Business code uniqueness
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS businesses_code3_uq
    ON businesses(code3)
    WHERE code3 IS NOT NULL;
  `);

  // ✅ Admin email uniqueness (GLOBAL, case-insensitive)
  // This enforces: only one admin can exist with an email, unless deleted.
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS admins_email_global_uq
    ON users (lower(email))
    WHERE role = 'ADMIN' AND email IS NOT NULL;
  `);

  // ✅ Usernames unique per business (prevents mixing inside a business)
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS users_business_username_uq
    ON users(business_id, username)
    WHERE username IS NOT NULL;
  `);

  // Helpful indexes
  await pool.query(`CREATE INDEX IF NOT EXISTS users_business_idx ON users(business_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`);
}

/* -------------------- auth routes -------------------- */

/**
 * POST /auth/admin/register
 * Body: { businessName, email, password }
 * Rule: Email can only be used once globally unless the account is deleted.
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

  const businessName = parsed.data.businessName.trim();
  const email = normalizeEmail(parsed.data.email);
  const password = parsed.data.password;

  try {
    // ✅ block duplicate admin emails explicitly (better message)
    const existing = await pool.query(
      `SELECT 1 FROM users WHERE role='ADMIN' AND lower(email)=lower($1) LIMIT 1`,
      [email]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ ok: false, message: "Email already in use" });
    }

    // Create business with unique code3
    const code3 = await generateUniqueCode3();
    const biz = await pool.query<{ id: string; code3: string }>(
      `INSERT INTO businesses (name, code3) VALUES ($1, $2) RETURNING id, code3`,
      [businessName, code3]
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

    const token = signToken({ userId: created.rows[0].id, role: "ADMIN", businessId });

    return res.json({
      ok: true,
      message: "Admin created",
      token,
      business: { id: businessId, name: businessName, code3: biz.rows[0].code3 },
      user: publicUser(created.rows[0]),
    });
  } catch (e: any) {
    const msg = e?.message ?? "Register failed";
    if (msg.toLowerCase().includes("admins_email_global_uq") || msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ ok: false, message: "Email already in use" });
    }
    return res.status(500).json({ ok: false, message: msg });
  }
});

/**
 * POST /auth/login
 * Admin: { role:"admin", email, password }
 * User:  { role:"user", username, password, businessCode3? }
 *
 * ✅ If businessCode3 is provided, user login is scoped to that business (prevents mixing).
 */
app.post("/auth/login", async (req, res) => {
  const schema = z.object({
    role: z.enum(["admin", "user"]),
    email: z.string().email().optional(),
    username: z.string().min(2).optional(),
    password: z.string().min(8),
    businessCode3: z.string().optional(), // NEW (optional for backward compatibility)
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid input", errors: parsed.error.flatten() });
  }

  const { role, email, username, password, businessCode3 } = parsed.data;

  try {
    let result;

    if (role === "admin") {
      const em = normalizeEmail(email ?? "");
      result = await pool.query<DbUser>(
        `SELECT * FROM users WHERE role='ADMIN' AND lower(email)=lower($1) LIMIT 1`,
        [em]
      );
    } else {
      const un = normalizeUsername(username ?? "");

      // ✅ If businessCode3 is provided, scope login to business
      if (businessCode3 && isValidCode3(businessCode3)) {
        const c3 = businessCode3.trim().toUpperCase();
        const biz = await pool.query<{ id: string }>(
          `SELECT id FROM businesses WHERE code3 = $1 LIMIT 1`,
          [c3]
        );
        if (biz.rows.length === 0) {
          return res.status(401).json({ message: "Invalid login" });
        }

        result = await pool.query<DbUser>(
          `SELECT * FROM users
           WHERE role='USER' AND business_id=$1 AND username=$2
           LIMIT 1`,
          [biz.rows[0].id, un]
        );
      } else {
        // fallback old behavior (not recommended, but won’t break older Flutter)
        result = await pool.query<DbUser>(
          `SELECT * FROM users WHERE role='USER' AND username=$1 LIMIT 1`,
          [un]
        );
      }
    }

    const user = result.rows[0];

    // ✅ Block inactive accounts
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
  const jwtUser = (req as any).user as JwtUser;

  const result = await pool.query<DbUser>(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
    [jwtUser.userId]
  );
  const user = result.rows[0];
  if (!user) return res.status(404).json({ message: "User not found" });

  res.json({ ok: true, user: publicUser(user) });
});

/**
 * POST /admin/create-user
 * Admin only.
 * Body: { username, password, fullName? }
 *
 * ✅ Enforces: username unique inside THIS admin’s business.
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
  const jwtUser = (req as any).user as JwtUser;

  try {
    const existing = await pool.query(
      `SELECT 1 FROM users WHERE business_id=$1 AND role='USER' AND username=$2 LIMIT 1`,
      [jwtUser.businessId, username.trim()]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Username already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const created = await pool.query<DbUser>(
      `INSERT INTO users (role, business_id, username, password_hash, full_name)
       VALUES ('USER', $1, $2, $3, $4)
       RETURNING *`,
      [jwtUser.businessId, username.trim(), passwordHash, fullName ?? null]
    );

    return res.json({ ok: true, user: publicUser(created.rows[0]) });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Create user failed" });
  }
});

/**
 * ✅ DELETE /admin/users/:id
 * Admin only.
 * Rule: If admin deletes a user, they can NEVER login again.
 *
 * We “deactivate” the user (is_active=false). Login already blocks inactive.
 */
app.delete("/admin/users/:id", requireAuth, requireAdmin, async (req, res) => {
  const schema = z.object({ id: z.string().uuid() });
  const parsed = schema.safeParse(req.params);
  if (!parsed.success) return res.status(400).json({ message: "Invalid user id" });

  const jwtUser = (req as any).user as JwtUser;
  const userId = parsed.data.id;

  try {
    // ensure user belongs to this admin’s business
    const found = await pool.query<DbUser>(
      `SELECT * FROM users WHERE id=$1 AND role='USER' AND business_id=$2 LIMIT 1`,
      [userId, jwtUser.businessId]
    );
    if (found.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    await pool.query(
      `UPDATE users SET is_active = FALSE WHERE id=$1`,
      [userId]
    );

    return res.json({ ok: true, message: "User deleted (deactivated)" });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Delete user failed" });
  }
});

/**
 * ✅ DELETE /admin/delete-account
 * Admin only.
 * Body: { password }
 *
 * Rule: Admin deletes account => business deleted => ALL users deleted (cascade).
 * After deletion, the same email can register again as a fresh account.
 */
app.delete("/admin/delete-account", requireAuth, requireAdmin, async (req, res) => {
  const schema = z.object({
    password: z.string().min(8),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Invalid input", errors: parsed.error.flatten() });
  }

  const jwtUser = (req as any).user as JwtUser;

  try {
    const adminRes = await pool.query<DbUser>(
      `SELECT * FROM users WHERE id=$1 AND role='ADMIN' LIMIT 1`,
      [jwtUser.userId]
    );
    const admin = adminRes.rows[0];
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    const ok = await bcrypt.compare(parsed.data.password, admin.password_hash);
    if (!ok) return res.status(401).json({ message: "Password incorrect" });

    // ✅ delete business => cascades users via FK ON DELETE CASCADE
    await pool.query(`DELETE FROM businesses WHERE id=$1`, [jwtUser.businessId]);

    return res.json({ ok: true, message: "Account deleted" });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Delete account failed" });
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
