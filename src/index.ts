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

type DbBusiness = {
  id: string;
  name: string;
  code3: string;
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

function normalizeUsername(u: string) {
  return u.trim();
}

function looksLikeBusinessPassword(pw: string) {
  const t = pw.trim();
  if (t.length !== 12) return false;
  if (t[3] !== "-") return false;
  const code3 = t.substring(0, 3);
  const secret8 = t.substring(4);
  if (!/^[A-Z0-9]{3}$/.test(code3)) return false;
  if (!/^[A-Za-z0-9]{8}$/.test(secret8)) return false;
  return true;
}

function extractCode3(pw: string) {
  return pw.trim().substring(0, 3).toUpperCase();
}

function generateCode3FromName(name: string) {
  // Try to get 3 letters from the business name; fallback random
  const letters = name
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .split("");
  const base = letters.join("");
  let code = (base + "XXX").substring(0, 3);
  if (!/^[A-Z0-9]{3}$/.test(code)) code = "SPX";
  return code;
}

async function pickUniqueCode3(businessName: string) {
  // Attempt a few variants to avoid collisions
  const base = generateCode3FromName(businessName);
  const variants = [
    base,
    base.substring(0, 2) + "1",
    base.substring(0, 2) + "2",
    "SP" + Math.floor(Math.random() * 10).toString(),
  ];

  for (const v of variants) {
    const code3 = v.toUpperCase();
    const exists = await pool.query(
      `SELECT 1 FROM businesses WHERE code3=$1 LIMIT 1`,
      [code3]
    );
    if (exists.rows.length === 0) return code3;
  }

  // Last resort: random until unique
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let i = 0; i < 200; i++) {
    const code3 =
      chars[Math.floor(Math.random() * chars.length)] +
      chars[Math.floor(Math.random() * chars.length)] +
      chars[Math.floor(Math.random() * chars.length)];
    const exists = await pool.query(
      `SELECT 1 FROM businesses WHERE code3=$1 LIMIT 1`,
      [code3]
    );
    if (exists.rows.length === 0) return code3;
  }

  // Extremely unlikely fallback
  return "SPX";
}

async function ensureTables() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      code3 TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      role TEXT NOT NULL CHECK (role IN ('ADMIN','USER')),
      business_id UUID,
      email TEXT,
      username TEXT,
      password_hash TEXT NOT NULL,
      full_name TEXT,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Ensure business_id exists + required + FK
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

  // Ensure a default business exists
  await pool.query(`
    INSERT INTO businesses (name)
    VALUES ('Default Business')
    ON CONFLICT DO NOTHING;
  `);

  // Ensure code3 exists on businesses
  const bizCodeCheck = await pool.query<{ exists: boolean }>(`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_name = 'businesses'
        AND column_name = 'code3'
    ) AS exists;
  `);
  if (!bizCodeCheck.rows[0].exists) {
    await pool.query(`ALTER TABLE businesses ADD COLUMN code3 TEXT;`);
  }

  // Backfill code3 for businesses where missing
  const missingCodes = await pool.query<DbBusiness>(
    `SELECT id, name, COALESCE(code3,'') AS code3 FROM businesses`
  );
  for (const b of missingCodes.rows) {
    if (!b.code3 || b.code3.trim().length !== 3) {
      const code3 = await pickUniqueCode3(b.name);
      await pool.query(`UPDATE businesses SET code3=$1 WHERE id=$2`, [
        code3,
        b.id,
      ]);
    }
  }

  // Make code3 unique + required
  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS businesses_code3_uq
    ON businesses(code3)
    WHERE code3 IS NOT NULL;
  `);

  await pool.query(
    `UPDATE businesses SET code3='SPX' WHERE code3 IS NULL OR code3=''`
  );
  await pool.query(`ALTER TABLE businesses ALTER COLUMN code3 SET NOT NULL;`);

  // Backfill existing users.business_id
  const defaultBiz = await pool.query<{ id: string }>(
    `SELECT id FROM businesses WHERE name = 'Default Business' LIMIT 1`
  );
  const defaultBusinessId = defaultBiz.rows[0].id;
  await pool.query(
    `UPDATE users SET business_id = $1 WHERE business_id IS NULL`,
    [defaultBusinessId]
  );

  await pool.query(`ALTER TABLE users ALTER COLUMN business_id SET NOT NULL;`);

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

  // Admin email unique globally
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
    // block existing admin email
    const existingAdmin = await pool.query(
      `SELECT 1 FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`,
      [email]
    );
    if (existingAdmin.rows.length > 0) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const code3 = await pickUniqueCode3(businessName);

    const biz = await pool.query<{ id: string; code3: string }>(
      `INSERT INTO businesses (name, code3) VALUES ($1, $2) RETURNING id, code3`,
      [businessName, code3]
    );
    const businessId = biz.rows[0].id;

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
      businessCode3: biz.rows[0].code3,
      user: publicUser(created.rows[0]),
    });
  } catch (e: any) {
    const msg = e?.message ?? "Register failed";
    if (msg.toLowerCase().includes("duplicate")) {
      return res.status(409).json({ message: "Email already in use" });
    }
    return res.status(500).json({ message: msg });
  }
});

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
    if (role === "admin") {
      const result = await pool.query<DbUser>(
        `SELECT * FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`,
        [(email ?? "").trim().toLowerCase()]
      );
      const user = result.rows[0];

      if (!user || !user.is_active) return res.status(401).json({ message: "Invalid login" });

      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ message: "Invalid login" });

      const token = signToken({
        userId: user.id,
        role: user.role,
        businessId: user.business_id,
      });

      const biz = await pool.query<DbBusiness>(
        `SELECT id, name, code3 FROM businesses WHERE id=$1 LIMIT 1`,
        [user.business_id]
      );

      return res.json({
        ok: true,
        token,
        businessCode3: biz.rows[0]?.code3 ?? null,
        user: publicUser(user),
      });
    }

    // USER login
    const uname = normalizeUsername(username ?? "");
    if (!uname) return res.status(400).json({ message: "Invalid input" });

    if (!looksLikeBusinessPassword(password)) {
      return res.status(401).json({ message: "Invalid login" });
    }

    const code3 = extractCode3(password);

    const biz = await pool.query<DbBusiness>(
      `SELECT id, name, code3 FROM businesses WHERE code3=$1 LIMIT 1`,
      [code3]
    );
    if (biz.rows.length === 0) return res.status(401).json({ message: "Invalid login" });

    const businessId = biz.rows[0].id;

    const result = await pool.query<DbUser>(
      `SELECT * FROM users WHERE role='USER' AND business_id=$1 AND username=$2 LIMIT 1`,
      [businessId, uname]
    );
    const user = result.rows[0];

    if (!user || !user.is_active) return res.status(401).json({ message: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid login" });

    const token = signToken({
      userId: user.id,
      role: user.role,
      businessId: user.business_id,
    });

    return res.json({
      ok: true,
      token,
      businessCode3: biz.rows[0].code3,
      user: publicUser(user),
    });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Login failed" });
  }
});

/* -------------------- protected routes -------------------- */

app.get("/me", requireAuth, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string };

  const result = await pool.query<DbUser>(`SELECT * FROM users WHERE id = $1 LIMIT 1`, [
    jwtUser.userId,
  ]);
  const user = result.rows[0];

  if (!user || !user.is_active) {
    return res.status(401).json({ message: "Account no longer exists" });
  }

  res.json({ ok: true, user: publicUser(user) });
});

/**
 * ✅ THIS IS THE ONLY FIX NEEDED FOR YOUR 404:
 * GET /admin/users (Admin only)
 */
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const jwt = (req as any).user as { businessId: string };

  try {
    const result = await pool.query<DbUser>(
      `SELECT * FROM users
       WHERE role='USER' AND business_id=$1
       ORDER BY created_at DESC`,
      [jwt.businessId]
    );

    return res.json({
      ok: true,
      users: result.rows.map(publicUser),
    });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "List users failed" });
  }
});

/**
 * POST /admin/users
 * Admin only.
 * Body: { username, password, fullName? }
 * password MUST be ABC-xxxxxxxx (12 chars)
 */
app.post("/admin/users", requireAuth, requireAdmin, async (req, res) => {
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

  const uname = normalizeUsername(username);

  // enforce your format
  if (!looksLikeBusinessPassword(password)) {
    return res.status(400).json({ message: "Password must look like ABC-1234XyZ9" });
  }

  // ensure password code3 matches this business
  const biz = await pool.query<DbBusiness>(
    `SELECT id, code3 FROM businesses WHERE id=$1 LIMIT 1`,
    [jwt.businessId]
  );
  const businessCode3 = biz.rows[0]?.code3 ?? null;
  if (!businessCode3) return res.status(500).json({ message: "Business missing code3" });

  if (extractCode3(password) !== businessCode3) {
    return res.status(400).json({ message: `Password must start with ${businessCode3}-` });
  }

  try {
    const existing = await pool.query(
      `SELECT 1 FROM users WHERE business_id = $1 AND username = $2 LIMIT 1`,
      [jwt.businessId, uname]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Username already in use" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const created = await pool.query<DbUser>(
      `INSERT INTO users (role, business_id, username, password_hash, full_name)
       VALUES ('USER', $1, $2, $3, $4)
       RETURNING *`,
      [jwt.businessId, uname, passwordHash, fullName ?? null]
    );

    return res.json({
      ok: true,
      message: "User created",
      businessCode3,
      user: publicUser(created.rows[0]),
    });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Create user failed" });
  }
});

app.delete("/admin/users/:username", requireAuth, requireAdmin, async (req, res) => {
  const jwt = (req as any).user as { businessId: string };
  const username = normalizeUsername(req.params.username ?? "");

  if (!username) return res.status(400).json({ message: "Invalid input" });

  try {
    const del = await pool.query(
      `DELETE FROM users
       WHERE role='USER' AND business_id=$1 AND username=$2
       RETURNING id`,
      [jwt.businessId, username]
    );

    if (del.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.json({ ok: true, message: "User deleted" });
  } catch (e: any) {
    return res.status(500).json({ message: e?.message ?? "Delete user failed" });
  }
});

app.delete("/admin/delete-account", requireAuth, requireAdmin, async (req, res) => {
  const jwt = (req as any).user as { businessId: string; userId: string };

  try {
    const admin = await pool.query(
      `SELECT 1 FROM users WHERE id=$1 AND role='ADMIN' AND business_id=$2 LIMIT 1`,
      [jwt.userId, jwt.businessId]
    );
    if (admin.rows.length === 0) {
      return res.status(401).json({ message: "Account no longer exists" });
    }

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
