// src/index.ts
import "dotenv/config";

import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { z } from "zod";

import { pool } from "./db.js";
import { signToken, requireAuth, requireAdmin } from "./auth.js";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT ?? 4000);
const RESET_TTL_MINUTES = 30;
const RESET_RATE_LIMIT_MAX = 3;
const RESET_RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const APP_BASE_URL = process.env.APP_BASE_URL?.replace(/\/+$/, "");

const resetRateLimit = new Map<string, number[]>();
const HEAD_ADMIN_KEY = process.env.HEAD_ADMIN_KEY ?? "";

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

  // Admin status fields (stored on users table)
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT;`);
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS desired_user_limit INT;`
  );
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_user_limit INT;`
  );
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS status_reason TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reviewed_by TEXT;`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);

  // Backfill status for existing rows
  await pool.query(
    `UPDATE users SET status='APPROVED' WHERE status IS NULL OR status=''`
  );
  await pool.query(
    `UPDATE users SET desired_user_limit=1 WHERE desired_user_limit IS NULL`
  );
  await pool.query(
    `UPDATE users SET approved_user_limit=1 WHERE role='ADMIN' AND approved_user_limit IS NULL`
  );
  await pool.query(
    `UPDATE users SET updated_at=now() WHERE updated_at IS NULL`
  );
  await pool.query(
    `ALTER TABLE users ALTER COLUMN status SET DEFAULT 'PENDING'`
  );
  await pool.query(`ALTER TABLE users ALTER COLUMN status SET NOT NULL`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      used_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS password_resets_token_hash_idx
    ON password_resets(token_hash);
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
  status?: string;
  desired_user_limit?: number | null;
  approved_user_limit?: number | null;
  status_reason?: string | null;
  reviewed_at?: string | null;
  reviewed_by?: string | null;
  updated_at?: string | null;
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

function adminSummaryRow(row: any) {
  return {
    adminId: row.id,
    businessName: row.business_name ?? null,
    email: row.email,
    status: row.status,
    desiredUserLimit: row.desired_user_limit,
    approvedUserLimit: row.approved_user_limit,
    businessCode3: row.code3,
    createdAt: row.created_at,
    reviewedAt: row.reviewed_at,
    statusReason: row.status_reason ?? null,
  };
}

function hashResetToken(rawToken: string) {
  return crypto.createHash("sha256").update(rawToken).digest("hex");
}

function shouldRateLimit(email: string) {
  const now = Date.now();
  const key = email.trim().toLowerCase();
  const list = resetRateLimit.get(key) ?? [];
  const filtered = list.filter((ts) => now - ts <= RESET_RATE_LIMIT_WINDOW_MS);
  if (filtered.length >= RESET_RATE_LIMIT_MAX) {
    resetRateLimit.set(key, filtered);
    return true;
  }
  filtered.push(now);
  resetRateLimit.set(key, filtered);
  return false;
}

async function sendResetEmail(email: string, rawToken: string) {
  const link = `stockpilot://reset-password?token=${rawToken}`;
  const webLink = APP_BASE_URL
    ? `${APP_BASE_URL}/auth/admin/reset-password-link?token=${rawToken}`
    : null;
  const host = process.env.SMTP_HOST;
  const portRaw = process.env.SMTP_PORT;
  const port = Number(portRaw ?? "");
  const user = process.env.SMTP_USER?.trim();
  const pass = process.env.SMTP_PASS?.replace(/\s+/g, "");
  const from = process.env.SMTP_FROM ?? (user ? `StockPilot Support <${user}>` : undefined);

  if (!host || !portRaw || !port || !user || !pass) {
    console.log(`RESET LINK: ${link}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    requireTLS: port === 587,
    auth: { user, pass },
  });

  const subject = "Reset your StockPilot password";
  const text =
    `You requested a password reset for your StockPilot admin account.\n\n` +
    `Reset link (expires in ${RESET_TTL_MINUTES} minutes):\n${webLink ?? link}\n\n` +
    `If the link doesn't open, copy this:\n${link}\n\n` +
    `If you did not request this, you can ignore this email.`;
  const html =
    `<p>You requested a password reset for your StockPilot admin account.</p>` +
    `<p><a href="${webLink ?? link}">Reset your password</a></p>` +
    (webLink ? `<p>Direct app link: <a href="${link}">${link}</a></p>` : "") +
    `<p>Link expires in ${RESET_TTL_MINUTES} minutes.</p>` +
    `<p>If you did not request this, you can ignore this email.</p>`;

  try {
    await transporter.sendMail({
      from: from ?? user,
      to: email,
      subject,
      text,
      html,
    });
  } catch (e) {
    console.error("Email send failed:", e);
    console.log(`RESET LINK: ${link}`);
  }
}

function requireHeadAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const key = (req.header("X-HEAD-ADMIN-KEY") ?? "").trim();
  if (!HEAD_ADMIN_KEY || key !== HEAD_ADMIN_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

async function requireApprovedAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) {
  const jwtUser = (req as any).user as { userId: string };
  const result = await pool.query(
    `SELECT status FROM users WHERE id=$1 AND role='ADMIN' LIMIT 1`,
    [jwtUser.userId]
  );
  const status = result.rows[0]?.status ?? "PENDING";
  if (status === "APPROVED") return next();

  const code =
    status === "DECLINED"
      ? "ACCOUNT_DECLINED"
      : status === "SUSPENDED"
        ? "ACCOUNT_SUSPENDED"
        : "ACCOUNT_PENDING";
  return res.status(403).json({ code, message: "Admin account is not approved." });
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
    desiredUserLimit: z.number().min(1).max(50).optional(),
    fullName: z.string().min(1).optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());

  const { businessName, email, password, desiredUserLimit, fullName } = parsed.data;

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
    `INSERT INTO users (business_id, role, email, password_hash, full_name, status, desired_user_limit)
     VALUES ($1, 'ADMIN', $2, $3, $4, 'PENDING', $5)
     RETURNING *`,
    [business.id, email, passwordHash, fullName ?? null, desiredUserLimit ?? 1]
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
    adminStatus: "PENDING",
    desiredUserLimit: desiredUserLimit ?? 1,
    admin: publicUser(created.rows[0]),
  });
};
app.post("/auth/register-admin", registerAdminHandler);
app.post("/auth/admin/register", registerAdminHandler);

/**
 * POST /auth/admin/request-password-reset
 * Body: { email }
 * Always returns { ok: true }
 */
app.post("/auth/admin/request-password-reset", async (req, res) => {
  const email =
    typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";

  if (!email || shouldRateLimit(email)) {
    return res.json({ ok: true });
  }

  try {
    const result = await pool.query<DbUser>(
      `SELECT id FROM users WHERE role='ADMIN' AND email=$1 LIMIT 1`,
      [email]
    );
    const user = result.rows[0];
    if (!user) return res.json({ ok: true });

    await pool.query(`DELETE FROM password_resets WHERE user_id=$1`, [user.id]);

    let rawToken = "";
    let tokenHash = "";
    for (let i = 0; i < 3; i += 1) {
      rawToken = crypto.randomBytes(32).toString("hex");
      tokenHash = hashResetToken(rawToken);
      try {
        await pool.query(
          `INSERT INTO password_resets (user_id, token_hash, expires_at)
           VALUES ($1, $2, now() + interval '${RESET_TTL_MINUTES} minutes')`,
          [user.id, tokenHash]
        );
        break;
      } catch (e: any) {
        if (i === 2) throw e;
      }
    }

    await sendResetEmail(email, rawToken);
  } catch (e) {
    console.error("Password reset request error:", e);
  }

  return res.json({ ok: true });
});

/**
 * GET /auth/admin/reset-password-link?token=...
 * Redirects to app deep link for easy click from email clients.
 */
app.get("/auth/admin/reset-password-link", (req, res) => {
  const token = typeof req.query.token === "string" ? req.query.token.trim() : "";
  if (!token) return res.status(400).send("Missing token");
  const link = `stockpilot://reset-password?token=${token}`;
  return res.redirect(302, link);
});

/**
 * POST /auth/admin/reset-password
 * Body: { token, newPassword }
 */
app.post("/auth/admin/reset-password", async (req, res) => {
  const schema = z.object({
    token: z.string().min(10),
    newPassword: z.string().min(8),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "Invalid input" });
  }

  const { token, newPassword } = parsed.data;
  const tokenHash = hashResetToken(token.trim());

  const result = await pool.query(
    `
    SELECT pr.id, pr.user_id, pr.expires_at, pr.used_at, u.role
    FROM password_resets pr
    JOIN users u ON u.id = pr.user_id
    WHERE pr.token_hash = $1
    LIMIT 1
    `,
    [tokenHash]
  );

  const row = result.rows[0] as
    | { id: string; user_id: string; expires_at: string; used_at: string | null; role: string }
    | undefined;

  if (!row || row.used_at || row.role !== "ADMIN") {
    return res.status(401).json({ error: "Invalid or expired link" });
  }

  if (new Date(row.expires_at).getTime() < Date.now()) {
    return res.status(401).json({ error: "Invalid or expired link" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const passwordHash = await bcrypt.hash(newPassword, 10);
    await client.query(`UPDATE users SET password_hash=$1 WHERE id=$2`, [
      passwordHash,
      row.user_id,
    ]);
    await client.query(`UPDATE password_resets SET used_at=now() WHERE id=$1`, [row.id]);

    await client.query("COMMIT");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    return res.status(500).json({ error: "Reset failed" });
  } finally {
    client.release();
  }
});

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
    let businessName: string | null = null;
    if (!businessId) {
      const code3 = await generateBusinessCode3();
      const biz = await pool.query(
        `INSERT INTO businesses (name, code3) VALUES ($1, $2) RETURNING *`,
        [user.email ?? "Business", code3]
      );
      businessId = biz.rows[0].id;
      businessCode3 = biz.rows[0].code3;
      businessName = biz.rows[0].name ?? null;
      await pool.query(`UPDATE users SET business_id = $1 WHERE id = $2`, [
        businessId,
        user.id,
      ]);
    } else {
      const biz = await pool.query(
        `SELECT name, code3 FROM businesses WHERE id = $1 LIMIT 1`,
        [businessId]
      );
      businessCode3 = biz.rows[0]?.code3;
      businessName = biz.rows[0]?.name ?? null;
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
      businessName,
      adminStatus: user.status,
      approvedUserLimit: user.approved_user_limit ?? null,
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

  const jwtUser = (req as any).user as { businessId: string; userId: string };
  const businessId = jwtUser.businessId;

  const existing = await pool.query<DbUser>(
    `SELECT 1 FROM users WHERE business_id = $1 AND username = $2 LIMIT 1`,
    [businessId, username]
  );
  if (existing.rows.length > 0) {
    return res.status(409).json({ error: "Username already in use" });
  }

  const adminLimitRes = await pool.query(
    `SELECT approved_user_limit FROM users WHERE id=$1 AND role='ADMIN' LIMIT 1`,
    [jwtUser.userId]
  );
  const approvedLimit = Number(adminLimitRes.rows[0]?.approved_user_limit ?? 0);
  if (!approvedLimit || approvedLimit < 1) {
    return res.status(409).json({
      code: "USER_LIMIT_REACHED",
      message: "User limit reached.",
    });
  }

  const countRes = await pool.query(
    `SELECT count(*)::int AS count
     FROM users
     WHERE business_id=$1 AND role='USER' AND is_active=TRUE`,
    [businessId]
  );
  const currentCount = Number(countRes.rows[0]?.count ?? 0);
  if (currentCount >= approvedLimit) {
    return res.status(409).json({
      code: "USER_LIMIT_REACHED",
      message: "User limit reached.",
    });
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
    `INSERT INTO users (business_id, role, username, password_hash, full_name, status)
     VALUES ($1, 'USER', $2, $3, $4, 'APPROVED')
     RETURNING *`,
    [businessId, username, passwordHash, fullName ?? null]
  );

  res.json({ ok: true, user: publicUser(created.rows[0]) });
};
app.post("/admin/create-user", requireAuth, requireAdmin, requireApprovedAdmin, createUserHandler);
app.post("/admin/users", requireAuth, requireAdmin, requireApprovedAdmin, createUserHandler);

/**
 * GET /admin/users
 * Admin only. Lists users for this business.
 */
app.get("/admin/users", requireAuth, requireAdmin, requireApprovedAdmin, async (req, res) => {
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
app.delete("/admin/users/:username", requireAuth, requireAdmin, requireApprovedAdmin, async (req, res) => {
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

/**
 * GET /admins/me/status
 */
app.get("/admins/me/status", requireAuth, requireAdmin, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string };
  const result = await pool.query(
    `SELECT status, desired_user_limit, approved_user_limit, status_reason
     FROM users WHERE id=$1 AND role='ADMIN' LIMIT 1`,
    [jwtUser.userId]
  );
  const row = result.rows[0];
  if (!row) return res.status(404).json({ error: "Admin not found" });
  return res.json({
    status: row.status,
    desiredUserLimit: row.desired_user_limit,
    approvedUserLimit: row.approved_user_limit,
    statusReason: row.status_reason ?? null,
  });
});

/**
 * DELETE /admins/me
 * Admin self-delete
 */
app.delete("/admins/me", requireAuth, requireAdmin, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string; businessId: string };
  const row = await pool.query(
    `SELECT status FROM users WHERE id=$1 AND role='ADMIN' LIMIT 1`,
    [jwtUser.userId]
  );
  const status = row.rows[0]?.status ?? "PENDING";
  if (!["PENDING", "DECLINED", "SUSPENDED"].includes(status)) {
    return res.status(403).json({ code: "ACCOUNT_APPROVED", message: "Approved admins cannot self-delete." });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`DELETE FROM password_resets WHERE user_id=$1`, [jwtUser.userId]);
    await client.query(`DELETE FROM users WHERE business_id=$1`, [jwtUser.businessId]);
    await client.query(`DELETE FROM businesses WHERE id=$1`, [jwtUser.businessId]);
    await client.query("COMMIT");
    return res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    return res.status(500).json({ error: "Delete failed" });
  } finally {
    client.release();
  }
});

/**
 * Head of Admins endpoints (X-HEAD-ADMIN-KEY)
 */
const headAdminListHandler = async (req: express.Request, res: express.Response) => {
  const status = (req.query.status ?? "ALL").toString().toUpperCase();
  const filter = ["PENDING", "APPROVED", "DECLINED", "SUSPENDED"].includes(status)
    ? "AND u.status = $1"
    : "";
  const params = filter ? [status] : [];
  const result = await pool.query(
    `
    SELECT u.id, u.email, u.status, u.desired_user_limit, u.approved_user_limit,
           u.created_at, u.reviewed_at, u.status_reason, b.name AS business_name, b.code3
    FROM users u
    JOIN businesses b ON b.id = u.business_id
    WHERE u.role='ADMIN' ${filter}
    ORDER BY u.created_at DESC
    `,
    params
  );
  return res.json({ ok: true, admins: result.rows.map(adminSummaryRow) });
};
app.get("/head-admin/admins", requireHeadAdmin, headAdminListHandler);
app.get("/api/head-admin/admins", requireHeadAdmin, headAdminListHandler);

const headAdminApproveHandler = async (req: express.Request, res: express.Response) => {
  const schema = z.object({
    approvedUserLimit: z.number().min(1).max(500),
    reason: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Invalid input" });
  const { approvedUserLimit, reason } = parsed.data;
  const adminId = req.params.adminId;

  const result = await pool.query(
    `
    UPDATE users
    SET status='APPROVED',
        approved_user_limit=$2,
        status_reason=$3,
        reviewed_at=now(),
        reviewed_by='HEAD_OF_ADMINS',
        updated_at=now()
    WHERE id=$1 AND role='ADMIN'
    RETURNING id
    `,
    [adminId, approvedUserLimit, reason ?? null]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Admin not found" });
  const row = await pool.query(
    `
    SELECT u.id, u.email, u.status, u.desired_user_limit, u.approved_user_limit,
           u.created_at, u.reviewed_at, u.status_reason, b.name AS business_name, b.code3
    FROM users u
    JOIN businesses b ON b.id = u.business_id
    WHERE u.id=$1
    `,
    [adminId]
  );
  return res.json({ ok: true, admin: adminSummaryRow(row.rows[0]) });
};
app.post("/head-admin/admins/:adminId/approve", requireHeadAdmin, headAdminApproveHandler);
app.post("/api/head-admin/admins/:adminId/approve", requireHeadAdmin, headAdminApproveHandler);

const headAdminDeclineHandler = async (req: express.Request, res: express.Response) => {
  const reason = typeof req.body?.reason === "string" ? req.body.reason : null;
  const adminId = req.params.adminId;
  const result = await pool.query(
    `
    UPDATE users
    SET status='DECLINED',
        status_reason=$2,
        reviewed_at=now(),
        reviewed_by='HEAD_OF_ADMINS',
        updated_at=now()
    WHERE id=$1 AND role='ADMIN'
    RETURNING id
    `,
    [adminId, reason]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Admin not found" });
  const row = await pool.query(
    `
    SELECT u.id, u.email, u.status, u.desired_user_limit, u.approved_user_limit,
           u.created_at, u.reviewed_at, u.status_reason, b.name AS business_name, b.code3
    FROM users u
    JOIN businesses b ON b.id = u.business_id
    WHERE u.id=$1
    `,
    [adminId]
  );
  return res.json({ ok: true, admin: adminSummaryRow(row.rows[0]) });
};
app.post("/head-admin/admins/:adminId/decline", requireHeadAdmin, headAdminDeclineHandler);
app.post("/api/head-admin/admins/:adminId/decline", requireHeadAdmin, headAdminDeclineHandler);

const headAdminSuspendHandler = async (req: express.Request, res: express.Response) => {
  const reason = typeof req.body?.reason === "string" ? req.body.reason : null;
  const adminId = req.params.adminId;
  const result = await pool.query(
    `
    UPDATE users
    SET status='SUSPENDED',
        status_reason=$2,
        reviewed_at=now(),
        reviewed_by='HEAD_OF_ADMINS',
        updated_at=now()
    WHERE id=$1 AND role='ADMIN'
    RETURNING id
    `,
    [adminId, reason]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Admin not found" });
  const row = await pool.query(
    `
    SELECT u.id, u.email, u.status, u.desired_user_limit, u.approved_user_limit,
           u.created_at, u.reviewed_at, u.status_reason, b.name AS business_name, b.code3
    FROM users u
    JOIN businesses b ON b.id = u.business_id
    WHERE u.id=$1
    `,
    [adminId]
  );
  return res.json({ ok: true, admin: adminSummaryRow(row.rows[0]) });
};
app.post("/head-admin/admins/:adminId/suspend", requireHeadAdmin, headAdminSuspendHandler);
app.post("/api/head-admin/admins/:adminId/suspend", requireHeadAdmin, headAdminSuspendHandler);

const headAdminUnsuspendHandler = async (req: express.Request, res: express.Response) => {
  const adminId = req.params.adminId;
  const result = await pool.query(
    `
    UPDATE users
    SET status='APPROVED',
        reviewed_at=now(),
        reviewed_by='HEAD_OF_ADMINS',
        updated_at=now()
    WHERE id=$1 AND role='ADMIN' AND status='SUSPENDED'
    RETURNING id
    `,
    [adminId]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: "Admin not found" });
  const row = await pool.query(
    `
    SELECT u.id, u.email, u.status, u.desired_user_limit, u.approved_user_limit,
           u.created_at, u.reviewed_at, u.status_reason, b.name AS business_name, b.code3
    FROM users u
    JOIN businesses b ON b.id = u.business_id
    WHERE u.id=$1
    `,
    [adminId]
  );
  return res.json({ ok: true, admin: adminSummaryRow(row.rows[0]) });
};
app.post("/head-admin/admins/:adminId/unsuspend", requireHeadAdmin, headAdminUnsuspendHandler);
app.post("/api/head-admin/admins/:adminId/unsuspend", requireHeadAdmin, headAdminUnsuspendHandler);

/**
 * GET /__debug/routes
 * Temporary route listing for debugging (no secrets).
 */
app.get("/__debug/routes", (_req, res) => {
  const stack = (app as any)._router?.stack ?? [];
  const routes = stack
    .map((layer: any) => {
      if (layer.route) {
        const methods = Object.keys(layer.route.methods || {}).map((m) => m.toUpperCase());
        return { path: layer.route.path, methods };
      }
      if (layer.name === "router" && layer.handle?.stack) {
        const nested = layer.handle.stack
          .filter((l: any) => l.route)
          .map((l: any) => ({
            path: l.route.path,
            methods: Object.keys(l.route.methods || {}).map((m: string) => m.toUpperCase()),
          }));
        return { path: layer.regexp?.toString?.() ?? "router", methods: ["USE"], nested };
      }
      return null;
    })
    .filter(Boolean);
  return res.json({ ok: true, routes });
});

/**
 * GET /__debug/head-admin-path
 * Temporary head-admin path helper (no secrets).
 */
app.get("/__debug/head-admin-path", (_req, res) => {
  return res.json({
    mountPath: "/",
    listAdminsPath: "/head-admin/admins",
    approvePath: "/head-admin/admins/:adminId/approve",
    declinePath: "/head-admin/admins/:adminId/decline",
    suspendPath: "/head-admin/admins/:adminId/suspend",
    unsuspendPath: "/head-admin/admins/:adminId/unsuspend",
  });
});

/**
 * GET /__debug/version
 * Deploy verification endpoint (no secrets).
 */
app.get("/__debug/version", (_req, res) => {
  const commit =
    process.env.RAILWAY_GIT_COMMIT_SHA?.slice(0, 7) ??
    process.env.GITHUB_SHA?.slice(0, 7) ??
    process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7) ??
    "unknown";
  const time =
    process.env.BUILD_TIME ??
    process.env.RAILWAY_BUILD_TIME ??
    new Date().toISOString();
  return res.json({
    commit,
    time,
    hasHeadAdminRoutes: true,
  });
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
