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

app.get("/", (_req, res) => {
  res.status(200).send("StockPilot backend is running ✅");
});

/* -------------------- helpers -------------------- */

async function ensureTables() {
  await pool.query(`CREATE EXTENSION IF NOT EXISTS pgcrypto;`);

  // 1) Businesses table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS businesses (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // 2) Users table (old version may already exist)
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

  // 3) Check if business_id exists, add it if it doesn't
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

  // 4) Make sure a default business exists (for old rows)
  await pool.query(`
    INSERT INTO businesses (name)
    VALUES ('Default Business')
    ON CONFLICT DO NOTHING;
  `);

  const defaultBiz = await pool.query<{ id: string }>(
    `SELECT id FROM businesses WHERE name = 'Default Business' LIMIT 1`
  );
  const defaultBusinessId = defaultBiz.rows[0].id;

  // 5) Backfill any users missing business_id
  await pool.query(
    `UPDATE users SET business_id = $1 WHERE business_id IS NULL`,
    [defaultBusinessId]
  );

  // 6) Now enforce NOT NULL
  await pool.query(`ALTER TABLE users ALTER COLUMN business_id SET NOT NULL;`);

  // 7) Add FK constraint safely (only if missing)
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

  // 8) Create per-business uniqueness
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
  await pool.query(`CREATE INDEX IF NOT EXISTS users_business_idx ON users(business_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_email_idx ON users(email);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);`);
}
