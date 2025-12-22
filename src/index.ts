import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { z } from "zod";

import { prisma } from "./db.js";
import { signToken, requireAuth, requireAdmin } from "./auth";


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT ?? 4000);

// Health check
app.get("/", (_req, res) => {
  res.json({ ok: true, app: "StockPilot Backend" });
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

  const existing = await prisma.user.findFirst({ where: { email } });
  if (existing) return res.status(409).json({ error: "Email already in use" });

  const passwordHash = await bcrypt.hash(password, 10);

  const admin = await prisma.user.create({
    data: { role: "ADMIN", email, passwordHash, fullName },
    select: { id: true, role: true, email: true, username: true, fullName: true, isActive: true },
  });

  res.json({ ok: true, admin });
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

  const user = await prisma.user.findFirst({
    where: email ? { email } : { username },
  });

  if (!user || !user.isActive) return res.status(401).json({ error: "Invalid login" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid login" });

  const token = signToken({ userId: user.id, role: user.role });

  res.json({
    ok: true,
    token,
    user: { id: user.id, role: user.role, email: user.email, username: user.username, fullName: user.fullName },
  });
});

// Example protected route
app.get("/me", requireAuth, async (req, res) => {
  const jwtUser = (req as any).user as { userId: string };
  const user = await prisma.user.findUnique({
    where: { id: jwtUser.userId },
    select: { id: true, role: true, email: true, username: true, fullName: true, isActive: true },
  });
  res.json({ ok: true, user });
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

  const existing = await prisma.user.findFirst({ where: { username } });
  if (existing) return res.status(409).json({ error: "Username already in use" });

  const passwordHash = await bcrypt.hash(password, 10);

  const created = await prisma.user.create({
    data: { role: "USER", username, passwordHash, fullName },
    select: { id: true, role: true, username: true, fullName: true, isActive: true },
  });

  res.json({ ok: true, user: created });
});

app.listen(PORT, () => {
  console.log(`✅ Running on http://localhost:${PORT}`);
});
