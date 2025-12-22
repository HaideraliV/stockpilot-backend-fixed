import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export type JwtUser = { userId: string; role: "ADMIN" | "USER" };

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

export function signToken(payload: JwtUser) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "2h" });
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing Authorization header" });
  }

  const token = header.slice("Bearer ".length);
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtUser;
    (req as any).user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user as JwtUser | undefined;
  if (!user) return res.status(401).json({ error: "Not authenticated" });
  if (user.role !== "ADMIN") return res.status(403).json({ error: "Admin only" });
  next();
}
