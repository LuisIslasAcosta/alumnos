import type { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";

export interface RefreshTokenRecord {
  id: number;
  user_id: number;
  user_kind: "user" | "student";
  token: string;
  expires_at: number;
  created_at: number;
}

export class RefreshTokenRepository {
  constructor(private readonly db: DatabaseSync) {}

  create(
    userId: number,
    userKind: "user" | "student",
    expiresInSeconds: number,
  ): { token: string; expiresAt: number } {
    const token = randomUUID();
    const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;

    const stmt = this.db.prepare(`
      INSERT INTO refresh_tokens (user_id, user_kind, token, expires_at)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(userId, userKind, token, expiresAt);

    return { token, expiresAt };
  }

  findByToken(token: string): RefreshTokenRecord | undefined {
    const stmt = this.db.prepare(`
      SELECT id, user_id, user_kind, token, expires_at, created_at
      FROM refresh_tokens
      WHERE token = ?
    `);
    return stmt.get(token) as RefreshTokenRecord | undefined;
  }

  delete(token: string): boolean {
    const stmt = this.db.prepare("DELETE FROM refresh_tokens WHERE token = ?");
    const result = stmt.run(token);
    return result.changes > 0;
  }

  deleteByUser(userId: number, userKind: "user" | "student"): number {
    const stmt = this.db.prepare(`
      DELETE FROM refresh_tokens
      WHERE user_id = ? AND user_kind = ?
    `);
    const result = stmt.run(userId, userKind);
    return Number(result.changes);
  }

  deleteExpired(): number {
    const now = Math.floor(Date.now() / 1000);
    const stmt = this.db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ?");
    const result = stmt.run(now);
    return Number(result.changes);
  }

  isValid(token: string): { valid: boolean; userId?: number; userKind?: "user" | "student" } {
    const record = this.findByToken(token);

    if (!record) {
      return { valid: false };
    }

    const now = Math.floor(Date.now() / 1000);
    if (record.expires_at < now) {
      this.delete(token);
      return { valid: false };
    }

    return {
      valid: true,
      userId: record.user_id,
      userKind: record.user_kind,
    };
  }
}
