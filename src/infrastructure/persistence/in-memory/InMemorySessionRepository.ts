import { Session } from "../../../core/domain/entities";
import { ISessionRepository } from "../../../core/ports/repositories";

export class InMemorySessionRepository implements ISessionRepository {
  private readonly sessions = new Map<string, Session>();

  async create(s: Session): Promise<void> { this.sessions.set(s.id, { ...s }); }
  async findById(id: string): Promise<Session | null> {
    const s = this.sessions.get(id);
    return s ? { ...s } : null;
  }
  /** No `await` between check and write => atomic in a single-threaded event loop. */
  async consume(id: string, at: Date): Promise<boolean> {
    const s = this.sessions.get(id);
    if (!s || s.usedAt || s.revokedAt) return false;
    this.sessions.set(id, { ...s, usedAt: at });
    return true;
  }
  async revokeFamily(familyId: string, at: Date): Promise<void> {
    for (const [id, s] of this.sessions) {
      if (s.familyId === familyId && !s.revokedAt) this.sessions.set(id, { ...s, revokedAt: at });
    }
  }
  async revokeAllForUser(userId: string, at: Date): Promise<void> {
    for (const [id, s] of this.sessions) {
      if (s.userId === userId && !s.revokedAt) this.sessions.set(id, { ...s, revokedAt: at });
    }
  }
  async purgeExpired(before: Date): Promise<number> {
    let n = 0;
    for (const [id, s] of this.sessions) {
      if (s.familyExpiresAt < before) { this.sessions.delete(id); n++; }
    }
    return n;
  }
}
