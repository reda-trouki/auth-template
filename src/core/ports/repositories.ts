import { Session, User } from "../domain/entities";

/**
 * CONTRACT (verified by tests/contract for every adapter):
 *  - findByEmail receives an already-normalized email.
 *  - create() MUST throw EmailAlreadyExistsError on duplicate email. Uniqueness has to be
 *    enforced by the store itself (unique index), not by a check-then-insert in the app,
 *    otherwise two concurrent registrations can both succeed.
 *  - Returned objects must be copies: mutating them must not alter stored state.
 */
export interface IUserRepository {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(user: User): Promise<void>;
  update(user: User): Promise<void>;
}

/**
 * CONTRACT:
 *  - consume() MUST be atomic compare-and-set: returns true for exactly ONE caller when
 *    several race on the same unused, unrevoked session.
 *    SQL equivalent: UPDATE sessions SET used_at=$2 WHERE id=$1 AND used_at IS NULL
 *                    AND revoked_at IS NULL   -> check affected rows === 1
 *  - Revoke operations are idempotent.
 */
export interface ISessionRepository {
  create(session: Session): Promise<void>;
  findById(id: string): Promise<Session | null>;
  consume(id: string, at: Date): Promise<boolean>;
  revokeFamily(familyId: string, at: Date): Promise<void>;
  revokeAllForUser(userId: string, at: Date): Promise<void>;
  /** Housekeeping hook; call from a cron/timer in the host project. */
  purgeExpired(before: Date): Promise<number>;
}
