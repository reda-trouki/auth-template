import { User } from "../../../core/domain/entities";
import { EmailAlreadyExistsError } from "../../../core/domain/errors";
import { IUserRepository } from "../../../core/ports/repositories";

const copy = (u: User): User => ({ ...u, roles: [...u.roles] });

/** For tests and prototypes. Not durable, single-process. */
export class InMemoryUserRepository implements IUserRepository {
  private readonly byId = new Map<string, User>();
  private readonly idByEmail = new Map<string, string>();

  async findById(id: string): Promise<User | null> {
    const u = this.byId.get(id);
    return u ? copy(u) : null;
  }
  async findByEmail(email: string): Promise<User | null> {
    const id = this.idByEmail.get(email);
    return id ? this.findById(id) : null;
  }
  async create(user: User): Promise<void> {
    if (this.idByEmail.has(user.email)) throw new EmailAlreadyExistsError(); // synchronous check+set = atomic
    this.byId.set(user.id, copy(user));
    this.idByEmail.set(user.email, user.id);
  }
  async update(user: User): Promise<void> {
    const existing = this.byId.get(user.id);
    if (!existing) throw new Error(`User ${user.id} not found`);
    if (existing.email !== user.email) {
      if (this.idByEmail.has(user.email)) throw new EmailAlreadyExistsError();
      this.idByEmail.delete(existing.email);
      this.idByEmail.set(user.email, user.id);
    }
    this.byId.set(user.id, copy(user));
  }
}
