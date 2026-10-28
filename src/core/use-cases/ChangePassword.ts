import { InvalidCredentialsError, UnauthenticatedError } from "../domain/errors";
import { PasswordPolicy } from "../domain/validation";
import { ISessionRepository, IUserRepository } from "../ports/repositories";
import { IClock, IEventBus, IPasswordHasher } from "../ports/services";

export class ChangePassword {
  constructor(
    private readonly users: IUserRepository,
    private readonly sessions: ISessionRepository,
    private readonly hasher: IPasswordHasher,
    private readonly policy: PasswordPolicy,
    private readonly clock: IClock,
    private readonly events: IEventBus,
  ) {}

  async execute(input: { userId: string; currentPassword: string; newPassword: string }): Promise<void> {
    const user = await this.users.findById(input.userId);
    if (!user) throw new UnauthenticatedError();
    if (!this.policy.isWithinBounds(input.currentPassword)) throw new InvalidCredentialsError();
    if (!(await this.hasher.verify(input.currentPassword, user.passwordHash))) throw new InvalidCredentialsError();

    this.policy.assertValid(input.newPassword);
    const now = this.clock.now();
    await this.users.update({ ...user, passwordHash: await this.hasher.hash(input.newPassword), updatedAt: now });
    // Every existing refresh token dies: a stolen session cannot survive a password change.
    await this.sessions.revokeAllForUser(user.id, now);
    await this.events.publish({ type: "PasswordChanged", userId: user.id, occurredAt: now });
  }
}
