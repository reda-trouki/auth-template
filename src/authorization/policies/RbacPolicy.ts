import { AuthorizationContext, Decision, IAuthorizationPolicy, IRoleProvider } from "../../core/ports/IAuthorizationPolicy";
import { matchesAction } from "../actions";

/** Allows when any permission granted by the subject's roles matches the action. Otherwise abstains. */
export class RbacPolicy implements IAuthorizationPolicy {
  readonly name = "rbac";
  constructor(private readonly roles: IRoleProvider) {}
  appliesTo(): boolean { return true; }

  async evaluate(ctx: AuthorizationContext): Promise<Decision> {
    const permissions = await this.roles.permissionsFor(ctx.subject.roles);
    for (const p of permissions) {
      if (matchesAction(p, ctx.action)) return { effect: "allow", reason: `role permission "${p}"` };
    }
    return { effect: "abstain" };
  }
}
