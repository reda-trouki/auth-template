import { ConfigError } from "../core/domain/errors";
import { IAuthorizationPolicy } from "../core/ports/IAuthorizationPolicy";

export class PolicyRegistry {
  private readonly policies = new Map<string, IAuthorizationPolicy>();

  /** Duplicate names are rejected: a silent overwrite could drop a security rule. */
  register(...policies: IAuthorizationPolicy[]): this {
    for (const p of policies) {
      if (!p || typeof p.name !== "string" || typeof p.appliesTo !== "function" || typeof p.evaluate !== "function") {
        throw new ConfigError("Invalid policy: needs name, appliesTo() and evaluate()");
      }
      if (this.policies.has(p.name)) throw new ConfigError(`Policy "${p.name}" is already registered`);
      this.policies.set(p.name, p);
    }
    return this;
  }

  unregister(name: string): boolean { return this.policies.delete(name); }
  all(): IAuthorizationPolicy[] { return [...this.policies.values()]; }
}
