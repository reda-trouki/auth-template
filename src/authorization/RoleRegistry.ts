import { ConfigError } from "../core/domain/errors";
import { IRoleProvider } from "../core/ports/IAuthorizationPolicy";

interface RoleDef { permissions: Set<string>; inherits: Set<string> }

/** Default in-memory IRoleProvider with inheritance. Implement IRoleProvider yourself to load roles from a DB. */
export class InMemoryRoleRegistry implements IRoleProvider {
  private readonly roles = new Map<string, RoleDef>();

  define(name: string, permissions: readonly string[], inherits: readonly string[] = []): this {
    this.roles.set(name, { permissions: new Set(permissions), inherits: new Set(inherits) });
    return this;
  }

  inherit(role: string, parent: string): this {
    const def = this.roles.get(role);
    if (!def) throw new ConfigError(`Cannot inherit: role "${role}" is not defined`);
    def.inherits.add(parent);
    return this;
  }

  has(name: string): boolean { return this.roles.has(name); }

  /** Cycle-safe (visited set). Unknown roles grant nothing (fail closed). */
  async permissionsFor(roles: readonly string[]): Promise<ReadonlySet<string>> {
    const out = new Set<string>();
    const visited = new Set<string>();
    const walk = (name: string): void => {
      if (visited.has(name)) return;
      visited.add(name);
      const def = this.roles.get(name);
      if (!def) return;
      def.permissions.forEach((p) => out.add(p));
      def.inherits.forEach(walk);
    };
    roles.forEach(walk);
    return out;
  }

  /** Fail-fast boot check: unknown parents and inheritance cycles are config bugs. Call after late edits. */
  validate(): void {
    for (const [name, def] of this.roles) {
      for (const parent of def.inherits) {
        if (!this.roles.has(parent)) throw new ConfigError(`Role "${name}" inherits unknown role "${parent}"`);
      }
    }
    const state = new Map<string, 1 | 2>(); // 1 = visiting, 2 = done
    const visit = (name: string, path: string[]): void => {
      if (state.get(name) === 2) return;
      if (state.get(name) === 1) throw new ConfigError(`Role inheritance cycle: ${[...path, name].join(" -> ")}`);
      state.set(name, 1);
      this.roles.get(name)?.inherits.forEach((p) => visit(p, [...path, name]));
      state.set(name, 2);
    };
    for (const name of this.roles.keys()) visit(name, []);
  }
}
