export interface AuthorizationContext {
  readonly subject: { id: string; roles: readonly string[]; attributes?: Record<string, unknown> };
  /** "resource:verb", e.g. "post:update" */
  readonly action: string;
  readonly resource?: { type: string; id?: string; data?: unknown };
  readonly environment?: { ip?: string; time: Date };
}

/** `abstain` = "not my concern". Policies only speak about what they know. */
export type Decision =
  | { effect: "allow"; reason?: string }
  | { effect: "deny"; reason: string }
  | { effect: "abstain" };

export interface IAuthorizationPolicy {
  readonly name: string;
  /** Cheap, synchronous pre-filter so irrelevant policies never run. */
  appliesTo(action: string): boolean;
  evaluate(ctx: AuthorizationContext): Decision | Promise<Decision>;
}

export interface ICombiningAlgorithm {
  readonly name: string;
  combine(decisions: readonly Decision[]): Decision;
}

/** Supplies the permissions a set of roles grants. Swap for a DB-backed provider at will. */
export interface IRoleProvider {
  permissionsFor(roles: readonly string[]): Promise<ReadonlySet<string>>;
}
