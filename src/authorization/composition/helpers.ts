import { AuthorizationContext, Decision, IAuthorizationPolicy } from "../../core/ports/IAuthorizationPolicy";
import { matchesAny } from "../actions";

export const allow = (reason?: string): Decision => ({ effect: "allow", reason });
export const deny = (reason: string): Decision => ({ effect: "deny", reason });
export const abstain = (): Decision => ({ effect: "abstain" });

type ActionSpec = string | readonly string[];
const toList = (a: ActionSpec): readonly string[] => (typeof a === "string" ? [a] : a);

/** Quickest way to add custom logic: an action pattern + a function returning a Decision. */
export function definePolicy(
  actions: ActionSpec,
  fn: (ctx: AuthorizationContext) => Decision | Promise<Decision>,
  name?: string,
): IAuthorizationPolicy {
  const list = toList(actions);
  return { name: name ?? `policy(${list.join(",")})`, appliesTo: (a) => matchesAny(list, a), evaluate: fn };
}

// ---- Specification pattern: boolean rules that compose -------------------------------

export interface Rule {
  readonly name: string;
  test(ctx: AuthorizationContext): boolean | Promise<boolean>;
}

export const rule = (name: string, test: Rule["test"]): Rule => ({ name, test });

export const all = (...rules: Rule[]): Rule =>
  rule(`all(${rules.map((r) => r.name).join(", ")})`, async (ctx) => {
    for (const r of rules) if (!(await r.test(ctx))) return false;
    return true;
  });

export const any = (...rules: Rule[]): Rule =>
  rule(`any(${rules.map((r) => r.name).join(", ")})`, async (ctx) => {
    for (const r of rules) if (await r.test(ctx)) return true;
    return false;
  });

export const not = (r: Rule): Rule => rule(`not(${r.name})`, async (ctx) => !(await r.test(ctx)));

export const hasRole = (role: string): Rule =>
  rule(`hasRole(${role})`, (ctx) => ctx.subject.roles.includes(role));

export const isOwner = (field = "ownerId"): Rule =>
  rule(`isOwner(${field})`, (ctx) => {
    const data = ctx.resource?.data;
    if (typeof data !== "object" || data === null) return false;
    const owner = (data as Record<string, unknown>)[field];
    return typeof owner === "string" && owner === ctx.subject.id;
  });

export const attributeEquals = (key: string, value: unknown): Rule =>
  rule(`attr(${key})`, (ctx) => ctx.subject.attributes?.[key] === value);

/** rule passes => allow, otherwise abstain (additive: other policies may still allow). */
export const allowWhen = (actions: ActionSpec, r: Rule, name?: string): IAuthorizationPolicy =>
  definePolicy(actions, async (ctx) => ((await r.test(ctx)) ? allow(r.name) : abstain()), name ?? `allowWhen(${r.name})`);

/** rule passes => deny, otherwise abstain (restrictive: overrides allows under DenyOverrides). */
export const denyWhen = (actions: ActionSpec, r: Rule, name?: string): IAuthorizationPolicy =>
  definePolicy(actions, async (ctx) => ((await r.test(ctx)) ? deny(r.name) : abstain()), name ?? `denyWhen(${r.name})`);
