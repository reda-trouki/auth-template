import { ForbiddenError } from "../core/domain/errors";
import {
  AuthorizationContext, Decision, IAuthorizationPolicy, ICombiningAlgorithm,
} from "../core/ports/IAuthorizationPolicy";
import { IClock, IEventBus, ILogger } from "../core/ports/services";
import { PolicyRegistry } from "./PolicyRegistry";

export interface PolicyEngineOptions { policyTimeoutMs: number }

const DENY = (reason: string): Decision => ({ effect: "deny", reason });

/**
 * The ONLY class that runs policies. Guarantees (fail closed):
 *  - a policy that throws, times out or returns garbage counts as DENY (never as allow, never as a crash)
 *  - a throwing appliesTo() is treated as "does not apply"... except that an unexpected error is logged
 *  - a broken combining algorithm yields DENY
 *  - invalid contexts are denied
 */
export class PolicyEngine {
  constructor(
    private readonly registry: PolicyRegistry,
    private readonly combiner: ICombiningAlgorithm,
    private readonly events: IEventBus,
    private readonly clock: IClock,
    private readonly logger: ILogger,
    private readonly options: PolicyEngineOptions = { policyTimeoutMs: 2000 },
  ) {}

  async decide(ctx: AuthorizationContext): Promise<Decision> {
    let decision: Decision;
    if (!ctx || typeof ctx.action !== "string" || ctx.action.length === 0 || !ctx.subject?.id) {
      decision = DENY("Invalid authorization context");
    } else {
      decision = await this.evaluateAll(ctx);
    }
    await this.audit(ctx, decision);
    return decision;
  }

  /** Throws ForbiddenError unless the final decision is an explicit allow. */
  async assert(ctx: AuthorizationContext): Promise<void> {
    const decision = await this.decide(ctx);
    if (decision.effect !== "allow") throw new ForbiddenError(); // reason stays server-side (audit event)
  }

  private async evaluateAll(ctx: AuthorizationContext): Promise<Decision> {
    const applicable = this.registry.all().filter((p) => this.safeAppliesTo(p, ctx.action));
    const decisions = await Promise.all(applicable.map((p) => this.safeEvaluate(p, ctx)));
    try {
      const combined = this.combiner.combine(decisions);
      return this.normalize(combined, this.combiner.name);
    } catch (err) {
      this.logger.error("Combining algorithm threw; denying", { err: String(err) });
      return DENY("Authorization error");
    }
  }

  private safeAppliesTo(policy: IAuthorizationPolicy, action: string): boolean {
    try { return policy.appliesTo(action) === true; }
    catch (err) {
      this.logger.error(`Policy "${policy.name}".appliesTo threw; skipping`, { err: String(err) });
      return false;
    }
  }

  private async safeEvaluate(policy: IAuthorizationPolicy, ctx: AuthorizationContext): Promise<Decision> {
    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("timed out")), this.options.policyTimeoutMs);
      });
      const result = await Promise.race([Promise.resolve().then(() => policy.evaluate(ctx)), timeout]);
      return this.normalize(result, policy.name);
    } catch (err) {
      this.logger.error(`Policy "${policy.name}" failed; counting as deny`, { err: String(err) });
      return DENY(`Policy "${policy.name}" failed`);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /** Anything that is not a well-formed decision becomes a deny. */
  private normalize(d: unknown, source: string): Decision {
    const x = d as { effect?: unknown; reason?: unknown } | null;
    if (x && x.effect === "allow") return { effect: "allow", reason: typeof x.reason === "string" ? x.reason : source };
    if (x && x.effect === "abstain") return { effect: "abstain" };
    if (x && x.effect === "deny") return DENY(typeof x.reason === "string" ? x.reason : `denied by ${source}`);
    this.logger.error(`"${source}" returned a malformed decision; denying`);
    return DENY(`Malformed decision from ${source}`);
  }

  private async audit(ctx: AuthorizationContext, decision: Decision): Promise<void> {
    try {
      await this.events.publish({
        type: "AuthorizationDecided",
        subjectId: ctx?.subject?.id ?? "unknown",
        action: ctx?.action ?? "unknown",
        effect: decision.effect === "allow" ? "allow" : "deny",
        reason: decision.effect === "abstain" ? undefined : decision.reason,
        resourceType: ctx?.resource?.type,
        resourceId: ctx?.resource?.id,
        occurredAt: this.clock.now(),
      });
    } catch { /* auditing must never change an authorization outcome */ }
  }
}
