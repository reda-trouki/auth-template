import { Decision, ICombiningAlgorithm } from "../../core/ports/IAuthorizationPolicy";

const NO_ALLOW: Decision = { effect: "deny", reason: "No policy allowed this action (default deny)" };

/** Any deny wins; otherwise any allow; otherwise deny. Safest default. */
export class DenyOverrides implements ICombiningAlgorithm {
  readonly name = "deny-overrides";
  combine(decisions: readonly Decision[]): Decision {
    const deny = decisions.find((d) => d.effect === "deny");
    if (deny) return deny;
    const allow = decisions.find((d) => d.effect === "allow");
    return allow ?? NO_ALLOW;
  }
}

/** Any allow wins; otherwise deny. Use only for permissive systems. */
export class AllowOverrides implements ICombiningAlgorithm {
  readonly name = "allow-overrides";
  combine(decisions: readonly Decision[]): Decision {
    return decisions.find((d) => d.effect === "allow") ?? decisions.find((d) => d.effect === "deny") ?? NO_ALLOW;
  }
}

/** First non-abstaining decision wins (ordered rule list); none => deny. */
export class FirstApplicable implements ICombiningAlgorithm {
  readonly name = "first-applicable";
  combine(decisions: readonly Decision[]): Decision {
    return decisions.find((d) => d.effect !== "abstain") ?? NO_ALLOW;
  }
}
