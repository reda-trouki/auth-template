/**
 * Action patterns: "*" (everything), "post:*" (any post action), or an exact "post:update".
 * Matching is exact-string based: no regex, so no ReDoS and no surprises.
 */
export function matchesAction(pattern: string, action: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(":*")) return action.startsWith(pattern.slice(0, -1));
  return pattern === action;
}

export const matchesAny = (patterns: readonly string[], action: string): boolean =>
  patterns.some((p) => matchesAction(p, action));
