import { AccessDecision } from '@resimantle/types';

/**
 * Decision escalation/de-escalation ordering.
 */
const DECISION_ORDER: AccessDecision[] = [
  AccessDecision.ALLOW,
  AccessDecision.ALLOW_WITH_LOGGING,
  AccessDecision.ALLOW_LIMITED,
  AccessDecision.ALLOW_READ_ONLY,
  AccessDecision.REQUIRE_APPROVAL,
  AccessDecision.QUARANTINE,
  AccessDecision.BLOCK,
];

/**
 * Utility class for working with access decisions.
 */
export class DecisionLogic {
  /**
   * Escalates a decision to the next stricter level.
   */
  escalate(current: AccessDecision): AccessDecision {
    const idx = DECISION_ORDER.indexOf(current);
    if (idx < 0 || idx >= DECISION_ORDER.length - 1) {
      return AccessDecision.BLOCK;
    }
    return DECISION_ORDER[idx + 1]!;
  }

  /**
   * De-escalates a decision to the next more permissive level.
   */
  deescalate(current: AccessDecision): AccessDecision {
    const idx = DECISION_ORDER.indexOf(current);
    if (idx <= 0) return AccessDecision.ALLOW;
    return DECISION_ORDER[idx - 1]!;
  }

  /**
   * Returns the more restrictive of two decisions.
   */
  moreRestrictive(a: AccessDecision, b: AccessDecision): AccessDecision {
    const idxA = DECISION_ORDER.indexOf(a);
    const idxB = DECISION_ORDER.indexOf(b);
    return idxA >= idxB ? a : b;
  }

  /**
   * Checks if a decision is blocking (prevents the operation).
   */
  isBlocking(decision: AccessDecision): boolean {
    return decision === AccessDecision.BLOCK || decision === AccessDecision.QUARANTINE;
  }

  /**
   * Checks if a decision requires human approval.
   */
  requiresHuman(decision: AccessDecision): boolean {
    return decision === AccessDecision.REQUIRE_APPROVAL;
  }
}
