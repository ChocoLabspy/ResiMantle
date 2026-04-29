import type { Explanation } from './types';
import { AccessDecision } from '@resimantle/types';

/**
 * The Explainer translates technical security decisions into
 * human-readable explanations. This is critical for the "Explain"
 * part of the Audit & Explain layer.
 *
 * Every decision ResiMantle makes should be explainable to a
 * non-technical stakeholder.
 */
export class Explainer {
  /**
   * Generates a human-readable explanation for a decision.
   */
  explain(decision: string, context: Record<string, unknown>): Explanation {
    const d = decision as AccessDecision;

    const humanReadable = this.buildHumanExplanation(d, context);
    const technicalDetails = this.buildTechnicalDetails(d, context);

    return { humanReadable, technicalDetails };
  }

  private buildHumanExplanation(decision: AccessDecision, ctx: Record<string, unknown>): string {
    const actor = ctx.actor || 'An unknown process';
    const resource = ctx.resource || 'a resource';

    switch (decision) {
      case AccessDecision.ALLOW:
        return `${actor} was allowed to access ${resource}. This is normal behavior within the established security profile.`;

      case AccessDecision.ALLOW_WITH_LOGGING:
        return `${actor} was allowed to access ${resource}, but the operation was logged with extra detail because it showed some unusual characteristics. No action is required unless this pattern repeats.`;

      case AccessDecision.ALLOW_LIMITED:
        return `${actor} was allowed to access ${resource} with reduced capabilities. Full access was restricted because the operation fell outside the expected behavioral baseline.`;

      case AccessDecision.ALLOW_READ_ONLY:
        return `${actor} was allowed to read ${resource}, but write operations were blocked. This is a precautionary measure because the actor's behavior profile doesn't include write access to this resource.`;

      case AccessDecision.REQUIRE_APPROVAL:
        return `${actor} attempted to access ${resource}, but the operation requires manual approval. The resource is in a restricted security zone and the access pattern is not part of the established profile.`;

      case AccessDecision.QUARANTINE:
        return `${actor} attempted to access ${resource}, and the operation was quarantined for review. The combination of the actor's behavior and the sensitivity of the resource triggered a high-confidence anomaly alert.`;

      case AccessDecision.BLOCK:
        return `${actor} was BLOCKED from accessing ${resource}. The security system determined with high confidence that this operation is either unauthorized, anomalous, or potentially malicious. The resource remains protected and no data was exposed.`;

      default:
        return `Decision "${decision}" was made for access to ${resource} by ${actor}.`;
    }
  }

  private buildTechnicalDetails(decision: AccessDecision, ctx: Record<string, unknown>): Record<string, unknown> {
    return {
      decision,
      actor: ctx.actor,
      resource: ctx.resource,
      anomalyScore: ctx.anomalyScore,
      zoneLevel: ctx.zoneLevel,
      isKnownActor: ctx.isKnownActor,
      timestamp: new Date().toISOString(),
    };
  }
}
