import type { AccessContext, GatekeeperEvent } from './types';
import { AccessDecision } from '@resimantle/types';
import { SealLevel } from '../deep-seal/types';
import { HardeningApplier } from '../deep-seal/hardening';
import { logger } from '../../common/logger';

/**
 * The Access Gatekeeper is the real-time decision engine.
 *
 * For every intercepted I/O operation, the Gatekeeper receives:
 * 1. The AccessContext (who, what, where)
 * 2. The anomaly score from the BehaviorModel
 * 3. The seal level from the DeepSeal layer
 *
 * It combines all this information to make a split-second decision:
 * ALLOW, ALLOW_WITH_LOGGING, REQUIRE_APPROVAL, QUARANTINE, or BLOCK.
 *
 * The Gatekeeper is designed to be extremely fast (< 1ms per decision)
 * and to NEVER produce false positives that would break the application
 * during the OPEN and OBSERVED phases.
 */
export class Gatekeeper {
  private decisionLog: GatekeeperEvent[] = [];
  private hardening: HardeningApplier;

  constructor() {
    this.hardening = new HardeningApplier();
  }

  /**
   * Evaluates an access request and returns a decision.
   *
   * Decision logic:
   * 1. Check the seal level of the zone
   * 2. Apply hardening rules for that level
   * 3. Factor in the anomaly score
   * 4. Check if the actor is known
   * 5. Return the most appropriate decision
   */
  async evaluate(context: AccessContext): Promise<GatekeeperEvent> {
    const startTime = performance.now();
    let decision: AccessDecision;
    let reason: string;

    const sealLevel = context.zoneLevel as SealLevel;
    const rules = this.hardening.getHardeningRules('dynamic', sealLevel);
    const sensitivity = resolveSensitivity(context.metadata);
    const actionClass = classifyAction(context.action, context.category);
    const isSensitive = sensitivity === 'high';

    // ── Decision Pipeline ─────────────────────────────────────────────────

    // Phase 1: Extreme anomaly → always block (regardless of seal level)
    if (context.anomalyScore >= 0.95) {
      decision = AccessDecision.BLOCK;
      reason = `Extreme anomaly score (${context.anomalyScore}) — automatic block`;
    }

    // Phase 2: SEALED zone + unknown actor → block
    else if (sealLevel === SealLevel.SEALED && !context.isKnownActor) {
      decision = AccessDecision.BLOCK;
      reason = `SEALED zone "${context.resource}" accessed by unknown actor "${context.actor}"`;
    }

    // Phase 3: Sensitive mutations in sealed zones are denied by default
    else if (isSensitive && isMutationLikeAction(actionClass) && rules.sensitiveMutationPolicy === 'deny') {
      decision = AccessDecision.BLOCK;
      reason = `Sensitive mutation denied by default for "${context.resource}" in ${sealLevel}`;
    }

    // Phase 4: Sensitive reads in sealed zones are denied by default
    else if (isSensitive && isReadLikeAction(actionClass) && rules.sensitiveReadPolicy === 'deny') {
      decision = AccessDecision.BLOCK;
      reason = `Sensitive read denied by default for "${context.resource}" in ${sealLevel}`;
    }

    // Phase 5: Sensitive mutations in restricted zones require approval
    else if (isSensitive && isMutationLikeAction(actionClass) && rules.sensitiveMutationPolicy === 'approval') {
      decision = AccessDecision.REQUIRE_APPROVAL;
      reason = `Sensitive mutation requires approval for "${context.resource}"`;
    }

    // Phase 6: SEALED zone + known actor but high anomaly → quarantine
    else if (sealLevel === SealLevel.SEALED && context.anomalyScore >= 0.7) {
      decision = AccessDecision.QUARANTINE;
      reason = `SEALED zone with high anomaly (${context.anomalyScore}) from known actor "${context.actor}"`;
    }

    // Phase 7: RESTRICTED zone + unknown actor → require approval
    else if (sealLevel === SealLevel.RESTRICTED && !context.isKnownActor) {
      decision = AccessDecision.REQUIRE_APPROVAL;
      reason = `RESTRICTED zone accessed by unknown actor "${context.actor}" — approval required`;
    }

    // Phase 8: Sensitive reads in restricted zones stay read-only by default
    else if (isSensitive && isReadLikeAction(actionClass) && rules.sensitiveReadPolicy === 'read-only') {
      decision = AccessDecision.ALLOW_READ_ONLY;
      reason = `Sensitive read constrained to read-only access for "${context.resource}"`;
    }

    // Phase 9: RESTRICTED zone + known actor + moderate anomaly → log
    else if (sealLevel === SealLevel.RESTRICTED && context.anomalyScore >= 0.5) {
      decision = AccessDecision.ALLOW_WITH_LOGGING;
      reason = `RESTRICTED zone, known actor, moderate anomaly (${context.anomalyScore})`;
    }

    // Phase 10: High anomaly score (any zone) → allow with logging
    else if (context.anomalyScore >= 0.6) {
      decision = AccessDecision.ALLOW_WITH_LOGGING;
      reason = `High anomaly score (${context.anomalyScore}) — allowing with enhanced logging`;
    }

    // Phase 11: OBSERVED zone → allow with logging (data collection)
    else if (sealLevel === SealLevel.OBSERVED && rules.logAllAccess) {
      decision = AccessDecision.ALLOW_WITH_LOGGING;
      reason = `OBSERVED zone — logging for behavioral analysis`;
    }

    // Phase 12: OPEN zone or low anomaly → allow
    else {
      decision = AccessDecision.ALLOW;
      reason = `Normal access (anomaly: ${context.anomalyScore}, zone: ${sealLevel})`;
    }

    const decisionTimeUs = Math.round((performance.now() - startTime) * 1000);

    const event: GatekeeperEvent = {
      context,
      decision,
      reason,
      timestamp: new Date().toISOString(),
      decisionTimeUs,
    };

    this.decisionLog.push(event);

    // Log significant decisions
    if (decision === AccessDecision.BLOCK || decision === AccessDecision.QUARANTINE) {
      logger.warn(`🚫 GATEKEEPER ${decision}: ${reason}`);
    } else if (decision === AccessDecision.REQUIRE_APPROVAL) {
      logger.info(`⚠️  GATEKEEPER REQUIRE_APPROVAL: ${reason}`);
    }

    return event;
  }

  /**
   * Returns all decisions made so far.
   */
  getDecisionLog(): GatekeeperEvent[] {
    return [...this.decisionLog];
  }

  /**
   * Returns statistics about decisions made.
   */
  getStats(): Record<AccessDecision, number> {
    const stats: Record<string, number> = {};
    for (const d of Object.values(AccessDecision)) {
      stats[d] = 0;
    }
    for (const event of this.decisionLog) {
      stats[event.decision] = (stats[event.decision] || 0) + 1;
    }
    return stats as Record<AccessDecision, number>;
  }
}

function classifyAction(action: string, category?: string): 'read' | 'mutate' | 'process' | 'egress' | 'other' {
  const normalized = `${category ?? ''} ${action}`.toLowerCase();

  if (/(read|search|\bget\b|\bhead\b|\boptions\b)/.test(normalized)) {
    return 'read';
  }

  if (/(spawn|exec|fork|shell|process)/.test(normalized)) {
    return 'process';
  }

  if (/(http|socket|connect|egress|post|put|patch|delete|write|rotate|update|create)/.test(normalized)) {
    return /(post|put|patch|delete|write|rotate|update|create)/.test(normalized)
      ? 'mutate'
      : 'egress';
  }

  return 'other';
}

function isReadLikeAction(actionClass: ReturnType<typeof classifyAction>): boolean {
  return actionClass === 'read';
}

function isMutationLikeAction(actionClass: ReturnType<typeof classifyAction>): boolean {
  return actionClass === 'mutate' || actionClass === 'process' || actionClass === 'egress';
}

function resolveSensitivity(metadata?: Record<string, unknown>): 'low' | 'medium' | 'high' {
  const sensitivity = metadata?.['sensitivity'];
  if (sensitivity === 'high' || sensitivity === 'medium' || sensitivity === 'low') {
    return sensitivity;
  }

  const riskTags = readStringArray(metadata?.['riskTags']);
  if (riskTags.some(tag => ['tokens', 'secrets', 'database', 'process', 'admin'].includes(tag))) {
    return 'high';
  }

  if (riskTags.length > 0) {
    return 'medium';
  }

  return 'low';
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}
