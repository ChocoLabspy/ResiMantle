import { SealLevel } from './types';
import type { SealManager } from './seal-manager';

/**
 * Describes a hardening action that was applied or would be applied.
 */
export interface HardeningAction {
  zone: string;
  level: SealLevel;
  action: string;
  description: string;
  appliedAt: string;
}

/**
 * The HardeningApplier translates seal levels into concrete defensive actions.
 *
 * Based on the current seal level of a zone, it returns the set of
 * hardening rules that should be enforced. These rules are consumed by
 * the Access Gatekeeper to make real-time decisions.
 *
 * Hardening actions by seal level:
 *
 * OPEN:       No restrictions. All access allowed.
 * OBSERVED:   Access is allowed but fully logged. Behavioral data collected.
 * RESTRICTED: Non-typical actors require approval. Rate limits applied.
 * SEALED:     Only known actors from the behavioral profile are allowed.
 *             Unknown actors are blocked. All operations logged in detail.
 */
export class HardeningApplier {
  private appliedActions: HardeningAction[] = [];

  /**
   * Returns the hardening rules for a given zone based on its seal level.
   * These rules define what the Gatekeeper should enforce.
   */
  getHardeningRules(zoneName: string, level: SealLevel): HardeningRuleSet {
    switch (level) {
      case SealLevel.OPEN:
        return {
          blockUnknownActors: false,
          requireApproval: false,
          enforceRateLimit: false,
          logAllAccess: false,
          sensitiveReadPolicy: 'allow',
          sensitiveMutationPolicy: 'allow',
          outboundEgressPolicy: 'allow',
          rateLimit: undefined,
        };

      case SealLevel.OBSERVED:
        return {
          blockUnknownActors: false,
          requireApproval: false,
          enforceRateLimit: false,
          logAllAccess: true,
          sensitiveReadPolicy: 'allow',
          sensitiveMutationPolicy: 'allow',
          outboundEgressPolicy: 'observe',
          rateLimit: undefined,
        };

      case SealLevel.RESTRICTED:
        return {
          blockUnknownActors: false,
          requireApproval: true,
          enforceRateLimit: true,
          logAllAccess: true,
          sensitiveReadPolicy: 'read-only',
          sensitiveMutationPolicy: 'approval',
          outboundEgressPolicy: 'observe',
          rateLimit: { maxPerMinute: 30, maxPerHour: 500 },
        };

      case SealLevel.SEALED:
        return {
          blockUnknownActors: true,
          requireApproval: true,
          enforceRateLimit: true,
          logAllAccess: true,
          sensitiveReadPolicy: 'deny',
          sensitiveMutationPolicy: 'deny',
          outboundEgressPolicy: 'loopback-only',
          rateLimit: { maxPerMinute: 10, maxPerHour: 100 },
        };

      default:
        return {
          blockUnknownActors: false,
          requireApproval: false,
          enforceRateLimit: false,
          logAllAccess: false,
          sensitiveReadPolicy: 'allow',
          sensitiveMutationPolicy: 'allow',
          outboundEgressPolicy: 'allow',
          rateLimit: undefined,
        };
    }
  }

  /**
   * Generates a summary of hardening actions for reporting.
   */
  async generateHardeningSummary(sealManager: SealManager): Promise<HardeningAction[]> {
    const zones = sealManager.getAllZones();
    const actions: HardeningAction[] = [];

    for (const zone of zones) {
      const rules = this.getHardeningRules(zone.name, zone.level);
      const descriptions: string[] = [];

      if (rules.logAllAccess) descriptions.push('All access logged');
      if (rules.requireApproval) descriptions.push('Non-typical access requires approval');
      if (rules.blockUnknownActors) descriptions.push('Unknown actors BLOCKED');
      if (rules.sensitiveReadPolicy === 'read-only') descriptions.push('Sensitive reads limited to read-only decisions');
      if (rules.sensitiveReadPolicy === 'deny') descriptions.push('Sensitive reads denied by default');
      if (rules.sensitiveMutationPolicy === 'approval') descriptions.push('Sensitive mutations require approval');
      if (rules.sensitiveMutationPolicy === 'deny') descriptions.push('Sensitive mutations denied by default');
      if (rules.outboundEgressPolicy === 'observe') descriptions.push('Outbound egress observed');
      if (rules.outboundEgressPolicy === 'loopback-only') descriptions.push('Outbound egress limited to loopback');
      if (rules.enforceRateLimit && rules.rateLimit) {
        descriptions.push(`Rate limited: ${rules.rateLimit.maxPerMinute}/min, ${rules.rateLimit.maxPerHour}/hr`);
      }

      if (descriptions.length > 0) {
        actions.push({
          zone: zone.name,
          level: zone.level,
          action: zone.level,
          description: descriptions.join('; '),
          appliedAt: new Date().toISOString(),
        });
      }
    }

    this.appliedActions = actions;
    return actions;
  }

  /**
   * Returns all previously applied actions.
   */
  getAppliedActions(): HardeningAction[] {
    return [...this.appliedActions];
  }
}

/**
 * The set of concrete rules enforced at a given seal level.
 */
export interface HardeningRuleSet {
  blockUnknownActors: boolean;
  requireApproval: boolean;
  enforceRateLimit: boolean;
  logAllAccess: boolean;
  sensitiveReadPolicy: 'allow' | 'read-only' | 'deny';
  sensitiveMutationPolicy: 'allow' | 'approval' | 'deny';
  outboundEgressPolicy: 'allow' | 'observe' | 'loopback-only';
  rateLimit?: { maxPerMinute: number; maxPerHour: number };
}
