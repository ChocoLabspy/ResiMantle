import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import type { PolicyRule, Policy, PolicyEvaluation } from './types';
import { PolicySchema } from './schemas';
import { DEFAULT_POLICY } from './defaults';
import { AccessDecision } from '@resimantle/types';
import { logger } from '../../common/logger';

/**
 * Context provided for policy evaluation.
 */
export interface PolicyContext {
  resource: string;
  actor: string;
  action?: string;
  metadata?: Record<string, unknown>;
}

/**
 * The Policy Engine evaluates access requests against a set of declarative rules.
 * Rules are loaded from a JSON policy file and sorted by priority (lowest = highest priority).
 *
 * Matching is done via regex patterns on the resource and actor fields.
 * The first matching rule (by priority order) determines the decision.
 */
export class PolicyEngine {
  private policy: Policy;
  private compiledRules: { rule: PolicyRule; resourceRegex: RegExp; actorRegex: RegExp }[] = [];

  constructor(policy?: Policy) {
    this.policy = policy || DEFAULT_POLICY;
    this.compileRules();
  }

  /**
   * Loads a policy from a JSON file path.
   * Falls back to the default policy if the file doesn't exist.
   */
  static async fromFile(policyPath: string): Promise<PolicyEngine> {
    if (!existsSync(policyPath)) {
      logger.info(`No policy file found at ${policyPath}, using defaults`);
      return new PolicyEngine();
    }

    try {
      const raw = await readFile(policyPath, 'utf-8');
      const parsed = JSON.parse(raw);
      const validated = PolicySchema.parse(parsed);
      return new PolicyEngine(validated);
    } catch (error) {
      logger.warn(`Failed to parse policy file: ${(error as Error).message}. Using defaults.`);
      return new PolicyEngine();
    }
  }

  /**
   * Evaluates an access request against the loaded policy.
   * Returns the decision and the matched rule (if any).
   */
  async evaluate(context: PolicyContext): Promise<PolicyEvaluation> {
    for (const { rule, resourceRegex, actorRegex } of this.compiledRules) {
      const resourceMatch = resourceRegex.test(context.resource);
      const actorMatch = actorRegex.test(context.actor);

      if (resourceMatch && actorMatch) {
        logger.debug(`Policy match: resource="${context.resource}" actor="${context.actor}" → ${rule.decision} (rule priority: ${rule.priority})`);
        return {
          decision: rule.decision,
          matchedRule: rule,
          reason: `Matched rule: resource="${rule.resourcePattern}" actor="${rule.actorPattern}"`,
        };
      }
    }

    return resolveDefaultDecision(context);
  }

  /**
   * Pre-compiles all rule patterns to RegExp for performance.
   * Rules are sorted by priority (ascending = highest priority first).
   */
  private compileRules(): void {
    const sorted = [...this.policy.rules].sort((a, b) => a.priority - b.priority);

    this.compiledRules = sorted.map(rule => ({
      rule,
      resourceRegex: new RegExp(rule.resourcePattern, 'i'),
      actorRegex: new RegExp(rule.actorPattern, 'i'),
    }));
  }

  /**
   * Returns all loaded rules.
   */
  getRules(): PolicyRule[] {
    return [...this.policy.rules];
  }

  /**
   * Adds a rule at runtime (useful for dynamic hardening).
   */
  addRule(rule: PolicyRule): void {
    this.policy.rules.push(rule);
    this.compileRules();
  }
}

function resolveDefaultDecision(context: PolicyContext): PolicyEvaluation {
  const sensitivity = context.metadata?.['sensitivity'];
  const actionKind = context.metadata?.['actionKind'];

  if (sensitivity === 'high') {
    if (actionKind === 'read' || actionKind === 'search') {
      return {
        decision: AccessDecision.ALLOW_READ_ONLY,
        reason: 'No matching policy rule found — inferred sensitive resource defaults to ALLOW_READ_ONLY',
      };
    }

    if (actionKind === 'mutate' || actionKind === 'process' || actionKind === 'egress') {
      return {
        decision: AccessDecision.REQUIRE_APPROVAL,
        reason: 'No matching policy rule found — inferred sensitive mutation defaults to REQUIRE_APPROVAL',
      };
    }
  }

  return {
    decision: AccessDecision.ALLOW,
    reason: 'No matching policy rule found — default ALLOW',
  };
}
