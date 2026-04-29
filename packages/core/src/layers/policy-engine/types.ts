import type { AccessDecision } from '@resimantle/types';

export interface PolicyRule {
  resourcePattern: string;
  actorPattern: string;
  decision: AccessDecision;
  priority: number;
  description?: string;
}

export interface Policy {
  version: string;
  rules: PolicyRule[];
}

export interface PolicyEvaluation {
  decision: AccessDecision;
  matchedRule?: PolicyRule;
  reason: string;
}
