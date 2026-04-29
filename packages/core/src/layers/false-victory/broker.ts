import { AccessDecision, RiskLevel } from '@resimantle/types';
import type { Auditor } from '../audit';
import { ShadowSink } from './shadow-sink';
import type {
  FalseVictoryContext,
  FalseVictoryPlan,
  FalseVictoryResponse,
  FalseVictoryResult,
  ShadowSinkRecord,
} from './types';

const ELIGIBLE_TRUST_STATES = new Set<FalseVictoryContext['trustState']>([
  'suspicious',
  'deceptive',
  'restricted',
  'quarantined',
]);

export const DEFAULT_FALSE_VICTORY_PLANS: FalseVictoryPlan[] = [
  {
    id: 'decoy-admin-accepted',
    name: 'Decoy Admin Accepted',
    appliesTo: ['decoy-admin-route'],
    responseShape: 'accepted-job',
    shadowSink: 'decoy-admin',
    explanation: 'Suspicious admin route traffic is redirected into a shadow job sink.',
    allowedDecisions: [
      AccessDecision.ALLOW_LIMITED,
      AccessDecision.ALLOW_WITH_LOGGING,
      AccessDecision.QUARANTINE,
      AccessDecision.BLOCK,
    ],
    resourcePatterns: ['/admin', '/internal', '/tokens/rotate', '/dump'],
  },
  {
    id: 'shadow-export-complete',
    name: 'Shadow Export Complete',
    appliesTo: ['tool-write'],
    responseShape: 'completed-export',
    shadowSink: 'tool-write',
    explanation: 'Suspicious write-like tool actions complete only inside a synthetic shadow workspace.',
    allowedDecisions: [
      AccessDecision.ALLOW_LIMITED,
      AccessDecision.ALLOW_READ_ONLY,
      AccessDecision.QUARANTINE,
    ],
    resourcePatterns: ['export', 'backup', 'snapshot', 'write'],
  },
];

interface FalseVictoryBrokerOptions {
  plans?: FalseVictoryPlan[];
  shadowSink?: ShadowSink;
  auditor?: Auditor;
}

export class FalseVictoryBroker {
  private plans: FalseVictoryPlan[];
  private shadowSink: ShadowSink;
  private auditor?: Auditor;

  constructor(resiMantleDir: string, options: FalseVictoryBrokerOptions = {}) {
    this.plans = options.plans ?? DEFAULT_FALSE_VICTORY_PLANS;
    this.shadowSink = options.shadowSink ?? new ShadowSink(resiMantleDir);
    this.auditor = options.auditor;
  }

  async evaluate(context: FalseVictoryContext): Promise<FalseVictoryResult> {
    if (!ELIGIBLE_TRUST_STATES.has(context.trustState)) {
      return {
        applied: false,
        reason: 'False victory is reserved for suspicious, deceptive, restricted, or quarantined actors.',
      };
    }

    const plan = this.selectPlan(context);
    if (!plan) {
      return {
        applied: false,
        reason: 'No false-victory plan matched the current action.',
      };
    }

    const record = await this.shadowSink.write({
      planId: plan.id,
      actorId: context.actorId,
      sessionId: context.sessionId,
      resource: context.resource,
      actionType: context.actionType,
      payload: context.metadata,
    });

    await this.auditor?.record({
      source: 'FalseVictory.ShadowSink',
      type: 'SHADOW_SINK_WRITTEN',
      severity: RiskLevel.INFO,
      details: {
        actorId: context.actorId,
        sessionId: context.sessionId,
        resource: context.resource,
        actionType: context.actionType,
        planId: plan.id,
        sinkRecordId: record.id,
      },
      explanation: `Shadow sink ${record.id} stored a synthetic ${context.actionType} action.`,
    });

    await this.auditor?.record({
      source: 'FalseVictory.Broker',
      type: 'FALSE_VICTORY_APPLIED',
      severity: RiskLevel.LOW,
      details: {
        actorId: context.actorId,
        sessionId: context.sessionId,
        resource: context.resource,
        actionType: context.actionType,
        trustState: context.trustState,
        planId: plan.id,
        sinkRecordId: record.id,
      },
      decision: plan.name,
      explanation: plan.explanation,
    });

    return {
      applied: true,
      reason: plan.explanation,
      planId: plan.id,
      sinkRecordId: record.id,
      response: this.buildResponse(plan, record),
    };
  }

  private selectPlan(context: FalseVictoryContext): FalseVictoryPlan | undefined {
    return this.plans.find(plan => {
      if (!plan.appliesTo.includes(context.actionType)) {
        return false;
      }

      if (plan.allowedDecisions?.length && context.decision && !plan.allowedDecisions.includes(context.decision)) {
        return false;
      }

      if (plan.allowedDecisions?.length && !context.decision) {
        return false;
      }

      if (!plan.resourcePatterns?.length) {
        return true;
      }

      const normalizedResource = context.resource.toLowerCase();
      return plan.resourcePatterns.some(pattern => normalizedResource.includes(pattern.toLowerCase()));
    });
  }

  private buildResponse(plan: FalseVictoryPlan, record: ShadowSinkRecord): FalseVictoryResponse {
    switch (plan.responseShape) {
      case 'accepted-job':
        return {
          statusCode: 202,
          headers: {
            'x-resimantle-shadow-id': record.id,
          },
          body: {
            success: true,
            status: 'queued',
            jobId: record.id,
          },
        };

      case 'completed-export':
        return {
          statusCode: 200,
          headers: {
            'x-resimantle-shadow-id': record.id,
          },
          body: {
            success: true,
            status: 'completed',
            artifactId: record.id,
          },
        };

      case 'forbidden-looking-success':
        return {
          statusCode: 200,
          headers: {
            'x-resimantle-shadow-id': record.id,
          },
          body: {
            success: true,
            status: 'applied',
            policyState: 'restricted',
          },
        };
    }
  }
}