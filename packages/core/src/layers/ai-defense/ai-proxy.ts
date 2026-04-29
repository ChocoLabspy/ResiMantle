import { randomUUID } from 'node:crypto';
import type { AICallAudit } from './types';
import { PromptShield } from './prompt-shield';
import { ToolPolicyEnforcer } from './tool-policy';
import { logger } from '../../common/logger';

interface ProxySessionRiskState {
  calls: number;
  score: number;
  flags: Set<string>;
}

/**
 * The AI Proxy intercepts and audits all outbound calls to AI model APIs.
 * It serves as a middleware layer that:
 * 1. Analyzes prompts for injection before sending them
 * 2. Enforces tool usage policies
 * 3. Logs all AI interactions for audit trail
 * 4. Blocks dangerous requests
 */
export class AiProxy {
  private shield: PromptShield;
  private toolPolicy: ToolPolicyEnforcer;
  private auditLog: AICallAudit[] = [];
  private sessionRisk = new Map<string, ProxySessionRiskState>();

  constructor() {
    this.shield = new PromptShield();
    this.toolPolicy = new ToolPolicyEnforcer();
  }

  /**
   * Intercepts an AI call, analyzes it, and produces an audit record.
   * Returns the audit record. If `blocked` is true, the caller should
   * NOT forward the request to the AI provider.
   */
  async intercept(callDetails: {
    prompt: string;
    model?: string;
    provider?: string;
    tools?: string[];
    sessionId?: string;
    actorId?: string;
  }): Promise<AICallAudit> {
    const startTime = Date.now();
    const sessionId = callDetails.sessionId ?? 'default';
    const actorId = callDetails.actorId ?? 'unknown';

    // Step 1: Analyze the prompt for injection
    const analysis = await this.shield.analyze(callDetails.prompt);
    const workflowRisk = this.toolPolicy.evaluateWorkflow(callDetails.tools ?? []);
    const sessionRisk = this.getSessionRisk(sessionId);

    let blocked = false;
    let blockReason: string | undefined;

    // Block if injection risk is HIGH or above
    if (!analysis.isSafe && analysis.score >= 0.5) {
      blocked = true;
      blockReason = `Prompt injection detected (score: ${analysis.score}). Flags: ${analysis.flags.join('; ')}`;
      logger.warn(`AI call BLOCKED: ${blockReason}`);
    }

    if (!blocked && isHighRiskIntent(analysis)) {
      blocked = true;
      blockReason = `High-risk agent intent detected (${analysis.categories.join(', ')})`;
      logger.warn(`AI call BLOCKED: ${blockReason}`);
    }

    // Step 2: Check tool policies
    if (!blocked && callDetails.tools) {
      for (const tool of callDetails.tools) {
        const result = await this.toolPolicy.enforce(tool);
        if (result.blocked) {
          blocked = true;
          blockReason = result.reason || `Tool "${tool}" blocked by policy`;
          logger.warn(`AI tool BLOCKED: ${blockReason}`);
          break;
        }
      }
    }

    if (!blocked && workflowRisk.blocked) {
      blocked = true;
      blockReason = workflowRisk.reason;
      logger.warn(`AI workflow BLOCKED: ${blockReason}`);
    }

    const nextSessionRisk = this.updateSessionRisk(sessionId, sessionRisk, analysis, workflowRisk);

    if (!blocked && nextSessionRisk.score >= 0.9) {
      blocked = true;
      blockReason = `Session risk threshold exceeded (${nextSessionRisk.score})`;
      logger.warn(`AI session BLOCKED: ${blockReason}`);
    }

    const audit: AICallAudit = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      sessionId,
      actorId,
      model: callDetails.model || 'unknown',
      provider: callDetails.provider || 'unknown',
      promptLength: callDetails.prompt.length,
      promptAnalysis: analysis,
      toolsUsed: callDetails.tools || [],
      blocked,
      blockReason,
      workflowRiskScore: workflowRisk.riskScore,
      sessionRiskScore: nextSessionRisk.score,
      workflowFlags: workflowRisk.flags,
      durationMs: Date.now() - startTime,
    };

    this.auditLog.push(audit);
    return audit;
  }

  /**
   * Returns all audit records for this session.
   */
  getAuditLog(): AICallAudit[] {
    return [...this.auditLog];
  }

  /**
   * Returns the prompt shield instance for direct usage.
   */
  getShield(): PromptShield {
    return this.shield;
  }

  private getSessionRisk(sessionId: string): ProxySessionRiskState {
    return this.sessionRisk.get(sessionId) ?? {
      calls: 0,
      score: 0,
      flags: new Set<string>(),
    };
  }

  private updateSessionRisk(
    sessionId: string,
    current: ProxySessionRiskState,
    analysis: AICallAudit['promptAnalysis'],
    workflowRisk: { riskScore: number; flags: string[] },
  ): ProxySessionRiskState {
    const next: ProxySessionRiskState = {
      calls: current.calls + 1,
      score: Math.min(1, Math.round((current.score + (analysis.score * 0.55) + (workflowRisk.riskScore * 0.45)) * 100) / 100),
      flags: new Set([...current.flags, ...analysis.categories, ...workflowRisk.flags]),
    };

    this.sessionRisk.set(sessionId, next);
    return next;
  }
}

function isHighRiskIntent(analysis: AICallAudit['promptAnalysis']): boolean {
  const highRiskCategories = new Set([
    'secret-access',
    'exfiltration',
    'stealth',
    'exploit-development',
    'privilege-escalation',
  ]);

  return analysis.score >= 0.45
    && analysis.categories.some(category => highRiskCategories.has(category));
}
