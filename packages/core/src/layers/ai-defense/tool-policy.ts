import type { ToolPolicy } from './types';

/**
 * Default tool policies for common AI agent tools.
 * Controls what operations AI agents are allowed to perform
 * through the ResiMantle protective layer.
 */
const DEFAULT_POLICIES: Map<string, ToolPolicy> = new Map([
  ['file_read', { toolName: 'file_read', allowed: true, requiresApproval: false, maxCallsPerMinute: 60 }],
  ['file_write', { toolName: 'file_write', allowed: true, requiresApproval: true, maxCallsPerMinute: 20 }],
  ['file_delete', { toolName: 'file_delete', allowed: false, requiresApproval: true, maxCallsPerMinute: 5 }],
  ['shell_exec', { toolName: 'shell_exec', allowed: false, requiresApproval: true, maxCallsPerMinute: 5, blockedActions: ['rm -rf', 'del /f', 'format', 'shutdown'] }],
  ['http_request', { toolName: 'http_request', allowed: true, requiresApproval: false, maxCallsPerMinute: 30 }],
  ['database_query', { toolName: 'database_query', allowed: true, requiresApproval: false, maxCallsPerMinute: 100, blockedActions: ['DROP', 'TRUNCATE', 'DELETE FROM', 'ALTER TABLE'] }],
  ['database_write', { toolName: 'database_write', allowed: true, requiresApproval: true, maxCallsPerMinute: 50 }],
  ['code_execute', { toolName: 'code_execute', allowed: false, requiresApproval: true, maxCallsPerMinute: 10 }],
  ['browser_navigate', { toolName: 'browser_navigate', allowed: true, requiresApproval: false, maxCallsPerMinute: 20 }],
  ['send_email', { toolName: 'send_email', allowed: false, requiresApproval: true, maxCallsPerMinute: 5 }],
  ['deploy', { toolName: 'deploy', allowed: false, requiresApproval: true, maxCallsPerMinute: 2 }],
]);

/**
 * Manages and enforces policies on AI agent tool usage.
 * Every tool invocation by an AI agent passes through this enforcer
 * before execution.
 */
export class ToolPolicyEnforcer {
  private policies: Map<string, ToolPolicy>;
  private callCounts: Map<string, { count: number; windowStart: number }> = new Map();

  constructor(customPolicies?: ToolPolicy[]) {
    this.policies = new Map(DEFAULT_POLICIES);

    // Merge custom policies
    if (customPolicies) {
      for (const p of customPolicies) {
        this.policies.set(p.toolName, p);
      }
    }
  }

  /**
   * Evaluates whether a specific tool invocation is allowed.
   * Checks: (1) whether the tool is allowed, (2) rate limits,
   * (3) blocked actions within the tool.
   */
  async enforce(toolName: string, action?: string): Promise<ToolPolicy & { rateLimited: boolean; blocked: boolean; reason?: string }> {
    const policy = this.policies.get(toolName) || {
      toolName,
      allowed: false,
      requiresApproval: true,
    };

    let rateLimited = false;
    let blocked = !policy.allowed;
    let reason: string | undefined;

    if (!policy.allowed) {
      reason = `Tool "${toolName}" is not allowed by policy`;
    }

    // Check rate limiting
    if (policy.allowed && policy.maxCallsPerMinute) {
      const now = Date.now();
      const entry = this.callCounts.get(toolName);

      if (entry && (now - entry.windowStart) < 60_000) {
        entry.count++;
        if (entry.count > policy.maxCallsPerMinute) {
          rateLimited = true;
          blocked = true;
          reason = `Rate limit exceeded: ${policy.maxCallsPerMinute} calls/minute for "${toolName}"`;
        }
      } else {
        this.callCounts.set(toolName, { count: 1, windowStart: now });
      }
    }

    // Check blocked actions
    if (action && policy.blockedActions) {
      const upperAction = action.toUpperCase();
      for (const blockedAction of policy.blockedActions) {
        if (upperAction.includes(blockedAction.toUpperCase())) {
          blocked = true;
          reason = `Action "${action}" matches blocked pattern "${blockedAction}" for tool "${toolName}"`;
          break;
        }
      }
    }

    return { ...policy, rateLimited, blocked, reason };
  }

  evaluateWorkflow(tools: string[]): { blocked: boolean; riskScore: number; flags: string[]; reason?: string } {
    const normalized = Array.from(new Set(tools.map(tool => tool.toLowerCase())));
    const flags: string[] = [];
    let riskScore = 0;

    if (includesAll(normalized, ['file_read', 'shell_exec', 'http_request'])) {
      flags.push('secret-to-shell-to-network chain');
      riskScore += 0.95;
    }

    if (includesAll(normalized, ['file_read', 'database_query', 'http_request'])) {
      flags.push('data-access to network egress chain');
      riskScore += 0.85;
    }

    if (includesAll(normalized, ['code_execute', 'http_request'])) {
      flags.push('code execution with network egress');
      riskScore += 0.9;
    }

    if (includesAll(normalized, ['file_delete', 'shell_exec'])) {
      flags.push('destructive shell workflow');
      riskScore += 0.8;
    }

    if (includesAll(normalized, ['deploy', 'shell_exec'])) {
      flags.push('deployment plus shell pivot');
      riskScore += 0.75;
    }

    const blocked = riskScore >= 0.85;

    return {
      blocked,
      riskScore: Math.min(1, Math.round(riskScore * 100) / 100),
      flags,
      reason: blocked ? `Risky tool workflow detected: ${flags.join(', ')}` : undefined,
    };
  }

  /**
   * Returns all registered policies.
   */
  getAllPolicies(): ToolPolicy[] {
    return Array.from(this.policies.values());
  }
}

function includesAll(tools: string[], expected: string[]): boolean {
  return expected.every(tool => tools.includes(tool));
}
