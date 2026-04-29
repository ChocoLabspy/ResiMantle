import type { RiskLevel } from '@resimantle/types';

export interface PromptAnalysis {
  isSafe: boolean;
  injectionRisk: RiskLevel;
  flags: string[];
  categories: string[];
  score: number;
  patternsMatched: number;
}

export interface ToolPolicy {
  toolName: string;
  allowed: boolean;
  requiresApproval: boolean;
  maxCallsPerMinute?: number;
  blockedActions?: string[];
}

export interface AICallAudit {
  id: string;
  timestamp: string;
  sessionId: string;
  actorId: string;
  model: string;
  provider: string;
  promptLength: number;
  promptAnalysis: PromptAnalysis;
  toolsUsed: string[];
  blocked: boolean;
  blockReason?: string;
  workflowRiskScore: number;
  sessionRiskScore: number;
  workflowFlags: string[];
  durationMs: number;
}
