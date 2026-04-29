/**
 * @resimantle/types — Shared types for the ResiMantle security framework.
 */

// ─── Maturation Phases ───────────────────────────────────────────────────────

/**
 * Represents the 5 maturation phases of the ResiMantle protective layer.
 * Each phase maps to a real state in the resin metaphor.
 */
export enum MaturationPhase {
  /** First application — basic external defenses only */
  FRESH_COAT = 'FRESH_COAT',
  /** The resin absorbs into the project structure; learning behavior */
  ABSORPTION = 'ABSORPTION',
  /** Hardening sensitive zones based on observations */
  DEEP_SEAL = 'DEEP_SEAL',
  /** Fully operational — stable behavioral model, active gatekeeper */
  CURING = 'CURING',
  /** Continuous re-coating on new deployments */
  RECOAT = 'RECOAT',
}

// ─── Risk Levels ─────────────────────────────────────────────────────────────

/**
 * Standard risk levels used across the system. These form a strict ordering
 * that the engine uses for aggregation and escalation logic.
 */
export enum RiskLevel {
  NONE = 'NONE',
  INFO = 'INFO',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

/** Numeric weight for each risk level (higher = more severe). */
export const RISK_WEIGHTS: Record<RiskLevel, number> = {
  [RiskLevel.NONE]: 0,
  [RiskLevel.INFO]: 1,
  [RiskLevel.LOW]: 2,
  [RiskLevel.MEDIUM]: 4,
  [RiskLevel.HIGH]: 8,
  [RiskLevel.CRITICAL]: 16,
};

// ─── Access Decisions ────────────────────────────────────────────────────────

/**
 * Possible access decisions made by the Access Gatekeeper.
 * Ordered from most permissive to most restrictive.
 */
export enum AccessDecision {
  ALLOW = 'ALLOW',
  ALLOW_WITH_LOGGING = 'ALLOW_WITH_LOGGING',
  ALLOW_LIMITED = 'ALLOW_LIMITED',
  ALLOW_READ_ONLY = 'ALLOW_READ_ONLY',
  REQUIRE_APPROVAL = 'REQUIRE_APPROVAL',
  QUARANTINE = 'QUARANTINE',
  BLOCK = 'BLOCK',
}

// ─── Security Events ────────────────────────────────────────────────────────

/**
 * Categories for security events emitted by the system.
 */
export enum SecurityEventType {
  SECRET_EXPOSED = 'SECRET_EXPOSED',
  VULNERABLE_DEPENDENCY = 'VULNERABLE_DEPENDENCY',
  CONFIG_ISSUE = 'CONFIG_ISSUE',
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  CANARY_TRIGGERED = 'CANARY_TRIGGERED',
  STORY_BOUND = 'STORY_BOUND',
  STORY_ASSET_READ = 'STORY_ASSET_READ',
  STORY_ASSET_SEARCHED = 'STORY_ASSET_SEARCHED',
  STORY_ASSET_INVOKED = 'STORY_ASSET_INVOKED',
  CANARY_REUSED = 'CANARY_REUSED',
  FALSE_VICTORY_APPLIED = 'FALSE_VICTORY_APPLIED',
  SHADOW_SINK_WRITTEN = 'SHADOW_SINK_WRITTEN',
  ANOMALY_DETECTED = 'ANOMALY_DETECTED',
  ACCESS_BLOCKED = 'ACCESS_BLOCKED',
  POLICY_VIOLATION = 'POLICY_VIOLATION',
  TOOL_POLICY_VIOLATION = 'TOOL_POLICY_VIOLATION',
  SCAN_COMPLETED = 'SCAN_COMPLETED',
  ENGINE_STARTED = 'ENGINE_STARTED',
  ENGINE_STOPPED = 'ENGINE_STOPPED',
}

/**
 * Core event representation emitted by any layer.
 */
export interface SecurityEvent {
  id: string;
  timestamp: string;
  source: string;
  type: SecurityEventType | string;
  severity: RiskLevel;
  details: Record<string, unknown>;
}

// ─── Layers ─────────────────────────────────────────────────────────────────

/**
 * Identifiers for the 9 architectural layers.
 */
export type LayerName =
  | 'SurfaceCoat'
  | 'AIDefense'
  | 'ResinTraps'
  | 'RuntimeMonitor'
  | 'BehaviorModel'
  | 'DeepSeal'
  | 'AccessGatekeeper'
  | 'PolicyEngine'
  | 'AuditExplain';

// ─── Finding (universal result type) ────────────────────────────────────────

/**
 * A single finding produced by any detector / analyzer.
 * This is the normalized output format for all scan results.
 */
export interface Finding {
  id: string;
  layer: LayerName;
  type: SecurityEventType | string;
  severity: RiskLevel;
  title: string;
  description: string;
  file?: string;
  line?: number;
  column?: number;
  evidence?: string;
  recommendation?: string;
  metadata?: Record<string, unknown>;
}

// ─── Scan Summary ───────────────────────────────────────────────────────────

/**
 * Aggregated summary of a complete scan run.
 */
export interface ScanSummary {
  startedAt: string;
  completedAt: string;
  durationMs: number;
  totalFindings: number;
  findingsBySeverity: Record<RiskLevel, number>;
  findings: Finding[];
  overallRisk: RiskLevel;
  filesScanned: number;
  phase: MaturationPhase;
}
