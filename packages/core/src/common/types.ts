// Placeholder for core-specific types that are not part of the public @resimantle/types package
export interface EngineOptions {
  cwd: string;
  configPath?: string;
  dryRun?: boolean;
}

export interface EngineScanOptions {
  scanPaths?: string[];
}

export type ProcessContainmentMode = 'off' | 'adaptive' | 'strict';

export interface ProcessContainmentCapabilityModes {
  reads?: ProcessContainmentMode;
  processes?: ProcessContainmentMode;
  sockets?: ProcessContainmentMode;
}

export interface ProcessContainmentAllowlist {
  readPatterns?: string[];
  processPatterns?: string[];
  socketHosts?: string[];
  socketHostPatterns?: string[];
  socketPathPatterns?: string[];
}

export type CompatibilityBaselineMode = 'off' | 'observe' | 'assist';

export interface CompatibilityBaselineConfig {
  enabled?: boolean;
  mode?: CompatibilityBaselineMode;
  persistencePath?: string;
  minOccurrences?: number;
  autoApplyToContainment?: boolean;
  reduceRiskFromKnownActivity?: boolean;
}

export interface RuntimeControlConfig {
  autoPosture?: boolean;
  sessionTtlMs?: number;
  heartbeatGraceMs?: number;
  capabilityQuarantine?: boolean;
}

export type ActorTrustState =
  | 'trusted'
  | 'observed'
  | 'suspicious'
  | 'deceptive'
  | 'restricted'
  | 'quarantined';
