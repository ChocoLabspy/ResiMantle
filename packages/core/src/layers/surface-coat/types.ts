import type { RiskLevel } from '@resimantle/types';

// ─── Secret Detection ──────────────────────────────────────────────────────

export interface ExposedSecret {
  file: string;
  line: number;
  type: string;
  name: string;
  risk: RiskLevel;
  evidence: string;
}

// ─── Dependency Analysis ───────────────────────────────────────────────────

export interface DependencyVulnerability {
  name: string;
  version: string;
  advisoryId: string;
  severity: RiskLevel;
  description: string;
}

// ─── Configuration Issues ──────────────────────────────────────────────────

export interface ConfigIssue {
  file: string;
  issue: string;
  recommendation: string;
  severity: RiskLevel;
}

// ─── Aggregated Scan Result ────────────────────────────────────────────────

export interface SurfaceScanResult {
  exposedSecrets: ExposedSecret[];
  vulnerableDependencies: DependencyVulnerability[];
  configIssues: ConfigIssue[];
  totalRisk: RiskLevel;
  filesScanned: number;
  durationMs: number;
}
