import type { SecurityEvent } from '@resimantle/types';
import { RiskLevel } from '@resimantle/types';

export interface AuditEntry {
  event: SecurityEvent;
  decision?: string;
  explanation?: string;
}

export interface Report {
  title: string;
  generatedAt: string;
  version: string;
  summary: string;
  overallRisk: RiskLevel;
  severityCounts: Record<string, number>;
  totalFindings: number;
  events: AuditEntry[];
}

export interface Explanation {
  humanReadable: string;
  technicalDetails: Record<string, unknown>;
}
