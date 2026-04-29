import { randomUUID } from 'node:crypto';
import { writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { AuditEntry } from './types';
import { RiskLevel } from '@resimantle/types';
import { logger } from '../../common/logger';

/**
 * The Auditor is the central logging component of the Audit & Explain layer.
 * It maintains an append-only log of all security events, decisions,
 * and explanations produced by the system.
 */
export class Auditor {
  private entries: AuditEntry[] = [];
  private logDir: string;

  constructor(resiMantleDir: string) {
    this.logDir = join(resiMantleDir, 'audit');
  }

  /**
   * Records a new audit entry.
   */
  async log(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
    logger.debug(`Audit: [${entry.event.severity}] ${entry.event.type} — ${entry.explanation || 'No explanation'}`);
  }

  /**
   * Records a structured security event without requiring callers to build
   * the full event envelope themselves.
   */
  async record(params: {
    source: string;
    type: string;
    severity?: RiskLevel;
    details?: Record<string, unknown>;
    decision?: string;
    explanation?: string;
  }): Promise<AuditEntry> {
    const entry: AuditEntry = {
      event: {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        source: params.source,
        type: params.type,
        severity: params.severity ?? RiskLevel.INFO,
        details: params.details ?? {},
      },
      decision: params.decision,
      explanation: params.explanation,
    };

    await this.log(entry);
    return entry;
  }

  /**
   * Persists all audit entries to disk as a JSON file.
   */
  async flush(): Promise<string> {
    if (!existsSync(this.logDir)) {
      await mkdir(this.logDir, { recursive: true });
    }

    const filename = `audit-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const filePath = join(this.logDir, filename);

    await writeFile(filePath, JSON.stringify(this.entries, null, 2), 'utf-8');
    logger.info(`Audit log written to ${filePath} (${this.entries.length} entries)`);
    return filePath;
  }

  /**
   * Returns all entries recorded so far.
   */
  getEntries(): AuditEntry[] {
    return [...this.entries];
  }

  /**
   * Returns entries filtered by severity level.
   */
  getEntriesBySeverity(severity: string): AuditEntry[] {
    return this.entries.filter(e => e.event.severity === severity);
  }
}
