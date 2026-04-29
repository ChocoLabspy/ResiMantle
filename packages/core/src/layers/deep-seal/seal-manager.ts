import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ProtectedZone, EscalationCondition } from './types';
import { SealLevel } from './types';
import { logger } from '../../common/logger';

/**
 * Default escalation conditions applied to every zone.
 */
const DEFAULT_ESCALATION: EscalationCondition[] = [
  { trigger: 'ANOMALY_COUNT', threshold: 3, targetLevel: SealLevel.OBSERVED },
  { trigger: 'ANOMALY_COUNT', threshold: 10, targetLevel: SealLevel.RESTRICTED },
  { trigger: 'ANOMALY_COUNT', threshold: 25, targetLevel: SealLevel.SEALED },
  { trigger: 'ANOMALY_SCORE', threshold: 0.85, targetLevel: SealLevel.SEALED },
];

/**
 * Default protected zones that are created on initialization.
 */
const DEFAULT_ZONES: Omit<ProtectedZone, 'createdAt' | 'anomalyCount' | 'observationCount'>[] = [
  {
    name: 'admin-endpoints',
    resourcePattern: '.*\\/admin.*',
    level: SealLevel.OBSERVED,
    escalationConditions: DEFAULT_ESCALATION,
  },
  {
    name: 'auth-routes',
    resourcePattern: '.*\\/(?:auth|login|signup|oauth|token).*',
    level: SealLevel.OBSERVED,
    escalationConditions: DEFAULT_ESCALATION,
  },
  {
    name: 'database-operations',
    resourcePattern: '.*(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE).*',
    level: SealLevel.OBSERVED,
    escalationConditions: DEFAULT_ESCALATION,
  },
  {
    name: 'sensitive-files',
    resourcePattern: '.*\\.(?:env|pem|key|cert|p12|pfx|jks)$',
    level: SealLevel.RESTRICTED,
    escalationConditions: DEFAULT_ESCALATION,
  },
  {
    name: 'system-paths',
    resourcePattern: '(?:\\/etc\\/|\\/proc\\/|\\/sys\\/|C:\\\\Windows\\\\)',
    level: SealLevel.SEALED,
    escalationConditions: DEFAULT_ESCALATION,
  },
  {
    name: 'shell-execution',
    resourcePattern: '.*(?:exec|spawn|fork|shell).*',
    level: SealLevel.RESTRICTED,
    escalationConditions: DEFAULT_ESCALATION,
  },
];

/**
 * The SealManager controls the "hardening" lifecycle of protected zones.
 *
 * Each zone progresses through seal levels based on observed anomalies:
 * OPEN → OBSERVED → RESTRICTED → SEALED
 *
 * This progression mirrors the resin metaphor:
 * - OPEN: Fresh coat, no restrictions
 * - OBSERVED: Absorption phase, learning behavior
 * - RESTRICTED: Deep Seal phase, applying stricter controls
 * - SEALED: Cured, fully hardened — only expected behavior allowed
 *
 * Zones can also be manually escalated or de-escalated.
 */
export class SealManager {
  private zones: Map<string, ProtectedZone> = new Map();
  private storePath: string;

  constructor(resiMantleDir: string) {
    this.storePath = join(resiMantleDir, 'zones.json');
  }

  /**
   * Initializes zones from disk or creates defaults.
   */
  async initialize(): Promise<void> {
    if (existsSync(this.storePath)) {
      await this.loadFromDisk();
    } else {
      this.createDefaultZones();
    }
    logger.info(`SealManager initialized with ${this.zones.size} zones`);
  }

  /**
   * Returns the seal level for a resource by matching it against all zones.
   * Returns the highest (most restrictive) matching level.
   */
  getZoneStatus(resource: string): { zone: ProtectedZone | null; level: SealLevel } {
    let highestLevel = SealLevel.OPEN;
    let matchedZone: ProtectedZone | null = null;

    for (const zone of this.zones.values()) {
      try {
        const regex = new RegExp(zone.resourcePattern, 'i');
        if (regex.test(resource)) {
          const currentOrder = SEAL_ORDER.indexOf(zone.level);
          const highestOrder = SEAL_ORDER.indexOf(highestLevel);

          if (currentOrder > highestOrder) {
            highestLevel = zone.level;
            matchedZone = zone;
          }
        }
      } catch {
        // Invalid regex — skip
      }
    }

    return { zone: matchedZone, level: highestLevel };
  }

  /**
   * Records an anomaly for a resource and potentially escalates the zone's seal level.
   */
  async recordAnomaly(resource: string, anomalyScore: number): Promise<{
    escalated: boolean;
    previousLevel?: SealLevel;
    newLevel?: SealLevel;
    zone?: string;
  }> {
    for (const zone of this.zones.values()) {
      try {
        const regex = new RegExp(zone.resourcePattern, 'i');
        if (!regex.test(resource)) continue;

        zone.anomalyCount++;
        zone.observationCount++;

        // Check escalation conditions
        for (const condition of zone.escalationConditions) {
          const shouldEscalate = this.checkEscalation(zone, condition, anomalyScore);
          if (shouldEscalate) {
            const currentOrder = SEAL_ORDER.indexOf(zone.level);
            const targetOrder = SEAL_ORDER.indexOf(condition.targetLevel);

            if (targetOrder > currentOrder) {
              const previousLevel = zone.level;
              zone.level = condition.targetLevel;
              zone.lastEscalatedAt = new Date().toISOString();

              logger.warn(`🔒 Zone "${zone.name}" ESCALATED: ${previousLevel} → ${zone.level} (anomalies: ${zone.anomalyCount}, score: ${anomalyScore})`);

              await this.persist();

              return {
                escalated: true,
                previousLevel,
                newLevel: zone.level,
                zone: zone.name,
              };
            }
          }
        }
      } catch {
        // Invalid regex — skip
      }
    }

    return { escalated: false };
  }

  /**
   * Records a normal observation (non-anomalous).
   */
  recordObservation(resource: string): void {
    for (const zone of this.zones.values()) {
      try {
        const regex = new RegExp(zone.resourcePattern, 'i');
        if (regex.test(resource)) {
          zone.observationCount++;
        }
      } catch {
        // Invalid regex — skip
      }
    }
  }

  /**
   * Manually sets the seal level of a zone.
   */
  async setSealLevel(zoneName: string, level: SealLevel): Promise<boolean> {
    const zone = this.zones.get(zoneName);
    if (!zone) return false;

    const prev = zone.level;
    zone.level = level;
    zone.lastEscalatedAt = new Date().toISOString();
    await this.persist();

    logger.info(`Zone "${zoneName}" seal level set: ${prev} → ${level}`);
    return true;
  }

  /**
   * Returns all zones.
   */
  getAllZones(): ProtectedZone[] {
    return Array.from(this.zones.values());
  }

  /**
   * Adds a new custom zone.
   */
  async addZone(zone: Omit<ProtectedZone, 'createdAt' | 'anomalyCount' | 'observationCount'>): Promise<void> {
    const fullZone: ProtectedZone = {
      ...zone,
      createdAt: new Date().toISOString(),
      anomalyCount: 0,
      observationCount: 0,
    };
    this.zones.set(zone.name, fullZone);
    await this.persist();
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private checkEscalation(
    zone: ProtectedZone,
    condition: EscalationCondition,
    anomalyScore: number,
  ): boolean {
    switch (condition.trigger) {
      case 'ANOMALY_COUNT':
        return zone.anomalyCount >= condition.threshold;
      case 'ANOMALY_SCORE':
        return anomalyScore >= condition.threshold;
      case 'UNKNOWN_ACTOR':
        return zone.anomalyCount >= condition.threshold;
      case 'TIME_BASED':
        return zone.observationCount >= condition.threshold;
      default:
        return false;
    }
  }

  private createDefaultZones(): void {
    const now = new Date().toISOString();
    for (const template of DEFAULT_ZONES) {
      const zone: ProtectedZone = {
        ...template,
        createdAt: now,
        anomalyCount: 0,
        observationCount: 0,
      };
      this.zones.set(zone.name, zone);
    }
  }

  private async persist(): Promise<void> {
    try {
      const dir = join(this.storePath, '..');
      if (!existsSync(dir)) await mkdir(dir, { recursive: true });

      const data = JSON.stringify(Array.from(this.zones.values()), null, 2);
      await writeFile(this.storePath, data, 'utf-8');
    } catch (error) {
      logger.error(`Failed to persist zones: ${(error as Error).message}`);
    }
  }

  private async loadFromDisk(): Promise<void> {
    try {
      const raw = await readFile(this.storePath, 'utf-8');
      const parsed: ProtectedZone[] = JSON.parse(raw);
      for (const zone of parsed) {
        this.zones.set(zone.name, zone);
      }
    } catch {
      this.createDefaultZones();
    }
  }
}

/** Seal level ordering from least to most restrictive. */
const SEAL_ORDER = [SealLevel.OPEN, SealLevel.OBSERVED, SealLevel.RESTRICTED, SealLevel.SEALED];
