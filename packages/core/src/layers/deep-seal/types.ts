export enum SealLevel {
  /** Fully open — no restrictions */
  OPEN = 'OPEN',
  /** Being observed — learning phase */
  OBSERVED = 'OBSERVED',
  /** Restricted — non-typical access requires approval */
  RESTRICTED = 'RESTRICTED',
  /** Fully sealed — only known actors/patterns allowed */
  SEALED = 'SEALED',
}

/**
 * A protected zone representing a resource or group of resources
 * that the Deep Seal layer manages.
 */
export interface ProtectedZone {
  /** Unique zone name */
  name: string;
  /** Regex pattern matching resources in this zone */
  resourcePattern: string;
  /** Current seal level */
  level: SealLevel;
  /** Conditions that would trigger escalation to a higher seal level */
  escalationConditions: EscalationCondition[];
  /** When this zone was created */
  createdAt: string;
  /** When the seal level was last changed */
  lastEscalatedAt?: string;
  /** Number of anomalies detected in this zone */
  anomalyCount: number;
  /** How many observations this zone has seen */
  observationCount: number;
}

/**
 * Conditions that trigger automatic seal level escalation.
 */
export interface EscalationCondition {
  /** Type of trigger */
  trigger: 'ANOMALY_COUNT' | 'ANOMALY_SCORE' | 'UNKNOWN_ACTOR' | 'TIME_BASED';
  /** Threshold value */
  threshold: number;
  /** What seal level to escalate to */
  targetLevel: SealLevel;
}

export interface DeepSealConfig {
  /** Anomaly count at which auto-sealing triggers */
  autoSealThreshold: number;
  /** Pre-configured zones */
  zones: ProtectedZone[];
}
