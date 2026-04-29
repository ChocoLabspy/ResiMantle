/**
 * Frequency classification for behavioral patterns.
 */
export enum FrequencyClass {
  NEVER_SEEN = 'NEVER_SEEN',
  RARE = 'RARE',
  OCCASIONAL = 'OCCASIONAL',
  FREQUENT = 'FREQUENT',
  CONSTANT = 'CONSTANT',
}

/**
 * A behavior profile for a specific resource (endpoint, file path, etc.).
 * Built over time by observing runtime events.
 */
export interface BehaviorProfile {
  /** The resource being profiled (URL, file path, DB table, etc.) */
  resource: string;
  /** Actors (modules/files) that typically access this resource */
  typicalActors: string[];
  /** How often this resource is accessed */
  frequency: FrequencyClass;
  /** Total access count during the observation window */
  accessCount: number;
  /** Average response time in milliseconds */
  avgDurationMs: number;
  /** Typical operation categories observed */
  typicalCategories: string[];
  /** Time window boundaries for this profile */
  observedFrom: string;
  observedUntil: string;
  /** Whether this profile is considered stable (enough data) */
  isStable: boolean;
}

/**
 * Result of an anomaly detection check.
 */
export interface AnomalyScore {
  /** Overall anomaly score from 0.0 (normal) to 1.0 (definitely anomalous) */
  score: number;
  /** Human-readable reasons for the score */
  reasons: string[];
  /** Whether this should trigger an alert */
  isAnomaly: boolean;
  /** Recommended action */
  recommendation: 'ALLOW' | 'LOG' | 'WARN' | 'BLOCK';
}

/**
 * An individual access pattern record used for statistical analysis.
 */
export interface AccessPattern {
  /** Source module or actor */
  actor: string;
  /** Target resource */
  resource: string;
  /** Event category */
  category: string;
  /** Timestamp of access */
  timestamp: number;
  /** Duration of operation */
  durationMs: number;
}
