import type { AccessDecision } from '@resimantle/types';

/**
 * Context provided to the Gatekeeper for an access decision.
 */
export interface AccessContext {
  /** The module/file/agent attempting access */
  actor: string;
  /** The resource being accessed (URL, file, query, etc.) */
  resource: string;
  /** The operation being performed */
  action: string;
  /** Anomaly score from the BehaviorModel (0.0 to 1.0) */
  anomalyScore: number;
  /** Current seal level of the zone containing this resource */
  zoneLevel: string;
  /** Whether the actor is a known actor for this resource */
  isKnownActor: boolean;
  /** Event category */
  category?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Result of a Gatekeeper evaluation.
 */
export interface GatekeeperEvent {
  context: AccessContext;
  decision: AccessDecision;
  reason: string;
  timestamp: string;
  /** Time taken to make the decision (microseconds) */
  decisionTimeUs: number;
}
