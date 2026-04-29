import type { AnomalyScore, AccessPattern } from './types';
import type { Profiler } from './profiler';
import { FrequencyClass } from './types';
import { logger } from '../../common/logger';

/**
 * Anomaly detection thresholds.
 */
const THRESHOLDS = {
  /** Score above which an event is considered anomalous */
  ANOMALY: 0.6,
  /** Score above which the system recommends blocking */
  BLOCK: 0.85,
  /** Score above which the system recommends warning */
  WARN: 0.7,
  /** Duration multiplier — flag if operation takes >N× the average */
  DURATION_MULTIPLIER: 5.0,
  /** Burst threshold — flag if >N events from same actor in 1 minute */
  BURST_THRESHOLD: 100,
};

/**
 * Resources that are inherently sensitive and receive higher base scores.
 */
const SENSITIVE_RESOURCE_PATTERNS = [
  { pattern: /\/etc\/(?:passwd|shadow|hosts)/, weight: 0.8 },
  { pattern: /\.env(?:\.|$)/, weight: 0.7 },
  { pattern: /(?:private|secret|credential|token)s?\./i, weight: 0.6 },
  { pattern: /\/admin\b/, weight: 0.5 },
  { pattern: /id_rsa|id_ed25519|\.pem$/, weight: 0.9 },
  { pattern: /\/proc\/|\/sys\//, weight: 0.7 },
  { pattern: /password|secret/i, weight: 0.5 },
  { pattern: /DROP\s+TABLE|DELETE\s+FROM|TRUNCATE/i, weight: 0.9 },
  { pattern: /--\s*$|;\s*DROP|UNION\s+SELECT/i, weight: 0.95 },
];

/**
 * The AnomalyDetector analyzes individual runtime events against
 * the behavioral profiles built by the Profiler.
 *
 * It uses multiple heuristics to calculate an anomaly score:
 * 1. **Unknown Actor**: Is this module/actor new for this resource?
 * 2. **Unusual Frequency**: Is this resource rarely accessed?
 * 3. **Duration Spike**: Is this operation unusually slow?
 * 4. **Sensitive Resource**: Is the target inherently sensitive?
 * 5. **Burst Detection**: Is this actor making too many requests?
 * 6. **Profile Stability**: Is the profile mature enough to trust?
 *
 * The final score is a weighted combination that determines the
 * recommended action (ALLOW, LOG, WARN, BLOCK).
 */
export class AnomalyDetector {
  private profiler: Profiler;
  private recentEvents: Map<string, number[]> = new Map();

  constructor(profiler: Profiler) {
    this.profiler = profiler;
  }

  /**
   * Analyzes an access pattern for anomalies.
   * Returns a score from 0.0 (normal) to 1.0 (definitely anomalous).
   */
  async detect(pattern: AccessPattern): Promise<AnomalyScore> {
    const reasons: string[] = [];
    let totalScore = 0;
    let factorCount = 0;

    const profile = this.profiler.getProfile(pattern.resource);

    // ── Factor 1: Unknown Actor ──────────────────────────────────────────
    if (profile && profile.isStable) {
      if (!this.profiler.isKnownActor(pattern.resource, pattern.actor)) {
        const unknownActorScore = 0.7;
        totalScore += unknownActorScore;
        factorCount++;
        reasons.push(`Unknown actor "${pattern.actor}" accessing "${pattern.resource}" (normally accessed by: ${profile.typicalActors.slice(0, 3).join(', ')})`);
      } else {
        factorCount++; // Count it but don't add score
      }
    }

    // ── Factor 2: Unusual Frequency ──────────────────────────────────────
    if (profile) {
      if (profile.frequency === FrequencyClass.RARE || profile.frequency === FrequencyClass.NEVER_SEEN) {
        const freqScore = profile.frequency === FrequencyClass.NEVER_SEEN ? 0.6 : 0.4;
        totalScore += freqScore;
        factorCount++;
        reasons.push(`Resource "${pattern.resource}" is accessed ${profile.frequency.toLowerCase()} (${profile.accessCount} times total)`);
      } else {
        factorCount++;
      }
    }

    // ── Factor 3: Duration Spike ─────────────────────────────────────────
    if (profile && profile.avgDurationMs > 0 && pattern.durationMs > 0) {
      const durationRatio = pattern.durationMs / profile.avgDurationMs;
      if (durationRatio > THRESHOLDS.DURATION_MULTIPLIER) {
        const durationScore = Math.min(0.8, 0.3 + (durationRatio / 20));
        totalScore += durationScore;
        factorCount++;
        reasons.push(`Operation took ${pattern.durationMs}ms (avg: ${profile.avgDurationMs}ms, ${durationRatio.toFixed(1)}× slower)`);
      } else {
        factorCount++;
      }
    }

    // ── Factor 4: Sensitive Resource ─────────────────────────────────────
    for (const sensitive of SENSITIVE_RESOURCE_PATTERNS) {
      if (sensitive.pattern.test(pattern.resource)) {
        totalScore += sensitive.weight;
        factorCount++;
        reasons.push(`Accessing sensitive resource matching pattern: ${sensitive.pattern.source}`);
        break; // Only apply the highest matching pattern
      }
    }

    // ── Factor 5: Burst Detection ────────────────────────────────────────
    const burstScore = this.checkBurst(pattern.actor, pattern.timestamp);
    if (burstScore > 0) {
      totalScore += burstScore;
      factorCount++;
      reasons.push(`Burst detected: actor "${pattern.actor}" making rapid requests`);
    }

    // ── Factor 6: No Profile (first time) ────────────────────────────────
    if (!profile) {
      // First time seeing this resource — moderate suspicion
      totalScore += 0.3;
      factorCount++;
      reasons.push(`No behavioral profile exists for "${pattern.resource}" (first observation)`);
    }

    // Calculate final score
    const score = factorCount > 0
      ? Math.min(1.0, totalScore / Math.max(factorCount, 1))
      : 0;

    // Round to 2 decimal places
    const roundedScore = Math.round(score * 100) / 100;

    const isAnomaly = roundedScore >= THRESHOLDS.ANOMALY;
    let recommendation: 'ALLOW' | 'LOG' | 'WARN' | 'BLOCK';

    if (roundedScore >= THRESHOLDS.BLOCK) {
      recommendation = 'BLOCK';
    } else if (roundedScore >= THRESHOLDS.WARN) {
      recommendation = 'WARN';
    } else if (roundedScore >= THRESHOLDS.ANOMALY) {
      recommendation = 'LOG';
    } else {
      recommendation = 'ALLOW';
    }

    if (isAnomaly) {
      logger.warn(`Anomaly detected (score: ${roundedScore}): ${reasons.join('; ')}`);
    }

    return {
      score: roundedScore,
      reasons,
      isAnomaly,
      recommendation,
    };
  }

  /**
   * Checks for request bursts from a specific actor.
   * Returns a score contribution (0 = no burst, up to 0.7 for severe bursts).
   */
  private checkBurst(actor: string, timestamp: number): number {
    const now = timestamp;
    const windowMs = 60_000; // 1 minute

    // Get or create the actor's event timestamps
    let timestamps = this.recentEvents.get(actor);
    if (!timestamps) {
      timestamps = [];
      this.recentEvents.set(actor, timestamps);
    }

    // Add current timestamp
    timestamps.push(now);

    // Remove timestamps outside the window
    const cutoff = now - windowMs;
    const filtered = timestamps.filter(t => t > cutoff);
    this.recentEvents.set(actor, filtered);

    // Check if the count exceeds the burst threshold
    if (filtered.length > THRESHOLDS.BURST_THRESHOLD) {
      const ratio = filtered.length / THRESHOLDS.BURST_THRESHOLD;
      return Math.min(0.7, 0.3 * ratio);
    }

    return 0;
  }
}
