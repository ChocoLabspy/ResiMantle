import type { AccessPattern, BehaviorProfile } from './types';
import { FrequencyClass } from './types';
import { logger } from '../../common/logger';

/**
 * Minimum number of observations before a profile is considered "stable".
 */
const STABILITY_THRESHOLD = 50;

/**
 * The Profiler learns what "normal" looks like for the application.
 * It builds statistical profiles for every observed resource,
 * tracking who accesses it, how often, and how long operations take.
 *
 * This is the "Absorption" phase of the resin metaphor —
 * the system is sinking into the project's structure, learning its shape.
 */
export class Profiler {
  /** All recorded access patterns (the raw data) */
  private patterns: AccessPattern[] = [];

  /** Built profiles keyed by resource name */
  private profiles: Map<string, BehaviorProfile> = new Map();

  /** Maximum patterns to keep in memory */
  private maxPatterns: number;

  constructor(maxPatterns = 100_000) {
    this.maxPatterns = maxPatterns;
  }

  /**
   * Records a new access pattern observation.
   */
  record(pattern: AccessPattern): void {
    this.patterns.push(pattern);

    // Evict old patterns if we exceed the limit (sliding window)
    if (this.patterns.length > this.maxPatterns) {
      this.patterns = this.patterns.slice(-Math.floor(this.maxPatterns * 0.8));
    }
  }

  /**
   * Builds behavioral profiles from the accumulated patterns.
   * Should be called periodically (e.g., every minute or on demand).
   */
  async buildProfiles(): Promise<BehaviorProfile[]> {
    const resourceMap = new Map<string, AccessPattern[]>();

    // Group patterns by resource
    for (const pattern of this.patterns) {
      const existing = resourceMap.get(pattern.resource) || [];
      existing.push(pattern);
      resourceMap.set(pattern.resource, existing);
    }

    // Build a profile for each resource
    const profiles: BehaviorProfile[] = [];

    for (const [resource, patterns] of resourceMap) {
      const actors = new Set<string>();
      const categories = new Set<string>();
      let totalDuration = 0;

      for (const p of patterns) {
        actors.add(p.actor);
        categories.add(p.category);
        totalDuration += p.durationMs;
      }

      const accessCount = patterns.length;
      const frequency = this.classifyFrequency(accessCount);
      const isStable = accessCount >= STABILITY_THRESHOLD;

      const timestamps = patterns.map(p => p.timestamp).sort();
      const observedFrom = new Date(timestamps[0]!).toISOString();
      const observedUntil = new Date(timestamps[timestamps.length - 1]!).toISOString();

      const profile: BehaviorProfile = {
        resource,
        typicalActors: Array.from(actors),
        frequency,
        accessCount,
        avgDurationMs: Math.round(totalDuration / accessCount),
        typicalCategories: Array.from(categories),
        observedFrom,
        observedUntil,
        isStable,
      };

      profiles.push(profile);
      this.profiles.set(resource, profile);
    }

    logger.debug(`Profiler: built ${profiles.length} profiles from ${this.patterns.length} patterns`);
    return profiles;
  }

  /**
   * Returns the profile for a specific resource (if it exists).
   */
  getProfile(resource: string): BehaviorProfile | undefined {
    return this.profiles.get(resource);
  }

  /**
   * Returns all built profiles.
   */
  getAllProfiles(): BehaviorProfile[] {
    return Array.from(this.profiles.values());
  }

  /**
   * Returns the typical actors for a given resource.
   * Used by the AnomalyDetector to check if an actor is "expected".
   */
  getTypicalActors(resource: string): string[] {
    return this.profiles.get(resource)?.typicalActors || [];
  }

  /**
   * Checks if a specific actor has been observed accessing a resource before.
   */
  isKnownActor(resource: string, actor: string): boolean {
    const profile = this.profiles.get(resource);
    if (!profile) return false;
    return profile.typicalActors.includes(actor);
  }

  /**
   * Returns raw pattern count (useful for determining maturation phase).
   */
  getObservationCount(): number {
    return this.patterns.length;
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private classifyFrequency(count: number): FrequencyClass {
    if (count === 0) return FrequencyClass.NEVER_SEEN;
    if (count <= 5) return FrequencyClass.RARE;
    if (count <= 50) return FrequencyClass.OCCASIONAL;
    if (count <= 500) return FrequencyClass.FREQUENT;
    return FrequencyClass.CONSTANT;
  }
}
