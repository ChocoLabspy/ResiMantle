import { EventEmitter } from 'node:events';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { RiskLevel } from '@resimantle/types';
import { COMMON_CONSTANTS } from '../common/constants';
import { AnomalyDetector } from '../layers/behavior-model/anomaly-detector';
import { Profiler } from '../layers/behavior-model/profiler';
import type { AccessPattern } from '../layers/behavior-model/types';
import { SealManager } from '../layers/deep-seal/seal-manager';
import { SealLevel } from '../layers/deep-seal/types';
import { RuntimeMonitor } from '../layers/runtime-monitor/monitor';
import type { MonitorAlert, MonitorOptions, RuntimeEvent } from '../layers/runtime-monitor/types';
import type { CoordinatedHttpResolution, CoordinatedReadResolution } from '../layers/resin-traps';
import type { ResiMantleEngine } from '../engine';

export interface RuntimeMantleObservation {
  event: RuntimeEvent;
  anomalyScore: number;
  isAnomaly: boolean;
  zoneLevel: SealLevel;
  isKnownActor: boolean;
  mantle?: CoordinatedReadResolution | CoordinatedHttpResolution;
}

export interface RuntimeMantleSessionSummary {
  sessionId: string;
  totalEvents: number;
  anomalies: number;
  syntheticResponses: number;
  blockedLikeDecisions: number;
  monitorAlerts: number;
  runtimePressure: number;
  runtimeStatus: 'normal' | 'elevated' | 'critical';
}

interface RuntimeMantleSessionOptions {
  sessionId?: string;
  runtimeOptions?: Partial<MonitorOptions>;
}

export class RuntimeMantleSession extends EventEmitter {
  readonly sessionId: string;

  private engine: ResiMantleEngine;
  private monitor: RuntimeMonitor;
  private profiler: Profiler;
  private anomalyDetector: AnomalyDetector;
  private sealManager: SealManager;
  private observations: RuntimeMantleObservation[] = [];
  private started = false;

  constructor(engine: ResiMantleEngine, options: RuntimeMantleSessionOptions = {}) {
    super();
    this.engine = engine;
    this.sessionId = options.sessionId ?? randomUUID();

    const resiMantleDir = join(engine.options.cwd, COMMON_CONSTANTS.OUTPUT_DIR);
    this.monitor = new RuntimeMonitor(resiMantleDir, options.runtimeOptions);
    this.profiler = new Profiler();
    this.anomalyDetector = new AnomalyDetector(this.profiler);
    this.sealManager = new SealManager(resiMantleDir);
  }

  async start(): Promise<void> {
    if (this.started) {
      return;
    }

    await this.engine.init();
    await this.sealManager.initialize();

    this.monitor.on('event', (event: RuntimeEvent) => {
      void this.analyzeEvent(event).then(observation => {
        this.emit('analysis', observation);
      });
    });

    this.monitor.on('alert', (alert: MonitorAlert) => {
      this.emit('alert', alert);
    });

    await this.monitor.start();
    this.started = true;
  }

  async stop(): Promise<void> {
    if (!this.started) {
      return;
    }

    await this.monitor.stop();
    await this.profiler.buildProfiles();
    await this.engine.getResourceInventory().persist();
    this.started = false;
  }

  async analyzeEvent(event: RuntimeEvent): Promise<RuntimeMantleObservation> {
    const pattern: AccessPattern = {
      actor: event.actor,
      resource: event.resource,
      category: event.category,
      timestamp: Date.now(),
      durationMs: event.durationMs ?? 0,
    };

    this.profiler.record(pattern);

    const anomaly = await this.anomalyDetector.detect(pattern);
    const zoneStatus = this.sealManager.getZoneStatus(event.resource);
    const isKnownActor = this.profiler.isKnownActor(event.resource, event.actor);

    if (anomaly.isAnomaly) {
      await this.sealManager.recordAnomaly(event.resource, anomaly.score);
    } else {
      this.sealManager.recordObservation(event.resource);
    }

    await this.engine.observeRuntimeEvent(event);

    const mantle = await this.resolveMantle(event, anomaly.score, zoneStatus.level, isKnownActor);

    await this.engine.getAuditor().record({
      source: 'RuntimeMantleSession',
      type: 'RUNTIME_MANTLE_EVENT',
      severity: anomaly.isAnomaly ? RiskLevel.HIGH : RiskLevel.INFO,
      details: {
        actorId: event.actor,
        sessionId: this.sessionId,
        resource: event.resource,
        category: event.category,
        anomalyScore: anomaly.score,
        zoneLevel: zoneStatus.level,
        isKnownActor,
        mantleSource: mantle?.source,
        effectiveDecision: mantle?.effectiveDecision,
      },
      decision: mantle?.effectiveDecision,
      explanation: anomaly.isAnomaly
        ? anomaly.reasons.join('; ')
        : `Observed ${event.category} on ${event.resource}`,
    });

    const observation: RuntimeMantleObservation = {
      event,
      anomalyScore: anomaly.score,
      isAnomaly: anomaly.isAnomaly,
      zoneLevel: zoneStatus.level,
      isKnownActor,
      mantle,
    };

    this.observations.push(observation);
    return observation;
  }

  getMonitor(): RuntimeMonitor {
    return this.monitor;
  }

  getProfiles() {
    return this.profiler.getAllProfiles();
  }

  getObservations(): RuntimeMantleObservation[] {
    return [...this.observations];
  }

  getSummary(): RuntimeMantleSessionSummary {
    const controlState = this.monitor.getControlState();

    return {
      sessionId: this.sessionId,
      totalEvents: this.observations.length,
      anomalies: this.observations.filter(observation => observation.isAnomaly).length,
      syntheticResponses: this.observations.filter(observation => observation.mantle?.source === 'synthetic').length,
      blockedLikeDecisions: this.observations.filter(observation => {
        const decision = observation.mantle?.effectiveDecision;
        return decision === 'BLOCK' || decision === 'QUARANTINE' || decision === 'REQUIRE_APPROVAL';
      }).length,
      monitorAlerts: controlState.alertCount,
      runtimePressure: controlState.pressureScore,
      runtimeStatus: controlState.status,
    };
  }

  private async resolveMantle(
    event: RuntimeEvent,
    anomalyScore: number,
    zoneLevel: SealLevel,
    isKnownActor: boolean,
  ): Promise<CoordinatedReadResolution | CoordinatedHttpResolution | undefined> {
    if (event.category === 'FILE_READ') {
      return this.engine.resolveReadSurface({
        actorId: event.actor,
        sessionId: this.sessionId,
        resource: event.resource,
        anomalyScore,
        zoneLevel: zoneLevel === SealLevel.OPEN ? undefined : zoneLevel,
        isKnownActor,
      });
    }

    if (event.category === 'HTTP_OUTBOUND') {
      const method = typeof event.details['method'] === 'string' ? String(event.details['method']) : 'GET';
      const path = extractHttpPath(event.resource);

      return this.engine.resolveHttpSurface({
        actorId: event.actor,
        sessionId: this.sessionId,
        path,
        method,
        anomalyScore,
        zoneLevel: zoneLevel === SealLevel.OPEN ? undefined : zoneLevel,
        isKnownActor,
        metadata: event.details,
      });
    }

    return undefined;
  }
}

function extractHttpPath(resource: string): string {
  try {
    const url = new URL(resource);
    return url.pathname || '/';
  } catch {
    return resource;
  }
}