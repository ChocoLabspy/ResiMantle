import { EventEmitter } from 'node:events';
import { writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type { RuntimeEvent, MonitorAlert, MonitorControlState, MonitorOptions, AccessLog } from './types';
import { DEFAULT_MONITOR_OPTIONS, RuntimeEventCategory } from './types';
import { HttpCollector } from './collectors/http-collector';
import { FsCollector } from './collectors/fs-collector';
import { ProcessCollector } from './collectors/process-collector';
import { logger } from '../../common/logger';

/**
 * The RuntimeMonitor is the central nervous system of the runtime defense layer.
 *
 * It activates collectors that transparently wrap Node.js built-in modules
 * (http, fs, child_process) to observe every I/O operation the application
 * performs. Events are buffered, emitted, and can be consumed by:
 * - The BehaviorModel (for profiling and anomaly detection)
 * - The AccessGatekeeper (for real-time blocking decisions)
 * - The Auditor (for persistent logging)
 *
 * The monitor NEVER modifies the behavior of the intercepted operations.
 * It only observes and reports. This is the core "resin" principle.
 */
export class RuntimeMonitor extends EventEmitter {
  private options: MonitorOptions;
  private httpCollector: HttpCollector | null = null;
  private fsCollector: FsCollector | null = null;
  private processCollector: ProcessCollector | null = null;

  private eventBuffer: RuntimeEvent[] = [];
  private accessLog: AccessLog[] = [];
  private recentEvents: RuntimeEvent[] = [];
  private alerts: MonitorAlert[] = [];
  private running = false;
  private flushInterval: ReturnType<typeof setInterval> | null = null;
  private outputDir: string;

  // Statistics
  private stats = {
    totalEvents: 0,
    eventsByCategory: new Map<RuntimeEventCategory, number>(),
    startTime: 0,
    blockedCount: 0,
  };

  constructor(outputDir: string, options?: Partial<MonitorOptions>) {
    super();
    this.outputDir = outputDir;
    this.options = {
      ...DEFAULT_MONITOR_OPTIONS,
      ...options,
      alerting: {
        ...DEFAULT_MONITOR_OPTIONS.alerting,
        ...(options?.alerting ?? {}),
      },
    };
  }

  /**
   * Starts the runtime monitor and activates all configured collectors.
   * After this call, all monitored I/O operations will emit events.
   */
  async start(): Promise<void> {
    if (this.running) return;

    logger.info('Runtime Monitor starting...');
    this.stats.startTime = Date.now();

    const eventHandler = (event: RuntimeEvent) => this.handleEvent(event);
    const ignorePatterns = this.options.ignorePatterns;

    // Activate HTTP collector
    if (this.options.interceptHttp) {
      this.httpCollector = new HttpCollector(eventHandler, ignorePatterns);
      await this.httpCollector.activate();
      logger.info('  ↪ HTTP interceptor activated');
    }

    // Activate FS collector
    if (this.options.interceptFs) {
      this.fsCollector = new FsCollector(eventHandler, ignorePatterns);
      await this.fsCollector.activate();
      logger.info('  ↪ Filesystem interceptor activated');
    }

    // Activate Process collector
    if (this.options.interceptProcess) {
      this.processCollector = new ProcessCollector(eventHandler);
      await this.processCollector.activate();
      logger.info('  ↪ Process interceptor activated');
    }

    // Start periodic flush
    this.flushInterval = setInterval(() => {
      this.flushBuffer().catch(err => {
        logger.error(`Failed to flush event buffer: ${err.message}`);
      });
    }, 30_000); // Flush every 30s

    this.running = true;
    logger.info(`Runtime Monitor active — intercepting: HTTP=${this.options.interceptHttp}, FS=${this.options.interceptFs}, Process=${this.options.interceptProcess}`);
  }

  /**
   * Stops the monitor and cleanly restores all intercepted modules.
   * This is critical — we must NEVER leave monkey-patches in place.
   */
  async stop(): Promise<void> {
    if (!this.running) return;

    logger.info('Runtime Monitor stopping...');

    // Deactivate collectors in reverse order
    if (this.processCollector) {
      await this.processCollector.deactivate();
      logger.info('  ↪ Process interceptor deactivated');
    }
    if (this.fsCollector) {
      await this.fsCollector.deactivate();
      logger.info('  ↪ Filesystem interceptor deactivated');
    }
    if (this.httpCollector) {
      await this.httpCollector.deactivate();
      logger.info('  ↪ HTTP interceptor deactivated');
    }

    // Clear flush interval
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }

    // Final flush
    await this.flushBuffer();

    this.running = false;
    const uptimeSeconds = Math.round((Date.now() - this.stats.startTime) / 1000);
    logger.info(`Runtime Monitor stopped. Uptime: ${uptimeSeconds}s, Total events: ${this.stats.totalEvents}, Blocked: ${this.stats.blockedCount}`);
  }

  /**
   * Manually record an event (useful for AI call tracking).
   */
  async logEvent(event: RuntimeEvent): Promise<void> {
    this.handleEvent(event);
  }

  /**
   * Returns runtime statistics.
   */
  getStats(): {
    totalEvents: number;
    eventsByCategory: Record<string, number>;
    uptimeMs: number;
    blockedCount: number;
    bufferSize: number;
    alertCount: number;
    pressureScore: number;
  } {
    const categoryStats: Record<string, number> = {};
    for (const [cat, count] of this.stats.eventsByCategory) {
      categoryStats[cat] = count;
    }

    return {
      totalEvents: this.stats.totalEvents,
      eventsByCategory: categoryStats,
      uptimeMs: this.running ? Date.now() - this.stats.startTime : 0,
      blockedCount: this.stats.blockedCount,
      bufferSize: this.eventBuffer.length,
      alertCount: this.alerts.length,
      pressureScore: this.getControlState().pressureScore,
    };
  }

  /**
   * Returns the full access log for audit purposes.
   */
  getAccessLog(): AccessLog[] {
    return [...this.accessLog];
  }

  /**
   * Returns all buffered events (for consumption by BehaviorModel).
   */
  getBufferedEvents(): RuntimeEvent[] {
    return [...this.eventBuffer];
  }

  getAlerts(): MonitorAlert[] {
    return [...this.alerts];
  }

  getControlState(): MonitorControlState {
    const windowEvents = this.getWindowEvents();
    const recentHighRiskEvents = windowEvents.filter(event => this.isHighRiskEvent(event)).length;
    const blockedEventsInWindow = windowEvents.filter(event => event.blocked).length;
    const pressureScore = this.calculatePressureScore(windowEvents);
    const lastAlertAt = this.alerts.at(-1)?.triggeredAt;

    return {
      pressureScore,
      recentHighRiskEvents,
      blockedEventsInWindow,
      status: pressureScore >= 8 ? 'critical' : pressureScore >= 4 ? 'elevated' : 'normal',
      alertCount: this.alerts.length,
      lastAlertAt,
    };
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  /**
   * Central event handler. All collector events flow through here.
   * Applies sampling, updates statistics, and emits for consumers.
   */
  private handleEvent(event: RuntimeEvent): void {
    this.recordEvent(event);

    if (event.category !== RuntimeEventCategory.MONITOR_ALERT) {
      const alertEvent = this.buildMonitorAlertEvent(event);
      if (alertEvent) {
        this.recordEvent(alertEvent);
      }
    }
  }

  private recordEvent(event: RuntimeEvent): void {
    // Apply sampling rate
    if (event.category !== RuntimeEventCategory.MONITOR_ALERT && this.options.sampleRate < 1.0 && Math.random() > this.options.sampleRate) {
      return;
    }

    // Update statistics
    this.stats.totalEvents++;
    const currentCount = this.stats.eventsByCategory.get(event.category) || 0;
    this.stats.eventsByCategory.set(event.category, currentCount + 1);

    if (event.blocked) {
      this.stats.blockedCount++;
    }

    // Buffer the event
    this.eventBuffer.push(event);
    if (event.category !== RuntimeEventCategory.MONITOR_ALERT) {
      this.recentEvents.push(event);
      this.pruneRecentEvents();
    }

    // Record in access log
    this.accessLog.push({
      event,
      allowed: !event.blocked,
      reason: event.blocked ? 'Blocked by Gatekeeper' : undefined,
    });

    // Emit for real-time consumers (BehaviorModel, Gatekeeper)
    this.emit('event', event);

    // Auto-flush if buffer is full
    if (this.eventBuffer.length >= this.options.maxBufferSize) {
      this.flushBuffer().catch(() => {});
    }
  }

  private buildMonitorAlertEvent(event: RuntimeEvent): RuntimeEvent | null {
    if (!this.options.alerting.enabled) {
      return null;
    }

    const windowEvents = this.getWindowEvents();
    const blockedWindowEvents = windowEvents.filter(candidate => candidate.blocked);
    const highRiskWindowEvents = windowEvents.filter(candidate => this.isHighRiskEvent(candidate));
    const pressureScore = this.calculatePressureScore(windowEvents);

    if (this.isIntegrityDriftEvent(event)) {
      return this.createAlertEvent(
        'preload-integrity-drift',
        'critical',
        'Runtime monitor detected preload integrity drift.',
        [event],
        pressureScore,
      );
    }

    if (blockedWindowEvents.length >= this.options.alerting.blockedEventThreshold) {
      return this.createAlertEvent(
        'blocked-event-burst',
        'warning',
        'Runtime monitor detected a burst of blocked events.',
        blockedWindowEvents,
        pressureScore,
      );
    }

    if (highRiskWindowEvents.length >= this.options.alerting.highRiskEventThreshold) {
      return this.createAlertEvent(
        'runtime-pressure-burst',
        pressureScore >= this.options.alerting.highRiskEventThreshold * 2 ? 'critical' : 'warning',
        'Runtime monitor detected elevated runtime pressure.',
        highRiskWindowEvents,
        pressureScore,
      );
    }

    return null;
  }

  private createAlertEvent(
    code: string,
    severity: MonitorAlert['severity'],
    message: string,
    sourceEvents: RuntimeEvent[],
    pressureScore: number,
  ): RuntimeEvent | null {
    const existingAlert = this.alerts.find(alert => {
      if (alert.code !== code) {
        return false;
      }

      const ageMs = Date.now() - Date.parse(alert.triggeredAt);
      return Number.isFinite(ageMs) && ageMs < this.options.alerting.windowMs;
    });
    if (existingAlert) {
      return null;
    }

    const alert: MonitorAlert = {
      id: `monitor-${randomUUID().slice(0, 8)}`,
      code,
      severity,
      triggeredAt: new Date().toISOString(),
      message,
      supportingEventIds: sourceEvents.slice(-5).map(event => event.id),
      pressureScore,
    };
    this.alerts.push(alert);
    if (this.alerts.length > 50) {
      this.alerts.shift();
    }

    this.emit('alert', alert);

    return {
      id: alert.id,
      timestamp: alert.triggeredAt,
      category: RuntimeEventCategory.MONITOR_ALERT,
      actor: 'RuntimeMonitor',
      resource: code,
      blocked: severity === 'critical',
      details: {
        code,
        severity,
        message,
        supportingEventIds: alert.supportingEventIds,
        pressureScore,
      },
    };
  }

  private pruneRecentEvents(): void {
    const windowStart = Date.now() - this.options.alerting.windowMs;
    this.recentEvents = this.recentEvents.filter(event => {
      const timestamp = Date.parse(event.timestamp);
      return !Number.isNaN(timestamp) && timestamp >= windowStart;
    });
  }

  private getWindowEvents(): RuntimeEvent[] {
    this.pruneRecentEvents();
    return [...this.recentEvents];
  }

  private isHighRiskEvent(event: RuntimeEvent): boolean {
    return event.blocked === true
      || event.category === RuntimeEventCategory.PROCESS_SPAWN
      || event.category === RuntimeEventCategory.SOCKET_EGRESS
      || event.category === RuntimeEventCategory.PRELOAD_INTEGRITY
      || event.details['isDangerous'] === true;
  }

  private isIntegrityDriftEvent(event: RuntimeEvent): boolean {
    return event.category === RuntimeEventCategory.PRELOAD_INTEGRITY
      && (event.blocked === true || event.details['status'] === 'drifted');
  }

  private calculatePressureScore(events: RuntimeEvent[]): number {
    return events.reduce((score, event) => {
      let eventScore = event.blocked ? 2 : 0;

      if (event.category === RuntimeEventCategory.PROCESS_SPAWN || event.category === RuntimeEventCategory.SOCKET_EGRESS) {
        eventScore += 2;
      } else if (event.category === RuntimeEventCategory.PRELOAD_INTEGRITY) {
        eventScore += 3;
      } else if (event.details['isDangerous'] === true) {
        eventScore += 1;
      }

      return score + eventScore;
    }, 0);
  }

  /**
   * Flushes buffered events to disk as a JSON log file.
   */
  private async flushBuffer(): Promise<void> {
    if (this.eventBuffer.length === 0) return;

    const eventsToFlush = [...this.eventBuffer];
    this.eventBuffer = [];

    const logDir = join(this.outputDir, 'runtime-logs');
    if (!existsSync(logDir)) {
      await mkdir(logDir, { recursive: true });
    }

    const filename = `events-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    const filePath = join(logDir, filename);

    await writeFile(filePath, JSON.stringify(eventsToFlush, null, 2), 'utf-8');
    logger.debug(`Flushed ${eventsToFlush.length} events to ${filePath}`);
  }
}
