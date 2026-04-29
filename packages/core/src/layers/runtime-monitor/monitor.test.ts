import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RuntimeMonitor } from './monitor';
import { RuntimeEventCategory, type MonitorAlert, type RuntimeEvent } from './types';

function createEvent(overrides: Partial<RuntimeEvent>): RuntimeEvent {
  return {
    id: overrides.id ?? `event-${Math.random().toString(16).slice(2, 8)}`,
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    category: overrides.category ?? RuntimeEventCategory.PROCESS_SPAWN,
    actor: overrides.actor ?? 'runtime-agent',
    resource: overrides.resource ?? 'powershell -Command Invoke-WebRequest',
    details: overrides.details ?? { isDangerous: true },
    blocked: overrides.blocked,
    durationMs: overrides.durationMs,
  };
}

describe('RuntimeMonitor', () => {
  it('derives alert events and pressure state from risky bursts', async () => {
    const outputDir = await mkdtemp(join(tmpdir(), 'resimantle-runtime-monitor-'));

    try {
      const monitor = new RuntimeMonitor(outputDir, {
        alerting: {
          enabled: true,
          windowMs: 60_000,
          highRiskEventThreshold: 2,
          blockedEventThreshold: 2,
        },
      });
      const alerts: MonitorAlert[] = [];

      monitor.on('alert', (alert: MonitorAlert) => {
        alerts.push(alert);
      });

      await monitor.logEvent(createEvent({ id: 'event-1', blocked: true }));
      await monitor.logEvent(createEvent({
        id: 'event-2',
        category: RuntimeEventCategory.SOCKET_EGRESS,
        resource: 'example.com:443',
        blocked: true,
        details: { reason: 'strict containment blocked direct socket egress' },
      }));

      const controlState = monitor.getControlState();
      const stats = monitor.getStats();

      expect(alerts.length).toBeGreaterThan(0);
      expect(alerts.some(alert => alert.code === 'blocked-event-burst' || alert.code === 'runtime-pressure-burst')).toBe(true);
      expect(monitor.getBufferedEvents().some(event => event.category === RuntimeEventCategory.MONITOR_ALERT)).toBe(true);
      expect(controlState.status).toBe('critical');
      expect(controlState.pressureScore).toBeGreaterThanOrEqual(6);
      expect(stats.alertCount).toBeGreaterThan(0);
    } finally {
      await rm(outputDir, { recursive: true, force: true });
    }
  });

  it('raises integrity drift alerts immediately', async () => {
    const outputDir = await mkdtemp(join(tmpdir(), 'resimantle-runtime-monitor-drift-'));

    try {
      const monitor = new RuntimeMonitor(outputDir, {
        alerting: {
          enabled: true,
          windowMs: 60_000,
          highRiskEventThreshold: 5,
          blockedEventThreshold: 5,
        },
      });

      await monitor.logEvent(createEvent({
        id: 'integrity-1',
        category: RuntimeEventCategory.PRELOAD_INTEGRITY,
        resource: 'node-preload.js',
        blocked: true,
        details: {
          status: 'drifted',
          phase: 'runtime-drift',
        },
      }));

      expect(monitor.getAlerts().some(alert => alert.code === 'preload-integrity-drift')).toBe(true);
      expect(monitor.getControlState().status).toBe('elevated');
    } finally {
      await rm(outputDir, { recursive: true, force: true });
    }
  });
});