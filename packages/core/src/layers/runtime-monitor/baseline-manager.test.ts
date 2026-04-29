import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CompatibilityBaselineManager } from './baseline-manager';
import { RuntimeEventCategory, type RuntimeEvent } from './types';

function createEvent(overrides: Partial<RuntimeEvent>): RuntimeEvent {
  return {
    id: overrides.id ?? `event-${Math.random().toString(16).slice(2, 8)}`,
    timestamp: overrides.timestamp ?? new Date().toISOString(),
    category: overrides.category ?? RuntimeEventCategory.FILE_READ,
    actor: overrides.actor ?? 'runtime-agent',
    resource: overrides.resource ?? 'src/index.ts',
    details: overrides.details ?? {},
    blocked: overrides.blocked,
    durationMs: overrides.durationMs,
  };
}

describe('CompatibilityBaselineManager', () => {
  it('learns repeated safe reads, processes and socket hosts into a containment allowlist', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-baseline-'));

    try {
      const manager = new CompatibilityBaselineManager(projectRoot, {
        enabled: true,
        mode: 'assist',
        persistencePath: '.resimantle/runtime-baseline.json',
        minOccurrences: 2,
        autoApplyToContainment: true,
      });
      await manager.initialize();

      manager.observe(createEvent({ resource: join(projectRoot, 'src', 'index.ts') }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({ resource: join(projectRoot, 'src', 'index.ts') }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({
        category: RuntimeEventCategory.PROCESS_SPAWN,
        resource: 'node scripts/safe-task.js',
      }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({
        category: RuntimeEventCategory.PROCESS_SPAWN,
        resource: 'node scripts/safe-task.js',
      }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({
        category: RuntimeEventCategory.SOCKET_EGRESS,
        resource: 'api.partner.internal:443',
        details: { host: 'api.partner.internal', port: 443 },
      }), { posture: 'guarded', integrityStatus: 'healthy' });
      manager.observe(createEvent({
        category: RuntimeEventCategory.SOCKET_EGRESS,
        resource: 'api.partner.internal:443',
        details: { host: 'api.partner.internal', port: 443 },
      }), { posture: 'guarded', integrityStatus: 'healthy' });

      const snapshot = manager.getSnapshot();

      expect(snapshot.observations).toBe(6);
  expect(snapshot.learnedAllowlist.readPatterns).toContain('(^|.*[\\/])src[\\/]index\\.ts$');
  expect(snapshot.learnedAllowlist.processPatterns).toContain('^node scripts/safe-task\\.js$');
      expect(snapshot.learnedAllowlist.socketHosts).toContain('api.partner.internal');
      expect(snapshot.candidates.reads[0]?.count).toBeGreaterThanOrEqual(2);

      await manager.persist();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('does not learn blocked, drifted or dangerous activity', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-baseline-skip-'));

    try {
      const manager = new CompatibilityBaselineManager(projectRoot, {
        enabled: true,
        mode: 'assist',
        persistencePath: '.resimantle/runtime-baseline.json',
        minOccurrences: 1,
        autoApplyToContainment: true,
      });
      await manager.initialize();

      manager.observe(createEvent({ blocked: true }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({
        category: RuntimeEventCategory.PROCESS_SPAWN,
        resource: 'powershell -Command Invoke-WebRequest',
        details: { isDangerous: true },
      }), { posture: 'normal', integrityStatus: 'healthy' });
      manager.observe(createEvent({ resource: join(projectRoot, 'src', 'secrets.env') }), { posture: 'sealed', integrityStatus: 'drifted' });

      const snapshot = manager.getSnapshot();

      expect(snapshot.observations).toBe(0);
      expect(snapshot.learnedAllowlist.readPatterns).toEqual([]);
      expect(snapshot.learnedAllowlist.processPatterns).toEqual([]);
      expect(snapshot.learnedAllowlist.socketHosts).toEqual([]);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});