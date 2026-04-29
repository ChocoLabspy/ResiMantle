import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { RuntimeEvent } from '../layers/runtime-monitor';
import { ResiMantleEngine } from '../engine';
import { RuntimeMantleSession } from './mantle-session';
import type { ResiMantleConfig } from '../config/schema';

function createConfig(scanPaths: string[]): ResiMantleConfig {
  return {
    version: '0.1.0',
    layers: {
      surfaceCoat: {
        enabled: true,
        scanPaths,
        ignorePatterns: [],
      },
      aiDefense: {
        enabled: true,
        proxyMode: false,
      },
      runtimeMonitor: {
        enabled: true,
        sampleRate: 1,
        control: {
          autoPosture: true,
          sessionTtlMs: 15 * 60_000,
          heartbeatGraceMs: 45_000,
          capabilityQuarantine: true,
        },
        containment: {
          mode: 'adaptive',
          allow: {
            readPatterns: [],
            processPatterns: [],
            socketHosts: [],
            socketHostPatterns: [],
            socketPathPatterns: [],
          },
        },
        baseline: {
          enabled: true,
          mode: 'assist',
          persistencePath: '.resimantle/runtime-baseline.json',
          minOccurrences: 3,
          autoApplyToContainment: true,
          reduceRiskFromKnownActivity: true,
        },
      },
    },
    policy: {
      path: './.resimantle/policy.json',
    },
  };
}

describe('RuntimeMantleSession', () => {
  it('routes runtime file reads through the engine mantle and updates inventory automatically', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-runtime-session-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'runtime-project' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src']));

      const session = new RuntimeMantleSession(engine, { sessionId: 'runtime-session' });
      const observation = await session.analyzeEvent({
        id: 'event-1',
        timestamp: new Date().toISOString(),
        category: 'FILE_READ' as never,
        actor: 'runtime-wrapper',
        resource: 'docs/runbooks/billing-reconcile.md',
        details: {
          method: 'readFile',
        },
      } satisfies RuntimeEvent);

      expect(observation.mantle?.source).toBe('synthetic');
      expect(engine.getResourceInventory().getProfile('docs/runbooks/billing-reconcile.md')).toBeDefined();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});