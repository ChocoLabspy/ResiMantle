import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ResiMantleEngine } from './engine';
import type { ResiMantleConfig } from './config/schema';

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

describe('ResiMantleEngine.scan', () => {
  it('returns zero findings when the current scan is clean', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-engine-clean-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, '.env.example'), 'API_KEY=placeholder\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'clean-project' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src']));

      const summary = await engine.scan();

      expect(summary.totalFindings).toBe(0);
      expect(summary.findings).toHaveLength(0);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('supports per-run scan path overrides without leaking findings from previous scans', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-engine-override-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await mkdir(join(projectRoot, 'other'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, '.env.example'), 'API_KEY=placeholder\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'override-project' }, null, 2));
      await writeFile(join(projectRoot, 'other', 'index.ts'), 'export const other = true;\n', 'utf-8');
      await writeFile(join(projectRoot, 'src', 'secret.ts'), 'const password = "supersecret123";\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['other']));

      const defaultSummary = await engine.scan();
      const overrideSummary = await engine.scan({ scanPaths: ['src'] });

      expect(defaultSummary.totalFindings).toBe(0);
      expect(overrideSummary.totalFindings).toBeGreaterThan(0);
      expect(overrideSummary.findings.some(finding => finding.file?.endsWith('secret.ts'))).toBe(true);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('auto-applies the mantle through the engine without manual overlay wiring', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-engine-mantle-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await mkdir(join(projectRoot, 'app', 'api', 'internal', 'billing', 'reconcile'), { recursive: true });
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, '.env.example'), 'API_KEY=placeholder\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({
        name: 'mantle-project',
        dependencies: {
          pg: '^8.0.0',
          stripe: '^18.0.0',
        },
      }, null, 2));
      await writeFile(join(projectRoot, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n', 'utf-8');
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');
      await writeFile(join(projectRoot, 'app', 'api', 'internal', 'billing', 'reconcile', 'route.ts'), 'export async function POST() { return Response.json({ ok: true }); }\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src']));

      const result = await engine.resolveReadSurface({
        actorId: 'agent-install',
        sessionId: 'session-install',
        resource: 'docs/runbooks/billing-reconcile.md',
        anomalyScore: 0.74,
      });

      expect(result.source).toBe('synthetic');
      expect(result.content).toContain('Billing Reconcile v2');
      expect(engine.getOverlayCoordinator()).not.toBeNull();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});