import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanSummary } from '@resimantle/types';
import { MaturationPhase, RiskLevel } from '@resimantle/types';
import { ResourceInventory } from './resource-inventory';

describe('ResourceInventory', () => {
  it('infers useful stack and risk tags from scan findings and runtime observations', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-inventory-'));

    try {
      const inventory = new ResourceInventory(resiMantleDir);
      await inventory.initialize();

      const summary: ScanSummary = {
        startedAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        durationMs: 10,
        totalFindings: 1,
        findingsBySeverity: {
          [RiskLevel.NONE]: 0,
          [RiskLevel.INFO]: 0,
          [RiskLevel.LOW]: 0,
          [RiskLevel.MEDIUM]: 1,
          [RiskLevel.HIGH]: 0,
          [RiskLevel.CRITICAL]: 0,
        },
        findings: [
          {
            id: 'finding-1',
            layer: 'SurfaceCoat',
            type: 'CONFIG_ISSUE',
            severity: RiskLevel.MEDIUM,
            title: 'Exposed billing database backup',
            description: 'billing database backup is stored in an internal admin path',
            file: 'backups/billing-ledger.sql',
          },
        ],
        overallRisk: RiskLevel.MEDIUM,
        filesScanned: 1,
        phase: MaturationPhase.FRESH_COAT,
      };

      await inventory.ingestScanSummary(summary);
      await inventory.observeRuntimeEvent({
        id: 'runtime-1',
        timestamp: new Date().toISOString(),
        category: 'HTTP_OUTBOUND' as never,
        actor: 'runtime-wrapper',
        resource: 'https://internal.example.local/admin/debug',
        details: {
          method: 'GET',
        },
      });

      const inferred = inventory.infer('docs/runbooks/billing-reconcile.md', 'read');

      expect(inferred.stackTags).toContain('billing');
      expect(inferred.riskTags).toContain('database');
      expect(inferred.riskTags).toContain('admin');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('persists observed resources to disk', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-inventory-persist-'));

    try {
      const inventory = new ResourceInventory(resiMantleDir);
      await inventory.observe({
        resource: '/internal/billing/reconcile',
        action: 'http',
        source: 'manual',
        stackTags: ['billing'],
        riskTags: ['admin'],
      });
      await inventory.persist();

      const reloaded = new ResourceInventory(resiMantleDir);
      await reloaded.initialize();

      expect(reloaded.getProfile('/internal/billing/reconcile')?.stackTags).toContain('billing');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('learns stack and risk context from manifests, lockfiles, and route topology', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-inventory-topology-'));

    try {
      await import('node:fs/promises').then(fs => fs.mkdir(join(projectRoot, 'app', 'api', 'internal', 'billing', 'reconcile'), { recursive: true }));
      await import('node:fs/promises').then(fs => fs.writeFile(join(projectRoot, 'package.json'), JSON.stringify({
        name: 'topology-project',
        dependencies: {
          next: '^15.0.0',
          pg: '^8.0.0',
          stripe: '^18.0.0',
          '@anthropic-ai/sdk': '^1.0.0',
        },
      }, null, 2), 'utf-8'));
      await import('node:fs/promises').then(fs => fs.writeFile(join(projectRoot, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n', 'utf-8'));
      await import('node:fs/promises').then(fs => fs.writeFile(join(projectRoot, 'app', 'api', 'internal', 'billing', 'reconcile', 'route.ts'), 'export async function POST() { return Response.json({ ok: true }); }\n', 'utf-8'));

      const inventory = new ResourceInventory(join(projectRoot, '.resimantle'));
      await inventory.ingestProjectTopology(projectRoot);

      const inferred = inventory.infer('/api/internal/billing/reconcile', 'POST');

      expect(inferred.stackTags).toContain('billing');
      expect(inferred.stackTags).toContain('database');
      expect(inferred.stackTags).toContain('ai');
      expect(inferred.riskTags).toContain('admin');
      expect(inventory.getProfile('package.json')).toBeDefined();
      expect(inventory.getProfile('/api/internal/billing/reconcile')).toBeDefined();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});