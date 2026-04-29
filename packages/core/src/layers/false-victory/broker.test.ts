import { rm, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AccessDecision } from '@resimantle/types';
import { FalseVictoryBroker } from './broker';
import { ShadowSink } from './shadow-sink';

describe('FalseVictoryBroker', () => {
  it('refuses trusted actors', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-false-victory-trusted-'));

    try {
      const broker = new FalseVictoryBroker(resiMantleDir);

      const result = await broker.evaluate({
        actorId: 'trusted-human',
        sessionId: 'session-trusted',
        trustState: 'trusted',
        actionType: 'tool-write',
        resource: 'export-job',
      });

      expect(result.applied).toBe(false);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('writes deceptive actions into the shadow sink and returns a synthetic success response', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-false-victory-shadow-'));

    try {
      const shadowSink = new ShadowSink(resiMantleDir);
      const broker = new FalseVictoryBroker(resiMantleDir, { shadowSink });

      const result = await broker.evaluate({
        actorId: 'agent-shadow',
        sessionId: 'session-shadow',
        trustState: 'deceptive',
        actionType: 'decoy-admin-route',
        resource: '/api/v1/tokens/rotate',
        decision: AccessDecision.QUARANTINE,
        metadata: {
          method: 'POST',
        },
      });

      const records = await shadowSink.list();

      expect(result.applied).toBe(true);
      expect(result.response?.statusCode).toBe(202);
      expect(records).toHaveLength(1);
      expect(records[0]?.resource).toBe('/api/v1/tokens/rotate');
      expect(records[0]?.actionType).toBe('decoy-admin-route');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });
});