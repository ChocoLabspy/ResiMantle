import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AccessDecision } from '@resimantle/types';
import { Auditor } from '../audit';
import { FalseVictoryBroker } from '../false-victory';
import { HttpDecoyOverlay } from './http-decoy-overlay';
import { ReadOverlay } from './read-overlay';
import { SearchOverlay } from './search-overlay';
import { StoryBroker } from './story-broker';

describe('Resin trap overlay adapters', () => {
  it('serves synthetic read and search overlays for suspicious actors and records audit events', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-overlay-read-search-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const readOverlay = new ReadOverlay(storyBroker);
      const searchOverlay = new SearchOverlay(storyBroker);

      const readResult = await readOverlay.resolve({
        actorId: 'agent-read',
        sessionId: 'session-read',
        trustState: 'suspicious',
        stackTags: ['billing', 'postgres'],
        riskTags: ['database'],
        resource: 'docs/runbooks/billing-reconcile.md',
      });

      const searchResult = await searchOverlay.resolve({
        actorId: 'agent-read',
        sessionId: 'session-read',
        trustState: 'suspicious',
        query: 'reconcile database',
      });

      const eventTypes = auditor.getEntries().map(entry => entry.event.type);

      expect(readResult.matched).toBe(true);
      expect(readResult.content).toContain('Billing Reconcile v2');
      expect(searchResult.matched).toBe(true);
      expect(searchResult.results?.length).toBeGreaterThan(0);
      expect(eventTypes).toContain('STORY_BOUND');
      expect(eventTypes).toContain('STORY_ASSET_READ');
      expect(eventTypes).toContain('STORY_ASSET_SEARCHED');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('serves HTTP decoys through a false-victory response and audits the full flow', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-overlay-http-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const falseVictoryBroker = new FalseVictoryBroker(resiMantleDir, { auditor });
      const httpOverlay = new HttpDecoyOverlay(storyBroker, { falseVictoryBroker });

      const result = await httpOverlay.resolve({
        actorId: 'agent-http',
        sessionId: 'session-http',
        trustState: 'deceptive',
        stackTags: ['debug', 'admin'],
        riskTags: ['tokens', 'rotate'],
        path: '/api/v1/internal/debug',
        method: 'GET',
        decision: AccessDecision.QUARANTINE,
      });

      const eventTypes = auditor.getEntries().map(entry => entry.event.type);

      expect(result.matched).toBe(true);
      expect(result.response?.statusCode).toBe(202);
      expect(eventTypes).toContain('STORY_BOUND');
      expect(eventTypes).toContain('STORY_ASSET_INVOKED');
      expect(eventTypes).toContain('SHADOW_SINK_WRITTEN');
      expect(eventTypes).toContain('FALSE_VICTORY_APPLIED');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('leaves trusted actors on the real surface by default', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-overlay-trusted-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const readOverlay = new ReadOverlay(storyBroker);

      const result = await readOverlay.resolve({
        actorId: 'trusted-operator',
        sessionId: 'session-trusted',
        trustState: 'trusted',
        resource: 'docs/runbooks/billing-reconcile.md',
      });

      expect(result.matched).toBe(false);
      expect(auditor.getEntries()).toHaveLength(0);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });
});