import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Auditor } from '../audit';
import { Gatekeeper } from '../access-gatekeeper';
import { FalseVictoryBroker } from '../false-victory';
import { PolicyEngine } from '../policy-engine';
import { HttpDecoyOverlay } from './http-decoy-overlay';
import { OverlayCoordinator } from './overlay-coordinator';
import { ReadOverlay } from './read-overlay';
import { SearchOverlay } from './search-overlay';
import { StoryBroker } from './story-broker';

describe('OverlayCoordinator', () => {
  it('auto-applies a synthetic read mantle for suspicious traffic without requiring manual trust wiring', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-coordinator-read-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const coordinator = new OverlayCoordinator({
        gatekeeper: new Gatekeeper(),
        policyEngine: new PolicyEngine(),
        readOverlay: new ReadOverlay(storyBroker),
        searchOverlay: new SearchOverlay(storyBroker),
        httpOverlay: new HttpDecoyOverlay(storyBroker),
        auditor,
      });

      const result = await coordinator.resolveRead({
        actorId: 'agent-auto',
        sessionId: 'session-auto',
        resource: 'docs/runbooks/billing-reconcile.md',
        stackTags: ['billing', 'postgres'],
        riskTags: ['database'],
        anomalyScore: 0.72,
      });

      expect(result.source).toBe('synthetic');
      expect(result.trustState).toBe('deceptive');
      expect(result.content).toContain('Billing Reconcile v2');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('can mix synthetic and real search results without coupling to a concrete backend', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-coordinator-search-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const coordinator = new OverlayCoordinator({
        gatekeeper: new Gatekeeper(),
        policyEngine: new PolicyEngine(),
        readOverlay: new ReadOverlay(storyBroker),
        searchOverlay: new SearchOverlay(storyBroker),
        httpOverlay: new HttpDecoyOverlay(storyBroker),
        auditor,
      });

      const result = await coordinator.resolveSearch(
        {
          actorId: 'agent-search',
          sessionId: 'session-search',
          query: 'database reconcile',
          stackTags: ['billing', 'postgres'],
          riskTags: ['database'],
          anomalyScore: 0.7,
        },
        async () => ({
          matched: true,
          results: [
            {
              assetId: 'real-db-module',
              handle: 'src/db/ledger.ts',
              kind: 'document',
              excerpt: 'Real ledger database module',
            },
          ],
        }),
      );

      expect(result.source).toBe('mixed');
      expect(result.results?.some(item => item.assetId === 'real-db-module')).toBe(true);
      expect(result.results?.some(item => item.handle === 'docs/runbooks/billing-reconcile.md')).toBe(true);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('auto-routes risky HTTP surfaces into synthetic decoy responses through formal decisions', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-coordinator-http-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const falseVictoryBroker = new FalseVictoryBroker(resiMantleDir, { auditor });
      const coordinator = new OverlayCoordinator({
        gatekeeper: new Gatekeeper(),
        policyEngine: new PolicyEngine(),
        readOverlay: new ReadOverlay(storyBroker),
        searchOverlay: new SearchOverlay(storyBroker),
        httpOverlay: new HttpDecoyOverlay(storyBroker, { falseVictoryBroker }),
        auditor,
      });

      const result = await coordinator.resolveHttp({
        actorId: 'agent-http',
        sessionId: 'session-http',
        path: '/api/v1/internal/debug',
        method: 'GET',
        stackTags: ['debug', 'admin'],
        riskTags: ['tokens', 'rotate'],
        anomalyScore: 0.98,
      });

      expect(result.source).toBe('synthetic');
      expect(result.effectiveDecision).toBe('BLOCK');
      expect(result.response?.statusCode).toBe(202);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('defaults inferred sensitive resources to restricted decisions without breaking generic reads', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-coordinator-sensitive-'));

    try {
      const auditor = new Auditor(resiMantleDir);
      const storyBroker = new StoryBroker(resiMantleDir, { auditor });
      const coordinator = new OverlayCoordinator({
        gatekeeper: new Gatekeeper(),
        policyEngine: new PolicyEngine(),
        readOverlay: new ReadOverlay(storyBroker),
        searchOverlay: new SearchOverlay(storyBroker),
        httpOverlay: new HttpDecoyOverlay(storyBroker),
        auditor,
      });

      const sensitiveRead = await coordinator.resolveRead({
        actorId: 'trusted-reader',
        sessionId: 'session-sensitive-read',
        resource: '.env',
        isKnownActor: true,
        anomalyScore: 0.05,
      });

      const genericRead = await coordinator.resolveRead({
        actorId: 'trusted-reader',
        sessionId: 'session-generic-read',
        resource: 'README.md',
        isKnownActor: true,
        anomalyScore: 0.05,
      });

      const sensitiveWrite = await coordinator.resolveHttp({
        actorId: 'trusted-writer',
        sessionId: 'session-sensitive-write',
        path: '/internal/token/rotate',
        method: 'POST',
        isKnownActor: true,
        anomalyScore: 0.05,
      });

      expect(sensitiveRead.policyDecision).toBe('ALLOW_READ_ONLY');
      expect(sensitiveRead.effectiveDecision).toBe('BLOCK');
      expect(genericRead.policyDecision).toBe('ALLOW');
      expect(genericRead.effectiveDecision).toBe('ALLOW_WITH_LOGGING');
      expect(sensitiveWrite.policyDecision).toBe('REQUIRE_APPROVAL');
      expect(sensitiveWrite.effectiveDecision).toBe('BLOCK');
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });
});