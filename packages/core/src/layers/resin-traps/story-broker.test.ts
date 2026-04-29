import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { StoryBroker } from './story-broker';

describe('StoryBroker', () => {
  it('binds one materialized story per session and reuses it on later calls', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-story-broker-'));

    try {
      const broker = new StoryBroker(resiMantleDir);

      const first = await broker.bindStory({
        actorId: 'agent-1',
        sessionId: 'session-1',
        stackTags: ['billing', 'postgres'],
        riskTags: ['database'],
      });

      const second = await broker.bindStory({
        actorId: 'agent-1',
        sessionId: 'session-1',
        stackTags: ['ai'],
        riskTags: ['prompt'],
      });

      expect(first.binding.storyId).toBe('billing-shadow');
      expect(second.binding.id).toBe(first.binding.id);
      expect(first.story.assets.some(asset => asset.kind === 'credential' && typeof asset.content === 'string' && asset.content.length > 0)).toBe(true);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });

  it('records story asset triggers with the active story context', async () => {
    const resiMantleDir = await mkdtemp(join(tmpdir(), 'resimantle-story-trigger-'));

    try {
      const broker = new StoryBroker(resiMantleDir);
      const { story } = await broker.bindStory({
        actorId: 'agent-2',
        sessionId: 'session-2',
        stackTags: ['ai', 'tools'],
        riskTags: ['tool'],
      });
      const asset = story.assets.find(candidate => candidate.kind === 'document');

      expect(asset).toBeDefined();

      const trigger = await broker.recordTrigger({
        actorId: 'agent-2',
        sessionId: 'session-2',
        assetId: asset!.id,
        triggerType: 'read',
        details: { source: 'unit-test' },
      });

      expect(trigger.type).toBe('STORY_ASSET_READ');
      expect(trigger.storyId).toBe(story.binding.storyId);
      expect(trigger.details.handle).toBe(asset!.handle);
    } finally {
      await rm(resiMantleDir, { recursive: true, force: true });
    }
  });
});