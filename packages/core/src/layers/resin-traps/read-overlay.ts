import { ELIGIBLE_OVERLAY_STATES } from './overlay-provider';
import type { OverlayProvider, ReadOverlayRequest, ReadOverlayResolution } from './overlay-provider';
import { StoryBroker } from './story-broker';

export class ReadOverlay implements OverlayProvider<ReadOverlayRequest, ReadOverlayResolution> {
  readonly kind = 'read' as const;

  constructor(private storyBroker: StoryBroker) {}

  canHandle(input: ReadOverlayRequest): boolean {
    return Boolean(input.resource);
  }

  async resolve(input: ReadOverlayRequest): Promise<ReadOverlayResolution> {
    if (!this.canHandle(input) || !ELIGIBLE_OVERLAY_STATES.has(input.trustState)) {
      return { matched: false };
    }

    const story = await this.storyBroker.getOrBindStory({
      actorId: input.actorId,
      sessionId: input.sessionId,
      stackTags: input.stackTags,
      riskTags: input.riskTags,
    });

    const normalizedResource = normalizeResource(input.resource);
    const asset = story.assets.find(candidate => {
      if (candidate.kind === 'endpoint') {
        return false;
      }
      return normalizeResource(candidate.handle) === normalizedResource;
    });

    if (!asset) {
      return { matched: false, storyId: story.binding.storyId };
    }

    await this.storyBroker.recordTrigger({
      actorId: input.actorId,
      sessionId: input.sessionId,
      assetId: asset.id,
      triggerType: 'read',
      details: {
        overlayKind: this.kind,
        resource: input.resource,
      },
    });

    return {
      matched: true,
      storyId: story.binding.storyId,
      assetId: asset.id,
      content: asset.content ?? asset.handle,
      metadata: {
        kind: asset.kind,
        handle: asset.handle,
        overlayKind: this.kind,
      },
    };
  }
}

function normalizeResource(value: string): string {
  return value.replace(/\\/g, '/').trim().toLowerCase();
}