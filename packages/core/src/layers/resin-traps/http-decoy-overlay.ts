import type { FalseVictoryBroker } from '../false-victory';
import { ELIGIBLE_OVERLAY_STATES } from './overlay-provider';
import type { HttpOverlayRequest, HttpOverlayResolution, OverlayProvider } from './overlay-provider';
import type { StoryAsset } from './types';
import { StoryBroker } from './story-broker';

interface HttpDecoyOverlayOptions {
  falseVictoryBroker?: FalseVictoryBroker;
}

export class HttpDecoyOverlay implements OverlayProvider<HttpOverlayRequest, HttpOverlayResolution> {
  readonly kind = 'http' as const;
  private falseVictoryBroker?: FalseVictoryBroker;

  constructor(private storyBroker: StoryBroker, options: HttpDecoyOverlayOptions = {}) {
    this.falseVictoryBroker = options.falseVictoryBroker;
  }

  canHandle(input: HttpOverlayRequest): boolean {
    return Boolean(input.path) && Boolean(input.method);
  }

  async resolve(input: HttpOverlayRequest): Promise<HttpOverlayResolution> {
    if (!this.canHandle(input) || !ELIGIBLE_OVERLAY_STATES.has(input.trustState)) {
      return { matched: false };
    }

    const story = await this.storyBroker.getOrBindStory({
      actorId: input.actorId,
      sessionId: input.sessionId,
      stackTags: input.stackTags,
      riskTags: input.riskTags,
    });

    const asset = story.assets.find(candidate => isMatchingEndpoint(candidate, input.path, input.method));
    if (!asset) {
      return { matched: false, storyId: story.binding.storyId };
    }

    await this.storyBroker.recordTrigger({
      actorId: input.actorId,
      sessionId: input.sessionId,
      assetId: asset.id,
      triggerType: 'invoke',
      details: {
        overlayKind: this.kind,
        resource: input.path,
        method: input.method,
      },
    });

    const falseVictory = this.falseVictoryBroker
      ? await this.falseVictoryBroker.evaluate({
        actorId: input.actorId,
        sessionId: input.sessionId,
        trustState: input.trustState,
        actionType: 'decoy-admin-route',
        resource: input.path,
        decision: input.decision,
        metadata: {
          ...input.metadata,
          ...input.body,
          method: input.method,
          assetId: asset.id,
          overlayKind: this.kind,
          storyId: story.binding.storyId,
        },
      })
      : { applied: false, reason: 'No false-victory broker configured.' };

    const response = falseVictory.applied && falseVictory.response
      ? {
        statusCode: falseVictory.response.statusCode ?? getStatusCode(asset),
        body: falseVictory.response.body,
        headers: falseVictory.response.headers,
      }
      : {
        statusCode: getStatusCode(asset),
        body: parseBody(asset),
        headers: {
          'x-resimantle-story': story.binding.storyId,
        },
      };

    return {
      matched: true,
      storyId: story.binding.storyId,
      assetId: asset.id,
      response,
      metadata: {
        overlayKind: this.kind,
        falseVictoryApplied: falseVictory.applied,
        planId: falseVictory.planId,
      },
    };
  }
}

function isMatchingEndpoint(asset: StoryAsset, path: string, method: string): boolean {
  if (asset.kind !== 'endpoint') {
    return false;
  }

  const expectedMethod = typeof asset.metadata['method'] === 'string'
    ? asset.metadata['method'].toUpperCase()
    : 'GET';

  return asset.handle === path && expectedMethod === method.toUpperCase();
}

function getStatusCode(asset: StoryAsset): number {
  return typeof asset.metadata['successStatus'] === 'number'
    ? asset.metadata['successStatus']
    : 200;
}

function parseBody(asset: StoryAsset): Record<string, unknown> {
  if (!asset.content) {
    return { ok: true };
  }

  try {
    return JSON.parse(asset.content) as Record<string, unknown>;
  } catch {
    return { ok: true, message: asset.content };
  }
}