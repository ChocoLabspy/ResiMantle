import { ELIGIBLE_OVERLAY_STATES } from './overlay-provider';
import type {
  OverlayProvider,
  SearchOverlayRequest,
  SearchOverlayResolution,
  SearchOverlayResultItem,
} from './overlay-provider';
import type { StoryAsset } from './types';
import { StoryBroker } from './story-broker';

export class SearchOverlay implements OverlayProvider<SearchOverlayRequest, SearchOverlayResolution> {
  readonly kind = 'search' as const;

  constructor(private storyBroker: StoryBroker) {}

  canHandle(input: SearchOverlayRequest): boolean {
    return Boolean(input.query.trim());
  }

  async resolve(input: SearchOverlayRequest): Promise<SearchOverlayResolution> {
    if (!this.canHandle(input) || !ELIGIBLE_OVERLAY_STATES.has(input.trustState)) {
      return { matched: false };
    }

    const story = await this.storyBroker.getOrBindStory({
      actorId: input.actorId,
      sessionId: input.sessionId,
      stackTags: input.stackTags,
      riskTags: input.riskTags,
    });

    const results = story.assets
      .map(asset => ({ asset, score: scoreAsset(asset, input.query) }))
      .filter(candidate => candidate.score > 0)
      .sort((left, right) => right.score - left.score)
      .slice(0, input.limit ?? 5)
      .map(candidate => toResultItem(candidate.asset, input.query));

    if (results.length === 0) {
      return { matched: false, storyId: story.binding.storyId };
    }

    await Promise.all(results.map(result => this.storyBroker.recordTrigger({
      actorId: input.actorId,
      sessionId: input.sessionId,
      assetId: result.assetId,
      triggerType: 'search',
      details: {
        overlayKind: this.kind,
        query: input.query,
      },
    })));

    return {
      matched: true,
      storyId: story.binding.storyId,
      results,
      metadata: {
        overlayKind: this.kind,
        count: results.length,
      },
    };
  }
}

function scoreAsset(asset: StoryAsset, query: string): number {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  const haystacks = [
    asset.handle.toLowerCase(),
    asset.content?.toLowerCase() ?? '',
    JSON.stringify(asset.metadata).toLowerCase(),
  ];

  let score = 0;
  for (const term of terms) {
    for (const haystack of haystacks) {
      if (haystack.includes(term)) {
        score += 1;
      }
    }
  }

  return score;
}

function toResultItem(asset: StoryAsset, query: string): SearchOverlayResultItem {
  return {
    assetId: asset.id,
    handle: asset.handle,
    kind: asset.kind,
    excerpt: buildExcerpt(asset, query),
  };
}

function buildExcerpt(asset: StoryAsset, query: string): string | undefined {
  if (!asset.content) {
    return undefined;
  }

  const normalizedQuery = query.trim().toLowerCase();
  const content = asset.content.replace(/\s+/g, ' ').trim();
  const lower = content.toLowerCase();
  const matchIndex = normalizedQuery ? lower.indexOf(normalizedQuery) : -1;

  if (matchIndex === -1) {
    return content.slice(0, 120);
  }

  const start = Math.max(0, matchIndex - 30);
  const end = Math.min(content.length, matchIndex + normalizedQuery.length + 50);
  return content.slice(start, end);
}