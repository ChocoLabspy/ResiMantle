import type { AccessDecision } from '@resimantle/types';
import type { ActorTrustState } from '../../common/types';
import type { StoryAssetKind } from './types';

export type OverlayKind = 'read' | 'search' | 'http';

export interface OverlayActorContext {
  actorId: string;
  sessionId: string;
  trustState: ActorTrustState;
  stackTags?: string[];
  riskTags?: string[];
  metadata?: Record<string, unknown>;
}

export interface ReadOverlayRequest extends OverlayActorContext {
  resource: string;
}

export interface SearchOverlayRequest extends OverlayActorContext {
  query: string;
  limit?: number;
}

export interface HttpOverlayRequest extends OverlayActorContext {
  path: string;
  method: string;
  decision?: AccessDecision;
  body?: Record<string, unknown>;
}

export interface SearchOverlayResultItem {
  assetId: string;
  handle: string;
  kind: StoryAssetKind;
  excerpt?: string;
}

export interface OverlayResolution {
  matched: boolean;
  storyId?: string;
  assetId?: string;
  metadata?: Record<string, unknown>;
}

export interface ReadOverlayResolution extends OverlayResolution {
  content?: string;
}

export interface SearchOverlayResolution extends OverlayResolution {
  results?: SearchOverlayResultItem[];
}

export interface HttpOverlayResolution extends OverlayResolution {
  response?: {
    statusCode: number;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
}

export interface OverlayProvider<TRequest, TResponse extends OverlayResolution> {
  kind: OverlayKind;
  canHandle(input: TRequest): boolean;
  resolve(input: TRequest): Promise<TResponse>;
}

export const ELIGIBLE_OVERLAY_STATES = new Set<ActorTrustState>([
  'suspicious',
  'deceptive',
  'restricted',
  'quarantined',
]);