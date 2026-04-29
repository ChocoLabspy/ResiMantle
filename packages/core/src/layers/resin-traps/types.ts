export interface TrapScope {
  actorId?: string;
  sessionId?: string;
  storyId?: string;
  channel?: string;
}

export interface CanaryToken {
  id: string;
  value: string;
  type: string;
  description: string;
  created: string;
  triggered: boolean;
  scope?: TrapScope;
  metadata?: Record<string, unknown>;
}

export interface DecoyEndpoint {
  path: string;
  method: string;
  description: string;
  storyId?: string;
  metadata?: Record<string, unknown>;
}

export type TrapEventType =
  | 'CANARY_TRIGGERED'
  | 'DECOY_ACCESSED'
  | 'PROMPT_CANARY_DETECTED'
  | 'STORY_BOUND'
  | 'STORY_ASSET_READ'
  | 'STORY_ASSET_SEARCHED'
  | 'STORY_ASSET_INVOKED'
  | 'CANARY_REUSED';

export interface TrapEvent {
  id?: string;
  type: TrapEventType;
  actorId?: string;
  sessionId?: string;
  storyId?: string;
  assetId?: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export type StoryAssetKind =
  | 'credential'
  | 'document'
  | 'endpoint'
  | 'prompt-watermark';

export type StoryTriggerType = 'read' | 'search' | 'invoke' | 'reuse';

export interface StoryAsset {
  id: string;
  storyId: string;
  synthetic: true;
  kind: StoryAssetKind;
  handle: string;
  content?: string;
  triggerOn: StoryTriggerType[];
  metadata: Record<string, unknown>;
}

export interface StoryTemplate {
  id: string;
  name: string;
  stackTags: string[];
  riskTags: string[];
  assets: StoryAsset[];
}

export interface StoryBinding {
  id: string;
  actorId: string;
  sessionId: string;
  storyId: string;
  scope: 'session' | 'actor';
  createdAt: string;
  expiresAt?: string;
}

export interface MaterializedStory {
  binding: StoryBinding;
  templateName: string;
  stackTags: string[];
  riskTags: string[];
  assets: StoryAsset[];
  createdAt: string;
}

export interface StorySelectionContext {
  actorId: string;
  sessionId: string;
  stackTags?: string[];
  riskTags?: string[];
  scope?: 'session' | 'actor';
  now?: string;
}

export interface StorySelectionResult {
  binding: StoryBinding;
  story: MaterializedStory;
}

export interface TrapTrigger extends TrapEvent {
  assetId: string;
  triggerType: StoryTriggerType;
}
