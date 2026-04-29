import { randomUUID } from 'node:crypto';
import { RiskLevel } from '@resimantle/types';
import type { Auditor } from '../audit';
import { CanaryManager } from './canary-manager';
import { PromptCanary } from './prompt-canary';
import { StoryCatalog } from './story-catalog';
import { TrapRegistry } from './trap-registry';
import type {
  MaterializedStory,
  StoryAsset,
  StoryBinding,
  StorySelectionContext,
  StorySelectionResult,
  StoryTemplate,
  TrapScope,
  TrapTrigger,
} from './types';

type StoryBrokerOptions = {
  catalog?: StoryCatalog;
  registry?: TrapRegistry;
  canaryManager?: CanaryManager;
  promptCanary?: PromptCanary;
  auditor?: Auditor;
};

type RecordTriggerInput = {
  actorId: string;
  sessionId: string;
  assetId: string;
  triggerType: TrapTrigger['triggerType'];
  details?: Record<string, unknown>;
};

export class StoryBroker {
  private catalog: StoryCatalog;
  private registry: TrapRegistry;
  private canaryManager: CanaryManager;
  private promptCanary: PromptCanary;
  private auditor?: Auditor;

  constructor(resiMantleDir: string, options: StoryBrokerOptions = {}) {
    this.catalog = options.catalog ?? new StoryCatalog();
    this.registry = options.registry ?? new TrapRegistry(resiMantleDir);
    this.canaryManager = options.canaryManager ?? new CanaryManager(resiMantleDir);
    this.promptCanary = options.promptCanary ?? new PromptCanary();
    this.auditor = options.auditor;
  }

  async bindStory(context: StorySelectionContext): Promise<StorySelectionResult> {
    const existingStory = await this.getActiveStory(context);
    if (existingStory) {
      return {
        binding: existingStory.binding,
        story: existingStory,
      };
    }

    const template = this.catalog.selectForContext(context);
    const binding = this.createBinding(context, template.id);
    const story = await this.materializeStory(template, binding);

    await this.registry.saveBinding(binding);
    await this.registry.saveStory(story);
    await this.registry.recordEvent({
      type: 'STORY_BOUND',
      actorId: binding.actorId,
      sessionId: binding.sessionId,
      storyId: binding.storyId,
      details: {
        bindingId: binding.id,
        assetIds: story.assets.map(asset => asset.id),
      },
    });
    await this.auditor?.record({
      source: 'ResinTraps.StoryBroker',
      type: 'STORY_BOUND',
      severity: RiskLevel.INFO,
      details: {
        actorId: binding.actorId,
        sessionId: binding.sessionId,
        storyId: binding.storyId,
        bindingId: binding.id,
        assetIds: story.assets.map(asset => asset.id),
      },
      explanation: `Bound deception story "${story.templateName}" to actor ${binding.actorId}.`,
    });

    return { binding, story };
  }

  async getActiveStory(context: Pick<StorySelectionContext, 'actorId' | 'sessionId'>): Promise<MaterializedStory | undefined> {
    return (await this.registry.getStoryBySession(context.sessionId))
      ?? (await this.registry.getStoryByActor(context.actorId));
  }

  async getOrBindStory(context: StorySelectionContext): Promise<MaterializedStory> {
    return (await this.getActiveStory(context)) ?? (await this.bindStory(context)).story;
  }

  async recordTrigger(input: RecordTriggerInput): Promise<TrapTrigger> {
    const activeStory = await this.getActiveStory({
      actorId: input.actorId,
      sessionId: input.sessionId,
    });

    const matchedAsset = activeStory?.assets.find(asset => asset.id === input.assetId);

    const trigger = await this.registry.recordTrigger({
      actorId: input.actorId,
      sessionId: input.sessionId,
      storyId: activeStory?.binding.storyId,
      assetId: input.assetId,
      triggerType: input.triggerType,
      details: {
        ...input.details,
        handle: matchedAsset?.handle,
        kind: matchedAsset?.kind,
      },
    });

    await this.auditTrigger(trigger, matchedAsset?.handle);
    return trigger;
  }

  private createBinding(context: StorySelectionContext, storyId: string): StoryBinding {
    const createdAt = context.now ?? new Date().toISOString();

    return {
      id: `story-${randomUUID().slice(0, 8)}`,
      actorId: context.actorId,
      sessionId: context.sessionId,
      storyId,
      scope: context.scope ?? 'session',
      createdAt,
    };
  }

  private async materializeStory(template: StoryTemplate, binding: StoryBinding): Promise<MaterializedStory> {
    const scope: TrapScope = {
      actorId: binding.actorId,
      sessionId: binding.sessionId,
      storyId: binding.storyId,
    };

    const assets: StoryAsset[] = template.assets.map(asset => ({
      ...asset,
      triggerOn: [...asset.triggerOn],
      metadata: { ...asset.metadata, bindingId: binding.id },
    }));

    const requestedCanaryTypes = Array.from(new Set(
      assets
        .filter(asset => asset.kind === 'credential')
        .map(asset => asset.metadata['canaryType'])
        .filter((value): value is string => typeof value === 'string'),
    ));

    const tokens = requestedCanaryTypes.length > 0
      ? await this.canaryManager.generateTokens({
        types: requestedCanaryTypes,
        scope,
        metadata: { bindingId: binding.id },
      })
      : [];

    const tokensByType = new Map(tokens.map(token => [token.type, token]));

    const materializedAssets = assets.map(asset => this.materializeAsset(asset, binding, tokensByType));

    return {
      binding,
      templateName: template.name,
      stackTags: [...template.stackTags],
      riskTags: [...template.riskTags],
      assets: materializedAssets,
      createdAt: binding.createdAt,
    };
  }

  private materializeAsset(
    asset: StoryAsset,
    binding: StoryBinding,
    tokensByType: Map<string, ReturnType<CanaryManager['getAllTokens']>[number]>,
  ): StoryAsset {
    const materialized: StoryAsset = {
      ...asset,
      metadata: { ...asset.metadata },
      triggerOn: [...asset.triggerOn],
    };

    if (materialized.kind === 'credential') {
      const canaryType = typeof materialized.metadata['canaryType'] === 'string'
        ? materialized.metadata['canaryType']
        : undefined;
      const token = canaryType ? tokensByType.get(canaryType) : undefined;

      if (token) {
        materialized.content = token.value;
        materialized.metadata = {
          ...materialized.metadata,
          tokenId: token.id,
        };
      }
    }

    if (materialized.kind === 'prompt-watermark' && materialized.content) {
      materialized.content = this.promptCanary.inject(materialized.content, {
        actorId: binding.actorId,
        sessionId: binding.sessionId,
        storyId: binding.storyId,
      });
    }

    return materialized;
  }

  private async auditTrigger(trigger: TrapTrigger, handle?: string): Promise<void> {
    await this.auditor?.record({
      source: 'ResinTraps.StoryBroker',
      type: toSecurityEventType(trigger.type),
      severity: triggerSeverity(trigger.triggerType),
      details: {
        actorId: trigger.actorId,
        sessionId: trigger.sessionId,
        storyId: trigger.storyId,
        assetId: trigger.assetId,
        ...trigger.details,
      },
      explanation: handle
        ? `Synthetic asset "${handle}" was triggered via ${trigger.triggerType}.`
        : `Synthetic asset ${trigger.assetId} was triggered via ${trigger.triggerType}.`,
    });
  }
}

function toSecurityEventType(type: TrapTrigger['type']): string {
  switch (type) {
    case 'STORY_ASSET_READ':
      return 'STORY_ASSET_READ';
    case 'STORY_ASSET_SEARCHED':
      return 'STORY_ASSET_SEARCHED';
    case 'STORY_ASSET_INVOKED':
      return 'STORY_ASSET_INVOKED';
    case 'CANARY_REUSED':
      return 'CANARY_REUSED';
    default:
      return 'CANARY_TRIGGERED';
  }
}

function triggerSeverity(triggerType: TrapTrigger['triggerType']): RiskLevel {
  switch (triggerType) {
    case 'read':
    case 'search':
      return RiskLevel.INFO;
    case 'invoke':
      return RiskLevel.LOW;
    case 'reuse':
      return RiskLevel.MEDIUM;
  }
}