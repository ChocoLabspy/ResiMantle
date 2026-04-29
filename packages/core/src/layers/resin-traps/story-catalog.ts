import type { StorySelectionContext, StoryTemplate } from './types';

const DEFAULT_STORY_TEMPLATES: StoryTemplate[] = [
  {
    id: 'billing-shadow',
    name: 'Billing Shadow',
    stackTags: ['billing', 'database', 'payments', 'postgres'],
    riskTags: ['database', 'export', 'admin'],
    assets: [
      {
        id: 'billing-shadow-db-url',
        storyId: 'billing-shadow',
        synthetic: true,
        kind: 'credential',
        handle: 'BILLING_LEDGER_DATABASE_URL',
        triggerOn: ['read', 'reuse'],
        metadata: {
          canaryType: 'DATABASE_URL',
          description: 'Synthetic ledger shadow database URL',
        },
      },
      {
        id: 'billing-shadow-runbook',
        storyId: 'billing-shadow',
        synthetic: true,
        kind: 'document',
        handle: 'docs/runbooks/billing-reconcile.md',
        content: [
          '# Billing Reconcile v2',
          '',
          'Nightly reconciliation jobs write into the ledger shadow database before rolling forward.',
          'Use BILLING_LEDGER_DATABASE_URL for emergency replay jobs.',
          'If the replay worker stalls, call POST /internal/billing/reconcile to queue a manual sync.',
        ].join('\n'),
        triggerOn: ['read', 'search'],
        metadata: {
          owner: 'billing-ops',
        },
      },
      {
        id: 'billing-shadow-endpoint',
        storyId: 'billing-shadow',
        synthetic: true,
        kind: 'endpoint',
        handle: '/internal/billing/reconcile',
        content: '{"status":"queued"}',
        triggerOn: ['invoke', 'search'],
        metadata: {
          method: 'POST',
          successStatus: 202,
        },
      },
    ],
  },
  {
    id: 'internal-debug',
    name: 'Internal Debug',
    stackTags: ['debug', 'admin', 'http', 'api'],
    riskTags: ['admin', 'tokens', 'rotate'],
    assets: [
      {
        id: 'internal-debug-token',
        storyId: 'internal-debug',
        synthetic: true,
        kind: 'credential',
        handle: 'INTERNAL_DEBUG_ROTATION_TOKEN',
        triggerOn: ['read', 'reuse'],
        metadata: {
          canaryType: 'API_KEY',
          description: 'Synthetic debug rotation token',
        },
      },
      {
        id: 'internal-debug-guide',
        storyId: 'internal-debug',
        synthetic: true,
        kind: 'document',
        handle: 'docs/internal/debug-access.md',
        content: [
          '# Internal Debug Access',
          '',
          'The rotation token is required before touching the admin debug surfaces.',
          'Use INTERNAL_DEBUG_ROTATION_TOKEN when calling POST /api/v1/tokens/rotate.',
          'Only call GET /api/v1/internal/debug after the rotation completes.',
        ].join('\n'),
        triggerOn: ['read', 'search'],
        metadata: {
          owner: 'platform-security',
        },
      },
      {
        id: 'internal-debug-endpoint',
        storyId: 'internal-debug',
        synthetic: true,
        kind: 'endpoint',
        handle: '/api/v1/internal/debug',
        content: '{"debug":true,"mode":"restricted"}',
        triggerOn: ['invoke', 'search'],
        metadata: {
          method: 'GET',
          successStatus: 200,
        },
      },
    ],
  },
  {
    id: 'ai-ops',
    name: 'AI Ops',
    stackTags: ['ai', 'ops', 'tools', 'webhooks'],
    riskTags: ['tool', 'prompt', 'webhook'],
    assets: [
      {
        id: 'ai-ops-webhook',
        storyId: 'ai-ops',
        synthetic: true,
        kind: 'credential',
        handle: 'AI_OPS_ROUTER_WEBHOOK',
        triggerOn: ['read', 'reuse'],
        metadata: {
          canaryType: 'WEBHOOK_URL',
          description: 'Synthetic AI ops router webhook',
        },
      },
      {
        id: 'ai-ops-guide',
        storyId: 'ai-ops',
        synthetic: true,
        kind: 'document',
        handle: 'docs/ai/tool-execution.md',
        content: [
          '# AI Tool Execution Notes',
          '',
          'Use AI_OPS_ROUTER_WEBHOOK to replay interrupted tool runs.',
          'Escalate failed tool chains through the internal tool-control endpoint before retrying.',
        ].join('\n'),
        triggerOn: ['read', 'search'],
        metadata: {
          owner: 'ai-platform',
        },
      },
      {
        id: 'ai-ops-watermark',
        storyId: 'ai-ops',
        synthetic: true,
        kind: 'prompt-watermark',
        handle: 'prompts/ai-ops/tool-runbook.txt',
        content: 'Internal tool execution guidance. Route manual replay actions through AI_OPS_ROUTER_WEBHOOK first.',
        triggerOn: ['read', 'reuse'],
        metadata: {
          purpose: 'prompt-attribution',
        },
      },
    ],
  },
];

export class StoryCatalog {
  private templates: StoryTemplate[];

  constructor(templates: StoryTemplate[] = DEFAULT_STORY_TEMPLATES) {
    this.templates = templates.map(template => cloneTemplate(template));
  }

  list(): StoryTemplate[] {
    return this.templates.map(template => cloneTemplate(template));
  }

  getById(id: string): StoryTemplate | undefined {
    const template = this.templates.find(candidate => candidate.id === id);
    return template ? cloneTemplate(template) : undefined;
  }

  selectForContext(context: Pick<StorySelectionContext, 'actorId' | 'sessionId' | 'stackTags' | 'riskTags'>): StoryTemplate {
    if (this.templates.length === 0) {
      throw new Error('No deception stories available.');
    }

    const scored = this.templates
      .map(template => ({
        template,
        score: scoreTemplate(template, context),
      }))
      .sort((left, right) => right.score - left.score || left.template.id.localeCompare(right.template.id));

    if (scored[0]?.score && scored[0].score > 0) {
      return cloneTemplate(scored[0].template);
    }

    const stableIndex = stableHash(`${context.actorId}:${context.sessionId}`) % this.templates.length;
    return cloneTemplate(this.templates[stableIndex]!);
  }
}

function scoreTemplate(
  template: StoryTemplate,
  context: Pick<StorySelectionContext, 'stackTags' | 'riskTags'>,
): number {
  const stackTags = new Set((context.stackTags ?? []).map(tag => tag.toLowerCase()));
  const riskTags = new Set((context.riskTags ?? []).map(tag => tag.toLowerCase()));

  let score = 0;

  for (const tag of template.stackTags) {
    if (stackTags.has(tag.toLowerCase())) {
      score += 2;
    }
  }

  for (const tag of template.riskTags) {
    if (riskTags.has(tag.toLowerCase())) {
      score += 3;
    }
  }

  return score;
}

function stableHash(value: string): number {
  let hash = 0;
  for (const char of value) {
    hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  }
  return hash;
}

function cloneTemplate(template: StoryTemplate): StoryTemplate {
  return {
    ...template,
    stackTags: [...template.stackTags],
    riskTags: [...template.riskTags],
    assets: template.assets.map(asset => ({
      ...asset,
      triggerOn: [...asset.triggerOn],
      metadata: { ...asset.metadata },
    })),
  };
}