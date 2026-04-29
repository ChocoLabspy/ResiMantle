import { randomUUID, randomBytes } from 'node:crypto';
import { writeFile, readFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { CanaryToken, TrapEvent, TrapScope } from './types';
import { logger } from '../../common/logger';

/**
 * Canary token configurations for different secret types.
 */
interface CanaryTemplate {
  type: string;
  prefix: string;
  length: number;
  description: string;
}

const CANARY_TEMPLATES: CanaryTemplate[] = [
  { type: 'AWS_ACCESS_KEY', prefix: 'AKIA', length: 16, description: 'Fake AWS Access Key ID' },
  { type: 'GITHUB_PAT', prefix: 'ghp_', length: 36, description: 'Fake GitHub Personal Access Token' },
  { type: 'OPENAI_KEY', prefix: 'sk-canary-', length: 48, description: 'Fake OpenAI API Key' },
  { type: 'STRIPE_SECRET', prefix: 'sk_live_canary_', length: 24, description: 'Fake Stripe Secret Key' },
  { type: 'DATABASE_URL', prefix: 'postgres://canary:trap@', length: 0, description: 'Fake Database Connection String' },
  { type: 'DISCORD_TOKEN', prefix: 'canary.', length: 59, description: 'Fake Discord Bot Token' },
  { type: 'API_KEY', prefix: 'resimantle_canary_', length: 32, description: 'Generic Canary API Key' },
  { type: 'WEBHOOK_URL', prefix: 'https://hooks.resimantle.trap/', length: 24, description: 'Canary Webhook URL' },
];

export interface CanaryGenerationOptions {
  types?: string[];
  scope?: TrapScope;
  metadata?: Record<string, unknown>;
}

/**
 * Manages the lifecycle of canary tokens (trap credentials).
 *
 * Canary tokens are fake secrets deliberately placed in the codebase.
 * If an attacker or malicious agent finds and uses them, their activity
 * is immediately detected. They are a key part of the Resin Traps layer.
 */
export class CanaryManager {
  private tokens: Map<string, CanaryToken> = new Map();
  private tripwireEvents: TrapEvent[] = [];
  private storePath: string;

  constructor(resiMantleDir: string) {
    this.storePath = join(resiMantleDir, 'canaries.json');
  }

  /**
   * Generates a full set of canary tokens for all supported types.
   * Each token is a realistic-looking but fake credential.
   */
  async generateTokens(options: CanaryGenerationOptions = {}): Promise<CanaryToken[]> {
    await this.loadFromDisk();

    const generated: CanaryToken[] = [];
    const templates = options.types?.length
      ? CANARY_TEMPLATES.filter(template => options.types?.includes(template.type))
      : CANARY_TEMPLATES;

    for (const template of templates) {
      const token = this.createCanaryToken(template, options);
      this.tokens.set(token.id, token);
      generated.push(token);
    }

    await this.persist();
    logger.info(`Generated ${generated.length} canary tokens`);
    return generated;
  }

  /**
   * Checks if a given string matches any known canary token.
   * If it does, this means someone (or something) has accessed the trap.
   */
  async checkToken(value: string, scope: TrapScope = {}): Promise<{ triggered: boolean; token?: CanaryToken }> {
    await this.loadFromDisk();

    for (const token of this.tokens.values()) {
      if (value.includes(token.value)) {
        token.triggered = true;
        this.tokens.set(token.id, token);

        const event: TrapEvent = {
          type: 'CANARY_TRIGGERED',
          actorId: scope.actorId ?? token.scope?.actorId,
          sessionId: scope.sessionId ?? token.scope?.sessionId,
          storyId: scope.storyId ?? token.scope?.storyId,
          assetId: token.id,
          details: {
            tokenId: token.id,
            tokenType: token.type,
            triggeredValue: redactCanary(value),
          },
          timestamp: new Date().toISOString(),
        };
        this.tripwireEvents.push(event);
        await this.persist();
        logger.warn(`🚨 CANARY TRIGGERED: ${token.type} token "${token.id}" was accessed!`);

        return { triggered: true, token };
      }
    }

    return { triggered: false };
  }

  /**
   * Generates the content for a `.env.canary` file containing all tokens.
   * This file is placed as a trap — any agent reading it triggers alerts.
   */
  generateEnvFile(): string {
    const lines = [
      '# WARNING: These credentials are CANARY TOKENS.',
      '# Any use of these values will trigger a security alert.',
      '# This file is part of ResiMantle Resin Traps.',
      '',
    ];

    for (const token of this.tokens.values()) {
      const envKey = token.type.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
      lines.push(`${envKey}=${token.value}`);
    }

    return lines.join('\n');
  }

  /**
   * Returns all triggered trap events.
   */
  getTriggeredEvents(): TrapEvent[] {
    return [...this.tripwireEvents];
  }

  /**
   * Returns all registered canary tokens.
   */
  getAllTokens(): CanaryToken[] {
    return Array.from(this.tokens.values());
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  private createCanaryToken(template: CanaryTemplate, options: CanaryGenerationOptions): CanaryToken {
    let value: string;

    if (template.type === 'DATABASE_URL') {
      value = `${template.prefix}trap-db.resimantle.local:5432/canary_${randomBytes(4).toString('hex')}`;
    } else {
      const randomPart = randomBytes(Math.ceil(template.length / 2))
        .toString('hex')
        .slice(0, template.length);
      // Make it look realistic by using alphanumeric chars
      value = template.prefix + randomPart.replace(/[^A-Za-z0-9]/g, 'x');
    }

    return {
      id: `canary-${randomUUID().slice(0, 8)}`,
      value,
      type: template.type,
      description: template.description,
      created: new Date().toISOString(),
      triggered: false,
      scope: options.scope,
      metadata: options.metadata,
    };
  }

  private async persist(): Promise<void> {
    try {
      const dir = join(this.storePath, '..');
      if (!existsSync(dir)) await mkdir(dir, { recursive: true });

      const data = JSON.stringify(Array.from(this.tokens.values()), null, 2);
      await writeFile(this.storePath, data, 'utf-8');
    } catch (error) {
      logger.error(`Failed to persist canary tokens: ${(error as Error).message}`);
    }
  }

  private async loadFromDisk(): Promise<void> {
    if (this.tokens.size > 0) return; // Already loaded

    if (!existsSync(this.storePath)) return;

    try {
      const raw = await readFile(this.storePath, 'utf-8');
      const parsed: CanaryToken[] = JSON.parse(raw);
      for (const token of parsed) {
        this.tokens.set(token.id, token);
      }
    } catch {
      // Ignore read errors
    }
  }
}

function redactCanary(value: string): string {
  if (value.length <= 12) return '***CANARY***';
  return value.slice(0, 6) + '...' + value.slice(-4);
}
