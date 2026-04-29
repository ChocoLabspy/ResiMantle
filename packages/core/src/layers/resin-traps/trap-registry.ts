import { randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { MaterializedStory, StoryBinding, TrapEvent, TrapTrigger } from './types';

type TrapEventInput = Omit<TrapEvent, 'id' | 'timestamp'> & Partial<Pick<TrapEvent, 'id' | 'timestamp'>>;
type TrapTriggerInput = Omit<TrapTrigger, 'id' | 'timestamp' | 'type'> & Partial<Pick<TrapTrigger, 'id' | 'timestamp'>>;

const TRIGGER_EVENT_TYPES: Record<TrapTrigger['triggerType'], TrapTrigger['type']> = {
  read: 'STORY_ASSET_READ',
  search: 'STORY_ASSET_SEARCHED',
  invoke: 'STORY_ASSET_INVOKED',
  reuse: 'CANARY_REUSED',
};

export class TrapRegistry {
  private bindingsPath: string;
  private storiesPath: string;
  private eventsPath: string;

  constructor(private resiMantleDir: string) {
    this.bindingsPath = join(resiMantleDir, 'deception-bindings.json');
    this.storiesPath = join(resiMantleDir, 'deception-stories.json');
    this.eventsPath = join(resiMantleDir, 'trap-events.log');
  }

  async saveBinding(binding: StoryBinding): Promise<void> {
    const bindings = await this.listBindings();
    const nextBindings = upsertById(bindings, binding);
    await this.writeJsonFile(this.bindingsPath, nextBindings);
  }

  async getBindingBySession(sessionId: string): Promise<StoryBinding | undefined> {
    const bindings = await this.listBindings();
    return bindings.find(binding => binding.sessionId === sessionId);
  }

  async listBindings(): Promise<StoryBinding[]> {
    return this.readJsonFile<StoryBinding[]>(this.bindingsPath, []);
  }

  async saveStory(story: MaterializedStory): Promise<void> {
    const stories = await this.listStories();
    const nextStories = upsertByStoryBinding(stories, story);
    await this.writeJsonFile(this.storiesPath, nextStories);
  }

  async getStoryBySession(sessionId: string): Promise<MaterializedStory | undefined> {
    const stories = await this.listStories();
    return stories.find(story => story.binding.sessionId === sessionId);
  }

  async getStoryByActor(actorId: string): Promise<MaterializedStory | undefined> {
    const stories = await this.listStories();
    return stories.find(story => story.binding.actorId === actorId);
  }

  async listStories(): Promise<MaterializedStory[]> {
    return this.readJsonFile<MaterializedStory[]>(this.storiesPath, []);
  }

  async recordEvent(event: TrapEventInput): Promise<TrapEvent> {
    const normalized: TrapEvent = {
      id: event.id ?? `trap-${randomUUID().slice(0, 8)}`,
      timestamp: event.timestamp ?? new Date().toISOString(),
      ...event,
    };

    await this.ensureDirectory();
    await appendFile(this.eventsPath, JSON.stringify(normalized) + '\n', 'utf-8');

    return normalized;
  }

  async recordTrigger(trigger: TrapTriggerInput): Promise<TrapTrigger> {
    const normalized: TrapTrigger = {
      id: trigger.id ?? `trigger-${randomUUID().slice(0, 8)}`,
      timestamp: trigger.timestamp ?? new Date().toISOString(),
      type: TRIGGER_EVENT_TYPES[trigger.triggerType],
      ...trigger,
    };

    await this.recordEvent(normalized);
    return normalized;
  }

  async listEvents(): Promise<TrapEvent[]> {
    if (!existsSync(this.eventsPath)) {
      return [];
    }

    const raw = await readFile(this.eventsPath, 'utf-8');
    return raw
      .split(/\r?\n/)
      .filter(Boolean)
      .map(line => JSON.parse(line) as TrapEvent);
  }

  async listTriggers(): Promise<TrapTrigger[]> {
    const events = await this.listEvents();
    return events.filter(isTrapTrigger);
  }

  private async ensureDirectory(): Promise<void> {
    if (!existsSync(this.resiMantleDir)) {
      await mkdir(this.resiMantleDir, { recursive: true });
    }
  }

  private async readJsonFile<T>(filePath: string, fallback: T): Promise<T> {
    if (!existsSync(filePath)) {
      return fallback;
    }

    const raw = await readFile(filePath, 'utf-8');
    return JSON.parse(raw) as T;
  }

  private async writeJsonFile<T>(filePath: string, value: T): Promise<void> {
    await this.ensureDirectory();
    await writeFile(filePath, JSON.stringify(value, null, 2), 'utf-8');
  }
}

function upsertById<T extends { id: string }>(items: T[], nextItem: T): T[] {
  const index = items.findIndex(item => item.id === nextItem.id);
  if (index === -1) {
    return [...items, nextItem];
  }

  const nextItems = [...items];
  nextItems[index] = nextItem;
  return nextItems;
}

function upsertByStoryBinding(items: MaterializedStory[], nextStory: MaterializedStory): MaterializedStory[] {
  const index = items.findIndex(item => item.binding.id === nextStory.binding.id);
  if (index === -1) {
    return [...items, nextStory];
  }

  const nextItems = [...items];
  nextItems[index] = nextStory;
  return nextItems;
}

function isTrapTrigger(event: TrapEvent): event is TrapTrigger {
  return typeof (event as Partial<TrapTrigger>).triggerType === 'string'
    && typeof event.assetId === 'string';
}