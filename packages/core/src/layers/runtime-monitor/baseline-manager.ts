import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import type {
  CompatibilityBaselineConfig,
  CompatibilityBaselineMode,
  ProcessContainmentAllowlist,
} from '../../common/types';
import { RuntimeEventCategory, type RuntimeEvent } from './types';

interface BaselineCounter {
  count: number;
  lastSeenAt: string;
}

interface StoredRuntimeBaseline {
  version: '0.1.0';
  updatedAt: string;
  observations: number;
  reads: Record<string, BaselineCounter>;
  processes: Record<string, BaselineCounter>;
  socketHosts: Record<string, BaselineCounter>;
}

export interface CompatibilityBaselineSnapshot {
  mode: CompatibilityBaselineMode;
  enabled: boolean;
  persistencePath: string;
  observations: number;
  updatedAt?: string;
  minOccurrences: number;
  autoApplyToContainment: boolean;
  reduceRiskFromKnownActivity: boolean;
  learnedAllowlist: ProcessContainmentAllowlist;
  candidates: {
    reads: Array<{ pattern: string; count: number; lastSeenAt: string }>;
    processes: Array<{ pattern: string; count: number; lastSeenAt: string }>;
    socketHosts: Array<{ host: string; count: number; lastSeenAt: string }>;
  };
}

interface ObserveContext {
  posture?: string;
  integrityStatus?: string;
}

const EMPTY_ALLOWLIST: ProcessContainmentAllowlist = {
  readPatterns: [],
  processPatterns: [],
  socketHosts: [],
  socketHostPatterns: [],
  socketPathPatterns: [],
};

export class CompatibilityBaselineManager {
  private rootDir: string;
  private config: Required<CompatibilityBaselineConfig>;
  private filePath: string;
  private state: StoredRuntimeBaseline;

  constructor(rootDir: string, config: CompatibilityBaselineConfig = {}) {
    this.rootDir = rootDir;
    this.config = normalizeBaselineConfig(config);
    this.filePath = isAbsolute(this.config.persistencePath)
      ? this.config.persistencePath
      : resolve(rootDir, this.config.persistencePath);
    this.state = createEmptyState();
  }

  async initialize(): Promise<void> {
    if (!this.isEnabled() || !existsSync(this.filePath)) {
      return;
    }

    try {
      const raw = await readFile(this.filePath, 'utf-8');
      this.state = normalizeStoredBaseline(JSON.parse(raw) as Partial<StoredRuntimeBaseline>);
    } catch {
      this.state = createEmptyState();
    }
  }

  observe(event: RuntimeEvent, context: ObserveContext = {}): void {
    if (!this.isEnabled() || !shouldLearnEvent(event, context)) {
      return;
    }

    const now = new Date().toISOString();
    const state = this.state;
    state.updatedAt = now;
    state.observations += 1;

    if (event.category === RuntimeEventCategory.FILE_READ) {
      const pattern = toReadPattern(this.rootDir, event.resource);
      if (pattern) {
        touchCounter(state.reads, pattern, now);
      }
      return;
    }

    if (event.category === RuntimeEventCategory.PROCESS_SPAWN) {
      const pattern = toProcessPattern(event.resource);
      if (pattern) {
        touchCounter(state.processes, pattern, now);
      }
      return;
    }

    if (event.category === RuntimeEventCategory.SOCKET_EGRESS) {
      const host = toSocketHost(event);
      if (host) {
        touchCounter(state.socketHosts, host, now);
      }
    }
  }

  getLearnedAllowlist(): ProcessContainmentAllowlist {
    if (!this.isEnabled() || this.config.mode === 'off') {
      return { ...EMPTY_ALLOWLIST };
    }

    return {
      readPatterns: collectQualifiedPatterns(this.state.reads, this.config.minOccurrences),
      processPatterns: collectQualifiedPatterns(this.state.processes, this.config.minOccurrences),
      socketHosts: collectQualifiedPatterns(this.state.socketHosts, this.config.minOccurrences),
      socketHostPatterns: [],
      socketPathPatterns: [],
    };
  }

  getSnapshot(): CompatibilityBaselineSnapshot {
    return {
      mode: this.config.mode,
      enabled: this.isEnabled(),
      persistencePath: this.filePath,
      observations: this.state.observations,
      updatedAt: this.state.updatedAt,
      minOccurrences: this.config.minOccurrences,
      autoApplyToContainment: this.config.autoApplyToContainment,
      reduceRiskFromKnownActivity: this.config.reduceRiskFromKnownActivity,
      learnedAllowlist: this.getLearnedAllowlist(),
      candidates: {
        reads: sortEntries(this.state.reads).map(([pattern, counter]) => ({
          pattern,
          count: counter.count,
          lastSeenAt: counter.lastSeenAt,
        })),
        processes: sortEntries(this.state.processes).map(([pattern, counter]) => ({
          pattern,
          count: counter.count,
          lastSeenAt: counter.lastSeenAt,
        })),
        socketHosts: sortEntries(this.state.socketHosts).map(([host, counter]) => ({
          host,
          count: counter.count,
          lastSeenAt: counter.lastSeenAt,
        })),
      },
    };
  }

  shouldAutoApplyToContainment(): boolean {
    return this.isEnabled() && this.config.mode === 'assist' && this.config.autoApplyToContainment;
  }

  shouldReduceRiskFromKnownActivity(): boolean {
    return this.isEnabled() && this.config.reduceRiskFromKnownActivity;
  }

  matchesLearnedAllowlist(event: RuntimeEvent): boolean {
    if (!this.shouldReduceRiskFromKnownActivity()) {
      return false;
    }

    const learned = this.getLearnedAllowlist();

    if (event.category === RuntimeEventCategory.FILE_READ) {
      const pattern = toReadPattern(this.rootDir, event.resource);
      return Boolean(pattern && learned.readPatterns?.includes(pattern));
    }

    if (event.category === RuntimeEventCategory.PROCESS_SPAWN) {
      const pattern = toProcessPattern(event.resource);
      return Boolean(pattern && learned.processPatterns?.includes(pattern));
    }

    if (event.category === RuntimeEventCategory.SOCKET_EGRESS) {
      const host = toSocketHost(event);
      return Boolean(host && learned.socketHosts?.includes(host));
    }

    return false;
  }

  async persist(): Promise<void> {
    if (!this.isEnabled()) {
      return;
    }

    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(this.filePath, JSON.stringify(this.state, null, 2), 'utf-8');
  }

  private isEnabled(): boolean {
    return this.config.enabled && this.config.mode !== 'off';
  }
}

function createEmptyState(): StoredRuntimeBaseline {
  return {
    version: '0.1.0',
    updatedAt: new Date(0).toISOString(),
    observations: 0,
    reads: {},
    processes: {},
    socketHosts: {},
  };
}

function normalizeBaselineConfig(config: CompatibilityBaselineConfig): Required<CompatibilityBaselineConfig> {
  return {
    enabled: config.enabled ?? true,
    mode: config.mode ?? 'assist',
    persistencePath: config.persistencePath ?? '.resimantle/runtime-baseline.json',
    minOccurrences: config.minOccurrences ?? 3,
    autoApplyToContainment: config.autoApplyToContainment ?? true,
    reduceRiskFromKnownActivity: config.reduceRiskFromKnownActivity ?? true,
  };
}

function normalizeStoredBaseline(value: Partial<StoredRuntimeBaseline>): StoredRuntimeBaseline {
  return {
    version: '0.1.0',
    updatedAt: typeof value.updatedAt === 'string' ? value.updatedAt : new Date(0).toISOString(),
    observations: typeof value.observations === 'number' ? value.observations : 0,
    reads: normalizeCounterMap(value.reads),
    processes: normalizeCounterMap(value.processes),
    socketHosts: normalizeCounterMap(value.socketHosts),
  };
}

function normalizeCounterMap(value: unknown): Record<string, BaselineCounter> {
  if (!value || typeof value !== 'object') {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .filter(([, counter]) => typeof counter === 'object' && counter !== null)
      .map(([key, counter]) => {
        const entry = counter as Record<string, unknown>;
        return [key, {
          count: typeof entry.count === 'number' ? entry.count : 0,
          lastSeenAt: typeof entry.lastSeenAt === 'string' ? entry.lastSeenAt : new Date(0).toISOString(),
        } satisfies BaselineCounter];
      }),
  );
}

function shouldLearnEvent(event: RuntimeEvent, context: ObserveContext): boolean {
  if (event.blocked || context.integrityStatus === 'drifted' || context.posture === 'restricted' || context.posture === 'sealed') {
    return false;
  }

  if (event.category === RuntimeEventCategory.PROCESS_SPAWN && event.details['isDangerous'] === true) {
    return false;
  }

  return event.category === RuntimeEventCategory.FILE_READ
    || event.category === RuntimeEventCategory.PROCESS_SPAWN
    || event.category === RuntimeEventCategory.SOCKET_EGRESS;
}

function touchCounter(target: Record<string, BaselineCounter>, key: string, now: string): void {
  const current = target[key];
  if (!current) {
    target[key] = { count: 1, lastSeenAt: now };
    return;
  }

  current.count += 1;
  current.lastSeenAt = now;
}

function collectQualifiedPatterns(target: Record<string, BaselineCounter>, minOccurrences: number): string[] {
  return sortEntries(target)
    .filter(([, counter]) => counter.count >= minOccurrences)
    .map(([key]) => key);
}

function sortEntries(target: Record<string, BaselineCounter>): Array<[string, BaselineCounter]> {
  return Object.entries(target).sort((left, right) => right[1].count - left[1].count);
}

function toReadPattern(rootDir: string, resource: string): string | undefined {
  const normalized = resource.trim();
  if (!normalized) {
    return undefined;
  }

  const relativePath = isAbsolute(normalized) ? relative(rootDir, normalized) : normalized;
  const candidate = normalizeSeparators(relativePath.startsWith('..') ? basename(normalized) : relativePath);
  if (!candidate || candidate.startsWith('..')) {
    return undefined;
  }

  return `(^|.*[\\/])${escapeRegExp(candidate).replace(/\//g, '[\\/]')}$`;
}

function toProcessPattern(command: string): string | undefined {
  const normalized = command.trim().replace(/\s+/g, ' ');
  return normalized ? `^${escapeRegExp(normalized)}$` : undefined;
}

function toSocketHost(event: RuntimeEvent): string | undefined {
  const host = typeof event.details['host'] === 'string'
    ? event.details['host']
    : event.resource.split(':')[0];
  const normalized = host?.trim().toLowerCase();
  if (!normalized || normalized === 'localhost' || normalized === '127.0.0.1' || normalized === '::1') {
    return undefined;
  }

  return normalized;
}

function normalizeSeparators(value: string): string {
  return value.replace(/\\/g, '/');
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}