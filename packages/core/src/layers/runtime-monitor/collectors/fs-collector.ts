import { randomUUID } from 'node:crypto';
import type { RuntimeEvent } from '../types';
import { RuntimeEventCategory } from '../types';

type EventCallback = (event: RuntimeEvent) => void;

/**
 * Methods from fs/promises that we intercept.
 */
const READ_METHODS = ['readFile', 'readdir', 'stat', 'lstat', 'access', 'realpath'] as const;
const WRITE_METHODS = ['writeFile', 'appendFile', 'mkdir', 'copyFile', 'rename', 'chmod', 'chown'] as const;
const DELETE_METHODS = ['unlink', 'rmdir', 'rm'] as const;

/**
 * The FsCollector intercepts filesystem operations made through `fs/promises`.
 * It wraps the most common read/write/delete methods to capture what files
 * are being accessed, by whom, and how long each operation takes.
 *
 * This collector is critical for detecting:
 * - Unauthorized file access (e.g., reading /etc/passwd)
 * - Unexpected writes to sensitive directories
 * - File deletions that could indicate sabotage
 */
export class FsCollector {
  private onEvent: EventCallback;
  private originals: Map<string, Function> = new Map();
  private active = false;
  private ignorePatterns: RegExp[];

  constructor(onEvent: EventCallback, ignorePatterns: string[] = []) {
    this.onEvent = onEvent;
    this.ignorePatterns = ignorePatterns.map(p => new RegExp(p));
  }

  /**
   * Activates filesystem interception by wrapping fs/promises methods.
   */
  async activate(): Promise<void> {
    if (this.active) return;

    const fsPromises = await import('node:fs/promises');
    const self = this;

    // Wrap read methods
    for (const method of READ_METHODS) {
      const original = (fsPromises as any)[method];
      if (typeof original !== 'function') continue;
      this.originals.set(`read:${method}`, original);

      (fsPromises as any)[method] = async function (...args: unknown[]) {
        const filePath = String(args[0] || '');
        if (self.shouldIgnore(filePath)) {
          return original.apply(fsPromises, args);
        }

        const startTime = Date.now();
        try {
          const result = await original.apply(fsPromises, args);
          self.emitEvent(RuntimeEventCategory.FILE_READ, filePath, method, Date.now() - startTime);
          return result;
        } catch (error) {
          self.emitEvent(RuntimeEventCategory.FILE_READ, filePath, method, Date.now() - startTime, (error as Error).message);
          throw error;
        }
      };
    }

    // Wrap write methods
    for (const method of WRITE_METHODS) {
      const original = (fsPromises as any)[method];
      if (typeof original !== 'function') continue;
      this.originals.set(`write:${method}`, original);

      (fsPromises as any)[method] = async function (...args: unknown[]) {
        const filePath = String(args[0] || '');
        if (self.shouldIgnore(filePath)) {
          return original.apply(fsPromises, args);
        }

        const startTime = Date.now();
        try {
          const result = await original.apply(fsPromises, args);
          self.emitEvent(RuntimeEventCategory.FILE_WRITE, filePath, method, Date.now() - startTime);
          return result;
        } catch (error) {
          self.emitEvent(RuntimeEventCategory.FILE_WRITE, filePath, method, Date.now() - startTime, (error as Error).message);
          throw error;
        }
      };
    }

    // Wrap delete methods
    for (const method of DELETE_METHODS) {
      const original = (fsPromises as any)[method];
      if (typeof original !== 'function') continue;
      this.originals.set(`delete:${method}`, original);

      (fsPromises as any)[method] = async function (...args: unknown[]) {
        const filePath = String(args[0] || '');
        if (self.shouldIgnore(filePath)) {
          return original.apply(fsPromises, args);
        }

        const startTime = Date.now();
        try {
          const result = await original.apply(fsPromises, args);
          self.emitEvent(RuntimeEventCategory.FILE_DELETE, filePath, method, Date.now() - startTime);
          return result;
        } catch (error) {
          self.emitEvent(RuntimeEventCategory.FILE_DELETE, filePath, method, Date.now() - startTime, (error as Error).message);
          throw error;
        }
      };
    }

    this.active = true;
  }

  /**
   * Restores all original fs/promises methods.
   */
  async deactivate(): Promise<void> {
    if (!this.active) return;

    const fsPromises = await import('node:fs/promises');

    for (const [key, original] of this.originals) {
      const method = key.split(':')[1]!;
      (fsPromises as any)[method] = original;
    }
    this.originals.clear();
    this.active = false;
  }

  private emitEvent(
    category: RuntimeEventCategory,
    filePath: string,
    method: string,
    durationMs: number,
    error?: string,
  ): void {
    const event: RuntimeEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      category,
      actor: this.getCallerInfo(),
      resource: filePath,
      details: {
        method,
        error,
      },
      blocked: false,
      durationMs,
    };
    this.onEvent(event);
  }

  private getCallerInfo(): string {
    const stack = new Error().stack;
    if (!stack) return 'unknown';

    const lines = stack.split('\n');
    for (const line of lines.slice(3)) {
      if (line.includes('node_modules') || line.includes('node:internal') || line.includes('node:fs')) continue;
      const match = line.match(/at\s+(?:(.+?)\s+\()?(.+?):(\d+):\d+\)?/);
      if (match) {
        return match[2] || match[1] || 'unknown';
      }
    }
    return 'unknown';
  }

  private shouldIgnore(filePath: string): boolean {
    return this.ignorePatterns.some(p => p.test(filePath));
  }
}
