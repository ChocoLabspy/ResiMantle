import { randomUUID } from 'node:crypto';
import type { RuntimeEvent } from '../types';
import { RuntimeEventCategory } from '../types';

type EventCallback = (event: RuntimeEvent) => void;

/**
 * Dangerous commands that should always be flagged.
 */
const DANGEROUS_COMMANDS = [
  'rm -rf', 'del /f', 'format', 'shutdown', 'reboot',
  'curl', 'wget', 'nc', 'netcat', 'nmap', 'telnet',
  'chmod 777', 'mkfs', 'dd if=',
  'powershell', 'cmd /c',
];

/**
 * The ProcessCollector intercepts child process spawning.
 * It wraps `child_process.spawn`, `exec`, `execSync`, `execFile`,
 * and `fork` to detect when the application creates subprocesses.
 *
 * This is critical for detecting:
 * - Reverse shells
 * - Unauthorized command execution by AI agents
 * - Data exfiltration via curl/wget
 * - Destructive commands (rm -rf, format)
 */
export class ProcessCollector {
  private onEvent: EventCallback;
  private originals: Map<string, Function> = new Map();
  private active = false;

  constructor(onEvent: EventCallback) {
    this.onEvent = onEvent;
  }

  /**
   * Activates process spawn interception.
   */
  async activate(): Promise<void> {
    if (this.active) return;

    const cp = await import('node:child_process');
    const self = this;

    // Wrap spawn
    const originalSpawn = cp.spawn;
    this.originals.set('spawn', originalSpawn);
    (cp as any).spawn = function (command: string, args?: string[], options?: any) {
      self.emitProcessEvent(command, args || [], 'spawn');
      return originalSpawn.call(cp, command, args as any, options);
    };

    // Wrap exec
    const originalExec = cp.exec;
    this.originals.set('exec', originalExec);
    (cp as any).exec = function (command: string, ...rest: unknown[]) {
      self.emitProcessEvent(command, [], 'exec');
      return (originalExec as Function).call(cp, command, ...rest);
    };

    // Wrap execSync
    const originalExecSync = cp.execSync;
    this.originals.set('execSync', originalExecSync);
    (cp as any).execSync = function (command: string, options?: any) {
      self.emitProcessEvent(command, [], 'execSync');
      return originalExecSync.call(cp, command, options);
    };

    // Wrap execFile
    const originalExecFile = cp.execFile;
    this.originals.set('execFile', originalExecFile);
    (cp as any).execFile = function (file: string, args?: string[], ...rest: unknown[]) {
      self.emitProcessEvent(file, args || [], 'execFile');
      return (originalExecFile as Function).call(cp, file, args, ...rest);
    };

    // Wrap fork
    const originalFork = cp.fork;
    this.originals.set('fork', originalFork);
    (cp as any).fork = function (modulePath: string, args?: string[], options?: any) {
      self.emitProcessEvent(modulePath, args || [], 'fork');
      return originalFork.call(cp, modulePath, args, options);
    };

    this.active = true;
  }

  /**
   * Restores original child_process methods.
   */
  async deactivate(): Promise<void> {
    if (!this.active) return;

    const cp = await import('node:child_process');

    for (const [method, original] of this.originals) {
      (cp as any)[method] = original;
    }
    this.originals.clear();
    this.active = false;
  }

  private emitProcessEvent(command: string, args: string[], method: string): void {
    const fullCommand = args.length > 0 ? `${command} ${args.join(' ')}` : command;
    const isDangerous = this.isDangerousCommand(fullCommand);

    const event: RuntimeEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      category: RuntimeEventCategory.PROCESS_SPAWN,
      actor: this.getCallerInfo(),
      resource: fullCommand,
      details: {
        command,
        args,
        method,
        isDangerous,
        dangerousMatches: isDangerous ? this.getDangerousMatches(fullCommand) : [],
      },
      blocked: false,
    };

    this.onEvent(event);
  }

  private isDangerousCommand(cmd: string): boolean {
    const lower = cmd.toLowerCase();
    return DANGEROUS_COMMANDS.some(d => lower.includes(d.toLowerCase()));
  }

  private getDangerousMatches(cmd: string): string[] {
    const lower = cmd.toLowerCase();
    return DANGEROUS_COMMANDS.filter(d => lower.includes(d.toLowerCase()));
  }

  private getCallerInfo(): string {
    const stack = new Error().stack;
    if (!stack) return 'unknown';

    const lines = stack.split('\n');
    for (const line of lines.slice(3)) {
      if (line.includes('node_modules') || line.includes('node:internal') || line.includes('node:child_process')) continue;
      const match = line.match(/at\s+(?:(.+?)\s+\()?(.+?):(\d+):\d+\)?/);
      if (match) {
        return match[2] || match[1] || 'unknown';
      }
    }
    return 'unknown';
  }
}
