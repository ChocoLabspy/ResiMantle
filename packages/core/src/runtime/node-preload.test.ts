import { createRequire } from 'node:module';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { COMMON_CONSTANTS } from '../common/constants';
import { ResiMantleEngine } from '../engine';
import type { ResiMantleConfig } from '../config/schema';
import { CompatibilityBaselineManager, RuntimeEventCategory, type RuntimeEvent } from '../layers/runtime-monitor';
import { MantleSidecarServer } from './mantle-sidecar';
import {
  flushNodePreloadHeartbeatForTest,
  getInstalledNodePreloadStateForTest,
  installNodePreload,
  uninstallNodePreload,
} from './node-preload';

const require = createRequire(import.meta.url);

afterEach(() => {
  uninstallNodePreload();
});

function createConfig(scanPaths: string[], containmentMode: 'off' | 'adaptive' | 'strict' = 'strict'): ResiMantleConfig {
  return {
    version: '0.1.0',
    layers: {
      surfaceCoat: {
        enabled: true,
        scanPaths,
        ignorePatterns: [],
      },
      aiDefense: {
        enabled: true,
        proxyMode: false,
      },
      runtimeMonitor: {
        enabled: true,
        sampleRate: 1,
        control: {
          autoPosture: true,
          sessionTtlMs: 15 * 60_000,
          heartbeatGraceMs: 45_000,
          capabilityQuarantine: true,
        },
        containment: {
          mode: containmentMode,
          allow: {
            readPatterns: [],
            processPatterns: [],
            socketHosts: [],
            socketHostPatterns: [],
            socketPathPatterns: [],
          },
        },
        baseline: {
          enabled: true,
          mode: 'assist',
          persistencePath: '.resimantle/runtime-baseline.json',
          minOccurrences: 3,
          autoApplyToContainment: true,
          reduceRiskFromKnownActivity: true,
        },
      },
    },
    policy: {
      path: './.resimantle/policy.json',
    },
  };
}

describe('node-preload', () => {
  it('patches and restores the Node fs and fetch surfaces cleanly', () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');
    const childProcessModule = require('node:child_process') as typeof import('node:child_process');
    const originalReadFile = fsModule.readFile;
    const originalPromiseReadFile = fsModule.promises.readFile;
    const originalReadFileSync = fsModule.readFileSync;
    const originalCreateReadStream = fsModule.createReadStream;
    const originalNetConnect = netModule.connect;
    const originalSpawn = childProcessModule.spawn;
    const originalSpawnSync = childProcessModule.spawnSync;
    const originalFetch = globalThis.fetch;

    const installed = installNodePreload({
      sidecarUrl: 'http://127.0.0.1:7563',
      sessionId: 'node-preload-session',
      actorId: 'node-preload-agent',
    });

    expect(installed).toBe(true);
    expect(Reflect.get(globalThis as Record<string, unknown>, '__resimantleNodePreloadState')).toBeUndefined();
    expect(fsModule.readFile).not.toBe(originalReadFile);
    expect(fsModule.promises.readFile).not.toBe(originalPromiseReadFile);
    expect(fsModule.readFileSync).not.toBe(originalReadFileSync);
    expect(fsModule.createReadStream).not.toBe(originalCreateReadStream);
    expect(netModule.connect).not.toBe(originalNetConnect);
    expect(childProcessModule.spawn).not.toBe(originalSpawn);
    expect(childProcessModule.spawnSync).not.toBe(originalSpawnSync);
    if (originalFetch) {
      expect(globalThis.fetch).not.toBe(originalFetch);
    }

    uninstallNodePreload();

    expect(fsModule.readFile).toBe(originalReadFile);
    expect(fsModule.promises.readFile).toBe(originalPromiseReadFile);
    expect(fsModule.readFileSync).toBe(originalReadFileSync);
    expect(fsModule.createReadStream).toBe(originalCreateReadStream);
    expect(netModule.connect).toBe(originalNetConnect);
    expect(childProcessModule.spawn).toBe(originalSpawn);
    expect(childProcessModule.spawnSync).toBe(originalSpawnSync);
    expect(globalThis.fetch).toBe(originalFetch);
  });

  it('blocks sensitive sync reads and direct raw socket egress only in strict mode', () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');

    const installed = installNodePreload({
      sidecarUrl: 'http://127.0.0.1:7563',
      sessionId: 'node-preload-strict-session',
      actorId: 'node-preload-agent',
      containmentMode: 'strict',
    });

    expect(installed).toBe(true);
    expect(() => fsModule.readFileSync('.env', 'utf-8')).toThrow(/blocked synthetic read access/i);
    expect(() => netModule.connect({ host: 'example.com', port: 443 })).toThrow(/blocked direct socket egress/i);

    const socket = netModule.connect({ host: '127.0.0.1', port: 9 });
    socket.on('error', () => undefined);
    socket.destroy();
  });

  it('honors containment allowlists in strict mode for sensitive reads and socket targets', async () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');
    const tempRoot = await mkdtemp(join(tmpdir(), 'resimantle-node-preload-allow-'));
    const allowedSecretPath = join(tempRoot, 'manual-allowed-secret.txt');

    try {
      await writeFile(allowedSecretPath, 'allowlisted-secret', 'utf-8');

      const installed = installNodePreload({
        sidecarUrl: 'http://127.0.0.1:7563',
        sessionId: 'node-preload-allow-session',
        actorId: 'node-preload-agent',
        containmentMode: 'strict',
        containmentAllowlist: {
          readPatterns: ['manual-allowed-secret\\.txt$'],
          socketHosts: ['allowed.example.invalid'],
        },
      });

      expect(installed).toBe(true);
      expect(fsModule.readFileSync(allowedSecretPath, 'utf-8')).toBe('allowlisted-secret');

      const socket = netModule.connect({ host: 'allowed.example.invalid', port: 443 });
      const code = await new Promise<string>((resolve) => {
        socket.once('error', (error: NodeJS.ErrnoException) => {
          resolve(error.code ?? 'UNKNOWN');
        });
      });

      expect(code).toBeTruthy();
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it('redeems bootstrap access into a scoped control session and reports telemetry', async () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-node-preload-session-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'node-preload-session' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src']));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const adminToken = server.getAuthToken();

      const installed = installNodePreload({
        sidecarUrl: address.url,
        sidecarBootstrapKey: bootstrapKey,
        sessionId: 'node-preload-session',
        actorId: 'node-preload-agent',
        containmentMode: 'strict',
      });

      expect(installed).toBe(true);
      expect(() => fsModule.readFileSync('.env', 'utf-8')).toThrow(/blocked synthetic read access/i);
      expect(() => netModule.connect({ host: 'example.com', port: 443 })).toThrow(/blocked direct socket egress/i);

      const readControlSnapshot = async (): Promise<{
        status: number;
        payload: {
          activeSessions: number;
          sessions: Array<{
            actorId: string;
            runtimeEvents: number;
            blockedRuntimeEvents: number;
            posture: string;
            integrityStatus: string;
            routeCounts: Record<string, number>;
            attestation: {
              heartbeatCount: number;
              driftCount: number;
              pid?: number;
            };
          }>;
        };
      }> => {
        const controlResponse = await fetch(`${address.url}/v1/control/sessions`, {
          headers: {
            'x-resimantle-sidecar-token': adminToken,
          },
        });

        return {
          status: controlResponse.status,
          payload: await controlResponse.json() as {
            activeSessions: number;
            sessions: Array<{
              actorId: string;
              runtimeEvents: number;
              blockedRuntimeEvents: number;
              posture: string;
              integrityStatus: string;
              routeCounts: Record<string, number>;
              attestation: {
                heartbeatCount: number;
                driftCount: number;
                pid?: number;
              };
            }>;
          },
        };
      };

      let controlSnapshot = await readControlSnapshot();
      for (let attempt = 0; attempt < 12 && (
        (controlSnapshot.payload.sessions[0]?.runtimeEvents ?? 0) < 2
        || (controlSnapshot.payload.sessions[0]?.attestation.heartbeatCount ?? 0) < 1
      ); attempt++) {
        await new Promise(resolve => setTimeout(resolve, 25));
        controlSnapshot = await readControlSnapshot();
      }

      const controlPayload = controlSnapshot.payload;
      const controlStatus = controlSnapshot.status;
      expect(controlStatus).toBe(200);
      expect(controlPayload.activeSessions).toBe(1);
      expect(controlPayload.sessions[0]?.actorId).toBe('node-preload-agent');
      expect(controlPayload.sessions[0]?.runtimeEvents).toBeGreaterThanOrEqual(2);
      expect(controlPayload.sessions[0]?.blockedRuntimeEvents).toBeGreaterThanOrEqual(2);
      expect(controlPayload.sessions[0]?.posture).toBe('restricted');
      expect(controlPayload.sessions[0]?.integrityStatus).toBe('healthy');
      expect(controlPayload.sessions[0]?.routeCounts['/v1/runtime-event']).toBeGreaterThanOrEqual(2);
      expect(controlPayload.sessions[0]?.routeCounts['/v1/session/heartbeat']).toBeGreaterThanOrEqual(1);
      expect(controlPayload.sessions[0]?.attestation.heartbeatCount).toBeGreaterThanOrEqual(1);
      expect(controlPayload.sessions[0]?.attestation.driftCount).toBe(0);
      expect(controlPayload.sessions[0]?.attestation.pid).toBe(process.pid);

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('applies capability-scoped socket quarantine without forcing sensitive reads into strict mode', async () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-node-preload-capability-'));
    const envPath = join(projectRoot, '.env');

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'node-preload-capability' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');
      await writeFile(envPath, 'dotenv-allowed-in-adaptive', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src'], 'adaptive'));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const sessionId = 'node-preload-capability-session';

      const sessionResponse = await fetch(`${address.url}/v1/bootstrap/session`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
        body: JSON.stringify({
          sessionId,
          actorId: 'node-preload-agent',
          runtime: 'node',
          pid: process.pid,
          ppid: process.ppid,
          cwd: process.cwd(),
          execPath: process.execPath,
          runtimeVersion: process.version,
          capabilities: ['fs.read', 'net.connect'],
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const sessionPayload = await sessionResponse.json() as { sessionToken: string };

      const installed = installNodePreload({
        sidecarUrl: address.url,
        sidecarToken: sessionPayload.sessionToken,
        sessionId,
        actorId: 'node-preload-agent',
        containmentMode: 'adaptive',
      });

      expect(installed).toBe(true);
      expect(fsModule.readFileSync(envPath, 'utf-8')).toBe('dotenv-allowed-in-adaptive');

      const runtimeEvent = (id: string) => fetch(`${address.url}/v1/runtime-event`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          event: {
            id,
            timestamp: new Date().toISOString(),
            category: 'SOCKET_EGRESS',
            actor: 'node-preload-agent',
            resource: 'example.com:443',
            blocked: true,
            details: {
              host: 'example.com',
              port: 443,
              source: 'test',
            },
          },
        }),
      });

      await runtimeEvent('socket-block-1');
      await runtimeEvent('socket-block-2');

      const heartbeatResponse = await fetch(`${address.url}/v1/session/heartbeat`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          pid: process.pid,
          ppid: process.ppid,
          cwd: process.cwd(),
          execPath: process.execPath,
          runtimeVersion: process.version,
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const heartbeatPayload = await heartbeatResponse.json() as {
        containment: {
          capabilityModes?: {
            reads?: string;
            sockets?: string;
          };
        };
      };

      expect(heartbeatPayload.containment.capabilityModes?.sockets).toBe('strict');
      expect(heartbeatPayload.containment.capabilityModes?.reads).toBe('adaptive');
      await flushNodePreloadHeartbeatForTest();

      const preloadState = getInstalledNodePreloadStateForTest();
      expect(preloadState?.containmentCapabilityModes.sockets).toBe('strict');
      expect(preloadState?.containmentCapabilityModes.reads).toBe('adaptive');
      expect(() => netModule.connect({ host: 'example.com', port: 443 })).toThrow(/blocked direct socket egress/i);
      expect(fsModule.readFileSync(envPath, 'utf-8')).toBe('dotenv-allowed-in-adaptive');

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('propagates inherited capability quarantine into child process env before child bootstrap', async () => {
    const childProcessModule = require('node:child_process') as typeof import('node:child_process');
    const originalSpawnSync = childProcessModule.spawnSync;
    let capturedEnv: NodeJS.ProcessEnv | undefined;

    (childProcessModule as typeof childProcessModule & { spawnSync: typeof childProcessModule.spawnSync }).spawnSync = ((command, args, options) => {
      capturedEnv = (options as { env?: NodeJS.ProcessEnv } | undefined)?.env;
      return {
        pid: 123,
        output: [null, Buffer.alloc(0), Buffer.alloc(0)],
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
        status: 0,
        signal: null,
      } as unknown as ReturnType<typeof childProcessModule.spawnSync>;
    }) as typeof childProcessModule.spawnSync;

    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-node-preload-childenv-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'node-preload-childenv' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src'], 'adaptive'));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();

      const installed = installNodePreload({
        sidecarUrl: address.url,
        sidecarBootstrapKey: bootstrapKey,
        sessionId: 'node-preload-childenv-session',
        actorId: 'node-preload-agent',
        containmentMode: 'adaptive',
      });

      expect(installed).toBe(true);
      expect(() => childProcessModule.spawnSync('powershell', ['-Command', 'Invoke-WebRequest https://example.com'])).toThrow(/risky child process pattern/i);
      expect(() => childProcessModule.spawnSync('powershell', ['-Command', 'Invoke-WebRequest https://example.com'])).toThrow(/risky child process pattern/i);

      for (let attempt = 0; attempt < 8; attempt++) {
        await flushNodePreloadHeartbeatForTest();
        if (getInstalledNodePreloadStateForTest()?.containmentCapabilityModes.processes === 'strict') {
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 25));
      }

      const preloadState = getInstalledNodePreloadStateForTest();
      expect(preloadState?.containmentMode).toBe('adaptive');
      expect(preloadState?.containmentCapabilityModes.processes).toBe('strict');
      expect(preloadState?.containmentCapabilityModes.reads).toBe('adaptive');

      capturedEnv = undefined;
      childProcessModule.spawnSync(process.execPath, ['-e', 'process.exit(0)'], {
        env: {
          EXTRA_FLAG: '1',
        } as NodeJS.ProcessEnv,
      });

      expect(capturedEnv?.['EXTRA_FLAG']).toBe('1');
      expect(capturedEnv?.[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV]).toBe('node-preload-childenv-session');
      expect(capturedEnv?.[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV]).toBeTruthy();
      expect(capturedEnv?.[COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV]).toBe('adaptive');
      expect(JSON.parse(capturedEnv?.[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV] ?? '{}')).toMatchObject({
        reads: 'adaptive',
        processes: 'strict',
      });

      await server.stop();
    } finally {
      uninstallNodePreload();
      (childProcessModule as typeof childProcessModule & { spawnSync: typeof childProcessModule.spawnSync }).spawnSync = originalSpawnSync;
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('prepares worker thread bootstrap metadata without leaking secrets through shared env', () => {
    const workerThreadsModule = require('node:worker_threads') as typeof import('node:worker_threads') & Record<string, unknown>;
    const originalWorker = workerThreadsModule.Worker as typeof import('node:worker_threads').Worker;
    const originalSetEnvironmentData = workerThreadsModule.setEnvironmentData as typeof import('node:worker_threads').setEnvironmentData;
    const capturedEnvironmentData: Array<{ key: string; value: unknown }> = [];
    let capturedFilename: string | URL | undefined;
    let capturedOptions: Record<string, unknown> | undefined;

    class FakeWorker {
      constructor(filename: string | URL, options?: Record<string, unknown>) {
        capturedFilename = filename;
        capturedOptions = options;
      }
    }

    try {
      (workerThreadsModule as typeof workerThreadsModule & { Worker: typeof originalWorker }).Worker = FakeWorker as unknown as typeof originalWorker;
      (workerThreadsModule as typeof workerThreadsModule & { setEnvironmentData: typeof originalSetEnvironmentData }).setEnvironmentData = ((key: unknown, value: unknown) => {
        capturedEnvironmentData.push({ key: String(key), value });
      }) as typeof originalSetEnvironmentData;

      const installed = installNodePreload({
        sidecarUrl: 'http://127.0.0.1:7563',
        sidecarBootstrapKey: 'bootstrap-secret',
        sessionId: 'worker-parent-session',
        actorId: 'node-preload-agent',
        containmentMode: 'adaptive',
        containmentCapabilityModes: {
          processes: 'strict',
        },
      });

      expect(installed).toBe(true);

      const worker = new (workerThreadsModule.Worker as unknown as typeof import('node:worker_threads').Worker)('worker-entry.js', {
        env: workerThreadsModule.SHARE_ENV,
        execArgv: ['--trace-warnings'],
        argv: ['--existing-arg'],
      });

      expect(worker).toBeInstanceOf(FakeWorker);
      expect(capturedFilename).toBe('worker-entry.js');
      expect(capturedOptions?.env).toBe(workerThreadsModule.SHARE_ENV);
      expect(capturedOptions?.execArgv).toEqual(expect.arrayContaining(['--trace-warnings', '--require', expect.any(String)]));
      expect(capturedOptions?.argv).toEqual(expect.arrayContaining(['--existing-arg']));

      const bootstrapArg = (capturedOptions?.argv as string[] | undefined)?.find(value => value.startsWith('--resimantle-worker-bootstrap='));
      expect(bootstrapArg).toBeTruthy();
      expect(capturedEnvironmentData).toHaveLength(2);
      expect(capturedEnvironmentData[0]?.key).toBe(bootstrapArg?.slice('--resimantle-worker-bootstrap='.length));
      expect(capturedEnvironmentData[0]?.value).toMatchObject({
        sidecarUrl: 'http://127.0.0.1:7563',
        sidecarBootstrapKey: 'bootstrap-secret',
        sessionId: 'worker-parent-session',
        parentSessionId: 'worker-parent-session',
        containmentMode: 'adaptive',
        containmentCapabilityModes: {
          reads: 'adaptive',
          processes: 'strict',
          sockets: 'adaptive',
        },
      });
      expect(capturedEnvironmentData[1]).toEqual({
        key: capturedEnvironmentData[0]?.key ?? '',
        value: undefined,
      });
    } finally {
      uninstallNodePreload();
      (workerThreadsModule as typeof workerThreadsModule & { Worker: typeof originalWorker }).Worker = originalWorker;
      (workerThreadsModule as typeof workerThreadsModule & { setEnvironmentData: typeof originalSetEnvironmentData }).setEnvironmentData = originalSetEnvironmentData;
    }
  });

  it('hydrates inherited worker bootstrap containment before sidecar bootstrap runs', () => {
    const workerThreadsModule = require('node:worker_threads') as typeof import('node:worker_threads') & Record<string, unknown>;
    const originalGetEnvironmentData = workerThreadsModule.getEnvironmentData as typeof import('node:worker_threads').getEnvironmentData;
    const argvMarker = '--resimantle-worker-bootstrap=worker-bootstrap-id';
    const previousArgv = [...process.argv];
    const previousEnv = {
      active: process.env[COMMON_CONSTANTS.ACTIVE_ENV],
      auto: process.env[COMMON_CONSTANTS.MANTLE_AUTO_ENV],
      sessionId: process.env[COMMON_CONSTANTS.SESSION_ID_ENV],
      parentSessionId: process.env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV],
      parentControlSessionId: process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV],
      sidecarUrl: process.env[COMMON_CONSTANTS.SIDECAR_URL_ENV],
      containment: process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV],
      allowlist: process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV],
      capabilityModes: process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV],
    };

    try {
      process.argv.push(argvMarker);
      (workerThreadsModule as typeof workerThreadsModule & { getEnvironmentData: typeof originalGetEnvironmentData }).getEnvironmentData = ((key: unknown) => {
        if (key !== 'worker-bootstrap-id') {
          return undefined;
        }

        return {
          sidecarUrl: 'http://127.0.0.1:7563',
          sidecarBootstrapKey: 'worker-bootstrap-secret',
          sessionId: 'worker-child-session',
          actorId: 'worker-agent',
          containmentMode: 'adaptive',
          containmentAllowlist: {
            readPatterns: ['safe-worker-file\\.txt$'],
          },
          containmentCapabilityModes: {
            reads: 'adaptive',
            processes: 'strict',
            sockets: 'adaptive',
          },
          parentSessionId: 'worker-parent-session',
          parentControlSessionId: 'ctrl-parent-session',
        };
      }) as typeof originalGetEnvironmentData;

      const installed = installNodePreload();

      expect(installed).toBe(true);
      expect(process.argv).not.toContain(argvMarker);
      expect(process.env[COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV]).toBeUndefined();
      expect(process.env[COMMON_CONSTANTS.ACTIVE_ENV]).toBe('1');
      expect(process.env[COMMON_CONSTANTS.MANTLE_AUTO_ENV]).toBe('1');
      expect(process.env[COMMON_CONSTANTS.SESSION_ID_ENV]).toBe('worker-child-session');
      expect(process.env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV]).toBe('worker-parent-session');
      expect(process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV]).toBe('ctrl-parent-session');

      const preloadState = getInstalledNodePreloadStateForTest();
      expect(preloadState?.containmentMode).toBe('adaptive');
      expect(preloadState?.containmentCapabilityModes.processes).toBe('strict');
      expect(preloadState?.containmentAllowlist.readPatterns).toContain('safe-worker-file\\.txt$');
    } finally {
      uninstallNodePreload();
      (workerThreadsModule as typeof workerThreadsModule & { getEnvironmentData: typeof originalGetEnvironmentData }).getEnvironmentData = originalGetEnvironmentData;
      process.argv.splice(0, process.argv.length, ...previousArgv);

      restoreEnv(COMMON_CONSTANTS.ACTIVE_ENV, previousEnv.active);
      restoreEnv(COMMON_CONSTANTS.MANTLE_AUTO_ENV, previousEnv.auto);
      restoreEnv(COMMON_CONSTANTS.SESSION_ID_ENV, previousEnv.sessionId);
      restoreEnv(COMMON_CONSTANTS.PARENT_SESSION_ID_ENV, previousEnv.parentSessionId);
      restoreEnv(COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV, previousEnv.parentControlSessionId);
      restoreEnv(COMMON_CONSTANTS.SIDECAR_URL_ENV, previousEnv.sidecarUrl);
      restoreEnv(COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV, previousEnv.containment);
      restoreEnv(COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV, previousEnv.allowlist);
      restoreEnv(COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV, previousEnv.capabilityModes);
    }
  });

  it('applies learned baseline containment from the sidecar to live preload enforcement', async () => {
    const fsModule = require('node:fs') as typeof import('node:fs');
    const netModule = require('node:net') as typeof import('node:net');
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-node-preload-baseline-'));
    const safeDir = join(projectRoot, 'safe');
    const baselineSecretPath = join(safeDir, 'manual-baseline-secret.txt');

    try {
      await mkdir(join(projectRoot, '.resimantle'));
      await mkdir(safeDir);
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'node-preload-baseline' }, null, 2));
      await writeFile(baselineSecretPath, 'baseline-allowed', 'utf-8');

      const baselineManager = new CompatibilityBaselineManager(projectRoot, {
        enabled: true,
        mode: 'assist',
        persistencePath: '.resimantle/runtime-baseline.json',
        minOccurrences: 3,
        autoApplyToContainment: true,
      });
      await baselineManager.initialize();

      const readEvent = (id: string): RuntimeEvent => ({
        id,
        timestamp: new Date().toISOString(),
        category: RuntimeEventCategory.FILE_READ,
        actor: 'baseline-seeder',
        resource: baselineSecretPath,
        details: {
          method: 'readFileSync',
        },
      });
      const socketEvent = (id: string): RuntimeEvent => ({
        id,
        timestamp: new Date().toISOString(),
        category: RuntimeEventCategory.SOCKET_EGRESS,
        actor: 'baseline-seeder',
        resource: 'baseline.example.invalid:443',
        details: {
          host: 'baseline.example.invalid',
          port: 443,
        },
      });

      baselineManager.observe(readEvent('baseline-read-1'), { posture: 'normal', integrityStatus: 'healthy' });
      baselineManager.observe(readEvent('baseline-read-2'), { posture: 'normal', integrityStatus: 'healthy' });
      baselineManager.observe(readEvent('baseline-read-3'), { posture: 'normal', integrityStatus: 'healthy' });
      baselineManager.observe(socketEvent('baseline-socket-1'), { posture: 'normal', integrityStatus: 'healthy' });
      baselineManager.observe(socketEvent('baseline-socket-2'), { posture: 'normal', integrityStatus: 'healthy' });
      baselineManager.observe(socketEvent('baseline-socket-3'), { posture: 'normal', integrityStatus: 'healthy' });
      await baselineManager.persist();

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['safe']));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const adminToken = server.getAuthToken();

      const installed = installNodePreload({
        sidecarUrl: address.url,
        sidecarBootstrapKey: bootstrapKey,
        sessionId: 'node-preload-baseline-session',
        actorId: 'node-preload-agent',
        containmentMode: 'strict',
      });

      expect(installed).toBe(true);

      const waitForBaselineSession = async (): Promise<void> => {
        for (let attempt = 0; attempt < 12; attempt++) {
          const response = await fetch(`${address.url}/v1/control/sessions`, {
            headers: {
              'x-resimantle-sidecar-token': adminToken,
            },
          });
          const payload = await response.json() as {
            activeSessions: number;
            baseline: {
              learnedAllowlist: {
                readPatterns?: string[];
                socketHosts?: string[];
              };
            };
            sessions: Array<{
              attestation: {
                heartbeatCount: number;
              };
            }>;
          };

          const hasSession = payload.activeSessions > 0;
          const hasHeartbeat = (payload.sessions[0]?.attestation.heartbeatCount ?? 0) > 0;
          const hasLearnedRule = payload.baseline.learnedAllowlist.readPatterns?.includes('(^|.*[\\/])safe[\\/]manual-baseline-secret\\.txt$');
          const localAllowlist = getInstalledNodePreloadStateForTest()?.containmentAllowlist;
          const preloadUpdated = localAllowlist?.readPatterns?.includes('(^|.*[\\/])safe[\\/]manual-baseline-secret\\.txt$');
          if (hasSession && hasHeartbeat && hasLearnedRule && preloadUpdated) {
            return;
          }

          await new Promise(resolve => setTimeout(resolve, 25));
        }

        throw new Error('Timed out waiting for baseline-backed preload session');
      };

      await waitForBaselineSession();

      let baselineRead: string | undefined;
      for (let attempt = 0; attempt < 8; attempt++) {
        try {
          baselineRead = fsModule.readFileSync(baselineSecretPath, 'utf-8');
          break;
        } catch {
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      }

      expect(baselineRead).toBe('baseline-allowed');

      const socket = netModule.connect({ host: 'baseline.example.invalid', port: 443 });
      const code = await new Promise<string>((resolve) => {
        socket.once('error', (error: NodeJS.ErrnoException) => {
          resolve(error.code ?? 'UNKNOWN');
        });
      });

      expect(code).toBeTruthy();

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }

  process.env[name] = value;
}