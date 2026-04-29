import { createHash, randomUUID } from 'node:crypto';
import * as fsPromises from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { PassThrough } from 'node:stream';
import { basename } from 'node:path';
import { normalizeContainmentAllowlist, serializeContainmentAllowlist } from '../common/containment';
import { COMMON_CONSTANTS } from '../common/constants';
import type {
  ProcessContainmentAllowlist,
  ProcessContainmentCapabilityModes,
  ProcessContainmentMode,
} from '../common/types';

const require = createRequire(typeof __filename === 'string' ? __filename : `${process.cwd()}/node-preload.js`);
const mutableFs = require('node:fs') as typeof import('node:fs') & Record<string, unknown>;
const mutableFsPromises = require('node:fs/promises') as typeof import('node:fs/promises') & Record<string, unknown>;
const mutableHttp = require('node:http') as typeof import('node:http') & Record<string, unknown>;
const mutableHttps = require('node:https') as typeof import('node:https') & Record<string, unknown>;
const mutableNet = require('node:net') as typeof import('node:net') & Record<string, unknown>;
const mutableTls = require('node:tls') as typeof import('node:tls') & Record<string, unknown>;
const mutableChildProcess = require('node:child_process') as typeof import('node:child_process') & Record<string, unknown>;
const mutableWorkerThreads = require('node:worker_threads') as typeof import('node:worker_threads') & Record<string, unknown>;

type NativeFetch = typeof globalThis.fetch;
type AnyFunction = (...args: any[]) => any;
type FsReadFileCallback = (error: NodeJS.ErrnoException | null, data?: string | Buffer) => void;

interface ReadResolutionPayload {
  source: 'synthetic' | 'real' | 'mixed' | 'blocked' | 'none';
  content?: string;
}

interface HttpResolutionPayload {
  source: 'synthetic' | 'real' | 'mixed' | 'blocked' | 'none';
  response?: {
    statusCode: number;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
}

interface SocketEndpoint {
  host?: string;
  port?: number;
  path?: string;
  label: string;
}

interface CompiledContainmentAllowlist {
  readPatterns: RegExp[];
  processPatterns: RegExp[];
  socketHosts: Set<string>;
  socketHostPatterns: RegExp[];
  socketPathPatterns: RegExp[];
}

interface BootstrapSessionPayload {
  sessionToken: string;
  sessionId?: string;
  controlSessionId?: string;
  posture?: string;
  integrityStatus?: string;
  containment?: {
    mode?: ProcessContainmentMode;
    allowlist?: ProcessContainmentAllowlist;
    capabilityModes?: ProcessContainmentCapabilityModes;
  };
  tokenExpiresAt?: string;
}

interface SessionHeartbeatPayload {
  accepted: boolean;
  posture?: string;
  integrityStatus?: string;
  riskScore?: number;
  containment?: {
    mode?: ProcessContainmentMode;
    allowlist?: ProcessContainmentAllowlist;
    capabilityModes?: ProcessContainmentCapabilityModes;
  };
  tokenExpiresAt?: string;
}

interface SidecarAuthHeader {
  name: string;
  value: string;
}

interface SidecarRequestError extends Error {
  statusCode?: number;
}

interface NodePreloadInstallOptions {
  sidecarUrl?: string;
  sidecarToken?: string;
  sidecarBootstrapKey?: string;
  sessionId?: string;
  actorId?: string;
  containmentMode?: ProcessContainmentMode;
  containmentAllowlist?: ProcessContainmentAllowlist;
  containmentCapabilityModes?: ProcessContainmentCapabilityModes;
}

interface PendingRequestAction {
  type: 'write' | 'end';
  args: unknown[];
}

interface HttpRequestProxy extends EventEmitter {
  aborted?: boolean;
  destroyed?: boolean;
  write: (...args: unknown[]) => boolean;
  end: (...args: unknown[]) => HttpRequestProxy;
  abort: () => void;
  destroy: (error?: Error) => void;
  setHeader: (name: string, value: string | number | readonly string[]) => void;
  getHeader: (name: string) => unknown;
  getHeaders: () => Record<string, unknown>;
  removeHeader: (name: string) => void;
  setTimeout: (timeout: number, callback?: () => void) => HttpRequestProxy;
}

interface NodePreloadState {
  sidecarUrl: string;
  sidecarToken?: string;
  sidecarTokenExpiresAt?: string;
  sidecarBootstrapKey?: string;
  controlSessionId?: string;
  bootstrapExchangePromise?: Promise<void>;
  heartbeatTimer?: ReturnType<typeof setInterval>;
  sessionId: string;
  actorId?: string;
  containmentMode: ProcessContainmentMode;
  containmentAllowlist: ProcessContainmentAllowlist;
  containmentCapabilityModes: Required<ProcessContainmentCapabilityModes>;
  compiledContainmentAllowlist: CompiledContainmentAllowlist;
  preloadPath: string;
  originalPromiseReadFile: AnyFunction;
  originalFsPromisesReadFile: AnyFunction;
  originalFsReadFile: AnyFunction;
  originalFsReadFileSync: AnyFunction;
  originalFsCreateReadStream: AnyFunction;
  originalFetch?: NativeFetch;
  originalHttpRequest: AnyFunction;
  originalHttpGet: AnyFunction;
  originalHttpsRequest: AnyFunction;
  originalHttpsGet: AnyFunction;
  originalNetConnect: AnyFunction;
  originalNetCreateConnection: AnyFunction;
  originalTlsConnect: AnyFunction;
  originalSpawn: AnyFunction;
  originalSpawnSync: AnyFunction;
  originalExec: AnyFunction;
  originalExecSync: AnyFunction;
  originalExecFile: AnyFunction;
  originalExecFileSync: AnyFunction;
  originalFork: AnyFunction;
  originalWorker?: typeof import('node:worker_threads').Worker;
}

interface WorkerBootstrapPayload {
  sidecarUrl: string;
  sidecarBootstrapKey?: string;
  sessionId: string;
  actorId?: string;
  containmentMode: ProcessContainmentMode;
  containmentAllowlist: ProcessContainmentAllowlist;
  containmentCapabilityModes: Required<ProcessContainmentCapabilityModes>;
  parentSessionId: string;
  parentControlSessionId?: string;
}

let installedState: NodePreloadState | null = null;

const BLOCKED_PROCESS_MATCHERS: RegExp[] = [
  /(^|\s)(curl|wget|nc|netcat|nmap|telnet)(\s|$)/i,
  /(^|\s)powershell(\.exe)?\s+(-c|-command)\b/i,
  /(^|\s)cmd(\.exe)?\s+\/c\b/i,
  /(^|\s)(bash|sh|zsh)\s+-c\b/i,
  /(^|\s)python(\.exe)?\s+-c\b/i,
];

const NODE_EXECUTABLE_NAMES = new Set(['node', 'node.exe', 'iojs', 'iojs.exe']);
const SESSION_HEARTBEAT_INTERVAL_MS = 15_000;
const WORKER_BOOTSTRAP_ARG_PREFIX = '--resimantle-worker-bootstrap=';
const NODE_PRELOAD_CAPABILITIES = [
  'fs.read',
  'fs.readSync',
  'fs.stream',
  'http.fetch',
  'http.request',
  'net.connect',
  'tls.connect',
  'process.spawn',
  'process.exec',
  'process.fork',
];
const SENSITIVE_READ_PATTERNS: RegExp[] = [
  /(^|[\\/])\.env(\.|$)/i,
  /(^|[\\/])\.npmrc$/i,
  /(^|[\\/])\.git([\\/]|$)/i,
  /(secret|credential|token|id_rsa|private\.key|\.pem|backup|dump)/i,
];

export function installNodePreload(options: NodePreloadInstallOptions = {}): boolean {
  if (installedState) {
    return true;
  }

  const workerBootstrap = resolveWorkerBootstrapPayload();
  if (workerBootstrap) {
    applyNonSecretWorkerBootstrapEnv(workerBootstrap);
  }

  const sidecarUrl = options.sidecarUrl ?? process.env[COMMON_CONSTANTS.SIDECAR_URL_ENV] ?? workerBootstrap?.sidecarUrl;
  if (!sidecarUrl) {
    return false;
  }

  const initialContainmentMode = resolveContainmentMode(options.containmentMode ?? workerBootstrap?.containmentMode);
  const initialContainmentAllowlist = resolveContainmentAllowlist(options.containmentAllowlist ?? workerBootstrap?.containmentAllowlist);
  const initialContainmentCapabilityModes = options.containmentCapabilityModes
    ?? workerBootstrap?.containmentCapabilityModes
    ?? resolveContainmentCapabilityModesFromEnv(initialContainmentMode);

  const state: NodePreloadState = {
    sidecarUrl,
    sidecarToken: options.sidecarToken
      ?? process.env[COMMON_CONSTANTS.SIDECAR_TOKEN_ENV],
    sidecarBootstrapKey: options.sidecarBootstrapKey
      ?? process.env[COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV]
      ?? workerBootstrap?.sidecarBootstrapKey,
    sessionId: options.sessionId ?? process.env[COMMON_CONSTANTS.SESSION_ID_ENV] ?? workerBootstrap?.sessionId ?? randomUUID(),
    actorId: options.actorId ?? workerBootstrap?.actorId,
    containmentMode: initialContainmentMode,
    containmentAllowlist: initialContainmentAllowlist,
    containmentCapabilityModes: resolveContainmentCapabilityModes(initialContainmentCapabilityModes, initialContainmentMode),
    compiledContainmentAllowlist: compileContainmentAllowlist(initialContainmentAllowlist),
    preloadPath: typeof __filename === 'string' ? __filename : `${process.cwd()}/node-preload.js`,
    originalPromiseReadFile: mutableFsPromises.readFile,
    originalFsPromisesReadFile: mutableFs.promises.readFile,
    originalFsReadFile: mutableFs.readFile,
    originalFsReadFileSync: mutableFs.readFileSync,
    originalFsCreateReadStream: mutableFs.createReadStream,
    originalFetch: globalThis.fetch,
    originalHttpRequest: mutableHttp.request,
    originalHttpGet: mutableHttp.get,
    originalHttpsRequest: mutableHttps.request,
    originalHttpsGet: mutableHttps.get,
    originalNetConnect: mutableNet.connect,
    originalNetCreateConnection: mutableNet.createConnection,
    originalTlsConnect: mutableTls.connect,
    originalSpawn: mutableChildProcess.spawn,
    originalSpawnSync: mutableChildProcess.spawnSync,
    originalExec: mutableChildProcess.exec,
    originalExecSync: mutableChildProcess.execSync,
    originalExecFile: mutableChildProcess.execFile,
    originalExecFileSync: mutableChildProcess.execFileSync,
    originalFork: mutableChildProcess.fork,
    originalWorker: mutableWorkerThreads.Worker,
  };

  scrubSidecarAuthEnv();
  queueMicrotask(() => {
    startSessionHeartbeat(state);
    void emitPreloadIntegrityEvent(state, 'healthy', 'installed');
  });

  const wrappedPromiseReadFile = async (...args: Parameters<typeof fsPromises.readFile>) => {
    const resource = String(args[0] ?? '');
    const sidecarResponse = await resolveReadThroughSidecar(state, resource);

    if (sidecarResponse?.source === 'synthetic') {
      return coerceSyntheticRead(sidecarResponse.content ?? '', args[1]) as Awaited<ReturnType<typeof fsPromises.readFile>>;
    }

    if (sidecarResponse?.source === 'blocked') {
      throw createBlockedReadError(resource);
    }

    return state.originalPromiseReadFile.apply(fsPromises, args);
  };

  (mutableFsPromises as any).readFile = wrappedPromiseReadFile;
  (mutableFs.promises as any).readFile = wrappedPromiseReadFile;

  (mutableFs as any).readFile = function (...args: any[]) {
    const { resource, options, callback } = normalizeReadFileCall(args);
    if (!callback) {
      return state.originalFsReadFile.apply(mutableFs, args as any);
    }

    void resolveReadThroughSidecar(state, resource)
      .then(result => {
        if (result?.source === 'synthetic') {
          queueMicrotask(() => callback(null, coerceSyntheticRead(result.content ?? '', options)));
          return;
        }

        if (result?.source === 'blocked') {
          queueMicrotask(() => callback(createBlockedReadError(resource)));
          return;
        }

        state.originalFsReadFile.call(mutableFs, resource, options, callback);
      })
      .catch(error => {
        queueMicrotask(() => callback(error as NodeJS.ErrnoException));
      });

    return undefined;
  };

  (mutableFs as any).readFileSync = function (...args: any[]) {
    const resource = String(args[0] ?? '');
    const blockReason = getBlockedReadSurfaceReason(state, resource);

    if (blockReason) {
      void emitReadContainmentEvent(state, resource, true, blockReason, 'sync');
      throw createBlockedReadError(resource);
    }

    return state.originalFsReadFileSync.apply(mutableFs, args);
  };

  (mutableFs as any).createReadStream = function (...args: any[]) {
    const resource = String(args[0] ?? '');
    const blockReason = getBlockedReadSurfaceReason(state, resource);

    if (blockReason) {
      void emitReadContainmentEvent(state, resource, true, blockReason, 'stream');
      return createBlockedReadStream(resource, blockReason);
    }

    return state.originalFsCreateReadStream.apply(mutableFs, args);
  };

  if (state.originalFetch) {
    (globalThis as typeof globalThis & { fetch: NativeFetch }).fetch = async function (input: any, init?: any): Promise<Response> {
      const request = new Request(input, init);
      if (isSidecarTraffic(request.url, state.sidecarUrl)) {
        return state.originalFetch!.call(globalThis, input, init);
      }

      const sidecarResponse = await resolveHttpThroughSidecar(state, request.url, request.method);
      if (sidecarResponse?.source === 'synthetic' || sidecarResponse?.source === 'blocked') {
        return buildFetchResponse(sidecarResponse);
      }

      return state.originalFetch!.call(globalThis, input, init);
    };
  }

  (mutableHttp as any).request = function (...args: any[]) {
    return createHttpProxyRequest(state, 'http', state.originalHttpRequest, args, false);
  };

  (mutableHttp as any).get = function (...args: any[]) {
    return createHttpProxyRequest(state, 'http', state.originalHttpRequest, args, true);
  };

  (mutableHttps as any).request = function (...args: any[]) {
    return createHttpProxyRequest(state, 'https', state.originalHttpsRequest, args, false);
  };

  (mutableHttps as any).get = function (...args: any[]) {
    return createHttpProxyRequest(state, 'https', state.originalHttpsRequest, args, true);
  };

  (mutableNet as any).connect = function (...args: any[]) {
    return connectSocketWithContainment(state, state.originalNetConnect, args);
  };

  (mutableNet as any).createConnection = function (...args: any[]) {
    return connectSocketWithContainment(state, state.originalNetCreateConnection, args);
  };

  (mutableTls as any).connect = function (...args: any[]) {
    return connectSocketWithContainment(state, state.originalTlsConnect, args);
  };

  (mutableChildProcess as any).spawn = function (command: string, args?: string[] | Record<string, unknown>, options?: Record<string, unknown>) {
    const normalized = normalizeSpawnCall(command, args, options);
    const fullCommand = formatProcessCommand(normalized.command, normalized.args);
    const blockReason = getBlockedProcessReason(state, fullCommand);

    if (blockReason) {
      void emitProcessContainmentEvent(state, fullCommand, true, blockReason);
      throw createBlockedProcessError(fullCommand, blockReason);
    }

    const nextOptions = protectChildProcessOptions(state, normalized.command, normalized.options);
    void emitProcessContainmentEvent(state, fullCommand, false, 'allowed');
    return state.originalSpawn.call(mutableChildProcess, normalized.command, normalized.args, nextOptions);
  };

  (mutableChildProcess as any).spawnSync = function (command: string, args?: string[] | Record<string, unknown>, options?: Record<string, unknown>) {
    const normalized = normalizeSpawnCall(command, args, options);
    const fullCommand = formatProcessCommand(normalized.command, normalized.args);
    const blockReason = getBlockedProcessReason(state, fullCommand);

    if (blockReason) {
      void emitProcessContainmentEvent(state, fullCommand, true, blockReason);
      throw createBlockedProcessError(fullCommand, blockReason);
    }

    const nextOptions = protectChildProcessOptions(state, normalized.command, normalized.options);
    void emitProcessContainmentEvent(state, fullCommand, false, 'allowed');
    return state.originalSpawnSync.call(mutableChildProcess, normalized.command, normalized.args, nextOptions);
  };

  (mutableChildProcess as any).exec = function (command: string, ...rest: unknown[]) {
    const blockReason = getBlockedProcessReason(state, command);
    if (blockReason) {
      void emitProcessContainmentEvent(state, command, true, blockReason);
      throw createBlockedProcessError(command, blockReason);
    }

    if (rest[0] && typeof rest[0] === 'object') {
      rest[0] = protectChildProcessOptions(state, command, rest[0] as Record<string, unknown>);
    } else if (!rest[0] || typeof rest[0] !== 'function') {
      rest.unshift(protectChildProcessOptions(state, command, {}));
    }

    void emitProcessContainmentEvent(state, command, false, 'allowed');
    return state.originalExec.call(mutableChildProcess, command, ...rest);
  };

  (mutableChildProcess as any).execSync = function (command: string, options?: Record<string, unknown>) {
    const blockReason = getBlockedProcessReason(state, command);
    if (blockReason) {
      void emitProcessContainmentEvent(state, command, true, blockReason);
      throw createBlockedProcessError(command, blockReason);
    }

    void emitProcessContainmentEvent(state, command, false, 'allowed');
    return state.originalExecSync.call(mutableChildProcess, command, protectChildProcessOptions(state, command, options ?? {}));
  };

  (mutableChildProcess as any).execFile = function (file: string, args?: string[] | Record<string, unknown>, ...rest: unknown[]) {
    const normalized = normalizeExecFileCall(file, args, rest);
    const fullCommand = formatProcessCommand(normalized.file, normalized.args);
    const blockReason = getBlockedProcessReason(state, fullCommand);

    if (blockReason) {
      void emitProcessContainmentEvent(state, fullCommand, true, blockReason);
      throw createBlockedProcessError(fullCommand, blockReason);
    }

    normalized.rest[0] = protectChildProcessOptions(state, normalized.file, normalized.options);
    void emitProcessContainmentEvent(state, fullCommand, false, 'allowed');
    return state.originalExecFile.call(mutableChildProcess, normalized.file, normalized.args, ...normalized.rest);
  };

  (mutableChildProcess as any).execFileSync = function (file: string, args?: string[] | Record<string, unknown>, options?: Record<string, unknown>) {
    const normalized = normalizeSpawnCall(file, args, options);
    const fullCommand = formatProcessCommand(normalized.command, normalized.args);
    const blockReason = getBlockedProcessReason(state, fullCommand);

    if (blockReason) {
      void emitProcessContainmentEvent(state, fullCommand, true, blockReason);
      throw createBlockedProcessError(fullCommand, blockReason);
    }

    void emitProcessContainmentEvent(state, fullCommand, false, 'allowed');
    return state.originalExecFileSync.call(
      mutableChildProcess,
      normalized.command,
      normalized.args,
      protectChildProcessOptions(state, normalized.command, normalized.options),
    );
  };

  (mutableChildProcess as any).fork = function (modulePath: string, args?: string[] | Record<string, unknown>, options?: Record<string, unknown>) {
    const normalized = normalizeForkCall(args, options);
    const fullCommand = formatProcessCommand(process.execPath, [modulePath, ...normalized.args]);
    const blockReason = getBlockedProcessReason(state, fullCommand);

    if (blockReason) {
      void emitProcessContainmentEvent(state, fullCommand, true, blockReason);
      throw createBlockedProcessError(fullCommand, blockReason);
    }

    const nextOptions = protectForkOptions(state, normalized.options);
    void emitProcessContainmentEvent(state, fullCommand, false, 'allowed');
    return state.originalFork.call(mutableChildProcess, modulePath, normalized.args, nextOptions);
  };

  if (state.originalWorker) {
    const OriginalWorker: typeof import('node:worker_threads').Worker = state.originalWorker;

    (mutableWorkerThreads as any).Worker = class ResiMantleWorker extends OriginalWorker {
      constructor(filename: string | URL, options?: Record<string, unknown>) {
        const registration = registerWorkerBootstrapPayload(state);
        const nextOptions = protectWorkerOptions(state, options ?? {}, registration.bootstrapId);

        try {
          super(filename, nextOptions);
        } finally {
          registration.dispose();
        }
      }
    };
  }

  syncBuiltinESMExports();

  installedState = state;
  return true;
}

export function uninstallNodePreload(): void {
  const state = installedState;
  if (!state) {
    return;
  }

  if (state.heartbeatTimer) {
    clearInterval(state.heartbeatTimer);
    state.heartbeatTimer = undefined;
  }

  (mutableFsPromises as any).readFile = state.originalPromiseReadFile;
  (mutableFs.promises as any).readFile = state.originalFsPromisesReadFile;
  (mutableFs as any).readFile = state.originalFsReadFile;
  (mutableFs as any).readFileSync = state.originalFsReadFileSync;
  (mutableFs as any).createReadStream = state.originalFsCreateReadStream;

  if (state.originalFetch) {
    globalThis.fetch = state.originalFetch;
  }

  (mutableHttp as any).request = state.originalHttpRequest;
  (mutableHttp as any).get = state.originalHttpGet;
  (mutableHttps as any).request = state.originalHttpsRequest;
  (mutableHttps as any).get = state.originalHttpsGet;
  (mutableNet as any).connect = state.originalNetConnect;
  (mutableNet as any).createConnection = state.originalNetCreateConnection;
  (mutableTls as any).connect = state.originalTlsConnect;
  (mutableChildProcess as any).spawn = state.originalSpawn;
  (mutableChildProcess as any).spawnSync = state.originalSpawnSync;
  (mutableChildProcess as any).exec = state.originalExec;
  (mutableChildProcess as any).execSync = state.originalExecSync;
  (mutableChildProcess as any).execFile = state.originalExecFile;
  (mutableChildProcess as any).execFileSync = state.originalExecFileSync;
  (mutableChildProcess as any).fork = state.originalFork;
  if (state.originalWorker) {
    (mutableWorkerThreads as any).Worker = state.originalWorker;
  }

  syncBuiltinESMExports();

  installedState = null;
}

export function getInstalledNodePreloadStateForTest(): Pick<NodePreloadState, 'containmentMode' | 'containmentAllowlist' | 'containmentCapabilityModes'> | null {
  if (!installedState) {
    return null;
  }

  return {
    containmentMode: installedState.containmentMode,
    containmentAllowlist: installedState.containmentAllowlist,
    containmentCapabilityModes: installedState.containmentCapabilityModes,
  };
}

export async function flushNodePreloadHeartbeatForTest(): Promise<void> {
  if (!installedState) {
    return;
  }

  await sendSessionHeartbeat(installedState);
}

if (
  (process.env[COMMON_CONSTANTS.ACTIVE_ENV] === '1' && process.env[COMMON_CONSTANTS.MANTLE_AUTO_ENV] === '1')
  || hasWorkerBootstrapArg()
) {
  installNodePreload();
}

function normalizeReadFileCall(args: any[]): {
  resource: string;
  options: unknown;
  callback?: FsReadFileCallback;
} {
  const resource = String(args[0] ?? '');
  const second = args[1];
  const third = args[2];

  if (typeof second === 'function') {
    return {
      resource,
      options: undefined,
      callback: second as FsReadFileCallback,
    };
  }

  return {
    resource,
    options: second,
    callback: third as FsReadFileCallback | undefined,
  };
}

function coerceSyntheticRead(content: string, options: unknown): string | Buffer {
  const encoding = getReadEncoding(options);
  if (encoding) {
    return Buffer.from(content, 'utf-8').toString(encoding);
  }

  return Buffer.from(content, 'utf-8');
}

function getReadEncoding(options: unknown): BufferEncoding | undefined {
  if (typeof options === 'string' && options !== 'buffer') {
    return options as BufferEncoding;
  }

  if (options && typeof options === 'object' && 'encoding' in options) {
    const encoding = (options as { encoding?: string | null }).encoding;
    if (encoding && encoding !== 'buffer') {
      return encoding as BufferEncoding;
    }
  }

  return undefined;
}

async function resolveReadThroughSidecar(state: NodePreloadState, resource: string): Promise<ReadResolutionPayload | null> {
  try {
    return await postJson<ReadResolutionPayload>(state, '/v1/read', {
      actorId: detectActor(state),
      sessionId: state.sessionId,
      resource,
      metadata: {
        source: 'node-preload.fs',
        cwd: process.cwd(),
      },
    });
  } catch {
    return null;
  }
}

async function resolveHttpThroughSidecar(
  state: NodePreloadState,
  resourceUrl: string,
  method: string,
): Promise<HttpResolutionPayload | null> {
  try {
    const url = new URL(resourceUrl);
    return await postJson<HttpResolutionPayload>(state, '/v1/http', {
      actorId: detectActor(state),
      sessionId: state.sessionId,
      path: `${url.pathname}${url.search}`,
      method,
      metadata: {
        source: 'node-preload.http',
        url: resourceUrl,
        hostname: url.hostname,
      },
    });
  } catch {
    return null;
  }
}

async function postJson<T>(state: NodePreloadState, path: string, payload: Record<string, unknown>): Promise<T> {
  return await postJsonWithAuth<T>(state, path, payload);
}

async function postJsonWithAuth<T>(
  state: NodePreloadState,
  path: string,
  payload: Record<string, unknown>,
  explicitAuth?: SidecarAuthHeader,
  allowRetry = true,
): Promise<T> {
  const auth = explicitAuth ?? await resolveSessionAuth(state);

  try {
    return await sendSidecarJsonRequest<T>(state, path, payload, auth);
  } catch (error) {
    if (allowRetry && !explicitAuth && isUnauthorizedError(error) && state.sidecarBootstrapKey) {
      state.sidecarToken = undefined;
      state.sidecarTokenExpiresAt = undefined;
      await ensureBootstrapSession(state, true);
      return await postJsonWithAuth<T>(state, path, payload, undefined, false);
    }

    throw error;
  }
}

async function resolveSessionAuth(state: NodePreloadState): Promise<SidecarAuthHeader | undefined> {
  await ensureBootstrapSession(state);

  return state.sidecarToken
    ? {
      name: COMMON_CONSTANTS.SIDECAR_TOKEN_HEADER,
      value: state.sidecarToken,
    }
    : undefined;
}

async function ensureBootstrapSession(state: NodePreloadState, forceRenew = false): Promise<void> {
  const tokenExpired = isSessionTokenExpired(state.sidecarTokenExpiresAt);
  if (!forceRenew && state.sidecarToken && !tokenExpired) {
    return;
  }

  if (!state.sidecarBootstrapKey) {
    return;
  }

  const bootstrapKey = state.sidecarBootstrapKey;

  if (!forceRenew && state.bootstrapExchangePromise) {
    await state.bootstrapExchangePromise;
    return;
  }

  state.bootstrapExchangePromise = (async () => {
    const payload = {
      sessionId: state.sessionId,
      actorId: detectActor(state),
      runtime: 'node',
      pid: process.pid,
      ppid: process.ppid,
      cwd: process.cwd(),
      execPath: process.execPath,
      argvHash: computeProcessArgvHash(),
      runtimeVersion: process.version,
      parentSessionId: process.env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV],
      parentControlSessionId: process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV],
      preloadPath: state.preloadPath,
      capabilities: NODE_PRELOAD_CAPABILITIES,
      integrity: {
        status: 'healthy',
        containmentMode: state.containmentMode,
      },
    };
    const session = await sendSidecarJsonRequest<BootstrapSessionPayload>(
      state,
      '/v1/bootstrap/session',
      payload,
      {
        name: COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_HEADER,
        value: bootstrapKey,
      },
    );

    state.sidecarToken = session.sessionToken;
    state.sidecarTokenExpiresAt = session.tokenExpiresAt;
    state.controlSessionId = session.controlSessionId;
    applyContainmentUpdate(state, session.containment);
    if (session.sessionId) {
      state.sessionId = session.sessionId;
    }
  })();

  try {
    await state.bootstrapExchangePromise;
  } finally {
    state.bootstrapExchangePromise = undefined;
  }
}

async function sendSidecarJsonRequest<T>(
  state: NodePreloadState,
  path: string,
  payload: Record<string, unknown>,
  auth?: SidecarAuthHeader,
): Promise<T> {
  const target = new URL(path, state.sidecarUrl);
  const body = JSON.stringify(payload);
  const requestFn = target.protocol === 'https:' ? state.originalHttpsRequest : state.originalHttpRequest;

  return await new Promise<T>((resolve, reject) => {
    const request = requestFn({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        connection: 'close',
        ...(auth
          ? { [auth.name]: auth.value }
          : {}),
      },
    }, (response: import('node:http').IncomingMessage) => {
      const chunks: Buffer[] = [];

      response.on('data', (chunk: Buffer | string) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });

      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8');
        if ((response.statusCode ?? 500) >= 400) {
          reject(createSidecarRequestError(response.statusCode ?? 500));
          return;
        }
        resolve(JSON.parse(raw || '{}') as T);
      });
    });

    request.on('error', reject);
    request.end(body);
  });
}

function createSidecarRequestError(statusCode: number): SidecarRequestError {
  const error = new Error(`Sidecar request failed with status ${statusCode}`) as SidecarRequestError;
  error.statusCode = statusCode;
  return error;
}

function isUnauthorizedError(error: unknown): error is SidecarRequestError {
  return typeof error === 'object'
    && error !== null
    && 'statusCode' in error
    && (error as SidecarRequestError).statusCode === 401;
}

function isSessionTokenExpired(expiresAt?: string): boolean {
  if (!expiresAt) {
    return false;
  }

  const expiry = Date.parse(expiresAt);
  if (Number.isNaN(expiry)) {
    return false;
  }

  return expiry <= Date.now() + 5_000;
}

function buildFetchResponse(result: HttpResolutionPayload): Response {
  const statusCode = result.response?.statusCode ?? 403;
  const body = result.response?.body ?? { success: false, status: 'blocked' };
  return new Response(JSON.stringify(body), {
    status: statusCode,
    headers: {
      'content-type': 'application/json',
      ...(result.response?.headers ?? {}),
    },
  });
}

function createHttpProxyRequest(
  state: NodePreloadState,
  protocol: 'http' | 'https',
  originalFn: AnyFunction,
  rawArgs: unknown[],
  autoEnd: boolean,
): HttpRequestProxy {
  const requestProxy = new EventEmitter() as HttpRequestProxy;
  const pendingActions: PendingRequestAction[] = [];
  const pendingHeaders = new Map<string, string | number | readonly string[]>();
  let realRequest: import('node:http').ClientRequest | null = null;
  let destroyed = false;
  let resolvedSynthetic: HttpResolutionPayload | null = null;
  let ended = autoEnd;

  requestProxy.write = (...args: unknown[]) => {
    if (realRequest) {
      return realRequest.write(args[0] as any, args[1] as any, args[2] as any);
    }

    pendingActions.push({ type: 'write', args });
    return true;
  };

  requestProxy.end = (...args: unknown[]) => {
    ended = true;

    if (realRequest) {
      realRequest.end(args[0] as any, args[1] as any, args[2] as any);
      return requestProxy;
    }

    pendingActions.push({ type: 'end', args });
    if (resolvedSynthetic) {
      emitSyntheticHttpResponse(requestProxy, resolvedSynthetic);
    }
    return requestProxy;
  };

  requestProxy.abort = () => {
    requestProxy.aborted = true;
    if (realRequest) {
      realRequest.abort();
    }
  };

  requestProxy.destroy = (error?: Error) => {
    destroyed = true;
    requestProxy.destroyed = true;
    if (realRequest) {
      realRequest.destroy(error);
      return;
    }
    if (error) {
      requestProxy.emit('error', error);
    }
  };

  requestProxy.setHeader = (name, value) => {
    if (realRequest) {
      realRequest.setHeader(name, value);
      return;
    }
    pendingHeaders.set(name, value);
  };

  requestProxy.getHeader = (name) => {
    if (realRequest) {
      return realRequest.getHeader(name);
    }
    return pendingHeaders.get(name);
  };

  requestProxy.getHeaders = () => {
    if (realRequest) {
      return realRequest.getHeaders();
    }
    return Object.fromEntries(pendingHeaders.entries());
  };

  requestProxy.removeHeader = (name) => {
    if (realRequest) {
      realRequest.removeHeader(name);
      return;
    }
    pendingHeaders.delete(name);
  };

  requestProxy.setTimeout = (timeout, callback) => {
    if (realRequest) {
      realRequest.setTimeout(timeout, callback);
    } else if (callback) {
      setTimeout(callback, timeout);
    }
    return requestProxy;
  };

  const args = [...rawArgs];

  void (async () => {
    const requestInfo = extractRequestInfo(protocol, args);
    if (isSidecarTraffic(requestInfo.url, state.sidecarUrl)) {
      attachRealRequest();
      return;
    }

    const sidecarResponse = await resolveHttpThroughSidecar(state, requestInfo.url, requestInfo.method);
    if ((sidecarResponse?.source === 'synthetic' || sidecarResponse?.source === 'blocked') && !destroyed) {
      resolvedSynthetic = sidecarResponse;
      if (ended) {
        emitSyntheticHttpResponse(requestProxy, sidecarResponse);
      }
      return;
    }

    attachRealRequest();
  })();

  if (autoEnd) {
    queueMicrotask(() => {
      if (!destroyed) {
        requestProxy.end();
      }
    });
  }

  return requestProxy;

  function attachRealRequest(): void {
    if (destroyed || realRequest) {
      return;
    }

    realRequest = originalFn.apply(null, args) as import('node:http').ClientRequest;
    for (const [name, value] of pendingHeaders) {
      realRequest.setHeader(name, value);
    }

    for (const eventName of ['response', 'error', 'close', 'finish', 'timeout', 'socket', 'connect', 'continue'] as const) {
      realRequest.on(eventName, (...eventArgs: unknown[]) => {
        requestProxy.emit(eventName, ...eventArgs);
      });
    }

    for (const action of pendingActions) {
      if (action.type === 'write') {
        realRequest.write(action.args[0] as any, action.args[1] as any, action.args[2] as any);
      } else {
        realRequest.end(action.args[0] as any, action.args[1] as any, action.args[2] as any);
      }
    }
  }
}

function emitSyntheticHttpResponse(requestProxy: HttpRequestProxy, result: HttpResolutionPayload): void {
  const stream = new PassThrough() as PassThrough & {
    statusCode?: number;
    headers?: Record<string, string>;
    statusMessage?: string;
  };

  const body = JSON.stringify(result.response?.body ?? { success: false, status: 'blocked' });
  stream.statusCode = result.response?.statusCode ?? 403;
  stream.headers = {
    'content-type': 'application/json',
    ...(result.response?.headers ?? {}),
  };
  stream.statusMessage = stream.statusCode === 202 ? 'Accepted' : stream.statusCode === 200 ? 'OK' : 'Forbidden';

  queueMicrotask(() => {
    requestProxy.emit('response', stream);
    stream.end(body);
  });
}

function extractRequestInfo(protocol: 'http' | 'https', args: unknown[]): { url: string; method: string } {
  const first = args[0];

  if (typeof first === 'string') {
    try {
      return {
        url: first,
        method: ((args[1] as { method?: string } | undefined)?.method ?? 'GET').toUpperCase(),
      };
    } catch {
      return { url: first, method: 'GET' };
    }
  }

  if (first instanceof URL) {
    return {
      url: first.toString(),
      method: ((args[1] as { method?: string } | undefined)?.method ?? 'GET').toUpperCase(),
    };
  }

  if (typeof first === 'object' && first !== null) {
    const options = first as { protocol?: string; hostname?: string; host?: string; port?: string | number; path?: string; method?: string };
    const hostname = options.hostname ?? options.host ?? 'localhost';
    const port = options.port ?? (protocol === 'https' ? 443 : 80);
    const path = options.path ?? '/';
    return {
      url: `${options.protocol ?? `${protocol}:`}//${hostname}:${port}${path}`,
      method: (options.method ?? 'GET').toUpperCase(),
    };
  }

  return {
    url: `${protocol}://unknown/`,
    method: 'GET',
  };
}

function createBlockedReadError(resource: string): Error & { code?: string } {
  const error = new Error(`ResiMantle blocked synthetic read access to ${resource}`) as Error & { code?: string };
  error.code = 'EACCES';
  return error;
}

function createBlockedSocketError(endpoint: string, reason: string): Error & { code?: string } {
  const error = new Error(`ResiMantle blocked socket egress to ${endpoint}: ${reason}`) as Error & { code?: string };
  error.code = 'EPERM';
  return error;
}

function createBlockedProcessError(command: string, reason: string): Error & { code?: string } {
  const error = new Error(`ResiMantle blocked child process "${command}": ${reason}`) as Error & { code?: string };
  error.code = 'EPERM';
  return error;
}

function createBlockedReadStream(resource: string, reason: string): import('node:fs').ReadStream {
  const stream = new PassThrough() as PassThrough & { path?: string; close?: () => void };
  stream.path = resource;
  stream.close = () => {
    stream.destroy();
  };

  queueMicrotask(() => {
    stream.destroy(createBlockedReadError(`${resource} (${reason})`));
  });

  return stream as unknown as import('node:fs').ReadStream;
}

function detectActor(state: NodePreloadState): string {
  if (state.actorId) {
    return state.actorId;
  }

  const stack = new Error().stack;
  if (!stack) {
    return 'node-preload';
  }

  for (const line of stack.split('\n').slice(3)) {
    if (line.includes('node:internal') || line.includes('node_modules')) {
      continue;
    }
    const match = line.match(/at\s+(?:(.+?)\s+\()?(.+?):(\d+):\d+\)?/);
    if (match) {
      return match[2] || match[1] || 'node-preload';
    }
  }

  return 'node-preload';
}

function isSidecarTraffic(resourceUrl: string, sidecarUrl: string): boolean {
  try {
    return new URL(resourceUrl).origin === new URL(sidecarUrl).origin;
  } catch {
    return false;
  }
}

function resolveContainmentMode(mode?: ProcessContainmentMode): ProcessContainmentMode {
  if (mode) {
    return mode;
  }

  const fromEnv = process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV];
  if (fromEnv === 'off' || fromEnv === 'strict' || fromEnv === 'adaptive') {
    return fromEnv;
  }

  return 'adaptive';
}

function normalizeSpawnCall(
  command: string,
  args?: string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): { command: string; args: string[]; options: Record<string, unknown> } {
  if (Array.isArray(args)) {
    return { command, args, options: options ?? {} };
  }

  return { command, args: [], options: (args as Record<string, unknown> | undefined) ?? {} };
}

function normalizeExecFileCall(
  file: string,
  args: string[] | Record<string, unknown> | undefined,
  rest: unknown[],
): { file: string; args: string[]; options: Record<string, unknown>; rest: unknown[] } {
  if (Array.isArray(args)) {
    const nextRest = [...rest];
    const options = nextRest[0] && typeof nextRest[0] === 'object' ? nextRest[0] as Record<string, unknown> : {};
    if (!(nextRest[0] && typeof nextRest[0] === 'object')) {
      nextRest.unshift(options);
    }
    return { file, args, options, rest: nextRest };
  }

  const nextRest = [...rest];
  const options = (args as Record<string, unknown> | undefined) ?? {};
  nextRest.unshift(options);
  return { file, args: [], options, rest: nextRest };
}

function normalizeForkCall(
  args?: string[] | Record<string, unknown>,
  options?: Record<string, unknown>,
): { args: string[]; options: Record<string, unknown> } {
  if (Array.isArray(args)) {
    return { args, options: options ?? {} };
  }

  return { args: [], options: (args as Record<string, unknown> | undefined) ?? {} };
}

function protectChildProcessOptions(
  state: NodePreloadState,
  command: string,
  options: Record<string, unknown>,
): Record<string, unknown> {
  const baseEnv = isRecord(options.env) ? options.env as NodeJS.ProcessEnv : process.env;
  const nextEnv = buildProtectedEnv(state, baseEnv, isNodeExecutable(command));
  return {
    ...options,
    env: nextEnv,
  };
}

function protectForkOptions(state: NodePreloadState, options: Record<string, unknown>): Record<string, unknown> {
  const baseEnv = isRecord(options.env) ? options.env as NodeJS.ProcessEnv : process.env;
  const nextExecArgv = Array.isArray(options.execArgv)
    ? mergeRequireIntoExecArgv(options.execArgv as string[], state.preloadPath)
    : [`--require`, state.preloadPath];

  return {
    ...options,
    execArgv: nextExecArgv,
    env: buildProtectedEnv(state, baseEnv, true),
  };
}

function protectWorkerOptions(
  state: NodePreloadState,
  options: Record<string, unknown>,
  bootstrapId?: string,
): Record<string, unknown> {
  const nextExecArgv = Array.isArray(options.execArgv)
    ? mergeRequireIntoExecArgv(options.execArgv as string[], state.preloadPath)
    : ['--require', state.preloadPath];

  const nextOptions: Record<string, unknown> = {
    ...options,
    execArgv: nextExecArgv,
  };

  if (bootstrapId) {
    nextOptions.argv = mergeWorkerBootstrapIntoArgv(options.argv, bootstrapId);
  }

  if (options.env !== mutableWorkerThreads.SHARE_ENV) {
    const baseEnv = isRecord(options.env) ? options.env as NodeJS.ProcessEnv : process.env;
    nextOptions.env = buildProtectedEnv(state, baseEnv, true);
  }

  return nextOptions;
}

function buildProtectedEnv(
  state: NodePreloadState,
  baseEnv: NodeJS.ProcessEnv,
  includeNodeOptions: boolean,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...baseEnv,
    [COMMON_CONSTANTS.ACTIVE_ENV]: '1',
    [COMMON_CONSTANTS.MANTLE_AUTO_ENV]: '1',
    [COMMON_CONSTANTS.SESSION_ID_ENV]: state.sessionId,
    [COMMON_CONSTANTS.PARENT_SESSION_ID_ENV]: state.sessionId,
    [COMMON_CONSTANTS.SIDECAR_URL_ENV]: state.sidecarUrl,
    [COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV]: state.containmentMode,
  };

  delete env[COMMON_CONSTANTS.SIDECAR_TOKEN_ENV];

  if (includeNodeOptions) {
    const bootstrapSecret = state.sidecarBootstrapKey ?? state.sidecarToken;
    if (bootstrapSecret) {
      env[COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV] = bootstrapSecret;
    }

    if (state.controlSessionId) {
      env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV] = state.controlSessionId;
    } else {
      delete env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV];
    }

    const serializedAllowlist = serializeContainmentAllowlist(state.containmentAllowlist);
    if (serializedAllowlist) {
      env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV] = serializedAllowlist;
    } else {
      delete env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV];
    }

    const serializedCapabilityModes = serializeContainmentCapabilityModes(state.containmentCapabilityModes, state.containmentMode);
    if (serializedCapabilityModes) {
      env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV] = serializedCapabilityModes;
    } else {
      delete env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV];
    }
  } else {
    delete env[COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV];
    delete env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV];
    delete env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV];
    delete env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV];
    delete env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV];
  }

  if (includeNodeOptions) {
    env.NODE_OPTIONS = mergeNodeOptions(env.NODE_OPTIONS, `--require ${state.preloadPath}`);
  }

  return env;
}

function mergeRequireIntoExecArgv(existing: string[], preloadPath: string): string[] {
  const nextArgv = [...existing];
  if (nextArgv.some((value, index) => value === '--require' && nextArgv[index + 1] === preloadPath)) {
    return nextArgv;
  }

  nextArgv.push('--require', preloadPath);
  return nextArgv;
}

function mergeWorkerBootstrapIntoArgv(existing: unknown, bootstrapId: string): string[] {
  const marker = `${WORKER_BOOTSTRAP_ARG_PREFIX}${bootstrapId}`;
  const nextArgv = Array.isArray(existing)
    ? existing.map(value => String(value))
    : [];

  if (!nextArgv.includes(marker)) {
    nextArgv.push(marker);
  }

  return nextArgv;
}

function mergeNodeOptions(existing: string | undefined, next: string): string {
  if (!existing?.trim()) {
    return next;
  }

  if (existing.includes(next)) {
    return existing;
  }

  return `${existing} ${next}`.trim();
}

function getBlockedProcessReason(state: NodePreloadState, command: string): string | null {
  const containmentMode = state.containmentCapabilityModes.processes;
  if (containmentMode === 'off') {
    return null;
  }

  if (state.compiledContainmentAllowlist.processPatterns.some(pattern => pattern.test(command))) {
    return null;
  }

  const matcher = BLOCKED_PROCESS_MATCHERS.find(pattern => pattern.test(command));
  if (!matcher) {
    return null;
  }

  return containmentMode === 'strict'
    ? `strict containment rejected risky child process pattern ${matcher}`
    : `adaptive containment rejected risky child process pattern ${matcher}`;
}

function formatProcessCommand(command: string, args: string[]): string {
  return args.length > 0 ? `${command} ${args.join(' ')}` : command;
}

function isNodeExecutable(command: string): boolean {
  const normalized = basename(command).toLowerCase();
  return NODE_EXECUTABLE_NAMES.has(normalized) || command === process.execPath;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function scrubSidecarAuthEnv(): void {
  delete process.env[COMMON_CONSTANTS.SIDECAR_TOKEN_ENV];
  delete process.env[COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV];
}

function hasWorkerBootstrapArg(): boolean {
  return process.argv.some(value => typeof value === 'string' && value.startsWith(WORKER_BOOTSTRAP_ARG_PREFIX));
}

function resolveWorkerBootstrapPayload(): WorkerBootstrapPayload | undefined {
  const bootstrapId = consumeWorkerBootstrapIdFromArgv();
  if (!bootstrapId) {
    return undefined;
  }

  const getEnvironmentData = (mutableWorkerThreads as { getEnvironmentData?: (key: string) => unknown }).getEnvironmentData;
  if (typeof getEnvironmentData !== 'function') {
    return undefined;
  }

  const payload = getEnvironmentData.call(mutableWorkerThreads, bootstrapId);
  return isWorkerBootstrapPayload(payload) ? payload : undefined;
}

function consumeWorkerBootstrapIdFromArgv(): string | undefined {
  const index = process.argv.findIndex(value => typeof value === 'string' && value.startsWith(WORKER_BOOTSTRAP_ARG_PREFIX));
  if (index < 0) {
    return undefined;
  }

  const [marker] = process.argv.splice(index, 1);
  return typeof marker === 'string' ? marker.slice(WORKER_BOOTSTRAP_ARG_PREFIX.length) : undefined;
}

function registerWorkerBootstrapPayload(state: NodePreloadState): {
  bootstrapId?: string;
  dispose: () => void;
} {
  const setEnvironmentData = (mutableWorkerThreads as { setEnvironmentData?: (key: string, value: unknown) => void }).setEnvironmentData;
  if (typeof setEnvironmentData !== 'function') {
    return { dispose: () => undefined };
  }

  const bootstrapId = randomUUID();
  setEnvironmentData.call(mutableWorkerThreads, bootstrapId, buildWorkerBootstrapPayload(state));

  return {
    bootstrapId,
    dispose: () => {
      setEnvironmentData.call(mutableWorkerThreads, bootstrapId, undefined);
    },
  };
}

function buildWorkerBootstrapPayload(state: NodePreloadState): WorkerBootstrapPayload {
  return {
    sidecarUrl: state.sidecarUrl,
    sidecarBootstrapKey: state.sidecarBootstrapKey ?? state.sidecarToken,
    sessionId: state.sessionId,
    actorId: state.actorId,
    containmentMode: state.containmentMode,
    containmentAllowlist: normalizeContainmentAllowlist(state.containmentAllowlist),
    containmentCapabilityModes: { ...state.containmentCapabilityModes },
    parentSessionId: state.sessionId,
    parentControlSessionId: state.controlSessionId,
  };
}

function applyNonSecretWorkerBootstrapEnv(payload: WorkerBootstrapPayload): void {
  process.env[COMMON_CONSTANTS.ACTIVE_ENV] = '1';
  process.env[COMMON_CONSTANTS.MANTLE_AUTO_ENV] = '1';
  process.env[COMMON_CONSTANTS.SESSION_ID_ENV] = payload.sessionId;
  process.env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV] = payload.parentSessionId;
  process.env[COMMON_CONSTANTS.SIDECAR_URL_ENV] = payload.sidecarUrl;
  process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV] = payload.containmentMode;

  if (payload.parentControlSessionId) {
    process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV] = payload.parentControlSessionId;
  } else {
    delete process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV];
  }

  const serializedAllowlist = serializeContainmentAllowlist(payload.containmentAllowlist);
  if (serializedAllowlist) {
    process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV] = serializedAllowlist;
  } else {
    delete process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV];
  }

  const serializedCapabilityModes = serializeContainmentCapabilityModes(payload.containmentCapabilityModes, payload.containmentMode);
  if (serializedCapabilityModes) {
    process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV] = serializedCapabilityModes;
  } else {
    delete process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV];
  }
}

function startSessionHeartbeat(state: NodePreloadState): void {
  if (state.heartbeatTimer) {
    return;
  }

  const emitHeartbeat = () => {
    void sendSessionHeartbeat(state);
  };

  emitHeartbeat();
  state.heartbeatTimer = setInterval(emitHeartbeat, SESSION_HEARTBEAT_INTERVAL_MS);
  if (typeof state.heartbeatTimer.unref === 'function') {
    state.heartbeatTimer.unref();
  }
}

async function sendSessionHeartbeat(state: NodePreloadState): Promise<void> {
  try {
    const response = await postJson<SessionHeartbeatPayload>(state, '/v1/session/heartbeat', {
      pid: process.pid,
      ppid: process.ppid,
      cwd: process.cwd(),
      execPath: process.execPath,
      argvHash: computeProcessArgvHash(),
      runtimeVersion: process.version,
      integrity: {
        status: 'healthy',
      },
    });

    if (response.tokenExpiresAt) {
      state.sidecarTokenExpiresAt = response.tokenExpiresAt;
    }

    applyContainmentUpdate(state, response.containment);

    if (response.integrityStatus === 'drifted') {
      await emitPreloadIntegrityEvent(state, 'drifted', 'runtime-drift');
    }
  } catch {
    // Heartbeats are best-effort; failed renewals will recover on demand.
  }
}

function computeProcessArgvHash(): string {
  return createHash('sha256')
    .update(JSON.stringify({
      execPath: process.execPath,
      argv: process.argv,
    }))
    .digest('hex');
}

function applyContainmentUpdate(
  state: NodePreloadState,
  update?: {
    mode?: ProcessContainmentMode;
    allowlist?: ProcessContainmentAllowlist;
    capabilityModes?: ProcessContainmentCapabilityModes;
  },
): void {
  if (!update) {
    return;
  }

  if (update.mode === 'off' || update.mode === 'adaptive' || update.mode === 'strict') {
    state.containmentMode = update.mode;
  }

  if (update.allowlist) {
    state.containmentAllowlist = normalizeContainmentAllowlist(update.allowlist);
    state.compiledContainmentAllowlist = compileContainmentAllowlist(state.containmentAllowlist);
  }

  state.containmentCapabilityModes = resolveContainmentCapabilityModes(update.capabilityModes ?? state.containmentCapabilityModes, state.containmentMode);
}

function resolveContainmentAllowlist(allowlist?: ProcessContainmentAllowlist): ProcessContainmentAllowlist {
  if (allowlist) {
    return normalizeContainmentAllowlist(allowlist);
  }

  const raw = process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV];
  if (!raw?.trim()) {
    return normalizeContainmentAllowlist({});
  }

  try {
    return normalizeContainmentAllowlist(JSON.parse(raw) as ProcessContainmentAllowlist);
  } catch {
    return normalizeContainmentAllowlist({});
  }
}

function isWorkerBootstrapPayload(value: unknown): value is WorkerBootstrapPayload {
  return isRecord(value)
    && typeof value.sidecarUrl === 'string'
    && typeof value.sessionId === 'string'
    && (value.containmentMode === 'off' || value.containmentMode === 'adaptive' || value.containmentMode === 'strict')
    && typeof value.parentSessionId === 'string'
    && isRecord(value.containmentCapabilityModes);
}

function resolveContainmentCapabilityModes(
  capabilityModes: ProcessContainmentCapabilityModes | undefined,
  baseMode: ProcessContainmentMode,
): Required<ProcessContainmentCapabilityModes> {
  return {
    reads: normalizeContainmentCapabilityMode(capabilityModes?.reads, baseMode),
    processes: normalizeContainmentCapabilityMode(capabilityModes?.processes, baseMode),
    sockets: normalizeContainmentCapabilityMode(capabilityModes?.sockets, baseMode),
  };
}

function resolveContainmentCapabilityModesFromEnv(
  baseMode: ProcessContainmentMode,
): ProcessContainmentCapabilityModes | undefined {
  const raw = process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV];
  if (!raw?.trim()) {
    return undefined;
  }

  try {
    return JSON.parse(raw) as ProcessContainmentCapabilityModes;
  } catch {
    return undefined;
  }
}

function normalizeContainmentCapabilityMode(
  mode: ProcessContainmentMode | undefined,
  fallbackMode: ProcessContainmentMode,
): ProcessContainmentMode {
  return mode === 'off' || mode === 'adaptive' || mode === 'strict' ? mode : fallbackMode;
}

function compileContainmentAllowlist(allowlist: ProcessContainmentAllowlist): CompiledContainmentAllowlist {
  return {
    readPatterns: compilePatterns(allowlist.readPatterns ?? []),
    processPatterns: compilePatterns(allowlist.processPatterns ?? []),
    socketHosts: new Set((allowlist.socketHosts ?? []).map(host => host.trim().toLowerCase()).filter(Boolean)),
    socketHostPatterns: compilePatterns(allowlist.socketHostPatterns ?? []),
    socketPathPatterns: compilePatterns(allowlist.socketPathPatterns ?? []),
  };
}

function compilePatterns(patterns: string[]): RegExp[] {
  return patterns.flatMap(pattern => {
    try {
      return [new RegExp(pattern, 'i')];
    } catch {
      return [];
    }
  });
}

function serializeContainmentCapabilityModes(
  capabilityModes: Required<ProcessContainmentCapabilityModes>,
  baseMode: ProcessContainmentMode,
): string | undefined {
  const hasOverride = capabilityModes.reads !== baseMode
    || capabilityModes.processes !== baseMode
    || capabilityModes.sockets !== baseMode;

  return hasOverride ? JSON.stringify(capabilityModes) : undefined;
}

async function emitProcessContainmentEvent(
  state: NodePreloadState,
  command: string,
  blocked: boolean,
  reason: string,
): Promise<void> {
  try {
    await postJson(state, '/v1/runtime-event', {
      event: {
        id: `proc-${randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        category: 'PROCESS_SPAWN',
        actor: detectActor(state),
        resource: command,
        blocked,
        details: {
          source: 'node-preload.process',
          reason,
          containmentMode: state.containmentMode,
        },
      },
    });
  } catch {
    // Best-effort containment audit only.
  }
}

async function emitPreloadIntegrityEvent(
  state: NodePreloadState,
  status: 'healthy' | 'drifted',
  phase: 'installed' | 'runtime-drift',
): Promise<void> {
  try {
    await postJson(state, '/v1/runtime-event', {
      event: {
        id: `integrity-${randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        category: 'PRELOAD_INTEGRITY',
        actor: detectActor(state),
        resource: state.preloadPath,
        blocked: status === 'drifted',
        details: {
          source: 'node-preload.integrity',
          phase,
          status,
          sessionId: state.sessionId,
          controlSessionId: state.controlSessionId,
          containmentMode: state.containmentMode,
          capabilities: NODE_PRELOAD_CAPABILITIES,
        },
      },
    });
  } catch {
    // Best-effort integrity audit only.
  }
}

function getBlockedReadSurfaceReason(state: NodePreloadState, resource: string): string | null {
  if (state.containmentCapabilityModes.reads !== 'strict') {
    return null;
  }

  if (matchesPathAllowlistPattern(state.compiledContainmentAllowlist.readPatterns, resource)) {
    return null;
  }

  const matcher = SENSITIVE_READ_PATTERNS.find(pattern => pattern.test(resource));
  if (!matcher) {
    return null;
  }

  return `strict containment rejected sensitive read pattern ${matcher}`;
}

function connectSocketWithContainment(
  state: NodePreloadState,
  originalFn: AnyFunction,
  rawArgs: unknown[],
): unknown {
  const endpoint = extractSocketEndpoint(rawArgs);
  const blockReason = getBlockedSocketReason(state, endpoint);

  if (blockReason) {
    void emitSocketContainmentEvent(state, endpoint, true, blockReason);
    throw createBlockedSocketError(endpoint.label, blockReason);
  }

  if (state.containmentMode === 'strict' || endpoint.host) {
    void emitSocketContainmentEvent(state, endpoint, false, 'allowed');
  }

  return originalFn.apply(null, rawArgs);
}

function extractSocketEndpoint(args: unknown[]): SocketEndpoint {
  const first = args[0];
  const second = args[1];

  if (typeof first === 'object' && first !== null) {
    const options = first as { host?: string; port?: number; path?: string };
    if (options.path) {
      return {
        path: options.path,
        label: options.path,
      };
    }

    return {
      host: options.host ?? '127.0.0.1',
      port: options.port,
      label: `${options.host ?? '127.0.0.1'}:${options.port ?? 'unknown'}`,
    };
  }

  if (typeof first === 'string' && Number.isNaN(Number(first))) {
    return {
      path: first,
      label: first,
    };
  }

  if (typeof first === 'number') {
    return {
      host: typeof second === 'string' ? second : '127.0.0.1',
      port: first,
      label: `${typeof second === 'string' ? second : '127.0.0.1'}:${first}`,
    };
  }

  return {
    label: 'unknown-socket-target',
  };
}

function getBlockedSocketReason(state: NodePreloadState, endpoint: SocketEndpoint): string | null {
  if (state.containmentCapabilityModes.sockets !== 'strict') {
    return null;
  }

  const socketPath = endpoint.path;
  if (socketPath) {
    if (matchesPathAllowlistPattern(state.compiledContainmentAllowlist.socketPathPatterns, socketPath)) {
      return null;
    }

    return null;
  }

  if (endpoint.host && isAllowlistedSocketHost(state, endpoint.host)) {
    return null;
  }

  if (!endpoint.host || isLoopbackHost(endpoint.host) || isSidecarHost(endpoint.host, state.sidecarUrl)) {
    return null;
  }

  return 'strict containment blocked direct socket egress outside loopback';
}

function isLoopbackHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return normalized === 'localhost'
    || normalized === '127.0.0.1'
    || normalized === '::1'
    || normalized.startsWith('127.');
}

function isSidecarHost(host: string, sidecarUrl: string): boolean {
  try {
    return new URL(sidecarUrl).hostname.toLowerCase() === host.trim().toLowerCase();
  } catch {
    return false;
  }
}

function matchesPathAllowlistPattern(patterns: RegExp[], resource: string): boolean {
  const normalizedResource = resource.includes('\\') ? resource.replace(/\\/g, '/') : resource;

  return patterns.some(pattern => {
    pattern.lastIndex = 0;
    if (pattern.test(resource)) {
      return true;
    }

    if (normalizedResource !== resource) {
      pattern.lastIndex = 0;
      return pattern.test(normalizedResource);
    }

    return false;
  });
}

function isAllowlistedSocketHost(state: NodePreloadState, host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return state.compiledContainmentAllowlist.socketHosts.has(normalized)
    || state.compiledContainmentAllowlist.socketHostPatterns.some(pattern => pattern.test(normalized));
}

async function emitReadContainmentEvent(
  state: NodePreloadState,
  resource: string,
  blocked: boolean,
  reason: string,
  mode: 'sync' | 'stream',
): Promise<void> {
  try {
    await postJson(state, '/v1/runtime-event', {
      event: {
        id: `read-${randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        category: 'FILE_READ',
        actor: detectActor(state),
        resource,
        blocked,
        details: {
          source: `node-preload.fs.${mode}`,
          reason,
          containmentMode: state.containmentMode,
        },
      },
    });
  } catch {
    // Best-effort containment audit only.
  }
}

async function emitSocketContainmentEvent(
  state: NodePreloadState,
  endpoint: SocketEndpoint,
  blocked: boolean,
  reason: string,
): Promise<void> {
  try {
    await postJson(state, '/v1/runtime-event', {
      event: {
        id: `sock-${randomUUID().slice(0, 8)}`,
        timestamp: new Date().toISOString(),
        category: 'SOCKET_EGRESS',
        actor: detectActor(state),
        resource: endpoint.label,
        blocked,
        details: {
          source: 'node-preload.socket',
          host: endpoint.host,
          port: endpoint.port,
          path: endpoint.path,
          reason,
          containmentMode: state.containmentMode,
        },
      },
    });
  } catch {
    // Best-effort containment audit only.
  }
}