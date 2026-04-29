import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { mergeContainmentAllowlists, normalizeContainmentAllowlist, serializeContainmentAllowlist } from '../common/containment';
import { COMMON_CONSTANTS } from '../common/constants';
import type {
  ActorTrustState,
  ProcessContainmentAllowlist,
  ProcessContainmentCapabilityModes,
  ProcessContainmentMode,
} from '../common/types';
import { SealLevel } from '../layers/deep-seal/types';
import { CompatibilityBaselineManager, type CompatibilityBaselineSnapshot, type RuntimeEvent } from '../layers/runtime-monitor';
import type {
  HttpSurfaceResolver,
  MantleHttpRequest,
  MantleReadRequest,
  MantleSearchRequest,
  ReadSurfaceResolver,
  SearchSurfaceResolver,
} from '../layers/resin-traps';
import type { ResiMantleEngine } from '../engine';

const SIDECAR_BLOCKED_EVENT_ALERT_THRESHOLD = 3;
const SIDECAR_RISK_ALERT_THRESHOLD = 5;
const SIDECAR_RESTRICTED_RISK_THRESHOLD = 5;
const SIDECAR_SEALED_RISK_THRESHOLD = 9;

export interface SidecarAddress {
  host: string;
  port: number;
  url: string;
}

interface MantleSidecarOptions {
  host?: string;
  port?: number;
  authToken?: string;
  containmentMode?: ProcessContainmentMode;
  containmentAllowlist?: ProcessContainmentAllowlist;
  bootstrap?: {
    nodeRequireSpecifier?: string;
    nodeImportSpecifier?: string;
  };
}

interface SidecarReadPayload extends MantleReadRequest {
  real?: {
    content?: string;
    metadata?: Record<string, unknown>;
  };
}

interface SidecarSearchPayload extends MantleSearchRequest {
  real?: {
    results?: Array<{
      assetId: string;
      handle: string;
      kind: 'credential' | 'document' | 'endpoint' | 'prompt-watermark';
      excerpt?: string;
    }>;
    metadata?: Record<string, unknown>;
  };
}

interface SidecarHttpPayload extends MantleHttpRequest {
  real?: {
    response?: {
      statusCode: number;
      body?: Record<string, unknown>;
      headers?: Record<string, string>;
    };
    metadata?: Record<string, unknown>;
  };
}

interface SidecarBootstrapSessionPayload {
  sessionId?: string;
  actorId?: string;
  runtime?: string;
  pid?: number;
  ppid?: number;
  cwd?: string;
  execPath?: string;
  argvHash?: string;
  runtimeVersion?: string;
  parentSessionId?: string;
  parentControlSessionId?: string;
  preloadPath?: string;
  capabilities?: string[];
  integrity?: Record<string, unknown>;
}

interface SidecarHeartbeatPayload {
  pid?: number;
  ppid?: number;
  cwd?: string;
  execPath?: string;
  argvHash?: string;
  runtimeVersion?: string;
  integrity?: Record<string, unknown>;
}

type SidecarIntegrityStatus = 'unknown' | 'healthy' | 'drifted';

type SidecarAlertSeverity = 'info' | 'warning' | 'critical';

type SidecarSessionPosture = 'normal' | 'guarded' | 'restricted' | 'sealed';
type SidecarCapability = 'read' | 'search' | 'http' | 'process' | 'socket';
type SidecarCapabilityMap<T> = Record<SidecarCapability, T>;

interface SidecarControlAlert {
  code: string;
  severity: SidecarAlertSeverity;
  message: string;
  triggeredAt: string;
  details?: Record<string, unknown>;
}

interface SidecarSessionAttestation {
  pid?: number;
  ppid?: number;
  cwd?: string;
  execPath?: string;
  argvHash?: string;
  runtimeVersion?: string;
  parentSessionId?: string;
  parentControlSessionId?: string;
  lastHeartbeatAt?: string;
  heartbeatCount: number;
  driftCount: number;
  lastDriftAt?: string;
}

interface SidecarControlSession {
  id: string;
  token: string;
  sessionId: string;
  actorId: string;
  runtime: string;
  pid?: number;
  preloadPath?: string;
  capabilities: string[];
  createdAt: string;
  expiresAt: string;
  lastSeenAt: string;
  requestCount: number;
  routeCounts: Record<string, number>;
  runtimeEvents: number;
  blockedRuntimeEvents: number;
  riskScore: number;
  posture: SidecarSessionPosture;
  capabilityPosture: SidecarCapabilityMap<SidecarSessionPosture>;
  capabilityRisk: SidecarCapabilityMap<number>;
  capabilityBlockedEvents: SidecarCapabilityMap<number>;
  integrityStatus: SidecarIntegrityStatus;
  knownBaselineMatches: number;
  attestation: SidecarSessionAttestation;
  alerts: SidecarControlAlert[];
}

type SidecarAuthorization =
  | { kind: 'admin' }
  | { kind: 'bootstrap' }
  | { kind: 'session'; session: SidecarControlSession };

interface SidecarControlSnapshot {
  activeSessions: number;
  bootstrapExchanges: number;
  blockedRequests: number;
  riskySessions: number;
  inheritedSessions: number;
  lineageRoots: number;
  deepestLineageDepth: number;
  baseline: CompatibilityBaselineSnapshot;
  sessions: Array<{
    id: string;
    sessionId: string;
    actorId: string;
    runtime: string;
    pid?: number;
    createdAt: string;
    expiresAt: string;
    lastSeenAt: string;
    requestCount: number;
    runtimeEvents: number;
    blockedRuntimeEvents: number;
    riskScore: number;
    posture: SidecarSessionPosture;
    capabilityPosture: SidecarCapabilityMap<SidecarSessionPosture>;
    parentSessionId?: string;
    parentControlSessionId?: string;
    lineageDepth: number;
    descendantCount: number;
    childControlSessionIds: string[];
    lineage: Array<{
      id: string;
      sessionId: string;
      actorId: string;
      runtime: string;
      posture: SidecarSessionPosture;
    }>;
    integrityStatus: SidecarIntegrityStatus;
    knownBaselineMatches: number;
    alertCount: number;
    routeCounts: Record<string, number>;
    attestation: {
      pid?: number;
      ppid?: number;
      cwd?: string;
      execPath?: string;
      lastHeartbeatAt?: string;
      heartbeatCount: number;
      driftCount: number;
    };
  }>;
}

export class MantleSidecarServer {
  private engine: ResiMantleEngine;
  private host: string;
  private port: number;
  private authToken: string;
  private bootstrapKey: string;
  private containmentMode: ProcessContainmentMode;
  private containmentAllowlist: ProcessContainmentAllowlist;
  private bootstrap?: MantleSidecarOptions['bootstrap'];
  private server: Server | null = null;
  private address: SidecarAddress | null = null;
  private bootstrapExchanges = 0;
  private blockedRequests = 0;
  private sessionsByToken = new Map<string, SidecarControlSession>();
  private sessionTtlMs: number;
  private heartbeatGraceMs: number;
  private autoPosture: boolean;
  private capabilityQuarantine: boolean;
  private baselineManager: CompatibilityBaselineManager;

  constructor(engine: ResiMantleEngine, options: MantleSidecarOptions = {}) {
    this.engine = engine;
    const configuredRuntimeMonitor = engine.getConfig()?.layers.runtimeMonitor;
    const configuredContainment = configuredRuntimeMonitor?.containment;
    this.host = options.host ?? '127.0.0.1';
    this.port = options.port ?? 7563;
    this.authToken = options.authToken ?? createSidecarAuthToken();
    this.bootstrapKey = createSidecarAuthToken();
    this.containmentMode = options.containmentMode ?? configuredContainment?.mode ?? 'adaptive';
    this.containmentAllowlist = options.containmentAllowlist ?? configuredContainment?.allow ?? {};
    this.bootstrap = options.bootstrap;
    this.sessionTtlMs = configuredRuntimeMonitor?.control.sessionTtlMs ?? 15 * 60_000;
    this.heartbeatGraceMs = configuredRuntimeMonitor?.control.heartbeatGraceMs ?? 45_000;
    this.autoPosture = configuredRuntimeMonitor?.control.autoPosture ?? true;
    this.capabilityQuarantine = configuredRuntimeMonitor?.control.capabilityQuarantine ?? true;
    this.baselineManager = new CompatibilityBaselineManager(engine.options.cwd, configuredRuntimeMonitor?.baseline);
  }

  async start(): Promise<SidecarAddress> {
    if (this.address) {
      return this.address;
    }

    await this.engine.init();
    await this.baselineManager.initialize();

    this.server = createServer((request, response) => {
      void this.handle(request, response);
    });

    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(this.port, this.host, () => {
        this.server!.off('error', reject);
        resolve();
      });
    });

    const address = this.server.address() as AddressInfo;
    this.address = {
      host: this.host,
      port: address.port,
      url: `http://${this.host}:${address.port}`,
    };

    await this.engine.getAuditor().record({
      source: 'MantleSidecarServer',
      type: 'SIDECAR_STARTED',
      details: {
        host: this.address.host,
        port: this.address.port,
        url: this.address.url,
      },
      explanation: `Mantle sidecar listening on ${this.address.url}`,
    });

    return this.address;
  }

  async stop(): Promise<void> {
    if (!this.server) {
      return;
    }

    const server = this.server;

    await new Promise<void>((resolve, reject) => {
      server.close(error => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });

      if ('closeIdleConnections' in server && typeof server.closeIdleConnections === 'function') {
        server.closeIdleConnections();
      }

      if ('closeAllConnections' in server && typeof server.closeAllConnections === 'function') {
        server.closeAllConnections();
      }
    });

    await this.engine.getResourceInventory().persist();
    await this.baselineManager.persist();
    this.server = null;
    this.address = null;
  }

  getAddress(): SidecarAddress | null {
    return this.address;
  }

  getAuthToken(): string {
    return this.authToken;
  }

  getBootstrapKey(): string {
    return this.bootstrapKey;
  }

  getEffectiveContainmentAllowlist(): ProcessContainmentAllowlist {
    return this.computeEffectiveContainmentAllowlist();
  }

  getControlSnapshot(): SidecarControlSnapshot {
    const activeSessions = Array.from(this.sessionsByToken.values())
      .filter(session => !this.isSessionExpired(session));
    const sessionsById = new Map(activeSessions.map(session => [session.id, session]));
    const sessionsBySessionId = createSnapshotSessionIdIndex(activeSessions);
    const childControlSessionIds = createSnapshotChildIndex(activeSessions, sessionsById, sessionsBySessionId);

    const sessions = activeSessions
      .sort((left, right) => right.riskScore - left.riskScore)
      .map(session => {
        const lineage = buildSnapshotLineage(session, sessionsById, sessionsBySessionId);
        const lineageDepth = Math.max(0, lineage.length - 1);

        return {
          id: session.id,
          sessionId: session.sessionId,
          actorId: session.actorId,
          runtime: session.runtime,
          pid: session.pid,
          createdAt: session.createdAt,
          expiresAt: session.expiresAt,
          lastSeenAt: session.lastSeenAt,
          requestCount: session.requestCount,
          runtimeEvents: session.runtimeEvents,
          blockedRuntimeEvents: session.blockedRuntimeEvents,
          riskScore: session.riskScore,
          posture: session.posture,
          capabilityPosture: { ...session.capabilityPosture },
          parentSessionId: session.attestation.parentSessionId,
          parentControlSessionId: session.attestation.parentControlSessionId,
          lineageDepth,
          descendantCount: countSnapshotDescendants(session.id, childControlSessionIds),
          childControlSessionIds: [...(childControlSessionIds.get(session.id) ?? [])],
          lineage,
          integrityStatus: session.integrityStatus,
          knownBaselineMatches: session.knownBaselineMatches,
          alertCount: session.alerts.length,
          routeCounts: { ...session.routeCounts },
          attestation: {
            pid: session.attestation.pid,
            ppid: session.attestation.ppid,
            cwd: session.attestation.cwd,
            execPath: session.attestation.execPath,
            lastHeartbeatAt: session.attestation.lastHeartbeatAt,
            heartbeatCount: session.attestation.heartbeatCount,
            driftCount: session.attestation.driftCount,
          },
        };
      });

    return {
      activeSessions: sessions.length,
      bootstrapExchanges: this.bootstrapExchanges,
      blockedRequests: this.blockedRequests,
      riskySessions: sessions.filter(session => session.riskScore >= SIDECAR_RISK_ALERT_THRESHOLD || session.alertCount > 0).length,
      inheritedSessions: sessions.filter(session => Boolean(session.parentControlSessionId || session.parentSessionId)).length,
      lineageRoots: sessions.filter(session => session.lineageDepth === 0).length,
      deepestLineageDepth: sessions.reduce((current, session) => Math.max(current, session.lineageDepth), 0),
      baseline: this.baselineManager.getSnapshot(),
      sessions,
    };
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const pathname = request.url ? new URL(request.url, 'http://localhost').pathname : '/';

    try {
      if (request.method === 'GET' && pathname === '/health') {
        this.json(response, 200, { ok: true, address: this.address });
        return;
      }

      if (request.method === 'GET' && pathname === '/env') {
        if (!this.authorizeRequest(request, 'bootstrap')) {
          this.blockedRequests++;
          this.json(response, 401, { error: 'Unauthorized' });
          return;
        }

        this.json(response, 200, this.buildEnvPayload());
        return;
      }

      if (request.method === 'GET' && pathname === '/v1/bootstrap/node') {
        if (!this.authorizeRequest(request, 'bootstrap')) {
          this.blockedRequests++;
          this.json(response, 401, { error: 'Unauthorized' });
          return;
        }

        this.json(response, 200, this.buildNodeBootstrapPayload());
        return;
      }

      if (request.method === 'POST' && pathname === '/v1/bootstrap/session') {
        const authorization = this.authorizeRequest(request, 'bootstrap');
        if (!authorization) {
          this.blockedRequests++;
          this.json(response, 401, { error: 'Unauthorized' });
          return;
        }

        const payload = await this.readJson<SidecarBootstrapSessionPayload>(request);
        const session = this.createControlSession(payload);
        this.json(response, 200, {
          sessionToken: session.token,
          sessionId: session.sessionId,
          controlSessionId: session.id,
          posture: session.posture,
          integrityStatus: session.integrityStatus,
          containment: this.buildSessionContainmentEnvelope(session),
          tokenExpiresAt: session.expiresAt,
          auth: {
            header: COMMON_CONSTANTS.SIDECAR_TOKEN_HEADER,
          },
        });
        return;
      }

      if (request.method === 'GET' && pathname === '/v1/control/sessions') {
        const authorization = this.authorizeRequest(request, 'admin');
        if (!authorization || authorization.kind !== 'admin') {
          this.blockedRequests++;
          this.json(response, 401, { error: 'Unauthorized' });
          return;
        }

        this.json(response, 200, this.getControlSnapshot());
        return;
      }

      const authorization = this.authorizeRequest(request, 'session');
      if (!authorization) {
        this.blockedRequests++;
        this.json(response, 401, { error: 'Unauthorized' });
        return;
      }

      this.recordControlRequest(authorization, pathname);

      if (request.method === 'POST' && pathname === '/v1/session/heartbeat') {
        if (authorization.kind !== 'session') {
          this.blockedRequests++;
          this.json(response, 401, { error: 'Unauthorized' });
          return;
        }

        const payload = await this.readJson<SidecarHeartbeatPayload>(request);
        const updatedSession = this.recordSessionHeartbeat(authorization.session, payload);
        this.json(response, 202, {
          accepted: true,
          posture: updatedSession.posture,
          integrityStatus: updatedSession.integrityStatus,
          riskScore: updatedSession.riskScore,
          containment: this.buildSessionContainmentEnvelope(updatedSession),
          tokenExpiresAt: updatedSession.expiresAt,
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/v1/read') {
        const payload = this.applySessionEnvelope(
          await this.readJson<SidecarReadPayload>(request),
          authorization,
          'read',
        );
        const fallback: ReadSurfaceResolver | undefined = this.allowRealFallback(authorization, 'read', payload) && payload.real
          ? async () => ({ matched: true, content: payload.real?.content, metadata: payload.real?.metadata })
          : undefined;
        const result = await this.engine.resolveReadSurface(payload, fallback);
        this.json(response, 200, result);
        return;
      }

      if (request.method === 'POST' && pathname === '/v1/search') {
        const payload = this.applySessionEnvelope(
          await this.readJson<SidecarSearchPayload>(request),
          authorization,
          'search',
        );
        const fallback: SearchSurfaceResolver | undefined = this.allowRealFallback(authorization, 'search', payload) && payload.real
          ? async () => ({ matched: true, results: payload.real?.results, metadata: payload.real?.metadata })
          : undefined;
        const result = await this.engine.resolveSearchSurface(payload, fallback);
        this.json(response, 200, result);
        return;
      }

      if (request.method === 'POST' && pathname === '/v1/http') {
        const payload = this.applySessionEnvelope(
          await this.readJson<SidecarHttpPayload>(request),
          authorization,
          'http',
        );
        const fallback: HttpSurfaceResolver | undefined = this.allowRealFallback(authorization, 'http', payload) && payload.real
          ? async () => ({ matched: true, response: payload.real?.response, metadata: payload.real?.metadata })
          : undefined;
        const result = await this.engine.resolveHttpSurface(payload, fallback);
        this.json(response, 200, result);
        return;
      }

      if (request.method === 'POST' && pathname === '/v1/runtime-event') {
        const payload = await this.readJson<{ event: RuntimeEvent }>(request);
        await this.engine.observeRuntimeEvent(payload.event);
        this.recordRuntimeEvent(authorization, payload.event);
        this.json(response, 202, { accepted: true });
        return;
      }

      this.json(response, 404, { error: 'Not found' });
    } catch (error) {
      this.json(response, 500, { error: (error as Error).message });
    }
  }

  private buildEnvPayload(): Record<string, string> {
    const address = this.address;
    const env: Record<string, string> = {
      [COMMON_CONSTANTS.ACTIVE_ENV]: '1',
      [COMMON_CONSTANTS.MANTLE_AUTO_ENV]: '1',
      [COMMON_CONSTANTS.SIDECAR_URL_ENV]: address?.url ?? '',
      [COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_KEY_ENV]: this.bootstrapKey,
      [COMMON_CONSTANTS.PROCESS_CONTAINMENT_ENV]: this.containmentMode,
    };

    const serializedAllowlist = serializeContainmentAllowlist(this.computeEffectiveContainmentAllowlist());
    if (serializedAllowlist) {
      env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_RULES_ENV] = serializedAllowlist;
    }

    return env;
  }

  private buildNodeBootstrapPayload(): Record<string, unknown> {
    const env = this.buildEnvPayload();
    const requireSpecifier = this.bootstrap?.nodeRequireSpecifier ?? COMMON_CONSTANTS.NODE_CJS_PRELOAD_SPECIFIER;
    const importSpecifier = this.bootstrap?.nodeImportSpecifier ?? COMMON_CONSTANTS.NODE_ESM_PRELOAD_SPECIFIER;

    return {
      runtime: 'node',
      env,
      auth: {
        header: COMMON_CONSTANTS.SIDECAR_TOKEN_HEADER,
        bootstrapHeader: COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_HEADER,
      },
      bootstrap: {
        exchangePath: '/v1/bootstrap/session',
        heartbeatPath: '/v1/session/heartbeat',
        sessionTtlMs: this.sessionTtlMs,
        heartbeatGraceMs: this.heartbeatGraceMs,
      },
      requireSpecifier,
      importSpecifier,
      nodeOptions: {
        require: `--require ${requireSpecifier}`,
        import: `--import ${importSpecifier}`,
      },
    };
  }

  private async readJson<T>(request: IncomingMessage): Promise<T> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const raw = Buffer.concat(chunks).toString('utf-8');
    return JSON.parse(raw || '{}') as T;
  }

  private json(response: ServerResponse, statusCode: number, body: unknown): void {
    response.statusCode = statusCode;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify(body));
  }

  private authorizeRequest(
    request: IncomingMessage,
    scope: 'admin' | 'bootstrap' | 'session',
  ): SidecarAuthorization | null {
    const tokenHeader = this.readHeader(request, COMMON_CONSTANTS.SIDECAR_TOKEN_HEADER);
    if (tokenHeader && this.matchesSecret(tokenHeader, this.authToken)) {
      return { kind: 'admin' };
    }

    if (scope === 'admin') {
      return null;
    }

    if (scope === 'bootstrap') {
      const bootstrapHeader = this.readHeader(request, COMMON_CONSTANTS.SIDECAR_BOOTSTRAP_HEADER) ?? tokenHeader;
      if (bootstrapHeader && this.matchesSecret(bootstrapHeader, this.bootstrapKey)) {
        return { kind: 'bootstrap' };
      }

      return null;
    }

    if (!tokenHeader) {
      return null;
    }

    const session = this.sessionsByToken.get(tokenHeader);
    if (!session) {
      return null;
    }

    if (this.isSessionExpired(session)) {
      this.sessionsByToken.delete(tokenHeader);
      return null;
    }

    return {
      kind: 'session',
      session,
    };
  }

  private createControlSession(payload: SidecarBootstrapSessionPayload): SidecarControlSession {
    const createdAt = new Date().toISOString();
    const session: SidecarControlSession = {
      id: `ctrl-${randomBytes(6).toString('hex')}`,
      token: createSidecarAuthToken(),
      sessionId: payload.sessionId?.trim() || `mantle-${randomBytes(6).toString('hex')}`,
      actorId: payload.actorId?.trim() || 'node-preload',
      runtime: payload.runtime?.trim() || 'unknown',
      pid: typeof payload.pid === 'number' ? payload.pid : undefined,
      preloadPath: payload.preloadPath?.trim(),
      capabilities: sanitizeCapabilities(payload.capabilities),
      createdAt,
      expiresAt: new Date(Date.now() + this.sessionTtlMs).toISOString(),
      lastSeenAt: createdAt,
      requestCount: 0,
      routeCounts: {},
      runtimeEvents: 0,
      blockedRuntimeEvents: 0,
      riskScore: 0,
      posture: 'normal',
      capabilityPosture: createCapabilityPostureMap('normal'),
      capabilityRisk: createCapabilityNumberMap(0),
      capabilityBlockedEvents: createCapabilityNumberMap(0),
      integrityStatus: resolveIntegrityStatus(payload.integrity),
      knownBaselineMatches: 0,
      attestation: {
        pid: typeof payload.pid === 'number' ? payload.pid : undefined,
        ppid: typeof payload.ppid === 'number' ? payload.ppid : undefined,
        cwd: payload.cwd?.trim(),
        execPath: payload.execPath?.trim(),
        argvHash: payload.argvHash?.trim(),
        runtimeVersion: payload.runtimeVersion?.trim(),
        parentSessionId: payload.parentSessionId?.trim(),
        parentControlSessionId: payload.parentControlSessionId?.trim(),
        heartbeatCount: 0,
        driftCount: 0,
      },
      alerts: [],
    };

    const parentSession = this.findParentControlSession(payload);
    if (parentSession) {
      inheritParentControlState(session, parentSession);
      this.pushSessionAlert(session, {
        code: 'parent-quarantine-inherited',
        severity: 'info',
        message: 'Child control session inherited quarantine posture from its parent runtime.',
        details: {
          parentControlSessionId: parentSession.id,
          parentSessionId: parentSession.sessionId,
          capabilityPosture: parentSession.capabilityPosture,
        },
      });
    }

    if (session.integrityStatus === 'drifted') {
      session.riskScore = SIDECAR_SEALED_RISK_THRESHOLD;
      this.pushSessionAlert(session, {
        code: 'preload-integrity-drift',
        severity: 'critical',
        message: 'Bootstrap session reported preload integrity drift during attachment.',
        details: payload.integrity,
      });
    }

    this.refreshSessionPosture(session);

    this.sessionsByToken.set(session.token, session);
    this.bootstrapExchanges++;
    return session;
  }

  private findParentControlSession(payload: SidecarBootstrapSessionPayload): SidecarControlSession | undefined {
    const activeSessions = Array.from(this.sessionsByToken.values())
      .filter(session => !this.isSessionExpired(session));

    const parentControlSessionId = payload.parentControlSessionId?.trim();
    if (parentControlSessionId) {
      return activeSessions.find(session => session.id === parentControlSessionId);
    }

    const parentSessionId = payload.parentSessionId?.trim();
    if (!parentSessionId) {
      return undefined;
    }

    return activeSessions
      .filter(session => session.sessionId === parentSessionId)
      .sort((left, right) => Date.parse(right.lastSeenAt) - Date.parse(left.lastSeenAt))[0];
  }

  private recordControlRequest(authorization: SidecarAuthorization, pathname: string): void {
    if (authorization.kind !== 'session') {
      return;
    }

    const session = authorization.session;
    session.lastSeenAt = new Date().toISOString();
    session.requestCount += 1;
    session.expiresAt = new Date(Date.now() + this.sessionTtlMs).toISOString();
    session.routeCounts[pathname] = (session.routeCounts[pathname] ?? 0) + 1;

    if (this.isHeartbeatStale(session)) {
      session.riskScore = Math.max(session.riskScore, SIDECAR_RESTRICTED_RISK_THRESHOLD);
      this.pushSessionAlert(session, {
        code: 'heartbeat-stale',
        severity: 'warning',
        message: 'Session heartbeat is stale; posture elevated until the process re-attests.',
        details: {
          lastHeartbeatAt: session.attestation.lastHeartbeatAt,
          graceMs: this.heartbeatGraceMs,
        },
      });
    }

    this.refreshSessionPosture(session);
  }

  private recordRuntimeEvent(authorization: SidecarAuthorization, event: RuntimeEvent): void {
    if (authorization.kind !== 'session') {
      return;
    }

    const session = authorization.session;
    session.runtimeEvents += 1;
    const affectedCapabilities = mapEventCapabilities(event);
    const isKnownCompatibleActivity = !event.blocked && this.baselineManager.matchesLearnedAllowlist(event);

    if (isKnownCompatibleActivity) {
      session.knownBaselineMatches += 1;
    }

    if (event.blocked) {
      session.blockedRuntimeEvents += 1;
      session.riskScore += 2;
      incrementCapabilityRisk(session, affectedCapabilities, 2, true);
    }

    if (!isKnownCompatibleActivity && (event.category === 'PROCESS_SPAWN' || event.category === 'SOCKET_EGRESS' || event.category === 'PRELOAD_INTEGRITY')) {
      session.riskScore += 1;
      incrementCapabilityRisk(session, affectedCapabilities, 1, false);
    }

    if (event.category === 'PRELOAD_INTEGRITY') {
      const status = typeof event.details['status'] === 'string' ? String(event.details['status']) : 'unknown';
      session.integrityStatus = status === 'drifted' ? 'drifted' : status === 'healthy' ? 'healthy' : 'unknown';

      if (session.integrityStatus === 'drifted') {
        session.riskScore = Math.max(session.riskScore, SIDECAR_SEALED_RISK_THRESHOLD);
        this.pushSessionAlert(session, {
          code: 'preload-integrity-drift',
          severity: 'critical',
          message: 'Runtime monitor reported preload integrity drift after bootstrap.',
          details: event.details,
        });
        setCapabilityRiskFloor(session, ALL_SIDECAR_CAPABILITIES, SIDECAR_SEALED_RISK_THRESHOLD);
      }
    }

    if (session.blockedRuntimeEvents >= SIDECAR_BLOCKED_EVENT_ALERT_THRESHOLD) {
      this.pushSessionAlert(session, {
        code: 'blocked-runtime-burst',
        severity: 'warning',
        message: 'Multiple runtime events were blocked for this control session.',
        details: {
          blockedRuntimeEvents: session.blockedRuntimeEvents,
          lastCategory: event.category,
          resource: event.resource,
        },
      });
    }

    if (session.riskScore >= SIDECAR_RISK_ALERT_THRESHOLD) {
      this.pushSessionAlert(session, {
        code: 'session-pressure',
        severity: 'warning',
        message: 'Control session accumulated elevated runtime pressure.',
        details: {
          riskScore: session.riskScore,
          category: event.category,
          blocked: event.blocked ?? false,
        },
      });
    }

    this.baselineManager.observe(event, {
      posture: session.posture,
      integrityStatus: session.integrityStatus,
    });
    this.refreshSessionPosture(session);
  }

  private recordSessionHeartbeat(
    session: SidecarControlSession,
    payload: SidecarHeartbeatPayload,
  ): SidecarControlSession {
    const now = new Date().toISOString();
    const drift = detectAttestationDrift(session.attestation, payload);

    session.lastSeenAt = now;
    session.expiresAt = new Date(Date.now() + this.sessionTtlMs).toISOString();
    session.attestation.lastHeartbeatAt = now;
    session.attestation.heartbeatCount += 1;

    if (typeof payload.pid === 'number' && session.attestation.pid === undefined) {
      session.attestation.pid = payload.pid;
    }
    if (typeof payload.ppid === 'number' && session.attestation.ppid === undefined) {
      session.attestation.ppid = payload.ppid;
    }
    if (payload.cwd?.trim() && !session.attestation.cwd) {
      session.attestation.cwd = payload.cwd.trim();
    }
    if (payload.execPath?.trim() && !session.attestation.execPath) {
      session.attestation.execPath = payload.execPath.trim();
    }
    if (payload.argvHash?.trim() && !session.attestation.argvHash) {
      session.attestation.argvHash = payload.argvHash.trim();
    }
    if (payload.runtimeVersion?.trim() && !session.attestation.runtimeVersion) {
      session.attestation.runtimeVersion = payload.runtimeVersion.trim();
    }

    if (drift.length > 0) {
      session.attestation.driftCount += drift.length;
      session.attestation.lastDriftAt = now;
      session.integrityStatus = 'drifted';
      session.riskScore = Math.max(session.riskScore + 4, SIDECAR_SEALED_RISK_THRESHOLD);
      this.pushSessionAlert(session, {
        code: 'attestation-drift',
        severity: 'critical',
        message: 'Session heartbeat drifted from its original process attestation.',
        details: {
          drift,
        },
      });
    } else if (session.integrityStatus === 'unknown') {
      session.integrityStatus = resolveIntegrityStatus(payload.integrity) === 'unknown' ? 'healthy' : resolveIntegrityStatus(payload.integrity);
    }

    this.refreshSessionPosture(session);
    return session;
  }

  private applySessionEnvelope<T extends SidecarReadPayload | SidecarSearchPayload | SidecarHttpPayload>(
    payload: T,
    authorization: SidecarAuthorization,
    surface: 'read' | 'search' | 'http',
  ): T {
    if (authorization.kind !== 'session') {
      return payload;
    }

    const session = authorization.session;
    const surfacePosture = this.resolveSurfacePosture(session, surface);
    const zoneLevel = moreRestrictiveZoneLevel(payload.zoneLevel, postureToZoneLevel(surfacePosture));
    const trustState = moreRestrictiveTrustState(payload.trustState, postureToTrustState(surfacePosture));
    const riskTags = mergeUniqueStrings(
      payload.riskTags,
      [`session:${session.posture}`],
      surfacePosture === session.posture ? undefined : [`surface:${surface}:${surfacePosture}`],
      session.attestation.driftCount > 0 ? ['attestation-drift'] : [],
    );
    const anomalyScore = Math.max(payload.anomalyScore ?? 0, resolvePostureAnomalyFloor(surfacePosture, surface, payload));
    const isKnownActor = resolveKnownActorForPosture(payload.isKnownActor, surfacePosture, surface, payload);

    return {
      ...payload,
      anomalyScore,
      isKnownActor,
      zoneLevel,
      trustState,
      riskTags,
      metadata: {
        ...(payload.metadata ?? {}),
        controlSessionId: session.id,
        controlPosture: session.posture,
        surfacePosture,
        controlRiskScore: session.riskScore,
        capabilityPosture: session.capabilityPosture,
        integrityStatus: session.integrityStatus,
        attestedPid: session.attestation.pid,
        attestationDriftCount: session.attestation.driftCount,
        heartbeatCount: session.attestation.heartbeatCount,
        knownBaselineMatches: session.knownBaselineMatches,
      },
    };
  }

  private refreshSessionPosture(session: SidecarControlSession): void {
    if (!this.autoPosture) {
      return;
    }

    session.capabilityPosture = this.capabilityQuarantine
      ? deriveCapabilityPostureMap(session)
      : createCapabilityPostureMap(session.posture);
    session.posture = derivePosture(session, session.capabilityPosture);
  }

  private allowRealFallback(
    authorization: SidecarAuthorization,
    surface: 'read' | 'search' | 'http',
    payload: SidecarReadPayload | SidecarSearchPayload | SidecarHttpPayload,
  ): boolean {
    if (authorization.kind !== 'session') {
      return true;
    }

    const posture = this.resolveSurfacePosture(authorization.session, surface);
    if (posture === 'sealed') {
      return false;
    }

    if (posture === 'restricted') {
      if (surface === 'http') {
        const method = 'method' in payload && typeof payload.method === 'string' ? payload.method.toUpperCase() : 'GET';
        return ['GET', 'HEAD', 'OPTIONS'].includes(method);
      }

      return false;
    }

    return true;
  }

  private buildSessionContainmentEnvelope(session: SidecarControlSession): {
    mode: ProcessContainmentMode;
    allowlist: ProcessContainmentAllowlist;
    capabilityModes: ProcessContainmentCapabilityModes;
    capabilityPosture: SidecarCapabilityMap<SidecarSessionPosture>;
  } {
    return {
      mode: this.containmentMode,
      allowlist: this.computeEffectiveContainmentAllowlist(),
      capabilityModes: {
        reads: resolveCapabilityContainmentMode(this.containmentMode, this.resolveContainmentCapabilityPosture(session, 'read'), this.capabilityQuarantine),
        processes: resolveCapabilityContainmentMode(this.containmentMode, this.resolveContainmentCapabilityPosture(session, 'process'), this.capabilityQuarantine),
        sockets: resolveCapabilityContainmentMode(this.containmentMode, this.resolveContainmentCapabilityPosture(session, 'socket'), this.capabilityQuarantine),
      },
      capabilityPosture: { ...session.capabilityPosture },
    };
  }

  private resolveContainmentCapabilityPosture(
    session: SidecarControlSession,
    capability: 'read' | 'process' | 'socket',
  ): SidecarSessionPosture {
    if (!this.capabilityQuarantine || this.isHeartbeatStale(session) || session.integrityStatus === 'drifted') {
      return session.posture;
    }

    if (capability === 'read') {
      return session.capabilityPosture.read;
    }

    return session.capabilityPosture[capability];
  }

  private resolveSurfacePosture(
    session: SidecarControlSession,
    surface: 'read' | 'search' | 'http',
  ): SidecarSessionPosture {
    if (!this.capabilityQuarantine || this.isHeartbeatStale(session) || session.integrityStatus === 'drifted') {
      return session.posture;
    }

    if (surface === 'read') {
      return session.capabilityPosture.read;
    }

    return session.capabilityPosture[surface];
  }

  private pushSessionAlert(
    session: SidecarControlSession,
    alert: Omit<SidecarControlAlert, 'triggeredAt'>,
  ): void {
    if (session.alerts.some(existing => existing.code === alert.code)) {
      return;
    }

    session.alerts.push({
      ...alert,
      triggeredAt: new Date().toISOString(),
    });
  }

  private readHeader(request: IncomingMessage, headerName: string): string | undefined {
    const value = request.headers[headerName];
    const headerValue = Array.isArray(value) ? value[0] : value;
    return typeof headerValue === 'string' && headerValue ? headerValue : undefined;
  }

  private isSessionExpired(session: SidecarControlSession): boolean {
    return Date.parse(session.expiresAt) <= Date.now();
  }

  private isHeartbeatStale(session: SidecarControlSession): boolean {
    if (!session.attestation.lastHeartbeatAt) {
      return false;
    }

    const lastHeartbeat = Date.parse(session.attestation.lastHeartbeatAt);
    return Number.isFinite(lastHeartbeat) && (Date.now() - lastHeartbeat) > this.heartbeatGraceMs;
  }

  private computeEffectiveContainmentAllowlist(): ProcessContainmentAllowlist {
    if (!this.baselineManager.shouldAutoApplyToContainment()) {
      return normalizeContainmentAllowlist(this.containmentAllowlist);
    }

    return mergeContainmentAllowlists(this.containmentAllowlist, this.baselineManager.getLearnedAllowlist());
  }

  private matchesSecret(provided: string, expectedValue: string): boolean {
    const expected = Buffer.from(expectedValue, 'utf-8');
    const candidate = Buffer.from(provided, 'utf-8');

    if (expected.length !== candidate.length) {
      return false;
    }

    return timingSafeEqual(expected, candidate);
  }
}

function createSidecarAuthToken(): string {
  return randomBytes(24).toString('hex');
}

const ALL_SIDECAR_CAPABILITIES: SidecarCapability[] = ['read', 'search', 'http', 'process', 'socket'];

function createCapabilityNumberMap(initialValue: number): SidecarCapabilityMap<number> {
  return {
    read: initialValue,
    search: initialValue,
    http: initialValue,
    process: initialValue,
    socket: initialValue,
  };
}

function createCapabilityPostureMap(initialValue: SidecarSessionPosture): SidecarCapabilityMap<SidecarSessionPosture> {
  return {
    read: initialValue,
    search: initialValue,
    http: initialValue,
    process: initialValue,
    socket: initialValue,
  };
}

function createSnapshotSessionIdIndex(
  sessions: SidecarControlSession[],
): Map<string, SidecarControlSession[]> {
  const index = new Map<string, SidecarControlSession[]>();

  for (const session of sessions) {
    const existing = index.get(session.sessionId) ?? [];
    existing.push(session);
    index.set(session.sessionId, existing);
  }

  for (const bucket of index.values()) {
    bucket.sort((left, right) => Date.parse(right.lastSeenAt) - Date.parse(left.lastSeenAt));
  }

  return index;
}

function createSnapshotChildIndex(
  sessions: SidecarControlSession[],
  sessionsById: Map<string, SidecarControlSession>,
  sessionsBySessionId: Map<string, SidecarControlSession[]>,
): Map<string, string[]> {
  const children = new Map<string, string[]>();

  for (const session of sessions) {
    const parent = resolveSnapshotParentSession(session, sessionsById, sessionsBySessionId);
    if (!parent) {
      continue;
    }

    const existing = children.get(parent.id) ?? [];
    existing.push(session.id);
    existing.sort();
    children.set(parent.id, existing);
  }

  return children;
}

function resolveSnapshotParentSession(
  session: SidecarControlSession,
  sessionsById: Map<string, SidecarControlSession>,
  sessionsBySessionId: Map<string, SidecarControlSession[]>,
): SidecarControlSession | undefined {
  const parentControlSessionId = session.attestation.parentControlSessionId?.trim();
  if (parentControlSessionId) {
    return sessionsById.get(parentControlSessionId);
  }

  const parentSessionId = session.attestation.parentSessionId?.trim();
  if (!parentSessionId) {
    return undefined;
  }

  return (sessionsBySessionId.get(parentSessionId) ?? [])
    .find(candidate => candidate.id !== session.id);
}

function buildSnapshotLineage(
  session: SidecarControlSession,
  sessionsById: Map<string, SidecarControlSession>,
  sessionsBySessionId: Map<string, SidecarControlSession[]>,
): Array<{
  id: string;
  sessionId: string;
  actorId: string;
  runtime: string;
  posture: SidecarSessionPosture;
}> {
  const lineage: Array<{
    id: string;
    sessionId: string;
    actorId: string;
    runtime: string;
    posture: SidecarSessionPosture;
  }> = [];
  const seen = new Set<string>();
  let cursor: SidecarControlSession | undefined = session;

  while (cursor && !seen.has(cursor.id)) {
    lineage.unshift({
      id: cursor.id,
      sessionId: cursor.sessionId,
      actorId: cursor.actorId,
      runtime: cursor.runtime,
      posture: cursor.posture,
    });
    seen.add(cursor.id);
    cursor = resolveSnapshotParentSession(cursor, sessionsById, sessionsBySessionId);
  }

  return lineage;
}

function countSnapshotDescendants(
  sessionId: string,
  childControlSessionIds: Map<string, string[]>,
): number {
  const seen = new Set<string>();
  const queue = [...(childControlSessionIds.get(sessionId) ?? [])];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current || seen.has(current)) {
      continue;
    }

    seen.add(current);
    queue.push(...(childControlSessionIds.get(current) ?? []));
  }

  return seen.size;
}

function inheritParentControlState(
  child: SidecarControlSession,
  parent: SidecarControlSession,
): void {
  child.capabilityPosture = { ...parent.capabilityPosture };
  child.capabilityRisk = { ...parent.capabilityRisk };
  child.capabilityBlockedEvents = { ...parent.capabilityBlockedEvents };
  child.riskScore = Math.max(child.riskScore, parent.riskScore);
}

function mapEventCapabilities(event: RuntimeEvent): SidecarCapability[] {
  switch (event.category) {
    case 'FILE_READ':
      return ['read'];
    case 'HTTP_OUTBOUND':
      return ['http'];
    case 'PROCESS_SPAWN':
      return ['process'];
    case 'SOCKET_EGRESS':
      return ['socket'];
    case 'PRELOAD_INTEGRITY':
      return [...ALL_SIDECAR_CAPABILITIES];
    default:
      return [];
  }
}

function incrementCapabilityRisk(
  session: SidecarControlSession,
  capabilities: SidecarCapability[],
  delta: number,
  blocked: boolean,
): void {
  for (const capability of capabilities) {
    session.capabilityRisk[capability] += delta;
    if (blocked) {
      session.capabilityBlockedEvents[capability] += 1;
    }
  }
}

function setCapabilityRiskFloor(
  session: SidecarControlSession,
  capabilities: SidecarCapability[],
  floor: number,
): void {
  for (const capability of capabilities) {
    session.capabilityRisk[capability] = Math.max(session.capabilityRisk[capability], floor);
  }
}

function sanitizeCapabilities(capabilities?: string[]): string[] {
  if (!Array.isArray(capabilities)) {
    return [];
  }

  return capabilities
    .map(capability => capability.trim())
    .filter(Boolean)
    .slice(0, 32);
}

function resolveIntegrityStatus(integrity?: Record<string, unknown>): SidecarIntegrityStatus {
  const status = typeof integrity?.status === 'string' ? integrity.status : 'unknown';
  if (status === 'healthy' || status === 'drifted') {
    return status;
  }

  return 'unknown';
}

function derivePosture(
  session: SidecarControlSession,
  capabilityPosture: SidecarCapabilityMap<SidecarSessionPosture>,
): SidecarSessionPosture {
  if (session.integrityStatus === 'drifted' || session.attestation.driftCount > 0 || session.riskScore >= SIDECAR_SEALED_RISK_THRESHOLD) {
    return 'sealed';
  }

  const hottestCapability = mostRestrictivePosture(Object.values(capabilityPosture));
  if (hottestCapability === 'sealed') {
    return 'sealed';
  }

  if (session.blockedRuntimeEvents >= 2 || session.riskScore >= SIDECAR_RESTRICTED_RISK_THRESHOLD || hottestCapability === 'restricted') {
    return 'restricted';
  }

  if (session.riskScore >= 2 || session.runtimeEvents >= 3 || hottestCapability === 'guarded') {
    return 'guarded';
  }

  return 'normal';
}

function detectAttestationDrift(
  attestation: SidecarSessionAttestation,
  payload: SidecarHeartbeatPayload,
): Array<{ field: string; expected: string | number; actual: string | number }> {
  const drift: Array<{ field: string; expected: string | number; actual: string | number }> = [];
  const checks = [
    ['pid', attestation.pid, payload.pid],
    ['ppid', attestation.ppid, payload.ppid],
    ['cwd', attestation.cwd, payload.cwd?.trim()],
    ['execPath', attestation.execPath, payload.execPath?.trim()],
    ['argvHash', attestation.argvHash, payload.argvHash?.trim()],
    ['runtimeVersion', attestation.runtimeVersion, payload.runtimeVersion?.trim()],
  ] as const;

  for (const [field, expected, actual] of checks) {
    if (expected !== undefined && actual !== undefined && expected !== actual) {
      drift.push({ field, expected, actual });
    }
  }

  return drift;
}

function postureToZoneLevel(posture: SidecarSessionPosture): SealLevel | undefined {
  switch (posture) {
    case 'guarded':
      return SealLevel.OBSERVED;
    case 'restricted':
      return SealLevel.RESTRICTED;
    case 'sealed':
      return SealLevel.SEALED;
    default:
      return undefined;
  }
}

function postureToTrustState(posture: SidecarSessionPosture): ActorTrustState | undefined {
  switch (posture) {
    case 'guarded':
      return 'observed';
    case 'restricted':
      return 'restricted';
    case 'sealed':
      return 'quarantined';
    default:
      return undefined;
  }
}

function moreRestrictiveZoneLevel(current: SealLevel | undefined, next: SealLevel | undefined): SealLevel | undefined {
  if (!next) {
    return current;
  }

  if (!current) {
    return next;
  }

  const order: Record<SealLevel, number> = {
    [SealLevel.OPEN]: 0,
    [SealLevel.OBSERVED]: 1,
    [SealLevel.RESTRICTED]: 2,
    [SealLevel.SEALED]: 3,
  };

  return order[next] > order[current] ? next : current;
}

function moreRestrictiveTrustState(
  current: ActorTrustState | undefined,
  next: ActorTrustState | undefined,
): ActorTrustState | undefined {
  if (!next) {
    return current;
  }

  if (!current) {
    return next;
  }

  const order: Record<ActorTrustState, number> = {
    trusted: 0,
    observed: 1,
    suspicious: 2,
    deceptive: 3,
    restricted: 4,
    quarantined: 5,
  };

  return order[next] > order[current] ? next : current;
}

function mergeUniqueStrings(...groups: Array<string[] | undefined>): string[] {
  return Array.from(new Set(groups.flatMap(group => group ?? []).filter(Boolean)));
}

function resolvePostureAnomalyFloor(
  posture: SidecarSessionPosture,
  surface: 'read' | 'search' | 'http',
  payload: SidecarReadPayload | SidecarSearchPayload | SidecarHttpPayload,
): number {
  if (posture === 'sealed') {
    return 0.98;
  }

  if (posture === 'restricted') {
    if (surface === 'http') {
      const method = 'method' in payload && typeof payload.method === 'string' ? payload.method.toUpperCase() : 'GET';
      return ['GET', 'HEAD', 'OPTIONS'].includes(method) ? 0.78 : 0.92;
    }

    return 0.72;
  }

  if (posture === 'guarded') {
    return 0.45;
  }

  return 0;
}

function resolveKnownActorForPosture(
  current: boolean | undefined,
  posture: SidecarSessionPosture,
  surface: 'read' | 'search' | 'http',
  payload: SidecarReadPayload | SidecarSearchPayload | SidecarHttpPayload,
): boolean {
  if (posture === 'sealed') {
    return false;
  }

  if (posture === 'restricted') {
    if (surface === 'http') {
      const method = 'method' in payload && typeof payload.method === 'string' ? payload.method.toUpperCase() : 'GET';
      return ['GET', 'HEAD', 'OPTIONS'].includes(method) ? (current ?? false) : false;
    }

    return current ?? false;
  }

  return current ?? true;
}

function deriveCapabilityPostureMap(session: SidecarControlSession): SidecarCapabilityMap<SidecarSessionPosture> {
  const directPosture = {
    read: deriveCapabilityPosture(session, 'read'),
    search: 'normal' as SidecarSessionPosture,
    http: deriveCapabilityPosture(session, 'http'),
    process: deriveCapabilityPosture(session, 'process'),
    socket: deriveCapabilityPosture(session, 'socket'),
  };

  directPosture.search = moreRestrictiveSessionPosture(directPosture.search, directPosture.read);
  return directPosture;
}

function deriveCapabilityPosture(
  session: SidecarControlSession,
  capability: SidecarCapability,
): SidecarSessionPosture {
  if (session.integrityStatus === 'drifted' || session.attestation.driftCount > 0) {
    return 'sealed';
  }

  const risk = session.capabilityRisk[capability];
  const blocked = session.capabilityBlockedEvents[capability];
  if (risk >= SIDECAR_SEALED_RISK_THRESHOLD) {
    return 'sealed';
  }

  if (blocked >= 2 || risk >= SIDECAR_RESTRICTED_RISK_THRESHOLD) {
    return 'restricted';
  }

  if (risk >= 2 || blocked >= 1) {
    return 'guarded';
  }

  return 'normal';
}

function mostRestrictivePosture(postures: SidecarSessionPosture[]): SidecarSessionPosture {
  return postures.reduce((current, next) => moreRestrictiveSessionPosture(current, next), 'normal');
}

function moreRestrictiveSessionPosture(
  current: SidecarSessionPosture,
  next: SidecarSessionPosture,
): SidecarSessionPosture {
  const order: Record<SidecarSessionPosture, number> = {
    normal: 0,
    guarded: 1,
    restricted: 2,
    sealed: 3,
  };

  return order[next] > order[current] ? next : current;
}

function resolveCapabilityContainmentMode(
  baseMode: ProcessContainmentMode,
  posture: SidecarSessionPosture,
  capabilityQuarantine: boolean,
): ProcessContainmentMode {
  if (!capabilityQuarantine || baseMode === 'off' || baseMode === 'strict') {
    return baseMode;
  }

  return posture === 'restricted' || posture === 'sealed' ? 'strict' : baseMode;
}