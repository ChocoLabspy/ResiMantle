import { AccessDecision, RiskLevel } from '@resimantle/types';
import type { ActorTrustState } from '../../common/types';
import type { Auditor } from '../audit';
import type { Gatekeeper } from '../access-gatekeeper';
import { SealLevel } from '../deep-seal/types';
import type { PolicyEngine } from '../policy-engine';
import { HttpDecoyOverlay } from './http-decoy-overlay';
import { ReadOverlay } from './read-overlay';
import { ResourceInventory } from './resource-inventory';
import { SearchOverlay } from './search-overlay';
import type {
  HttpOverlayRequest,
  ReadOverlayRequest,
  SearchOverlayRequest,
  SearchOverlayResultItem,
} from './overlay-provider';

export type MantleDelivery = 'synthetic' | 'real' | 'mixed' | 'blocked' | 'none';

export interface MantleSurfaceContext {
  actorId: string;
  sessionId: string;
  trustState?: ActorTrustState;
  stackTags?: string[];
  riskTags?: string[];
  anomalyScore?: number;
  isKnownActor?: boolean;
  zoneLevel?: SealLevel;
  metadata?: Record<string, unknown>;
}

export interface MantleReadRequest extends MantleSurfaceContext {
  resource: string;
}

export interface MantleSearchRequest extends MantleSurfaceContext {
  query: string;
  limit?: number;
}

export interface MantleHttpRequest extends MantleSurfaceContext {
  path: string;
  method: string;
  body?: Record<string, unknown>;
}

export interface RealReadResolution {
  matched: boolean;
  content?: string;
  metadata?: Record<string, unknown>;
}

export interface RealSearchResolution {
  matched: boolean;
  results?: SearchOverlayResultItem[];
  metadata?: Record<string, unknown>;
}

export interface RealHttpResolution {
  matched: boolean;
  response?: {
    statusCode: number;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
  metadata?: Record<string, unknown>;
}

export type ReadSurfaceResolver = (request: MantleReadRequest) => Promise<RealReadResolution>;
export type SearchSurfaceResolver = (request: MantleSearchRequest) => Promise<RealSearchResolution>;
export type HttpSurfaceResolver = (request: MantleHttpRequest) => Promise<RealHttpResolution>;

export interface MantleDecisionContext {
  trustState: ActorTrustState;
  policyDecision: AccessDecision;
  gatekeeperDecision: AccessDecision;
  effectiveDecision: AccessDecision;
  zoneLevel: SealLevel;
  policyReason: string;
  gatekeeperReason: string;
}

export interface CoordinatedReadResolution extends MantleDecisionContext {
  source: MantleDelivery;
  content?: string;
  storyId?: string;
  assetId?: string;
  metadata?: Record<string, unknown>;
}

export interface CoordinatedSearchResolution extends MantleDecisionContext {
  source: MantleDelivery;
  results?: SearchOverlayResultItem[];
  storyId?: string;
  metadata?: Record<string, unknown>;
}

export interface CoordinatedHttpResolution extends MantleDecisionContext {
  source: MantleDelivery;
  response?: {
    statusCode: number;
    body?: Record<string, unknown>;
    headers?: Record<string, string>;
  };
  storyId?: string;
  assetId?: string;
  metadata?: Record<string, unknown>;
}

interface OverlayCoordinatorOptions {
  gatekeeper: Gatekeeper;
  policyEngine?: PolicyEngine | null;
  readOverlay: ReadOverlay;
  searchOverlay: SearchOverlay;
  httpOverlay: HttpDecoyOverlay;
  inventory?: ResourceInventory;
  auditor?: Auditor;
}

const BLOCKING_DECISIONS = new Set<AccessDecision>([
  AccessDecision.REQUIRE_APPROVAL,
  AccessDecision.QUARANTINE,
  AccessDecision.BLOCK,
]);

const DECISION_ORDER: Record<AccessDecision, number> = {
  [AccessDecision.ALLOW]: 0,
  [AccessDecision.ALLOW_WITH_LOGGING]: 1,
  [AccessDecision.ALLOW_READ_ONLY]: 2,
  [AccessDecision.ALLOW_LIMITED]: 3,
  [AccessDecision.REQUIRE_APPROVAL]: 4,
  [AccessDecision.QUARANTINE]: 5,
  [AccessDecision.BLOCK]: 6,
};

const TRUST_ORDER: Record<ActorTrustState, number> = {
  trusted: 0,
  observed: 1,
  suspicious: 2,
  deceptive: 3,
  restricted: 4,
  quarantined: 5,
};

export class OverlayCoordinator {
  private gatekeeper: Gatekeeper;
  private policyEngine?: PolicyEngine | null;
  private readOverlay: ReadOverlay;
  private searchOverlay: SearchOverlay;
  private httpOverlay: HttpDecoyOverlay;
  private inventory?: ResourceInventory;
  private auditor?: Auditor;

  constructor(options: OverlayCoordinatorOptions) {
    this.gatekeeper = options.gatekeeper;
    this.policyEngine = options.policyEngine;
    this.readOverlay = options.readOverlay;
    this.searchOverlay = options.searchOverlay;
    this.httpOverlay = options.httpOverlay;
    this.inventory = options.inventory;
    this.auditor = options.auditor;
  }

  async resolveRead(request: MantleReadRequest, fallback?: ReadSurfaceResolver): Promise<CoordinatedReadResolution> {
    const decision = await this.evaluateDecision('read', request.resource, request);
    const synthetic = await this.readOverlay.resolve(this.toReadOverlayRequest(request, decision));
    const real = fallback ? await fallback(request) : { matched: false };

    let result: CoordinatedReadResolution;

    if (synthetic.matched) {
      result = {
        ...decision,
        source: 'synthetic',
        content: synthetic.content,
        storyId: synthetic.storyId,
        assetId: synthetic.assetId,
        metadata: synthetic.metadata,
      };
    } else if (real.matched) {
      result = {
        ...decision,
        source: 'real',
        content: real.content,
        metadata: real.metadata,
      };
    } else if (BLOCKING_DECISIONS.has(decision.effectiveDecision)) {
      result = {
        ...decision,
        source: 'blocked',
        metadata: { reason: decision.effectiveDecision },
      };
    } else {
      result = {
        ...decision,
        source: 'none',
      };
    }

    await this.auditOutcome('read', request, result);
    return result;
  }

  async resolveSearch(request: MantleSearchRequest, fallback?: SearchSurfaceResolver): Promise<CoordinatedSearchResolution> {
    const decision = await this.evaluateDecision('search', request.query, request);
    const synthetic = await this.searchOverlay.resolve(this.toSearchOverlayRequest(request, decision));
    const real = fallback ? await fallback(request) : { matched: false };

    const syntheticResults = synthetic.results ?? [];
    const realResults = real.results ?? [];

    let result: CoordinatedSearchResolution;

    if (synthetic.matched && real.matched) {
      result = {
        ...decision,
        source: 'mixed',
        storyId: synthetic.storyId,
        results: mergeResults(syntheticResults, realResults, request.limit),
        metadata: {
          ...real.metadata,
          ...synthetic.metadata,
          syntheticCount: syntheticResults.length,
          realCount: realResults.length,
        },
      };
    } else if (synthetic.matched) {
      result = {
        ...decision,
        source: 'synthetic',
        storyId: synthetic.storyId,
        results: syntheticResults,
        metadata: synthetic.metadata,
      };
    } else if (real.matched) {
      result = {
        ...decision,
        source: 'real',
        results: realResults,
        metadata: real.metadata,
      };
    } else if (BLOCKING_DECISIONS.has(decision.effectiveDecision)) {
      result = {
        ...decision,
        source: 'blocked',
        metadata: { reason: decision.effectiveDecision },
      };
    } else {
      result = {
        ...decision,
        source: 'none',
      };
    }

    await this.auditOutcome('search', request, result);
    return result;
  }

  async resolveHttp(request: MantleHttpRequest, fallback?: HttpSurfaceResolver): Promise<CoordinatedHttpResolution> {
    const decision = await this.evaluateDecision(request.method, request.path, request);
    const synthetic = await this.httpOverlay.resolve(this.toHttpOverlayRequest(request, decision));
    const real = fallback ? await fallback(request) : { matched: false };

    let result: CoordinatedHttpResolution;

    if (synthetic.matched) {
      result = {
        ...decision,
        source: 'synthetic',
        storyId: synthetic.storyId,
        assetId: synthetic.assetId,
        response: synthetic.response,
        metadata: synthetic.metadata,
      };
    } else if (real.matched) {
      result = {
        ...decision,
        source: 'real',
        response: real.response,
        metadata: real.metadata,
      };
    } else if (BLOCKING_DECISIONS.has(decision.effectiveDecision)) {
      result = {
        ...decision,
        source: 'blocked',
        metadata: { reason: decision.effectiveDecision },
      };
    } else {
      result = {
        ...decision,
        source: 'none',
      };
    }

    await this.auditOutcome('http', request, result);
    return result;
  }

  private async evaluateDecision(
    action: string,
    resource: string,
    request: MantleSurfaceContext,
  ): Promise<MantleDecisionContext> {
    const inferred = this.inventory?.infer(resource, action, {
      stackTags: request.stackTags,
      riskTags: request.riskTags,
    }) ?? {
      stackTags: request.stackTags ?? [],
      riskTags: request.riskTags ?? [],
      matchedResources: [],
    };

    request.stackTags = inferred.stackTags;
    request.riskTags = inferred.riskTags;

    const zoneLevel = request.zoneLevel ?? inferZoneLevel(resource, action, inferred.riskTags);
    const decisionMetadata = {
      ...(request.metadata ?? {}),
      actionKind: classifyActionKind(action),
      matchedResources: inferred.matchedResources,
      sensitivity: inferSensitivity(zoneLevel, inferred.riskTags),
      stackTags: inferred.stackTags,
      riskTags: inferred.riskTags,
      zoneLevel,
    };
    request.metadata = decisionMetadata;

    const policyEvaluation = this.policyEngine
      ? await this.policyEngine.evaluate({
        resource,
        actor: request.actorId,
        action,
        metadata: decisionMetadata,
      })
      : {
        decision: AccessDecision.ALLOW,
        reason: 'No policy engine configured — default ALLOW',
      };

    const gatekeeperEvent = await this.gatekeeper.evaluate({
      actor: request.actorId,
      resource,
      action,
      anomalyScore: request.anomalyScore ?? 0,
      zoneLevel,
      isKnownActor: request.isKnownActor ?? request.trustState === 'trusted',
      category: action,
      metadata: decisionMetadata,
    });

    const effectiveDecision = moreRestrictiveDecision(policyEvaluation.decision, gatekeeperEvent.decision);
    const derivedTrustState = deriveTrustState(
      request.trustState ?? defaultTrustState(request.isKnownActor),
      effectiveDecision,
    );

    return {
      trustState: derivedTrustState,
      policyDecision: policyEvaluation.decision,
      gatekeeperDecision: gatekeeperEvent.decision,
      effectiveDecision,
      zoneLevel,
      policyReason: policyEvaluation.reason,
      gatekeeperReason: gatekeeperEvent.reason,
    };
  }

  private toReadOverlayRequest(request: MantleReadRequest, decision: MantleDecisionContext): ReadOverlayRequest {
    return {
      actorId: request.actorId,
      sessionId: request.sessionId,
      trustState: decision.trustState,
      stackTags: request.stackTags,
      riskTags: request.riskTags,
      resource: request.resource,
      metadata: request.metadata,
    };
  }

  private toSearchOverlayRequest(request: MantleSearchRequest, decision: MantleDecisionContext): SearchOverlayRequest {
    return {
      actorId: request.actorId,
      sessionId: request.sessionId,
      trustState: decision.trustState,
      stackTags: request.stackTags,
      riskTags: request.riskTags,
      query: request.query,
      limit: request.limit,
      metadata: request.metadata,
    };
  }

  private toHttpOverlayRequest(request: MantleHttpRequest, decision: MantleDecisionContext): HttpOverlayRequest {
    return {
      actorId: request.actorId,
      sessionId: request.sessionId,
      trustState: decision.trustState,
      stackTags: request.stackTags,
      riskTags: request.riskTags,
      path: request.path,
      method: request.method,
      decision: decision.effectiveDecision,
      body: request.body,
      metadata: request.metadata,
    };
  }

  private async auditOutcome(
    overlayKind: 'read' | 'search' | 'http',
    request: MantleReadRequest | MantleSearchRequest | MantleHttpRequest,
    result: CoordinatedReadResolution | CoordinatedSearchResolution | CoordinatedHttpResolution,
  ): Promise<void> {
    const resource = 'resource' in request ? request.resource : 'query' in request ? request.query : request.path;
    const assetId = 'assetId' in result ? result.assetId : undefined;
    await this.inventory?.observe({
      resource,
      action: overlayKind,
      stackTags: request.stackTags,
      riskTags: request.riskTags,
      source: 'heuristic',
    });
    await this.auditor?.record({
      source: 'ResinTraps.OverlayCoordinator',
      type: 'MANTLE_DECISION',
      severity: decisionSeverity(result.effectiveDecision),
      decision: result.effectiveDecision,
      details: {
        actorId: request.actorId,
        sessionId: request.sessionId,
        overlayKind,
        source: result.source,
        resource,
        storyId: result.storyId,
        assetId,
        stackTags: request.stackTags,
        riskTags: request.riskTags,
        trustState: result.trustState,
        policyDecision: result.policyDecision,
        gatekeeperDecision: result.gatekeeperDecision,
        effectiveDecision: result.effectiveDecision,
      },
      explanation: `Mantle resolved ${overlayKind} access with source=${result.source} and decision=${result.effectiveDecision}.`,
    });
  }
}

function mergeResults(
  synthetic: SearchOverlayResultItem[],
  real: SearchOverlayResultItem[],
  limit?: number,
): SearchOverlayResultItem[] {
  const merged: SearchOverlayResultItem[] = [];
  const seenHandles = new Set<string>();

  for (const item of [...synthetic, ...real]) {
    const normalized = item.handle.toLowerCase();
    if (seenHandles.has(normalized)) {
      continue;
    }
    seenHandles.add(normalized);
    merged.push(item);

    if (limit && merged.length >= limit) {
      break;
    }
  }

  return merged;
}

function moreRestrictiveDecision(left: AccessDecision, right: AccessDecision): AccessDecision {
  return DECISION_ORDER[left] >= DECISION_ORDER[right] ? left : right;
}

function defaultTrustState(isKnownActor?: boolean): ActorTrustState {
  return isKnownActor ? 'trusted' : 'observed';
}

function deriveTrustState(baseTrustState: ActorTrustState, decision: AccessDecision): ActorTrustState {
  let derived = baseTrustState;

  if (decision === AccessDecision.BLOCK || decision === AccessDecision.QUARANTINE) {
    derived = baseTrustState === 'trusted' ? 'restricted' : 'quarantined';
  } else if (
    decision === AccessDecision.REQUIRE_APPROVAL
    || decision === AccessDecision.ALLOW_LIMITED
    || decision === AccessDecision.ALLOW_READ_ONLY
  ) {
    derived = baseTrustState === 'trusted' ? 'restricted' : 'deceptive';
  } else if (decision === AccessDecision.ALLOW_WITH_LOGGING && baseTrustState !== 'trusted') {
    derived = 'suspicious';
  }

  return TRUST_ORDER[derived] >= TRUST_ORDER[baseTrustState] ? derived : baseTrustState;
}

function inferZoneLevel(resource: string, action: string, riskTags: string[] = []): SealLevel {
  const target = `${action} ${resource}`.toLowerCase();

  if (riskTags.some(tag => ['tokens', 'secrets', 'process'].includes(tag))) {
    return SealLevel.SEALED;
  }

  if (riskTags.some(tag => ['admin', 'database', 'prompt', 'tool', 'webhook'].includes(tag))) {
    return SealLevel.RESTRICTED;
  }

  if (/(\.env|\.git|backup|dump|rotate|token|secret|credential|database)/.test(target)) {
    return SealLevel.SEALED;
  }

  if (/(admin|internal|debug|billing|webhook|prompt|tool)/.test(target)) {
    return SealLevel.RESTRICTED;
  }

  return SealLevel.OBSERVED;
}

function inferSensitivity(zoneLevel: SealLevel, riskTags: string[]): 'low' | 'medium' | 'high' {
  if (zoneLevel === SealLevel.SEALED || riskTags.some(tag => ['tokens', 'secrets', 'database', 'process', 'admin'].includes(tag))) {
    return 'high';
  }

  if (zoneLevel === SealLevel.RESTRICTED || riskTags.length > 0) {
    return 'medium';
  }

  return 'low';
}

function classifyActionKind(action: string): 'read' | 'search' | 'mutate' | 'process' | 'egress' | 'other' {
  const normalized = action.toLowerCase();

  if (normalized === 'read' || normalized === 'search' || normalized === 'get' || normalized === 'head') {
    return normalized === 'search' ? 'search' : 'read';
  }

  if (/(spawn|exec|fork|shell|process)/.test(normalized)) {
    return 'process';
  }

  if (['post', 'put', 'patch', 'delete'].includes(normalized)) {
    return 'mutate';
  }

  if (/(http|socket|connect|egress)/.test(normalized)) {
    return 'egress';
  }

  return 'other';
}

function decisionSeverity(decision: AccessDecision): RiskLevel {
  switch (decision) {
    case AccessDecision.BLOCK:
      return RiskLevel.HIGH;
    case AccessDecision.QUARANTINE:
    case AccessDecision.REQUIRE_APPROVAL:
      return RiskLevel.MEDIUM;
    case AccessDecision.ALLOW_LIMITED:
    case AccessDecision.ALLOW_READ_ONLY:
      return RiskLevel.LOW;
    case AccessDecision.ALLOW_WITH_LOGGING:
      return RiskLevel.INFO;
    case AccessDecision.ALLOW:
    default:
      return RiskLevel.NONE;
  }
}