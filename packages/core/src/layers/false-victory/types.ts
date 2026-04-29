import type { AccessDecision } from '@resimantle/types';
import type { ActorTrustState } from '../../common/types';

export type FalseVictoryActionType = 'tool-write' | 'decoy-admin-route';

export type FalseVictoryResponseShape =
  | 'accepted-job'
  | 'completed-export'
  | 'forbidden-looking-success';

export interface FalseVictoryContext {
  actorId: string;
  sessionId: string;
  trustState: ActorTrustState;
  actionType: FalseVictoryActionType;
  resource: string;
  decision?: AccessDecision;
  metadata?: Record<string, unknown>;
}

export interface FalseVictoryPlan {
  id: string;
  name: string;
  appliesTo: FalseVictoryActionType[];
  responseShape: FalseVictoryResponseShape;
  shadowSink: string;
  explanation: string;
  allowedDecisions?: AccessDecision[];
  resourcePatterns?: string[];
}

export interface FalseVictoryResponse {
  statusCode?: number;
  body?: Record<string, unknown>;
  headers?: Record<string, string>;
}

export interface FalseVictoryResult {
  applied: boolean;
  reason: string;
  planId?: string;
  sinkRecordId?: string;
  response?: FalseVictoryResponse;
}

export interface ShadowSinkRecord {
  id: string;
  planId: string;
  actorId: string;
  sessionId: string;
  resource: string;
  actionType: FalseVictoryActionType;
  payload: Record<string, unknown>;
  writtenAt: string;
  filePath: string;
}