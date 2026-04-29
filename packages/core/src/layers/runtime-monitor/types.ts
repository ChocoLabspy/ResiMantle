export enum RuntimeEventCategory {
  HTTP_OUTBOUND = 'HTTP_OUTBOUND',
  FILE_READ = 'FILE_READ',
  FILE_WRITE = 'FILE_WRITE',
  FILE_DELETE = 'FILE_DELETE',
  PROCESS_SPAWN = 'PROCESS_SPAWN',
  AI_CALL = 'AI_CALL',
  DATABASE_QUERY = 'DATABASE_QUERY',
  SOCKET_EGRESS = 'SOCKET_EGRESS',
  PRELOAD_INTEGRITY = 'PRELOAD_INTEGRITY',
  MONITOR_ALERT = 'MONITOR_ALERT',
}

export interface RuntimeEvent {
  id: string;
  timestamp: string;
  category: RuntimeEventCategory;
  actor: string;
  resource: string;
  details: Record<string, unknown>;
  blocked?: boolean;
  durationMs?: number;
}

export interface AccessLog {
  event: RuntimeEvent;
  allowed: boolean;
  reason?: string;
}

export interface EndpointProfile {
  path: string;
  frequency: number;
  lastAccessed: string;
}

export interface MonitorAlertingOptions {
  enabled: boolean;
  windowMs: number;
  highRiskEventThreshold: number;
  blockedEventThreshold: number;
}

export interface MonitorAlert {
  id: string;
  code: string;
  severity: 'warning' | 'critical';
  triggeredAt: string;
  message: string;
  supportingEventIds: string[];
  pressureScore: number;
}

export interface MonitorControlState {
  pressureScore: number;
  recentHighRiskEvents: number;
  blockedEventsInWindow: number;
  status: 'normal' | 'elevated' | 'critical';
  alertCount: number;
  lastAlertAt?: string;
}

export interface MonitorOptions {
  interceptHttp: boolean;
  interceptFs: boolean;
  interceptProcess: boolean;
  ignorePatterns: string[];
  sampleRate: number;
  maxBufferSize: number;
  alerting: MonitorAlertingOptions;
}

export const DEFAULT_MONITOR_OPTIONS: MonitorOptions = {
  interceptHttp: true,
  interceptFs: true,
  interceptProcess: true,
  ignorePatterns: ['node_modules', '\\.resimantle', '\\.git'],
  sampleRate: 1,
  maxBufferSize: 500,
  alerting: {
    enabled: true,
    windowMs: 10_000,
    highRiskEventThreshold: 4,
    blockedEventThreshold: 3,
  },
};
