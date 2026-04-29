import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ResiMantleEngine } from '../engine';
import { MantleSidecarServer } from './mantle-sidecar';
import type { ResiMantleConfig } from '../config/schema';

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
            readPatterns: ['manual-allowed-secret\\.txt$'],
            processPatterns: ['^powershell\\s+-Command\\s+Write-Output allowlisted$'],
            socketHosts: ['allowed.example.invalid'],
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

describe('MantleSidecarServer', () => {
  it('serves mantle decisions over HTTP for external wrappers', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-sidecar-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'sidecar-project' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src']));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const token = server.getAuthToken();

      const bootstrapResponse = await fetch(`${address.url}/v1/bootstrap/node`, {
        headers: {
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
      });
      const bootstrapPayload = await bootstrapResponse.json() as {
        runtime: string;
        env: Record<string, string>;
        auth: { header: string; bootstrapHeader: string };
        bootstrap: { exchangePath: string; heartbeatPath: string; sessionTtlMs: number; heartbeatGraceMs: number };
        nodeOptions: { require: string };
      };

      const sessionResponse = await fetch(`${address.url}/v1/bootstrap/session`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
        body: JSON.stringify({
          sessionId: 'sidecar-session',
          actorId: 'sidecar-client',
          runtime: 'node',
          pid: process.pid,
          ppid: process.ppid,
          cwd: projectRoot,
          execPath: process.execPath,
          runtimeVersion: process.version,
          capabilities: ['fs.read', 'http.request'],
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const sessionPayload = await sessionResponse.json() as {
        sessionToken: string;
        sessionId: string;
        controlSessionId: string;
        tokenExpiresAt: string;
      };

      const unauthorizedResponse = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          actorId: 'unauthorized-sidecar-client',
          sessionId: 'unauthorized-sidecar-session',
          resource: 'docs/runbooks/billing-reconcile.md',
        }),
      });

      const directReadResponse = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          actorId: 'sidecar-client',
          sessionId: 'sidecar-session',
          resource: 'src/index.ts',
          real: {
            content: 'export const ok = true;\n',
          },
        }),
      });

      const heartbeatResponse = await fetch(`${address.url}/v1/session/heartbeat`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          pid: process.pid,
          ppid: process.ppid,
          cwd: `${projectRoot}-drift`,
          execPath: process.execPath,
          runtimeVersion: process.version,
          integrity: {
            status: 'healthy',
          },
        }),
      });

      const sealedReadResponse = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          actorId: 'sidecar-client',
          sessionId: 'sidecar-session',
          resource: 'src/index.ts',
          real: {
            content: 'export const ok = true;\n',
          },
        }),
      });

      const directReadPayload = await directReadResponse.json() as { source: string; content?: string };
      const heartbeatPayload = await heartbeatResponse.json() as {
        accepted: boolean;
        posture: string;
        integrityStatus: string;
        riskScore: number;
      };
      const sealedReadPayload = await sealedReadResponse.json() as { source: string; metadata?: Record<string, unknown> };

      const bootstrapRouteResponse = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': bootstrapKey,
        },
        body: JSON.stringify({
          actorId: 'bootstrap-sidecar-client',
          sessionId: 'bootstrap-sidecar-session',
          resource: 'docs/runbooks/billing-reconcile.md',
        }),
      });

      const response = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          actorId: 'sidecar-client',
          sessionId: 'sidecar-session',
          resource: 'docs/runbooks/billing-reconcile.md',
          anomalyScore: 0.75,
        }),
      });

      await fetch(`${address.url}/v1/runtime-event`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          event: {
            id: 'event-integrity',
            timestamp: new Date().toISOString(),
            category: 'PRELOAD_INTEGRITY',
            actor: 'sidecar-client',
            resource: 'node-preload.js',
            blocked: true,
            details: {
              status: 'drifted',
            },
          },
        }),
      });

      await fetch(`${address.url}/v1/runtime-event`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          event: {
            id: 'event-process',
            timestamp: new Date().toISOString(),
            category: 'PROCESS_SPAWN',
            actor: 'sidecar-client',
            resource: 'powershell -Command Invoke-WebRequest',
            blocked: true,
            details: {
              source: 'test',
            },
          },
        }),
      });

      const controlResponse = await fetch(`${address.url}/v1/control/sessions`, {
        headers: {
          'x-resimantle-sidecar-token': token,
        },
      });
      const controlPayload = await controlResponse.json() as {
        activeSessions: number;
        bootstrapExchanges: number;
        riskySessions: number;
        sessions: Array<{
          sessionId: string;
          runtimeEvents: number;
          blockedRuntimeEvents: number;
          riskScore: number;
          posture: string;
          integrityStatus: string;
          alertCount: number;
          routeCounts: Record<string, number>;
          attestation: {
            heartbeatCount: number;
            driftCount: number;
            cwd?: string;
          };
        }>;
      };

      const payload = await response.json() as { source: string; content?: string };

      expect(bootstrapResponse.status).toBe(200);
      expect(bootstrapPayload.runtime).toBe('node');
      expect(bootstrapPayload.env['RESIMANTLE_SIDECAR_URL']).toBe(address.url);
      expect(bootstrapPayload.env['RESIMANTLE_SIDECAR_BOOTSTRAP_KEY']).toBe(bootstrapKey);
      expect(bootstrapPayload.env['RESIMANTLE_PROCESS_CONTAINMENT']).toBe('strict');
      expect(bootstrapPayload.env['RESIMANTLE_PROCESS_CONTAINMENT_RULES']).toContain('manual-allowed-secret');
      expect(bootstrapPayload.auth.header).toBe('x-resimantle-sidecar-token');
      expect(bootstrapPayload.auth.bootstrapHeader).toBe('x-resimantle-sidecar-bootstrap');
      expect(bootstrapPayload.bootstrap.exchangePath).toBe('/v1/bootstrap/session');
      expect(bootstrapPayload.bootstrap.heartbeatPath).toBe('/v1/session/heartbeat');
      expect(bootstrapPayload.nodeOptions.require).toContain('node-preload.js');
      expect(sessionResponse.status).toBe(200);
      expect(sessionPayload.sessionId).toBe('sidecar-session');
      expect(sessionPayload.sessionToken).toBeTruthy();
      expect(unauthorizedResponse.status).toBe(401);
      expect(bootstrapRouteResponse.status).toBe(401);
      expect(directReadResponse.status).toBe(200);
      expect(directReadPayload.source).toBe('real');
      expect(heartbeatResponse.status).toBe(202);
      expect(heartbeatPayload.accepted).toBe(true);
      expect(heartbeatPayload.posture).toBe('sealed');
      expect(heartbeatPayload.integrityStatus).toBe('drifted');
      expect(sealedReadResponse.status).toBe(200);
      expect(sealedReadPayload.source).toBe('blocked');
      expect(response.status).toBe(200);
      expect(payload.source).toBe('synthetic');
      expect(payload.content).toContain('Billing Reconcile v2');
      expect(controlResponse.status).toBe(200);
      expect(controlPayload.activeSessions).toBe(1);
      expect(controlPayload.bootstrapExchanges).toBe(1);
      expect(controlPayload.riskySessions).toBe(1);
      expect(controlPayload.sessions[0]?.sessionId).toBe('sidecar-session');
      expect(controlPayload.sessions[0]?.runtimeEvents).toBe(2);
      expect(controlPayload.sessions[0]?.blockedRuntimeEvents).toBe(2);
      expect(controlPayload.sessions[0]?.riskScore).toBeGreaterThanOrEqual(5);
      expect(controlPayload.sessions[0]?.posture).toBe('sealed');
      expect(controlPayload.sessions[0]?.integrityStatus).toBe('drifted');
      expect(controlPayload.sessions[0]?.alertCount).toBeGreaterThan(0);
      expect(controlPayload.sessions[0]?.routeCounts['/v1/read']).toBe(3);
      expect(controlPayload.sessions[0]?.routeCounts['/v1/session/heartbeat']).toBe(1);
      expect(controlPayload.sessions[0]?.routeCounts['/v1/runtime-event']).toBe(2);
      expect(controlPayload.sessions[0]?.attestation.heartbeatCount).toBe(1);
      expect(controlPayload.sessions[0]?.attestation.driftCount).toBeGreaterThan(0);
      expect(controlPayload.sessions[0]?.attestation.cwd).toBe(projectRoot);

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('quarantines risky process capability without breaking compatible read fallback', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-sidecar-capability-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'sidecar-capability-project' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src'], 'adaptive'));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const token = server.getAuthToken();

      const sessionResponse = await fetch(`${address.url}/v1/bootstrap/session`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
        body: JSON.stringify({
          sessionId: 'sidecar-capability-session',
          actorId: 'sidecar-client',
          runtime: 'node',
          pid: process.pid,
          ppid: process.ppid,
          cwd: projectRoot,
          execPath: process.execPath,
          runtimeVersion: process.version,
          capabilities: ['fs.read', 'process.spawn'],
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const sessionPayload = await sessionResponse.json() as { sessionToken: string };

      const sendRuntimeEvent = (id: string) => fetch(`${address.url}/v1/runtime-event`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          event: {
            id,
            timestamp: new Date().toISOString(),
            category: 'PROCESS_SPAWN',
            actor: 'sidecar-client',
            resource: 'powershell -Command Invoke-WebRequest',
            blocked: true,
            details: {
              source: 'test',
            },
          },
        }),
      });

      await sendRuntimeEvent('process-block-1');
      await sendRuntimeEvent('process-block-2');

      const heartbeatResponse = await fetch(`${address.url}/v1/session/heartbeat`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          pid: process.pid,
          ppid: process.ppid,
          cwd: projectRoot,
          execPath: process.execPath,
          runtimeVersion: process.version,
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const heartbeatPayload = await heartbeatResponse.json() as {
        posture: string;
        containment: {
          capabilityModes?: {
            reads?: string;
            processes?: string;
          };
        };
      };

      const readResponse = await fetch(`${address.url}/v1/read`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': sessionPayload.sessionToken,
        },
        body: JSON.stringify({
          actorId: 'sidecar-client',
          sessionId: 'sidecar-capability-session',
          resource: 'src/index.ts',
          real: {
            content: 'export const ok = true;\n',
          },
        }),
      });
      const readPayload = await readResponse.json() as { source: string; content?: string };

      const controlResponse = await fetch(`${address.url}/v1/control/sessions`, {
        headers: {
          'x-resimantle-sidecar-token': token,
        },
      });
      const controlPayload = await controlResponse.json() as {
        sessions: Array<{
          posture: string;
          capabilityPosture: {
            read: string;
            process: string;
          };
        }>;
      };

      expect(heartbeatPayload.posture).toBe('restricted');
      expect(heartbeatPayload.containment.capabilityModes?.processes).toBe('strict');
      expect(heartbeatPayload.containment.capabilityModes?.reads).toBe('adaptive');
      expect(readPayload.source).toBe('real');
      expect(readPayload.content).toBe('export const ok = true;\n');
      expect(controlPayload.sessions[0]?.posture).toBe('restricted');
      expect(controlPayload.sessions[0]?.capabilityPosture.process).toBe('restricted');
      expect(controlPayload.sessions[0]?.capabilityPosture.read).toBe('normal');

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('inherits parent capability quarantine into child bootstrap sessions', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-sidecar-inherit-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ name: 'sidecar-inherit-project' }, null, 2));
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const engine = new ResiMantleEngine({ cwd: projectRoot });
      await engine.init(createConfig(['src'], 'adaptive'));

      const server = new MantleSidecarServer(engine, { port: 0 });
      const address = await server.start();
      const bootstrapKey = server.getBootstrapKey();
      const adminToken = server.getAuthToken();

      const parentResponse = await fetch(`${address.url}/v1/bootstrap/session`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
        body: JSON.stringify({
          sessionId: 'parent-sidecar-session',
          actorId: 'parent-client',
          runtime: 'node',
          pid: process.pid,
          ppid: process.ppid,
          cwd: projectRoot,
          execPath: process.execPath,
          runtimeVersion: process.version,
          capabilities: ['fs.read', 'process.spawn'],
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const parentPayload = await parentResponse.json() as {
        sessionToken: string;
        controlSessionId: string;
      };

      const emitBlockedProcess = (id: string) => fetch(`${address.url}/v1/runtime-event`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-token': parentPayload.sessionToken,
        },
        body: JSON.stringify({
          event: {
            id,
            timestamp: new Date().toISOString(),
            category: 'PROCESS_SPAWN',
            actor: 'parent-client',
            resource: 'powershell -Command Invoke-WebRequest https://example.com',
            blocked: true,
            details: {
              source: 'test',
            },
          },
        }),
      });

      await emitBlockedProcess('inherit-process-block-1');
      await emitBlockedProcess('inherit-process-block-2');

      const childResponse = await fetch(`${address.url}/v1/bootstrap/session`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-resimantle-sidecar-bootstrap': bootstrapKey,
        },
        body: JSON.stringify({
          sessionId: 'child-sidecar-session',
          actorId: 'child-client',
          runtime: 'node',
          pid: process.pid,
          ppid: process.ppid,
          cwd: projectRoot,
          execPath: process.execPath,
          runtimeVersion: process.version,
          parentSessionId: 'parent-sidecar-session',
          parentControlSessionId: parentPayload.controlSessionId,
          capabilities: ['fs.read', 'process.spawn'],
          integrity: {
            status: 'healthy',
          },
        }),
      });
      const childPayload = await childResponse.json() as {
        posture: string;
        containment: {
          capabilityModes?: {
            reads?: string;
            processes?: string;
          };
        };
      };

      const controlResponse = await fetch(`${address.url}/v1/control/sessions`, {
        headers: {
          'x-resimantle-sidecar-token': adminToken,
        },
      });
      const controlPayload = await controlResponse.json() as {
        inheritedSessions: number;
        deepestLineageDepth: number;
        sessions: Array<{
          id: string;
          sessionId: string;
          posture: string;
          parentControlSessionId?: string;
          lineageDepth: number;
          descendantCount: number;
          lineage: Array<{
            id: string;
            sessionId: string;
          }>;
          capabilityPosture: {
            read: string;
            process: string;
          };
        }>;
      };

      const childSession = controlPayload.sessions.find(session => session.sessionId === 'child-sidecar-session');

      expect(childPayload.posture).toBe('restricted');
      expect(childPayload.containment.capabilityModes?.processes).toBe('strict');
      expect(childPayload.containment.capabilityModes?.reads).toBe('adaptive');
      expect(controlPayload.inheritedSessions).toBe(1);
      expect(controlPayload.deepestLineageDepth).toBe(1);
      expect(childSession?.posture).toBe('restricted');
      expect(childSession?.parentControlSessionId).toBe(parentPayload.controlSessionId);
      expect(childSession?.lineageDepth).toBe(1);
      expect(childSession?.descendantCount).toBe(0);
      expect(childSession?.lineage.map(node => node.id)).toEqual([
        parentPayload.controlSessionId,
        childSession?.id ?? '',
      ]);
      expect(childSession?.lineage.map(node => node.sessionId)).toEqual([
        'parent-sidecar-session',
        'child-sidecar-session',
      ]);
      expect(childSession?.capabilityPosture.process).toBe('restricted');
      expect(childSession?.capabilityPosture.read).toBe('normal');

      await server.stop();
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});