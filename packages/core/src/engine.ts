import { randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { logger } from './common/logger';
import { COMMON_CONSTANTS } from './common/constants';
import type { ResiMantleConfig } from './config/schema';
import type { EngineOptions, EngineScanOptions } from './common/types';
import { ConfigLoader } from './config/loader';
import { MaturationPhase, RiskLevel, SecurityEventType } from '@resimantle/types';
import type { Finding, SecurityEvent, ScanSummary } from '@resimantle/types';
import type { RuntimeEvent } from './layers/runtime-monitor';

import { SurfaceCoatScanner } from './layers/surface-coat';
import { AiProxy } from './layers/ai-defense';
import {
  CanaryManager,
  HttpDecoyOverlay,
  OverlayCoordinator,
  ReadOverlay,
  ResourceInventory,
  SearchOverlay,
  StoryBroker,
  type CoordinatedHttpResolution,
  type CoordinatedReadResolution,
  type CoordinatedSearchResolution,
  type HttpSurfaceResolver,
  type MantleHttpRequest,
  type MantleReadRequest,
  type MantleSearchRequest,
  type ReadSurfaceResolver,
  type SearchSurfaceResolver,
} from './layers/resin-traps';
import { FalseVictoryBroker } from './layers/false-victory';
import { Gatekeeper } from './layers/access-gatekeeper';
import { PolicyEngine } from './layers/policy-engine';
import { Auditor, Reporter } from './layers/audit';

/**
 * The ResiMantle Engine is the central orchestrator of all 9 defensive layers.
 * It coordinates initialization, scanning, monitoring, and reporting
 * while maintaining the core principle: never modify the protected application.
 */
export class ResiMantleEngine {
  public options: EngineOptions;
  private config: ResiMantleConfig | null = null;
  private resiMantleDir: string;

  // Layer instances
  private auditor: Auditor;
  private canaryManager: CanaryManager;
  private aiProxy: AiProxy;
  private resourceInventory: ResourceInventory;
  private storyBroker: StoryBroker;
  private falseVictoryBroker: FalseVictoryBroker;
  private gatekeeper: Gatekeeper;
  private policyEngine: PolicyEngine | null = null;
  private overlayCoordinator: OverlayCoordinator | null = null;

  constructor(options: EngineOptions) {
    this.options = options;
    this.resiMantleDir = join(options.cwd, COMMON_CONSTANTS.OUTPUT_DIR);
    this.auditor = new Auditor(this.resiMantleDir);
    this.canaryManager = new CanaryManager(this.resiMantleDir);
    this.aiProxy = new AiProxy();
    this.resourceInventory = new ResourceInventory(this.resiMantleDir);
    this.storyBroker = new StoryBroker(this.resiMantleDir, {
      auditor: this.auditor,
      canaryManager: this.canaryManager,
    });
    this.falseVictoryBroker = new FalseVictoryBroker(this.resiMantleDir, {
      auditor: this.auditor,
    });
    this.gatekeeper = new Gatekeeper();
  }

  /**
   * Initializes the engine: loads config, creates output directory,
   * and boots all enabled layers.
   */
  async init(config?: ResiMantleConfig): Promise<void> {
    // Load config from disk or use provided
    this.config = config || await ConfigLoader.load(this.options.cwd, this.options.configPath);

    // Ensure .resimantle directory exists
    if (!existsSync(this.resiMantleDir)) {
      await mkdir(this.resiMantleDir, { recursive: true });
    }

    await this.resourceInventory.initialize();
    await this.resourceInventory.ingestProjectTopology(this.options.cwd);

    // Initialize policy engine
    this.policyEngine = await PolicyEngine.fromFile(
      join(this.options.cwd, this.config.policy.path)
    );
    this.overlayCoordinator = new OverlayCoordinator({
      gatekeeper: this.gatekeeper,
      policyEngine: this.policyEngine,
      readOverlay: new ReadOverlay(this.storyBroker),
      searchOverlay: new SearchOverlay(this.storyBroker),
      httpOverlay: new HttpDecoyOverlay(this.storyBroker, {
        falseVictoryBroker: this.falseVictoryBroker,
      }),
      inventory: this.resourceInventory,
      auditor: this.auditor,
    });

    // Log engine start
    await this.auditor.log({
      event: this.createEvent(SecurityEventType.ENGINE_STARTED, RiskLevel.NONE, {
        cwd: this.options.cwd,
        version: COMMON_CONSTANTS.VERSION,
      }),
    });

    logger.info(`ResiMantle Engine v${COMMON_CONSTANTS.VERSION} initialized`);
  }

  /**
   * Runs a complete Surface Coat scan and returns a structured summary.
   * This is the main "resimantle scan" operation.
   */
  async scan(options: EngineScanOptions = {}): Promise<ScanSummary> {
    if (!this.config) await this.init();
    const cfg = this.config!;

    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    if (!cfg.layers.surfaceCoat.enabled) {
      logger.info('Surface Coat is disabled. Skipping scan.');
      return this.emptyScanSummary(startedAt, startTime);
    }

    logger.info('Running Surface Coat scan...');

    const configuredScanPaths = options.scanPaths?.length
      ? options.scanPaths
      : cfg.layers.surfaceCoat.scanPaths;
    const resolvedScanPaths = Array.from(new Set(configuredScanPaths.map(p =>
      p === '.' ? this.options.cwd : join(this.options.cwd, p)
    )));

    const scanner = new SurfaceCoatScanner({
      projectRoot: this.options.cwd,
      scanPaths: resolvedScanPaths,
      ignorePatterns: cfg.layers.surfaceCoat.ignorePatterns,
    });

    const result = await scanner.scan();
    const findings: Finding[] = [];

    // Convert findings into audit entries
    for (const secret of result.exposedSecrets) {
      findings.push({
        id: randomUUID(),
        layer: 'SurfaceCoat',
        type: SecurityEventType.SECRET_EXPOSED,
        severity: secret.risk,
        title: `Exposed ${secret.name}`,
        description: `Found ${secret.name} in ${secret.file}:${secret.line}`,
        file: secret.file,
        line: secret.line,
        evidence: secret.evidence,
        recommendation: `Remove or rotate the exposed ${secret.name} immediately`,
      });

      await this.auditor.log({
        event: this.createEvent(SecurityEventType.SECRET_EXPOSED, secret.risk, {
          file: secret.file,
          line: secret.line,
          type: secret.type,
          name: secret.name,
          evidence: secret.evidence,
          recommendation: `Remove or rotate the exposed ${secret.name} immediately`,
        }),
        explanation: `Found ${secret.name} in ${secret.file}:${secret.line}`,
      });
    }

    for (const vuln of result.vulnerableDependencies) {
      findings.push({
        id: randomUUID(),
        layer: 'SurfaceCoat',
        type: SecurityEventType.VULNERABLE_DEPENDENCY,
        severity: vuln.severity,
        title: `Vulnerable dependency: ${vuln.name}`,
        description: `${vuln.name}@${vuln.version}: ${vuln.description} (${vuln.advisoryId})`,
        recommendation: `Update ${vuln.name} to the latest patched version`,
        metadata: {
          advisoryId: vuln.advisoryId,
          version: vuln.version,
        },
      });

      await this.auditor.log({
        event: this.createEvent(SecurityEventType.VULNERABLE_DEPENDENCY, vuln.severity, {
          name: vuln.name,
          version: vuln.version,
          advisoryId: vuln.advisoryId,
          description: vuln.description,
          recommendation: `Update ${vuln.name} to the latest patched version`,
        }),
        explanation: `${vuln.name}@${vuln.version}: ${vuln.description} (${vuln.advisoryId})`,
      });
    }

    for (const issue of result.configIssues) {
      findings.push({
        id: randomUUID(),
        layer: 'SurfaceCoat',
        type: SecurityEventType.CONFIG_ISSUE,
        severity: issue.severity,
        title: issue.issue,
        description: `${issue.file}: ${issue.issue}`,
        file: issue.file,
        recommendation: issue.recommendation,
      });

      await this.auditor.log({
        event: this.createEvent(SecurityEventType.CONFIG_ISSUE, issue.severity, {
          file: issue.file,
          issue: issue.issue,
          recommendation: issue.recommendation,
        }),
        explanation: `${issue.file}: ${issue.issue}`,
      });
    }

    // Build scan summary
    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startTime;

    const findingsBySeverity = this.countBySeverity(findings);

    const summary: ScanSummary = {
      startedAt,
      completedAt,
      durationMs,
      totalFindings: findings.length,
      findingsBySeverity,
      findings,
      overallRisk: result.totalRisk,
      filesScanned: result.filesScanned,
      phase: MaturationPhase.FRESH_COAT,
    };

    // Log scan completion
    await this.auditor.log({
      event: this.createEvent(SecurityEventType.SCAN_COMPLETED, RiskLevel.NONE, {
        filesScanned: result.filesScanned,
        totalFindings: findings.length,
        durationMs,
        overallRisk: result.totalRisk,
      }),
    });

    await this.resourceInventory.ingestScanSummary(summary);
    await this.resourceInventory.persist();

    return summary;
  }

  /**
   * Generates security reports from the current audit data.
   */
  async report(format: 'md' | 'json' | 'both' = 'both'): Promise<string[]> {
    const reporter = new Reporter(this.auditor.getEntries(), this.resiMantleDir);
    return reporter.writeToDisk(format);
  }

  /**
   * Returns the AI Proxy for prompt analysis and tool policy enforcement.
   */
  getAiProxy(): AiProxy {
    return this.aiProxy;
  }

  /**
   * Returns the Canary Manager for token generation and checking.
   */
  getCanaryManager(): CanaryManager {
    return this.canaryManager;
  }

  /**
   * Returns the Policy Engine for access evaluation.
   */
  getPolicyEngine(): PolicyEngine | null {
    return this.policyEngine;
  }

  /**
   * Returns the loaded configuration after initialization.
   */
  getConfig(): ResiMantleConfig | null {
    return this.config;
  }

  /**
   * Returns the Auditor for manual audit log access.
   */
  getAuditor(): Auditor {
    return this.auditor;
  }

  /**
   * Returns the auto-built resource inventory used to infer mantle context.
   */
  getResourceInventory(): ResourceInventory {
    return this.resourceInventory;
  }

  /**
   * Feeds runtime telemetry back into the resource inventory so later mantle
   * decisions can adapt without manual hints.
   */
  async observeRuntimeEvent(event: RuntimeEvent): Promise<void> {
    await this.resourceInventory.observeRuntimeEvent(event);
  }

  /**
   * Returns the zero-touch overlay coordinator that applies the mantle to
   * supported read, search, and HTTP surfaces.
   */
  getOverlayCoordinator(): OverlayCoordinator | null {
    return this.overlayCoordinator!;
  }

  /**
   * Applies the mantle to a read surface and falls back to the real surface
   * only when synthetic overlays are not selected.
   */
  async resolveReadSurface(
    request: MantleReadRequest,
    fallback?: ReadSurfaceResolver,
  ): Promise<CoordinatedReadResolution> {
    const coordinator = await this.getOrCreateOverlayCoordinator();
    return coordinator.resolveRead(request, fallback);
  }

  /**
   * Applies the mantle to a search surface and can merge synthetic and real
   * results without coupling ResiMantle to the search backend.
   */
  async resolveSearchSurface(
    request: MantleSearchRequest,
    fallback?: SearchSurfaceResolver,
  ): Promise<CoordinatedSearchResolution> {
    const coordinator = await this.getOrCreateOverlayCoordinator();
    return coordinator.resolveSearch(request, fallback);
  }

  /**
   * Applies the mantle to an HTTP-like surface and can return decoy or false
   * victory responses before the real backend is reached.
   */
  async resolveHttpSurface(
    request: MantleHttpRequest,
    fallback?: HttpSurfaceResolver,
  ): Promise<CoordinatedHttpResolution> {
    const coordinator = await this.getOrCreateOverlayCoordinator();
    return coordinator.resolveHttp(request, fallback);
  }

  // ── Internal Helpers ──────────────────────────────────────────────────────

  private async getOrCreateOverlayCoordinator(): Promise<OverlayCoordinator> {
    if (!this.overlayCoordinator) {
      if (!this.config) {
        await this.init();
      } else {
        this.overlayCoordinator = new OverlayCoordinator({
          gatekeeper: this.gatekeeper,
          policyEngine: this.policyEngine,
          readOverlay: new ReadOverlay(this.storyBroker),
          searchOverlay: new SearchOverlay(this.storyBroker),
          httpOverlay: new HttpDecoyOverlay(this.storyBroker, {
            falseVictoryBroker: this.falseVictoryBroker,
          }),
          auditor: this.auditor,
        });
      }
    }

    return this.overlayCoordinator!;
  }

  private createEvent(type: SecurityEventType, severity: RiskLevel, details: Record<string, unknown>): SecurityEvent {
    return {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      source: 'ResiMantleEngine',
      type,
      severity,
      details,
    };
  }

  private emptyScanSummary(startedAt: string, startTime: number): ScanSummary {
    return {
      startedAt,
      completedAt: new Date().toISOString(),
      durationMs: Date.now() - startTime,
      totalFindings: 0,
      findingsBySeverity: this.countBySeverity([]),
      findings: [],
      overallRisk: RiskLevel.NONE,
      filesScanned: 0,
      phase: MaturationPhase.FRESH_COAT,
    };
  }

  private countBySeverity(findings: { severity: RiskLevel }[]): Record<RiskLevel, number> {
    const counts: Record<string, number> = {};
    for (const level of Object.values(RiskLevel)) {
      counts[level] = 0;
    }
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    return counts as Record<RiskLevel, number>;
  }
}
