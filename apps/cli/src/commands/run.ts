import { Command } from 'commander';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import chalk from 'chalk';
import {
  COMMON_CONSTANTS,
  MantleSidecarServer,
  type ProcessContainmentMode,
  ResiMantleEngine,
  RuntimeMantleSession,
  serializeContainmentAllowlist,
} from '@resimantle/core';
import { randomUUID } from 'node:crypto';

export const runCommand = new Command('run')
  .description('Run a command wrapped by ResiMantle protective layer')
  .argument('<command...>', 'Command to run')
  .option('--dry-run', 'Show what would be intercepted without actually running', false)
  .option('--no-http', 'Disable HTTP interception')
  .option('--no-fs', 'Disable filesystem interception')
  .option('--no-process', 'Disable process spawn interception')
  .option('--no-sidecar', 'Disable the local sidecar auto-bridge for wrappers')
  .option('--containment <mode>', 'Process and raw socket containment mode (off|adaptive|strict)')
  .option('--sidecar-host <host>', 'Host for the local sidecar', '127.0.0.1')
  .option('--sidecar-port <port>', 'Port for the local sidecar (0 = ephemeral)', '0')
  .action(async (commandArgs: string[], options) => {
    const cwd = process.cwd();
    const sessionId = randomUUID();
    const nodePreloadReference = resolveNodePreloadReference();

    console.log('');
    console.log(chalk.cyan('  ┌─────────────────────────────────────────────────┐'));
    console.log(chalk.cyan('  │') + chalk.white.bold('        🧪  RESIMANTLE RUNTIME WRAPPER            ') + chalk.cyan('│'));
    console.log(chalk.cyan('  └─────────────────────────────────────────────────┘'));
    console.log('');
    console.log(chalk.gray(`  Wrapping: ${chalk.white(commandArgs.join(' '))}`));
    console.log(chalk.gray(`  Mode: ${options.dryRun ? chalk.yellow('DRY RUN') : chalk.green('LIVE')}`));
    console.log('');

    if (options.dryRun) {
      console.log(chalk.yellow('  ⚠  Dry run mode — showing configuration only.\n'));
      console.log(chalk.white('  Interceptors:'));
      console.log(`    HTTP:    ${options.http !== false ? chalk.green('✓ ON') : chalk.red('✗ OFF')}`);
      console.log(`    FS:      ${options.fs !== false ? chalk.green('✓ ON') : chalk.red('✗ OFF')}`);
      console.log(`    Process: ${options.process !== false ? chalk.green('✓ ON') : chalk.red('✗ OFF')}`);
      console.log(`    Sidecar: ${options.sidecar !== false ? chalk.green('✓ ON') : chalk.red('✗ OFF')}`);
      console.log('');
      return;
    }

    const engine = new ResiMantleEngine({ cwd });
    await engine.init();
    const configuredContainment = engine.getConfig()?.layers.runtimeMonitor.containment;
    const containmentMode = resolveContainmentMode(options.containment, configuredContainment?.mode);
    const configuredContainmentAllowlist = configuredContainment?.allow ?? {};

    const runtimeSession = new RuntimeMantleSession(engine, {
      sessionId,
      runtimeOptions: {
        interceptHttp: options.http !== false,
        interceptFs: options.fs !== false,
        interceptProcess: options.process !== false,
      },
    });

    const sidecar = options.sidecar !== false
      ? new MantleSidecarServer(engine, {
        host: options.sidecarHost,
        port: parsePort(options.sidecarPort, 0),
        containmentMode,
        containmentAllowlist: configuredContainmentAllowlist,
        bootstrap: {
          nodeRequireSpecifier: nodePreloadReference,
        },
      })
      : null;

    const sidecarAddress = sidecar ? await sidecar.start() : null;
    const sidecarBootstrapKey = sidecar ? sidecar.getBootstrapKey() : undefined;
    const containmentAllowlist = sidecar ? sidecar.getEffectiveContainmentAllowlist() : configuredContainmentAllowlist;
    const serializedAllowlist = serializeContainmentAllowlist(containmentAllowlist);
    await runtimeSession.start();
    const nodeOptions = sidecarAddress
      ? mergeNodeOptions(process.env['NODE_OPTIONS'], `--require ${nodePreloadReference}`)
      : process.env['NODE_OPTIONS'];

    console.log(chalk.green('  ✓ ') + chalk.white('Runtime Mantle Session active') + chalk.gray(` (${sessionId})`));
    console.log(chalk.green('  ✓ ') + chalk.white('Automatic varnish active for read/search/http surfaces'));
    console.log(chalk.green('  ✓ ') + chalk.white('Resource inventory active'));
    console.log(chalk.green('  ✓ ') + chalk.white('Policy + Gatekeeper decisions active'));
    if (sidecarAddress) {
      console.log(chalk.green('  ✓ ') + chalk.white('Local sidecar active') + chalk.gray(` (${sidecarAddress.url})`));
      console.log(chalk.green('  ✓ ') + chalk.white('Node preloader injected') + chalk.gray(` (${nodePreloadReference})`));
    }
    console.log('');
    console.log(chalk.cyan('  ─'.repeat(25)));
    console.log(chalk.gray('  Launching wrapped process...'));
    console.log('');

    // Spawn the wrapped process
    const [cmd, ...args] = commandArgs;
    const child = spawn(cmd!, args, {
      cwd,
      stdio: 'inherit',
      shell: true,
      env: {
        ...process.env,
        RESIMANTLE_ACTIVE: '1',
        RESIMANTLE_MANTLE_AUTO: '1',
        RESIMANTLE_SESSION_ID: sessionId,
        ...(sidecarBootstrapKey ? { RESIMANTLE_SIDECAR_BOOTSTRAP_KEY: sidecarBootstrapKey } : {}),
        RESIMANTLE_PROCESS_CONTAINMENT: containmentMode,
        ...(serializedAllowlist ? { RESIMANTLE_PROCESS_CONTAINMENT_RULES: serializedAllowlist } : {}),
        ...(nodeOptions ? { NODE_OPTIONS: nodeOptions } : {}),
        ...(sidecarAddress ? { RESIMANTLE_SIDECAR_URL: sidecarAddress.url } : {}),
      },
    });

    // Handle process exit
    child.on('exit', async (code) => {
      console.log('');
      console.log(chalk.cyan('  ─'.repeat(25)));
      console.log(chalk.gray(`  Process exited with code ${code}`));
      console.log('');

      const controlSnapshot = sidecar?.getControlSnapshot();
      await runtimeSession.stop();
      await sidecar?.stop();

      const stats = runtimeSession.getMonitor().getStats();
      const profiles = runtimeSession.getProfiles();
      const sessionSummary = runtimeSession.getSummary();
      const inventoryProfiles = engine.getResourceInventory().getAllProfiles();

      console.log(chalk.cyan('  ┌─────────────────────────────────────────────────┐'));
      console.log(chalk.cyan('  │') + chalk.white.bold('          📊  RUNTIME SESSION SUMMARY             ') + chalk.cyan('│'));
      console.log(chalk.cyan('  └─────────────────────────────────────────────────┘'));
      console.log('');
      console.log(chalk.white(`  Total Events:     ${chalk.cyan(String(stats.totalEvents))}`));
      console.log(chalk.white(`  High Friction:    ${sessionSummary.blockedLikeDecisions > 0 ? chalk.yellow(String(sessionSummary.blockedLikeDecisions)) : chalk.green('0')}`));
      console.log(chalk.white(`  Synthetic Paths:  ${sessionSummary.syntheticResponses > 0 ? chalk.cyan(String(sessionSummary.syntheticResponses)) : chalk.green('0')}`));
      console.log(chalk.white(`  Anomalies:        ${sessionSummary.anomalies > 0 ? chalk.yellow(String(sessionSummary.anomalies)) : chalk.green('0')}`));
      console.log(chalk.white(`  Monitor Alerts:   ${sessionSummary.monitorAlerts > 0 ? chalk.yellow(String(sessionSummary.monitorAlerts)) : chalk.green('0')}`));
      console.log(chalk.white(`  Runtime Pressure: ${sessionSummary.runtimePressure > 0 ? chalk.cyan(String(sessionSummary.runtimePressure)) : chalk.green('0')}`));
      console.log(chalk.white(`  Runtime Status:   ${formatRuntimeStatus(sessionSummary.runtimeStatus)}`));
      console.log(chalk.white(`  Uptime:           ${chalk.gray(Math.round(stats.uptimeMs / 1000) + 's')}`));
      console.log(chalk.white(`  Profiles Built:   ${chalk.cyan(String(profiles.length))}`));
      console.log(chalk.white(`  Inventory Items:  ${chalk.cyan(String(inventoryProfiles.length))}`));
      console.log('');

      if (controlSnapshot) {
        const hottestSession = controlSnapshot.sessions[0];
        const deepestSession = controlSnapshot.sessions.reduce((current, session) => {
          if (!current || session.lineageDepth > current.lineageDepth) {
            return session;
          }

          return current;
        }, controlSnapshot.sessions[0]);
        const learned = controlSnapshot.baseline.learnedAllowlist;
        const learnedCount = (learned.readPatterns?.length ?? 0)
          + (learned.processPatterns?.length ?? 0)
          + (learned.socketHosts?.length ?? 0);

        console.log(chalk.white.bold('  Control Plane:'));
        console.log(chalk.white(`    Active Sessions: ${chalk.cyan(String(controlSnapshot.activeSessions))}`));
        console.log(chalk.white(`    Risky Sessions:  ${controlSnapshot.riskySessions > 0 ? chalk.yellow(String(controlSnapshot.riskySessions)) : chalk.green('0')}`));
        console.log(chalk.white(`    Inherited:       ${controlSnapshot.inheritedSessions > 0 ? chalk.cyan(String(controlSnapshot.inheritedSessions)) : chalk.gray('0')}`));
        console.log(chalk.white(`    Lineage Roots:   ${chalk.cyan(String(controlSnapshot.lineageRoots))}`));
        console.log(chalk.white(`    Tree Depth:      ${chalk.cyan(String(controlSnapshot.deepestLineageDepth))}`));
        console.log(chalk.white(`    Baseline Mode:   ${chalk.cyan(controlSnapshot.baseline.mode)}`));
        console.log(chalk.white(`    Compat Bias:     ${controlSnapshot.baseline.reduceRiskFromKnownActivity ? chalk.green('KNOWN-SAFE') : chalk.gray('STATIC')}`));
        console.log(chalk.white(`    Learned Rules:   ${learnedCount > 0 ? chalk.cyan(String(learnedCount)) : chalk.gray('0')}`));

        if (deepestSession && deepestSession.lineageDepth > 0) {
          console.log(chalk.white(`    Deepest Chain:   ${chalk.gray(formatSessionLineage(deepestSession.lineage))}`));
        }

        if (hottestSession) {
          console.log(chalk.white(`    Top Session:     ${chalk.cyan(formatControlSessionHandle(hottestSession))} ${formatPosture(hottestSession.posture)} ${chalk.gray(`risk=${hottestSession.riskScore}`)}`));
          console.log(chalk.white(`    Integrity:       ${formatIntegrity(hottestSession.integrityStatus)} ${chalk.gray(`heartbeats=${hottestSession.attestation.heartbeatCount}`)}`));
          console.log(chalk.white(`    Capabilities:    ${chalk.gray(formatCapabilityPosture(hottestSession.capabilityPosture))}`));
          console.log(chalk.white(`    Lineage:         ${chalk.gray(formatSessionLineage(hottestSession.lineage))}`));
          console.log(chalk.white(`    Descendants:     ${hottestSession.descendantCount > 0 ? chalk.cyan(String(hottestSession.descendantCount)) : chalk.gray('0')}`));
          console.log(chalk.white(`    Known-Safe Hits: ${hottestSession.knownBaselineMatches > 0 ? chalk.cyan(String(hottestSession.knownBaselineMatches)) : chalk.gray('0')}`));
        }

        console.log('');
      }

      // Events by category
      if (Object.keys(stats.eventsByCategory).length > 0) {
        console.log(chalk.white.bold('  Events by Category:'));
        for (const [cat, count] of Object.entries(stats.eventsByCategory)) {
          console.log(chalk.gray(`    ${cat}: `) + chalk.white(String(count)));
        }
        console.log('');
      }

      // Flush audit log
      const auditPath = await engine.getAuditor().flush();
      console.log(chalk.green('  ✓ ') + chalk.white('Audit log saved: ') + chalk.gray(auditPath));
      console.log('');

      process.exit(code ?? 0);
    });

    child.on('error', async (err) => {
      console.log(chalk.red(`\n  ✗ Failed to start process: ${err.message}\n`));
      await runtimeSession.stop();
      await sidecar?.stop();
      process.exit(1);
    });

    // Handle SIGINT gracefully
    process.on('SIGINT', async () => {
      console.log(chalk.yellow('\n  Received SIGINT — shutting down gracefully...'));
      child.kill('SIGINT');
    });
  });

function parsePort(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
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

function resolveContainmentMode(value: string | undefined, fallback?: ProcessContainmentMode): ProcessContainmentMode {
  if (value === 'off' || value === 'strict' || value === 'adaptive') {
    return value;
  }

  return fallback ?? 'adaptive';
}

function resolveNodePreloadReference(): string {
  try {
    const cliEntry = process.argv[1] ?? `${process.cwd()}\\resimantle.js`;
    const localRequire = createRequire(cliEntry);
    return localRequire.resolve(COMMON_CONSTANTS.NODE_CJS_PRELOAD_SPECIFIER);
  } catch {
    return COMMON_CONSTANTS.NODE_CJS_PRELOAD_SPECIFIER;
  }
}

function formatRuntimeStatus(status: 'normal' | 'elevated' | 'critical'): string {
  switch (status) {
    case 'critical':
      return chalk.red('CRITICAL');
    case 'elevated':
      return chalk.yellow('ELEVATED');
    default:
      return chalk.green('NORMAL');
  }
}

function formatCapabilityPosture(posture: {
  read: string;
  search: string;
  http: string;
  process: string;
  socket: string;
}): string {
  return `read=${posture.read}, search=${posture.search}, http=${posture.http}, process=${posture.process}, socket=${posture.socket}`;
}

function formatControlSessionHandle(session: { id: string; sessionId: string }): string {
  return `${session.sessionId}#${session.id.slice(-6)}`;
}

function formatSessionLineage(
  lineage: Array<{ id: string; sessionId: string }>,
): string {
  if (lineage.length === 0) {
    return 'root';
  }

  return lineage.map(formatControlSessionHandle).join(' -> ');
}

function formatPosture(posture: string): string {
  switch (posture) {
    case 'sealed':
      return chalk.red('SEALED');
    case 'restricted':
      return chalk.yellow('RESTRICTED');
    case 'guarded':
      return chalk.cyan('GUARDED');
    default:
      return chalk.green('NORMAL');
  }
}

function formatIntegrity(status: string): string {
  switch (status) {
    case 'drifted':
      return chalk.red('DRIFTED');
    case 'healthy':
      return chalk.green('HEALTHY');
    default:
      return chalk.gray('UNKNOWN');
  }
}
