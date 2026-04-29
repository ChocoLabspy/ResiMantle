import { Command } from 'commander';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import chalk from 'chalk';
import { COMMON_CONSTANTS } from '@resimantle/core';

export const statusCommand = new Command('status')
  .description('Show current ResiMantle protection status')
  .action(async () => {
    const cwd = process.cwd();
    const configPath = join(cwd, COMMON_CONSTANTS.DEFAULT_CONFIG_FILE);
    const resiMantleDir = join(cwd, COMMON_CONSTANTS.OUTPUT_DIR);

    console.log('');
    console.log(chalk.cyan('  ┌───────────────────────────────────────┐'));
    console.log(chalk.cyan('  │') + chalk.white.bold('      🛡️  ResiMantle Status Report      ') + chalk.cyan('│'));
    console.log(chalk.cyan('  └───────────────────────────────────────┘'));
    console.log('');

    // Check if initialized
    const initialized = existsSync(configPath);
    if (!initialized) {
      console.log(chalk.yellow('  ⚠  ResiMantle is NOT initialized in this directory.'));
      console.log(chalk.gray(`     Run ${chalk.white('resimantle init')} to get started.\n`));
      return;
    }

    console.log(chalk.green('  ✓ ') + chalk.white('Initialized: ') + chalk.green('Yes'));

    // Read config
    try {
      const configRaw = await readFile(configPath, 'utf-8');
      const config = JSON.parse(configRaw);
      const runtimeMonitor = config.layers?.runtimeMonitor ?? {};
      const control = runtimeMonitor.control ?? {};
      const containment = runtimeMonitor.containment ?? {};
      const baseline = runtimeMonitor.baseline ?? {};

      console.log(chalk.green('  ✓ ') + chalk.white('Version: ') + chalk.cyan(config.version || 'unknown'));
      console.log('');

      // Layer status
      console.log(chalk.white.bold('  Layer Status:'));
      console.log('');

      const layers = [
        { name: 'Surface Coat', key: 'surfaceCoat', desc: 'Static analysis & secret detection' },
        { name: 'AI Defense', key: 'aiDefense', desc: 'Prompt injection & tool policy' },
        { name: 'Runtime Monitor', key: 'runtimeMonitor', desc: 'Live behavioral observation' },
      ];

      for (const layer of layers) {
        const layerConfig = config.layers?.[layer.key];
        const enabled = layerConfig?.enabled ?? false;
        const status = enabled ? chalk.green('●  ENABLED') : chalk.red('○  DISABLED');
        console.log(`    ${status}  ${chalk.white(layer.name)}`);
        console.log(chalk.gray(`              ${layer.desc}`));
      }

      console.log('');

      console.log(chalk.white.bold('  Runtime Control:'));
      console.log(chalk.white(`    Auto posture: ${control.autoPosture === false ? chalk.red('OFF') : chalk.green('ON')}`));
      console.log(chalk.white(`    Capability Q.: ${control.capabilityQuarantine === false ? chalk.red('OFF') : chalk.green('ON')}`));
      console.log(chalk.white(`    Containment:  ${chalk.cyan(containment.mode || 'adaptive')}`));
      console.log(chalk.white(`    Session TTL:  ${chalk.gray(String(control.sessionTtlMs ?? 15 * 60_000) + 'ms')}`));
      console.log(chalk.white(`    Heartbeat:    ${chalk.gray(String(control.heartbeatGraceMs ?? 45_000) + 'ms grace')}`));
      console.log('');

      const activeRuntime = readActiveRuntimeContext();
      if (activeRuntime.active) {
        console.log(chalk.white.bold('  Active Runtime Context:'));
        console.log(chalk.white(`    Session:      ${activeRuntime.sessionId ? chalk.cyan(activeRuntime.sessionId) : chalk.gray('unknown')}`));
        console.log(chalk.white(`    Parent Sess.: ${activeRuntime.parentSessionId ? chalk.gray(activeRuntime.parentSessionId) : chalk.gray('root')}`));
        console.log(chalk.white(`    Parent Ctrl.: ${activeRuntime.parentControlSessionId ? chalk.gray(activeRuntime.parentControlSessionId) : chalk.gray('none')}`));
        console.log(chalk.white(`    Inherited:    ${chalk.gray(formatInheritedCapabilityModes(activeRuntime.capabilityModes))}`));
        console.log('');
      }

      console.log(chalk.white.bold('  Compatibility Baseline:'));
      console.log(chalk.white(`    Mode:         ${chalk.cyan(baseline.mode || 'assist')}`));
      console.log(chalk.white(`    Auto-apply:   ${baseline.autoApplyToContainment === false ? chalk.red('OFF') : chalk.green('ON')}`));
      console.log(chalk.white(`    Cooldown bias:${baseline.reduceRiskFromKnownActivity === false ? chalk.red('OFF') : chalk.green('ON')}`));
      console.log(chalk.white(`    Threshold:    ${chalk.gray(String(baseline.minOccurrences ?? 3) + ' hits')}`));

      const baselinePath = resolveBaselinePath(cwd, baseline.persistencePath as string | undefined);
      if (existsSync(baselinePath)) {
        const baselineRaw = JSON.parse(await readFile(baselinePath, 'utf-8')) as {
          updatedAt?: string;
          reads?: Record<string, { count: number }>;
          processes?: Record<string, { count: number }>;
          socketHosts?: Record<string, { count: number }>;
        };
        const learnedReads = Object.keys(baselineRaw.reads ?? {}).length;
        const learnedProcesses = Object.keys(baselineRaw.processes ?? {}).length;
        const learnedSockets = Object.keys(baselineRaw.socketHosts ?? {}).length;
        console.log(chalk.white(`    Stored file:  ${chalk.gray(baselinePath)}`));
        console.log(chalk.white(`    Learned:      ${chalk.cyan(String(learnedReads + learnedProcesses + learnedSockets))} ${chalk.gray(`(reads=${learnedReads}, proc=${learnedProcesses}, sockets=${learnedSockets})`)}`));
        if (baselineRaw.updatedAt) {
          console.log(chalk.white(`    Updated:      ${chalk.gray(baselineRaw.updatedAt)}`));
        }
      } else {
        console.log(chalk.white(`    Stored file:  ${chalk.gray('No baseline persisted yet')}`));
      }

      console.log('');

      // Check for canaries
      const canaryPath = join(resiMantleDir, 'canaries.json');
      if (existsSync(canaryPath)) {
        const canaries = JSON.parse(await readFile(canaryPath, 'utf-8'));
        console.log(chalk.green('  ✓ ') + chalk.white('Canary Tokens: ') + chalk.yellow(`${canaries.length} deployed`));
      } else {
        console.log(chalk.yellow('  ⚠ ') + chalk.white('Canary Tokens: ') + chalk.gray('Not generated'));
      }

      // Check for latest report
      const reportPath = join(resiMantleDir, 'report.json');
      if (existsSync(reportPath)) {
        const report = JSON.parse(await readFile(reportPath, 'utf-8'));
        console.log(chalk.green('  ✓ ') + chalk.white('Last Report: ') + chalk.gray(report.generatedAt));
        console.log(chalk.green('  ✓ ') + chalk.white('Last Risk: ') + chalk.cyan(report.overallRisk));
        console.log(chalk.green('  ✓ ') + chalk.white('Last Findings: ') + chalk.cyan(String(report.totalFindings)));
      } else {
        console.log(chalk.yellow('  ⚠ ') + chalk.white('Last Report: ') + chalk.gray('No report generated yet'));
      }

    } catch (error) {
      console.log(chalk.red(`  ✗ Error reading config: ${(error as Error).message}`));
    }

    console.log('');
    console.log(chalk.gray(`  Phase: ${chalk.cyan('FRESH_COAT')} → Run scans and monitor to advance.`));
    console.log('');
  });

function resolveBaselinePath(cwd: string, persistencePath?: string): string {
  const candidate = persistencePath || join('.resimantle', 'runtime-baseline.json');
  return isAbsolute(candidate) ? candidate : resolve(cwd, candidate);
}

function readActiveRuntimeContext(): {
  active: boolean;
  sessionId?: string;
  parentSessionId?: string;
  parentControlSessionId?: string;
  capabilityModes?: {
    reads?: string;
    processes?: string;
    sockets?: string;
  };
} {
  const rawCapabilityModes = process.env[COMMON_CONSTANTS.PROCESS_CONTAINMENT_CAPABILITY_MODES_ENV];
  let capabilityModes: { reads?: string; processes?: string; sockets?: string } | undefined;

  if (rawCapabilityModes?.trim()) {
    try {
      capabilityModes = JSON.parse(rawCapabilityModes) as { reads?: string; processes?: string; sockets?: string };
    } catch {
      capabilityModes = undefined;
    }
  }

  return {
    active: process.env[COMMON_CONSTANTS.ACTIVE_ENV] === '1' || Boolean(process.env[COMMON_CONSTANTS.SESSION_ID_ENV]),
    sessionId: process.env[COMMON_CONSTANTS.SESSION_ID_ENV],
    parentSessionId: process.env[COMMON_CONSTANTS.PARENT_SESSION_ID_ENV],
    parentControlSessionId: process.env[COMMON_CONSTANTS.PARENT_CONTROL_SESSION_ID_ENV],
    capabilityModes,
  };
}

function formatInheritedCapabilityModes(capabilityModes?: {
  reads?: string;
  processes?: string;
  sockets?: string;
}): string {
  if (!capabilityModes) {
    return 'default containment';
  }

  return `read=${capabilityModes.reads ?? 'inherit'}, process=${capabilityModes.processes ?? 'inherit'}, socket=${capabilityModes.sockets ?? 'inherit'}`;
}
