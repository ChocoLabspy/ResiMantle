import { Command } from 'commander';
import chalk from 'chalk';
import { createRequire } from 'node:module';
import {
  COMMON_CONSTANTS,
  MantleSidecarServer,
  type ProcessContainmentMode,
  ResiMantleEngine,
} from '@resimantle/core';

export const sidecarCommand = new Command('sidecar')
  .description('Start the zero-touch ResiMantle sidecar for external wrappers and adapters')
  .option('--host <host>', 'Host for the local sidecar', '127.0.0.1')
  .option('--port <port>', 'Port for the local sidecar', '7563')
  .option('--containment <mode>', 'Process and raw socket containment mode (off|adaptive|strict)')
  .action(async (options) => {
    const cwd = process.cwd();
    const nodePreloadReference = resolveNodePreloadReference();

    const engine = new ResiMantleEngine({ cwd });
    await engine.init();
    const configuredContainment = engine.getConfig()?.layers.runtimeMonitor.containment;
    const containmentMode = resolveContainmentMode(options.containment, configuredContainment?.mode);
    const containmentAllowlist = configuredContainment?.allow ?? {};

    const sidecar = new MantleSidecarServer(engine, {
      host: options.host,
      port: parsePort(options.port, 7563),
      containmentMode,
      containmentAllowlist,
      bootstrap: {
        nodeRequireSpecifier: nodePreloadReference,
      },
    });

    const address = await sidecar.start();
    const sidecarBootstrapKey = sidecar.getBootstrapKey();

    console.log('');
    console.log(chalk.cyan('  ┌─────────────────────────────────────────────────┐'));
    console.log(chalk.cyan('  │') + chalk.white.bold('         🧴  RESIMANTLE SIDECAR ACTIVE            ') + chalk.cyan('│'));
    console.log(chalk.cyan('  └─────────────────────────────────────────────────┘'));
    console.log('');
    console.log(chalk.green('  ✓ ') + chalk.white('Control plane URL: ') + chalk.cyan(address.url));
    console.log(chalk.green('  ✓ ') + chalk.white('Health endpoint: ') + chalk.gray(`${address.url}/health`));
    console.log(chalk.green('  ✓ ') + chalk.white('Read/Search/HTTP API: ') + chalk.gray(`${address.url}/v1/*`));
    console.log(chalk.green('  ✓ ') + chalk.white('Node bootstrap: ') + chalk.gray(`${address.url}/v1/bootstrap/node`));
    console.log('');
    console.log(chalk.white.bold('  Recommended environment:'));
    console.log(chalk.gray(`    RESIMANTLE_ACTIVE=1`));
    console.log(chalk.gray(`    RESIMANTLE_MANTLE_AUTO=1`));
    console.log(chalk.gray(`    RESIMANTLE_SIDECAR_URL=${address.url}`));
    console.log(chalk.gray(`    RESIMANTLE_SIDECAR_BOOTSTRAP_KEY=${sidecarBootstrapKey}`));
    console.log(chalk.gray(`    RESIMANTLE_PROCESS_CONTAINMENT=${containmentMode}`));
    console.log(chalk.gray(`    NODE_OPTIONS=--require ${nodePreloadReference}`));
    console.log('');
    console.log(chalk.gray(`  Output directory: ${cwd}/${COMMON_CONSTANTS.OUTPUT_DIR}`));
    console.log(chalk.gray('  Press Ctrl+C to stop.'));
    console.log('');

    process.on('SIGINT', async () => {
      console.log(chalk.yellow('\n  Stopping sidecar...'));
      await sidecar.stop();
      const auditPath = await engine.getAuditor().flush();
      console.log(chalk.green('  ✓ ') + chalk.white('Audit log saved: ') + chalk.gray(auditPath));
      console.log('');
      process.exit(0);
    });
  });

function parsePort(raw: string, fallback: number): number {
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
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