import { Command } from 'commander';
import { join } from 'node:path';
import chalk from 'chalk';
import {
  RuntimeMonitor,
  Profiler,
  AnomalyDetector,
  COMMON_CONSTANTS,
} from '@resimantle/core';
import type { RuntimeEvent, AccessPattern } from '@resimantle/core';

export const monitorCommand = new Command('monitor')
  .description('Start the standalone Runtime Monitor')
  .option('--no-http', 'Disable HTTP interception')
  .option('--no-fs', 'Disable filesystem interception')
  .option('--no-process', 'Disable process spawn interception')
  .action(async (options) => {
    const cwd = process.cwd();
    const resiMantleDir = join(cwd, COMMON_CONSTANTS.OUTPUT_DIR);

    console.log('');
    console.log(chalk.cyan('  🔍 Starting standalone Runtime Monitor...'));
    console.log('');

    const monitor = new RuntimeMonitor(resiMantleDir, {
      interceptHttp: options.http !== false,
      interceptFs: options.fs !== false,
      interceptProcess: options.process !== false,
    });

    const profiler = new Profiler();
    const anomalyDetector = new AnomalyDetector(profiler);

    let eventCount = 0;

    // Print events in real-time
    monitor.on('event', async (event: RuntimeEvent) => {
      eventCount++;

      const pattern: AccessPattern = {
        actor: event.actor,
        resource: event.resource,
        category: event.category,
        timestamp: Date.now(),
        durationMs: event.durationMs || 0,
      };
      profiler.record(pattern);

      const anomaly = await anomalyDetector.detect(pattern);
      const anomalyIndicator = anomaly.isAnomaly
        ? chalk.red(` ⚠ ANOMALY(${anomaly.score})`)
        : '';

      console.log(
        chalk.gray(`  [${eventCount}] `) +
        chalk.cyan(event.category.padEnd(18)) +
        chalk.white(truncate(event.resource, 50)) +
        chalk.gray(` ← ${truncate(event.actor, 30)}`) +
        (event.durationMs ? chalk.gray(` ${event.durationMs}ms`) : '') +
        anomalyIndicator
      );
    });

    monitor.on('alert', (alert) => {
      const severity = alert.severity === 'critical' ? chalk.red('CRITICAL') : chalk.yellow('WARNING');
      console.log(chalk.gray('  [!] ') + severity + chalk.white(` ${alert.code}`) + chalk.gray(` pressure=${alert.pressureScore}`));
      console.log(chalk.gray(`      ${alert.message}`));
    });

    await monitor.start();

    console.log(chalk.green('  ✓ Monitor is active. Watching I/O operations...'));
    console.log(chalk.gray('  Press Ctrl+C to stop.\n'));

    // Handle graceful shutdown
    process.on('SIGINT', async () => {
      console.log(chalk.yellow('\n  Stopping monitor...'));
      await monitor.stop();

      const stats = monitor.getStats();
      const controlState = monitor.getControlState();
      console.log(chalk.cyan(`\n  Total events captured: ${stats.totalEvents}`));
      console.log(chalk.cyan(`  Monitor alerts: ${stats.alertCount}`));
      console.log(chalk.cyan(`  Runtime pressure: ${controlState.pressureScore}`));
      console.log(chalk.cyan(`  Runtime status: ${controlState.status}`));
      console.log('');
      process.exit(0);
    });
  });

function truncate(str: string, max: number): string {
  if (str.length <= max) return str;
  return str.slice(0, max - 3) + '...';
}
