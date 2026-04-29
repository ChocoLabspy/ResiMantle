import { Command } from 'commander';
import { COMMON_CONSTANTS } from '@resimantle/core';
import { showBanner } from './ui/banner.js';

import { initCommand } from './commands/init.js';
import { scanCommand } from './commands/scan.js';
import { monitorCommand } from './commands/monitor.js';
import { reportCommand } from './commands/report.js';
import { statusCommand } from './commands/status.js';
import { policyCommand } from './commands/policy.js';
import { canaryCommand } from './commands/canary.js';
import { runCommand } from './commands/run.js';
import { sidecarCommand } from './commands/sidecar.js';

export async function main() {
  const program = new Command();

  program
    .name('resimantle')
    .description('ResiMantle - Adaptive security resin for AI-era software')
    .version(COMMON_CONSTANTS.VERSION)
    .hook('preAction', () => {
      showBanner();
    });

  // Register commands
  program.addCommand(initCommand);
  program.addCommand(scanCommand);
  program.addCommand(monitorCommand);
  program.addCommand(reportCommand);
  program.addCommand(statusCommand);
  program.addCommand(policyCommand);
  program.addCommand(canaryCommand);
  program.addCommand(runCommand);
  program.addCommand(sidecarCommand);

  await program.parseAsync(process.argv);
}
