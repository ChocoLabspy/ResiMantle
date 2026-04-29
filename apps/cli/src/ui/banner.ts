import chalk from 'chalk';
import { COMMON_CONSTANTS } from '@resimantle/core';

export function showBanner() {
  const v = COMMON_CONSTANTS.VERSION;
  console.log('');
  console.log(chalk.cyan('  ╔═══════════════════════════════════════════════════╗'));
  console.log(chalk.cyan('  ║') + chalk.white.bold('                                                   ') + chalk.cyan('║'));
  console.log(chalk.cyan('  ║') + chalk.white.bold('    🛡️  ') + chalk.blueBright.bold('R e s i M a n t l e') + chalk.white.bold(`  v${v}              `) + chalk.cyan('║'));
  console.log(chalk.cyan('  ║') + chalk.gray('    Adaptive security resin for AI-era software    ') + chalk.cyan('║'));
  console.log(chalk.cyan('  ║') + chalk.white.bold('                                                   ') + chalk.cyan('║'));
  console.log(chalk.cyan('  ╚═══════════════════════════════════════════════════╝'));
  console.log('');
}
