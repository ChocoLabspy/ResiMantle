import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { CanaryManager, COMMON_CONSTANTS } from '@resimantle/core';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';

export const canaryCommand = new Command('canary')
  .description('Manage canary tokens and decoys')
  .addCommand(
    new Command('generate')
      .description('Generate new canary tokens')
      .action(async () => {
        const cwd = process.cwd();
        const resiMantleDir = join(cwd, COMMON_CONSTANTS.OUTPUT_DIR);
        const spinner = ora({ text: chalk.cyan('Generating canary tokens...'), color: 'cyan' }).start();

        try {
          const manager = new CanaryManager(resiMantleDir);
          const tokens = await manager.generateTokens();

          spinner.succeed(chalk.green(`Generated ${tokens.length} canary tokens!`));
          console.log('');

          for (const token of tokens) {
            console.log(chalk.yellow('  🐦 ') + chalk.white(token.type));
            console.log(chalk.gray(`     ID: ${token.id}`));
            console.log(chalk.gray(`     ${token.description}`));
            console.log('');
          }

          // Write .env.canary
          const envContent = manager.generateEnvFile();
          await writeFile(join(resiMantleDir, '.env.canary'), envContent, 'utf-8');
          console.log(chalk.green('  ✓ ') + chalk.white('Trap file written: ') + chalk.cyan('.resimantle/.env.canary'));
          console.log('');
        } catch (error) {
          spinner.fail(chalk.red(`Failed: ${(error as Error).message}`));
        }
      })
  )
  .addCommand(
    new Command('list')
      .description('List all canary tokens')
      .action(async () => {
        const cwd = process.cwd();
        const resiMantleDir = join(cwd, COMMON_CONSTANTS.OUTPUT_DIR);

        try {
          const manager = new CanaryManager(resiMantleDir);
          // Force load from disk by checking a dummy token
          await manager.checkToken('__load__');
          const tokens = manager.getAllTokens();

          if (tokens.length === 0) {
            console.log(chalk.yellow('\n  No canary tokens found. Run `resimantle canary generate` first.\n'));
            return;
          }

          console.log(chalk.cyan(`\n  Canary Tokens (${tokens.length}):\n`));

          for (const token of tokens) {
            const status = token.triggered ? chalk.red('🚨 TRIGGERED') : chalk.green('✓  Active');
            console.log(`  ${status}  ${chalk.white(token.type)}`);
            console.log(chalk.gray(`         ID: ${token.id} | Created: ${token.created}`));
            console.log('');
          }
        } catch (error) {
          console.log(chalk.red(`  Error: ${(error as Error).message}`));
        }
      })
  );
