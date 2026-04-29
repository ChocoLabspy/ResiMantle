import { Command } from 'commander';
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { ConfigLoader, COMMON_CONSTANTS, CanaryManager } from '@resimantle/core';

export const initCommand = new Command('init')
  .description('Initialize ResiMantle in the current directory')
  .option('--force', 'Overwrite existing configuration', false)
  .action(async (options) => {
    const cwd = process.cwd();
    const configPath = join(cwd, COMMON_CONSTANTS.DEFAULT_CONFIG_FILE);
    const resiMantleDir = join(cwd, COMMON_CONSTANTS.OUTPUT_DIR);

    // Check if already initialized
    if (existsSync(configPath) && !options.force) {
      console.log(chalk.yellow('\n  ⚠  ResiMantle is already initialized in this directory.'));
      console.log(chalk.gray('     Use --force to overwrite the existing configuration.\n'));
      return;
    }

    console.log(chalk.cyan('\n  🧪 Applying the first coat of resin...\n'));

    // 1. Create resimantle.config.json
    const configContent = ConfigLoader.generateDefault();
    await writeFile(configPath, configContent, 'utf-8');
    console.log(chalk.green('  ✓ ') + chalk.white('Created ') + chalk.cyan(COMMON_CONSTANTS.DEFAULT_CONFIG_FILE));

    // 2. Create .resimantle/ directory
    if (!existsSync(resiMantleDir)) {
      await mkdir(resiMantleDir, { recursive: true });
    }
    console.log(chalk.green('  ✓ ') + chalk.white('Created ') + chalk.cyan('.resimantle/') + chalk.gray(' (output directory)'));

    // 3. Generate canary tokens
    const canaryMgr = new CanaryManager(resiMantleDir);
    const tokens = await canaryMgr.generateTokens();
    console.log(chalk.green('  ✓ ') + chalk.white('Generated ') + chalk.yellow(`${tokens.length} canary tokens`) + chalk.gray(' (resin traps)'));

    // 4. Write .env.canary trap file
    const envCanary = canaryMgr.generateEnvFile();
    await writeFile(join(resiMantleDir, '.env.canary'), envCanary, 'utf-8');
    console.log(chalk.green('  ✓ ') + chalk.white('Deployed ') + chalk.red('.env.canary') + chalk.gray(' trap file'));

    // 5. Check .gitignore
    const gitignorePath = join(cwd, '.gitignore');
    if (!existsSync(gitignorePath)) {
      await writeFile(gitignorePath, '# ResiMantle\n.resimantle/\n', 'utf-8');
      console.log(chalk.green('  ✓ ') + chalk.white('Created ') + chalk.cyan('.gitignore') + chalk.gray(' (added .resimantle/)'));
    } else {
      const content = await readFile(gitignorePath, 'utf-8');
      if (!content.includes('.resimantle/')) {
        await appendFile(gitignorePath, '\n# ResiMantle\n.resimantle/\n');
        console.log(chalk.green('  ✓ ') + chalk.white('Updated ') + chalk.cyan('.gitignore') + chalk.gray(' (added .resimantle/)'));
      }
    }

    console.log(chalk.cyan('\n  ═══════════════════════════════════════════'));
    console.log(chalk.cyan('  ║') + chalk.white(' Fresh Coat applied! ') + chalk.green('Phase: FRESH_COAT') + chalk.cyan('  ║'));
    console.log(chalk.cyan('  ═══════════════════════════════════════════\n'));
    console.log(chalk.gray('  Next steps:'));
    console.log(chalk.gray('  • Run ') + chalk.white('resimantle scan') + chalk.gray(' to detect surface vulnerabilities'));
    console.log(chalk.gray('  • Run ') + chalk.white('resimantle report') + chalk.gray(' to generate a security report'));
    console.log(chalk.gray('  • Run ') + chalk.white('resimantle run <cmd>') + chalk.gray(' to monitor your app at runtime\n'));
  });
