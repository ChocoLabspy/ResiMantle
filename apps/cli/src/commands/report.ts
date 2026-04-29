import { Command, InvalidArgumentError } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { ResiMantleEngine } from '@resimantle/core';

type ReportFormat = 'md' | 'json' | 'both';

export const reportCommand = new Command('report')
  .description('Generate a security report')
  .option('-p, --path <paths...>', 'Override configured scan paths for this run')
  .option('--format <format>', 'Report format: md, json, or both', parseReportFormat, 'both')
  .action(async (options) => {
    const cwd = process.cwd();
    const spinner = ora({ text: chalk.cyan('Running scan and generating report...'), color: 'cyan' }).start();
    const scanPaths = normalizeCliPaths(options.path);

    try {
      const engine = new ResiMantleEngine({ cwd });
      await engine.init();

      // Run a full scan first
      const summary = await engine.scan({ scanPaths });
      spinner.text = chalk.cyan(`Found ${summary.totalFindings} issues. Writing report...`);

      // Generate report
      const files = await engine.report(options.format as ReportFormat);

      spinner.succeed(chalk.green('Report generated successfully!'));
      console.log('');

      for (const file of files) {
        console.log(chalk.green('  ✓ ') + chalk.white(file));
      }

      console.log('');
      console.log(chalk.gray(`  Total findings: ${summary.totalFindings}`));
      console.log(chalk.gray(`  Overall risk: ${summary.overallRisk}`));
      console.log('');
    } catch (error) {
      spinner.fail(chalk.red(`Report generation failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

function parseReportFormat(value: string): ReportFormat {
  const normalized = value.toLowerCase();
  if (normalized === 'md' || normalized === 'json' || normalized === 'both') {
    return normalized;
  }

  throw new InvalidArgumentError('Report format must be one of: md, json, both.');
}

function normalizeCliPaths(paths: string[] | undefined): string[] | undefined {
  if (!paths || paths.length === 0) return undefined;
  return Array.from(new Set(paths.filter(Boolean)));
}
