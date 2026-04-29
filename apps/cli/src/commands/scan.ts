import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { ResiMantleEngine } from '@resimantle/core';
import { RiskLevel } from '@resimantle/types';
import type { ScanSummary } from '@resimantle/types';

const RISK_COLORS: Record<string, (s: string) => string> = {
  [RiskLevel.NONE]: chalk.green,
  [RiskLevel.INFO]: chalk.blueBright,
  [RiskLevel.LOW]: chalk.yellow,
  [RiskLevel.MEDIUM]: chalk.hex('#FFA500'),
  [RiskLevel.HIGH]: chalk.red,
  [RiskLevel.CRITICAL]: chalk.bgRed.white.bold,
};

const RISK_ICONS: Record<string, string> = {
  [RiskLevel.NONE]: '🟢',
  [RiskLevel.INFO]: '🔵',
  [RiskLevel.LOW]: '🟡',
  [RiskLevel.MEDIUM]: '🟠',
  [RiskLevel.HIGH]: '🔴',
  [RiskLevel.CRITICAL]: '🚨',
};

export const scanCommand = new Command('scan')
  .description('Run a Surface Coat scan on the codebase')
  .option('-p, --path <paths...>', 'Override configured scan paths for this run')
  .option('--json', 'Output results as JSON', false)
  .option('--report', 'Generate a report file after scanning', false)
  .action(async (options) => {
    const cwd = process.cwd();
    const spinner = ora({ text: chalk.cyan('Initializing Surface Coat scanner...'), color: 'cyan' }).start();
    const scanPaths = normalizeCliPaths(options.path);

    try {
      const engine = new ResiMantleEngine({ cwd });
      await engine.init();
      spinner.text = chalk.cyan('Scanning codebase for vulnerabilities...');

      const summary = await engine.scan({ scanPaths });

      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(summary, null, 2));
        return;
      }

      // Beautiful terminal output
      printScanResults(summary);

      // Generate report if requested
      if (options.report) {
        const reportSpinner = ora({ text: chalk.cyan('Generating report...'), color: 'cyan' }).start();
        const files = await engine.report('both');
        reportSpinner.succeed(chalk.green(`Reports written to: ${files.join(', ')}`));
      }

    } catch (error) {
      spinner.fail(chalk.red(`Scan failed: ${(error as Error).message}`));
      process.exit(1);
    }
  });

function printScanResults(summary: ScanSummary): void {
  const riskColor = RISK_COLORS[summary.overallRisk] || chalk.white;
  const riskIcon = RISK_ICONS[summary.overallRisk] || '❓';

  console.log('');
  console.log(chalk.cyan('  ┌─────────────────────────────────────────────────┐'));
  console.log(chalk.cyan('  │') + chalk.white.bold('          🛡️  SURFACE COAT SCAN RESULTS          ') + chalk.cyan('│'));
  console.log(chalk.cyan('  └─────────────────────────────────────────────────┘'));
  console.log('');

  // Overall risk
  console.log(`  ${riskIcon}  Overall Risk: ${riskColor(summary.overallRisk)}`);
  console.log(chalk.gray(`     Files scanned: ${summary.filesScanned}`));
  console.log(chalk.gray(`     Duration: ${summary.durationMs}ms`));
  console.log(chalk.gray(`     Total findings: ${summary.totalFindings}`));
  console.log('');

  // Severity breakdown
  if (summary.totalFindings > 0) {
    console.log(chalk.white.bold('  Findings by Severity:'));
    console.log('');

    for (const level of [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]) {
      const count = summary.findingsBySeverity[level] || 0;
      if (count === 0) continue;

      const color = RISK_COLORS[level] || chalk.white;
      const icon = RISK_ICONS[level] || '•';
      const bar = '█'.repeat(Math.min(count, 30));
      console.log(`    ${icon}  ${color(level.padEnd(10))} ${color(bar)} ${chalk.white.bold(String(count))}`);
    }

    console.log('');
    console.log(chalk.gray('  ─'.repeat(25)));
    console.log('');

    // Top findings
    const topFindings = summary.findings
      .filter(f => f.severity === RiskLevel.CRITICAL || f.severity === RiskLevel.HIGH)
      .slice(0, 10);

    if (topFindings.length > 0) {
      console.log(chalk.white.bold('  Top Critical/High Findings:'));
      console.log('');

      for (const finding of topFindings) {
        const color = RISK_COLORS[finding.severity] || chalk.white;
        const icon = RISK_ICONS[finding.severity] || '•';
        console.log(`    ${icon}  ${color(finding.type)}`);
        if (finding.file) {
          console.log(chalk.gray(`       File: ${finding.file}${finding.line ? `:${finding.line}` : ''}`));
        }
        if (finding.evidence) {
          console.log(chalk.gray(`       Evidence: ${finding.evidence}`));
        }
        if (finding.recommendation) {
          console.log(chalk.cyan(`       Fix: ${finding.recommendation}`));
        }
        console.log('');
      }
    }
  } else {
    console.log(chalk.green('  ✨ No security issues found! Your surface is clean.'));
    console.log('');
  }

  console.log(chalk.gray(`  Scan completed at ${summary.completedAt}`));
  console.log(chalk.gray(`  Run ${chalk.white('resimantle report')} for a full detailed report.`));
  console.log('');
}

function normalizeCliPaths(paths: string[] | undefined): string[] | undefined {
  if (!paths || paths.length === 0) return undefined;
  return Array.from(new Set(paths.filter(Boolean)));
}
