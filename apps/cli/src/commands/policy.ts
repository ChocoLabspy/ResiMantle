import { Command } from 'commander';
import chalk from 'chalk';
import { PromptShield, ToolPolicyEnforcer } from '@resimantle/core';
import { RiskLevel } from '@resimantle/types';

export const policyCommand = new Command('policy')
  .description('Manage and validate policies')
  .addCommand(
    new Command('tools')
      .description('List all AI tool policies')
      .action(async () => {
        const enforcer = new ToolPolicyEnforcer();
        const policies = enforcer.getAllPolicies();

        console.log(chalk.cyan('\n  AI Tool Policies:\n'));

        for (const policy of policies) {
          const status = policy.allowed ? chalk.green('✓ ALLOWED') : chalk.red('✗ BLOCKED');
          const approval = policy.requiresApproval ? chalk.yellow(' (approval required)') : '';
          const rate = policy.maxCallsPerMinute ? chalk.gray(` [${policy.maxCallsPerMinute}/min]`) : '';

          console.log(`    ${status}  ${chalk.white(policy.toolName)}${approval}${rate}`);

          if (policy.blockedActions && policy.blockedActions.length > 0) {
            console.log(chalk.gray(`            Blocked actions: ${policy.blockedActions.join(', ')}`));
          }
        }

        console.log('');
      })
  )
  .addCommand(
    new Command('test-prompt')
      .description('Test a prompt against the injection shield')
      .argument('<prompt>', 'The prompt text to analyze')
      .action(async (prompt: string) => {
        const shield = new PromptShield();
        const result = await shield.analyze(prompt);

        const RISK_COLORS: Record<string, (s: string) => string> = {
          [RiskLevel.NONE]: chalk.green,
          [RiskLevel.INFO]: chalk.blueBright,
          [RiskLevel.LOW]: chalk.yellow,
          [RiskLevel.MEDIUM]: chalk.hex('#FFA500'),
          [RiskLevel.HIGH]: chalk.red,
          [RiskLevel.CRITICAL]: chalk.bgRed.white.bold,
        };

        const color = RISK_COLORS[result.injectionRisk] || chalk.white;

        console.log('');
        console.log(chalk.cyan('  Prompt Shield Analysis:'));
        console.log('');
        console.log(`  Safe: ${result.isSafe ? chalk.green('YES') : chalk.red('NO')}`);
        console.log(`  Risk: ${color(result.injectionRisk)}`);
        console.log(`  Score: ${color(String(result.score))}`);
        console.log(`  Patterns matched: ${chalk.white(String(result.patternsMatched))}`);

        if (result.flags.length > 0) {
          console.log('');
          console.log(chalk.white.bold('  Flags:'));
          for (const flag of result.flags) {
            console.log(chalk.red(`    ⚠  ${flag}`));
          }
        }
        console.log('');
      })
  );
