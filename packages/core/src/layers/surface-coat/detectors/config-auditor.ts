import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { RiskLevel } from '@resimantle/types';
import type { ConfigIssue } from '../types';

/**
 * A single config-auditing rule.
 */
interface ConfigRule {
  /** Files to check (basenames) */
  files: string[];
  /** Pattern that indicates an issue */
  pattern: RegExp;
  /** Human-readable issue description */
  issue: string;
  /** Recommended fix */
  recommendation: string;
  /** Severity of the issue */
  severity: RiskLevel;
}

/**
 * Rules for detecting dangerous configuration patterns across
 * common project configuration files.
 */
const CONFIG_RULES: ConfigRule[] = [
  // ── Node.js / Express ────────────────────────────────────────────────────
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /app\.listen\(\s*(?:80|443|3000|8080)\s*[,)]/,
    issue: 'Hardcoded port number detected',
    recommendation: 'Use environment variables: process.env.PORT || 3000',
    severity: RiskLevel.LOW,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /cors\(\s*\)|\cors\(\s*\{\s*origin\s*:\s*['"]?\*['"]?\s*\}/,
    issue: 'CORS is configured to accept all origins',
    recommendation: 'Restrict CORS to specific trusted domains',
    severity: RiskLevel.HIGH,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /(?:NODE_ENV|node_env)\s*[!=]==?\s*['"](?:development|dev)['"]/,
    issue: 'Code may behave differently in development mode',
    recommendation: 'Ensure production environment is explicitly set in deployments',
    severity: RiskLevel.INFO,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /eval\s*\(/,
    issue: 'Direct eval() usage detected — potential code injection vector',
    recommendation: 'Remove eval() and use safe alternatives (JSON.parse, Function constructors with caution)',
    severity: RiskLevel.CRITICAL,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /child_process.*exec\s*\(|execSync\s*\(/,
    issue: 'Uncontrolled shell execution detected',
    recommendation: 'Use execFile() with explicit arguments instead of exec() to prevent command injection',
    severity: RiskLevel.HIGH,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /\.innerHTML\s*=|\.outerHTML\s*=/,
    issue: 'Direct innerHTML assignment — potential XSS vector',
    recommendation: 'Use textContent, DOM APIs, or a sanitizer library (DOMPurify)',
    severity: RiskLevel.HIGH,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /new\s+Function\s*\(/,
    issue: 'Dynamic Function constructor detected — potential code injection',
    recommendation: 'Avoid dynamic function creation from strings',
    severity: RiskLevel.HIGH,
  },
  {
    files: ['*.ts', '*.js', '*.mjs', '*.cjs'],
    pattern: /console\.(log|warn|error|debug|info)\s*\(/,
    issue: 'Console logging detected in source code',
    recommendation: 'Use a structured logger (e.g., pino, winston) for production; remove console statements',
    severity: RiskLevel.INFO,
  },

  // ── Docker ───────────────────────────────────────────────────────────────
  {
    files: ['Dockerfile', 'Dockerfile.*'],
    pattern: /FROM\s+.*:latest/i,
    issue: 'Docker image uses `:latest` tag — unpredictable builds',
    recommendation: 'Pin a specific image version tag for reproducible builds',
    severity: RiskLevel.MEDIUM,
  },
  {
    files: ['Dockerfile', 'Dockerfile.*'],
    pattern: /USER\s+root/i,
    issue: 'Container runs as root user',
    recommendation: 'Create a non-root user: USER node',
    severity: RiskLevel.HIGH,
  },

  // ── Environment files ────────────────────────────────────────────────────
  {
    files: ['.env', '.env.local', '.env.production', '.env.development'],
    pattern: /^(?!#).*=.+/m,
    issue: '.env file contains values — ensure it is gitignored',
    recommendation: 'Add .env* to .gitignore; use .env.example with placeholder values',
    severity: RiskLevel.MEDIUM,
  },

  // ── Package.json ─────────────────────────────────────────────────────────
  {
    files: ['package.json'],
    pattern: /"scripts"\s*:\s*\{[^}]*"(preinstall|postinstall|prepare)"\s*:/,
    issue: 'Lifecycle scripts detected (preinstall/postinstall) — supply chain risk',
    recommendation: 'Review lifecycle scripts carefully; consider using --ignore-scripts for CI',
    severity: RiskLevel.MEDIUM,
  },

  // ── tsconfig ─────────────────────────────────────────────────────────────
  {
    files: ['tsconfig.json', 'tsconfig.*.json'],
    pattern: /"strict"\s*:\s*false/,
    issue: 'TypeScript strict mode is disabled',
    recommendation: 'Enable "strict": true for maximum type safety',
    severity: RiskLevel.MEDIUM,
  },

  // ── Git ──────────────────────────────────────────────────────────────────
  {
    files: ['.gitignore'],
    pattern: /^$/m,
    issue: '.gitignore exists but may be incomplete',
    recommendation: 'Ensure .env, .resimantle/, node_modules/, dist/ are gitignored',
    severity: RiskLevel.INFO,
  },
];

/**
 * Audits project configuration files for dangerous patterns,
 * misconfigurations, and security anti-patterns.
 */
export class ConfigAuditor {
  /**
   * Audits a specific file against all applicable rules.
   */
  async audit(filePath: string): Promise<ConfigIssue[]> {
    if (!existsSync(filePath)) return [];

    const name = basename(filePath);
    const findings: ConfigIssue[] = [];

    let content: string;
    try {
      content = await readFile(filePath, 'utf-8');
    } catch {
      return [];
    }

    for (const rule of CONFIG_RULES) {
      if (!matchesFilePattern(name, rule.files)) continue;

      if (rule.pattern.test(content)) {
        findings.push({
          file: filePath,
          issue: rule.issue,
          recommendation: rule.recommendation,
          severity: rule.severity,
        });
      }
    }

    return findings;
  }

  /**
   * Checks for missing critical files in the project root.
   */
  async checkMissingFiles(rootDir: string): Promise<ConfigIssue[]> {
    const findings: ConfigIssue[] = [];

    const criticalFiles: { file: string; issue: string; rec: string; severity: RiskLevel }[] = [
      { file: '.gitignore', issue: 'No .gitignore file found', rec: 'Create a .gitignore to prevent committing secrets and build artifacts', severity: RiskLevel.HIGH },
      { file: '.env.example', issue: 'No .env.example template found', rec: 'Create .env.example with placeholder values for team onboarding', severity: RiskLevel.LOW },
    ];

    for (const check of criticalFiles) {
      if (!existsSync(join(rootDir, check.file))) {
        findings.push({
          file: check.file,
          issue: check.issue,
          recommendation: check.rec,
          severity: check.severity,
        });
      }
    }

    // Check if .env files are gitignored
    const gitignorePath = join(rootDir, '.gitignore');
    if (existsSync(gitignorePath)) {
      const gitignore = await readFile(gitignorePath, 'utf-8');
      if (!gitignore.includes('.env')) {
        findings.push({
          file: '.gitignore',
          issue: '.env files are NOT in .gitignore — secrets may be committed',
          recommendation: 'Add `.env*` to .gitignore immediately',
          severity: RiskLevel.CRITICAL,
        });
      }
    }

    return findings;
  }
}

/**
 * Checks if a filename matches any of the given glob-like patterns.
 */
function matchesFilePattern(filename: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern.startsWith('*.')) {
      if (filename.endsWith(pattern.slice(1))) return true;
    } else if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      if (regex.test(filename)) return true;
    } else {
      if (filename === pattern) return true;
    }
  }
  return false;
}
