import { readFile } from 'node:fs/promises';
import { RiskLevel } from '@resimantle/types';
import type { ExposedSecret } from '../types';

/**
 * A single secret-matching rule.
 */
interface SecretPattern {
  /** Display name (e.g. "AWS Access Key") */
  name: string;
  /** Internal type tag */
  type: string;
  /** Regex to test against each line */
  pattern: RegExp;
  /** How dangerous this secret is */
  risk: RiskLevel;
}

/**
 * 30+ patterns covering the most common secret leaks.
 * Each pattern is designed to minimize false positives by using anchored
 * prefixes and realistic character-class constraints.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  // ── AWS ──────────────────────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    type: 'AWS_ACCESS_KEY',
    pattern: /(?:^|[^A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?:$|[^A-Z0-9])/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'AWS Secret Access Key',
    type: 'AWS_SECRET_KEY',
    pattern: /(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
    risk: RiskLevel.CRITICAL,
  },

  // ── GitHub ───────────────────────────────────────────────────────────────
  {
    name: 'GitHub Personal Access Token',
    type: 'GITHUB_PAT',
    pattern: /ghp_[A-Za-z0-9]{36}/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'GitHub OAuth Token',
    type: 'GITHUB_OAUTH',
    pattern: /gho_[A-Za-z0-9]{36}/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'GitHub App Token',
    type: 'GITHUB_APP',
    pattern: /(?:ghu|ghs)_[A-Za-z0-9]{36}/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'GitHub Fine-Grained Token',
    type: 'GITHUB_FINE_GRAINED',
    pattern: /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/,
    risk: RiskLevel.CRITICAL,
  },

  // ── GitLab ───────────────────────────────────────────────────────────────
  {
    name: 'GitLab Personal Access Token',
    type: 'GITLAB_PAT',
    pattern: /glpat-[A-Za-z0-9\-_]{20,}/,
    risk: RiskLevel.CRITICAL,
  },

  // ── Slack ────────────────────────────────────────────────────────────────
  {
    name: 'Slack Bot Token',
    type: 'SLACK_BOT',
    pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'Slack Webhook URL',
    type: 'SLACK_WEBHOOK',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/,
    risk: RiskLevel.MEDIUM,
  },

  // ── Discord ──────────────────────────────────────────────────────────────
  {
    name: 'Discord Bot Token',
    type: 'DISCORD_BOT_TOKEN',
    pattern: /(?:[MN][A-Za-z\d]{23,})\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'Discord Webhook URL',
    type: 'DISCORD_WEBHOOK',
    pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/,
    risk: RiskLevel.MEDIUM,
  },

  // ── Google / GCP ─────────────────────────────────────────────────────────
  {
    name: 'Google API Key',
    type: 'GOOGLE_API_KEY',
    pattern: /AIza[A-Za-z0-9_\\-]{35}/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'Google OAuth Client Secret',
    type: 'GOOGLE_OAUTH_SECRET',
    pattern: /GOCSPX-[A-Za-z0-9_-]{28}/,
    risk: RiskLevel.HIGH,
  },

  // ── Stripe ───────────────────────────────────────────────────────────────
  {
    name: 'Stripe Secret Key',
    type: 'STRIPE_SECRET',
    pattern: /sk_live_[A-Za-z0-9]{24,}/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'Stripe Publishable Key (live)',
    type: 'STRIPE_PUBLISHABLE',
    pattern: /pk_live_[A-Za-z0-9]{24,}/,
    risk: RiskLevel.LOW,
  },

  // ── Twilio ───────────────────────────────────────────────────────────────
  {
    name: 'Twilio Account SID',
    type: 'TWILIO_SID',
    pattern: /AC[a-f0-9]{32}/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'Twilio Auth Token',
    type: 'TWILIO_AUTH',
    pattern: /(?:twilio_auth_token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?/i,
    risk: RiskLevel.CRITICAL,
  },

  // ── SendGrid ─────────────────────────────────────────────────────────────
  {
    name: 'SendGrid API Key',
    type: 'SENDGRID_KEY',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
    risk: RiskLevel.HIGH,
  },

  // ── Mailgun ──────────────────────────────────────────────────────────────
  {
    name: 'Mailgun API Key',
    type: 'MAILGUN_KEY',
    pattern: /key-[A-Za-z0-9]{32}/,
    risk: RiskLevel.HIGH,
  },

  // ── npm ──────────────────────────────────────────────────────────────────
  {
    name: 'npm Token',
    type: 'NPM_TOKEN',
    pattern: /npm_[A-Za-z0-9]{36}/,
    risk: RiskLevel.HIGH,
  },

  // ── PyPI ─────────────────────────────────────────────────────────────────
  {
    name: 'PyPI API Token',
    type: 'PYPI_TOKEN',
    pattern: /pypi-[A-Za-z0-9_-]{100,}/,
    risk: RiskLevel.HIGH,
  },

  // ── Heroku ───────────────────────────────────────────────────────────────
  {
    name: 'Heroku API Key',
    type: 'HEROKU_KEY',
    pattern: /(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}['"]?/i,
    risk: RiskLevel.HIGH,
  },

  // ── OpenAI ───────────────────────────────────────────────────────────────
  {
    name: 'OpenAI API Key',
    type: 'OPENAI_KEY',
    pattern: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'OpenAI Project API Key',
    type: 'OPENAI_PROJECT_KEY',
    pattern: /sk-proj-[A-Za-z0-9_-]{40,}/,
    risk: RiskLevel.CRITICAL,
  },

  // ── Anthropic ────────────────────────────────────────────────────────────
  {
    name: 'Anthropic API Key',
    type: 'ANTHROPIC_KEY',
    pattern: /sk-ant-[A-Za-z0-9_-]{40,}/,
    risk: RiskLevel.CRITICAL,
  },

  // ── Supabase ─────────────────────────────────────────────────────────────
  {
    name: 'Supabase Service Role Key',
    type: 'SUPABASE_SERVICE_KEY',
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/,
    risk: RiskLevel.CRITICAL,
  },

  // ── Firebase ─────────────────────────────────────────────────────────────
  {
    name: 'Firebase Config (API Key in code)',
    type: 'FIREBASE_KEY',
    pattern: /(?:apiKey|firebase_api_key)\s*[=:]\s*['"]AIza[A-Za-z0-9_\\-]{35}['"]/i,
    risk: RiskLevel.MEDIUM,
  },

  // ── Generic high-entropy secrets ─────────────────────────────────────────
  {
    name: 'Private Key Block',
    type: 'PRIVATE_KEY',
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'Generic API Key Assignment',
    type: 'GENERIC_API_KEY',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"][A-Za-z0-9_\-/.+]{16,}['"]/i,
    risk: RiskLevel.MEDIUM,
  },
  {
    name: 'Generic Password Assignment',
    type: 'GENERIC_PASSWORD',
    pattern: /(?:password|passwd|pwd|secret)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'Database Connection String',
    type: 'DATABASE_URL',
    pattern: /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s'"]{10,}/i,
    risk: RiskLevel.CRITICAL,
  },
  {
    name: 'Bearer Token in Code',
    type: 'BEARER_TOKEN',
    pattern: /['"]Bearer\s+[A-Za-z0-9_\-.]{20,}['"]/,
    risk: RiskLevel.HIGH,
  },
  {
    name: 'Basic Auth Credentials',
    type: 'BASIC_AUTH',
    pattern: /['"]Basic\s+[A-Za-z0-9+/=]{10,}['"]/,
    risk: RiskLevel.HIGH,
  },
];

/**
 * Files/directories that should never be scanned for secrets.
 */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pdf', '.zip', '.tar', '.gz', '.rar',
  '.mp3', '.mp4', '.avi', '.mov', '.webm',
  '.exe', '.dll', '.so', '.dylib',
  '.lock', '.min.js', '.min.css',
]);

/**
 * Detects exposed secrets, API keys, tokens, credentials, and private keys
 * in source code files using a curated set of 30+ high-precision regex patterns.
 */
export class SecretDetector {
  /**
   * Scans a single file for exposed secrets.
   * Returns all matches found with file, line, type, and risk information.
   */
  async detect(filePath: string): Promise<ExposedSecret[]> {
    // Skip binary and minified files
    const ext = filePath.substring(filePath.lastIndexOf('.'));
    if (BINARY_EXTENSIONS.has(ext)) return [];

    // Skip very large files (>2MB) to avoid performance issues
    let content: string;
    try {
      content = await readFile(filePath, 'utf-8');
    } catch {
      return []; // Can't read = can't scan
    }

    if (content.length > 2_000_000) return [];

    const findings: ExposedSecret[] = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      // Skip comments that are obviously documentation/examples
      const trimmed = line.trim();
      if (trimmed.startsWith('//') && trimmed.includes('example')) continue;
      if (trimmed.startsWith('#') && trimmed.includes('example')) continue;

      for (const rule of SECRET_PATTERNS) {
        if (rule.pattern.test(line)) {
          // Redact the match for safe storage
          const match = line.match(rule.pattern);
          const evidence = match ? redact(match[0]) : '[redacted]';

          findings.push({
            file: filePath,
            line: i + 1,
            type: rule.type,
            name: rule.name,
            risk: rule.risk,
            evidence,
          });
        }
      }
    }

    return findings;
  }
}

/**
 * Redacts a matched secret string, showing only the first 4 and last 4 characters.
 */
function redact(value: string): string {
  if (value.length <= 12) return '***REDACTED***';
  return value.slice(0, 4) + '****' + value.slice(-4);
}
