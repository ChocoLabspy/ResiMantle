import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { RiskLevel } from '@resimantle/types';
import type { DependencyVulnerability } from '../types';

/**
 * Known vulnerable package patterns.
 * In production this would query a live advisory database (OSV, Snyk, npm audit).
 * For now we maintain a curated built-in database of known-bad packages
 * and version ranges, plus heuristic checks.
 */
interface AdvisoryEntry {
  name: string;
  /** Semver range that is vulnerable (simplified check) */
  vulnerableBelow?: string;
  advisoryId: string;
  severity: RiskLevel;
  description: string;
}

const KNOWN_ADVISORIES: AdvisoryEntry[] = [
  { name: 'lodash', vulnerableBelow: '4.17.21', advisoryId: 'CVE-2021-23337', severity: RiskLevel.HIGH, description: 'Prototype pollution via template' },
  { name: 'minimist', vulnerableBelow: '1.2.6', advisoryId: 'CVE-2021-44906', severity: RiskLevel.CRITICAL, description: 'Prototype pollution' },
  { name: 'node-fetch', vulnerableBelow: '2.6.7', advisoryId: 'CVE-2022-0235', severity: RiskLevel.HIGH, description: 'Exposure of sensitive information' },
  { name: 'express', vulnerableBelow: '4.19.2', advisoryId: 'CVE-2024-29041', severity: RiskLevel.MEDIUM, description: 'Open redirect via malformed URLs' },
  { name: 'jsonwebtoken', vulnerableBelow: '9.0.0', advisoryId: 'CVE-2022-23529', severity: RiskLevel.CRITICAL, description: 'Insecure key handling' },
  { name: 'axios', vulnerableBelow: '1.6.0', advisoryId: 'CVE-2023-45857', severity: RiskLevel.HIGH, description: 'CSRF token leakage' },
  { name: 'tar', vulnerableBelow: '6.2.1', advisoryId: 'CVE-2024-28863', severity: RiskLevel.HIGH, description: 'Denial of service via crafted tar' },
  { name: 'semver', vulnerableBelow: '7.5.2', advisoryId: 'CVE-2022-25883', severity: RiskLevel.MEDIUM, description: 'ReDoS via long version strings' },
  { name: 'tough-cookie', vulnerableBelow: '4.1.3', advisoryId: 'CVE-2023-26136', severity: RiskLevel.MEDIUM, description: 'Prototype pollution' },
  { name: 'xml2js', vulnerableBelow: '0.5.0', advisoryId: 'CVE-2023-0842', severity: RiskLevel.MEDIUM, description: 'Prototype pollution' },
  { name: 'word-wrap', vulnerableBelow: '1.2.4', advisoryId: 'CVE-2023-26115', severity: RiskLevel.MEDIUM, description: 'ReDoS vulnerability' },
  { name: 'socket.io', vulnerableBelow: '4.6.2', advisoryId: 'CVE-2023-32695', severity: RiskLevel.MEDIUM, description: 'DoS via malformed packet' },
  { name: 'postcss', vulnerableBelow: '8.4.31', advisoryId: 'CVE-2023-44270', severity: RiskLevel.MEDIUM, description: 'Line return parsing error' },
  { name: 'undici', vulnerableBelow: '5.28.4', advisoryId: 'CVE-2024-30260', severity: RiskLevel.HIGH, description: 'Proxy-Authorization header leak' },
  { name: 'ip', vulnerableBelow: '2.0.1', advisoryId: 'CVE-2024-29415', severity: RiskLevel.CRITICAL, description: 'SSRF via incorrect IP validation' },
  { name: 'braces', vulnerableBelow: '3.0.3', advisoryId: 'CVE-2024-4068', severity: RiskLevel.HIGH, description: 'ReDoS via unbalanced braces' },
  { name: 'ws', vulnerableBelow: '8.17.1', advisoryId: 'CVE-2024-37890', severity: RiskLevel.HIGH, description: 'DoS via crafted request' },
  { name: 'path-to-regexp', vulnerableBelow: '6.3.0', advisoryId: 'CVE-2024-45296', severity: RiskLevel.HIGH, description: 'ReDoS via backtracking' },
];

/**
 * Packages that are inherently risky to use in production.
 */
const RISKY_PACKAGES: { name: string; reason: string; severity: RiskLevel }[] = [
  { name: 'eval', reason: 'Arbitrary code execution via eval()', severity: RiskLevel.CRITICAL },
  { name: 'shell-exec', reason: 'Uncontrolled shell execution', severity: RiskLevel.CRITICAL },
  { name: 'serialize-javascript', reason: 'Serialization can lead to code injection', severity: RiskLevel.MEDIUM },
  { name: 'node-serialize', reason: 'Known deserialization RCE vulnerability', severity: RiskLevel.CRITICAL },
  { name: 'vm2', reason: 'Sandbox escapes are common (deprecated)', severity: RiskLevel.HIGH },
  { name: 'event-stream', reason: 'Previously contained malicious code (supply chain attack)', severity: RiskLevel.CRITICAL },
  { name: 'flatmap-stream', reason: 'Malicious package from event-stream incident', severity: RiskLevel.CRITICAL },
  { name: 'colors', reason: 'Compromised by maintainer (v1.4.1+)', severity: RiskLevel.HIGH },
  { name: 'faker', reason: 'Compromised by maintainer (v6.6.6+)', severity: RiskLevel.HIGH },
];

/**
 * Checks project dependencies against a built-in advisory database
 * and identifies inherently risky packages.
 */
export class DependencyChecker {
  /**
   * Scans the package.json at the given root directory for known vulnerable
   * or risky dependencies. Checks both `dependencies` and `devDependencies`.
   */
  async check(rootDir: string): Promise<DependencyVulnerability[]> {
    const pkgPath = join(rootDir, 'package.json');
    if (!existsSync(pkgPath)) return [];

    let pkg: Record<string, unknown>;
    try {
      const raw = await readFile(pkgPath, 'utf-8');
      pkg = JSON.parse(raw);
    } catch {
      return [];
    }

    const allDeps: Record<string, string> = {
      ...(pkg.dependencies as Record<string, string> || {}),
      ...(pkg.devDependencies as Record<string, string> || {}),
    };

    const findings: DependencyVulnerability[] = [];

    for (const [name, versionRange] of Object.entries(allDeps)) {
      // Check against known advisories
      for (const advisory of KNOWN_ADVISORIES) {
        if (advisory.name === name) {
          const installedVersion = stripSemverPrefix(versionRange);
          if (advisory.vulnerableBelow && isVersionBelow(installedVersion, advisory.vulnerableBelow)) {
            findings.push({
              name,
              version: versionRange,
              advisoryId: advisory.advisoryId,
              severity: advisory.severity,
              description: advisory.description,
            });
          }
        }
      }

      // Check for inherently risky packages
      for (const risky of RISKY_PACKAGES) {
        if (risky.name === name) {
          findings.push({
            name,
            version: versionRange,
            advisoryId: 'RISKY_PACKAGE',
            severity: risky.severity,
            description: risky.reason,
          });
        }
      }
    }

    return findings;
  }
}

/**
 * Strips common semver prefixes (^, ~, >=, etc.)
 */
function stripSemverPrefix(version: string): string {
  return version.replace(/^[\^~>=<\s]+/, '');
}

/**
 * Simplified semver comparison. Returns true if `a` is strictly below `b`.
 * Handles major.minor.patch format.
 */
function isVersionBelow(a: string, b: string): boolean {
  const parseVersion = (v: string) => {
    const parts = v.split('.').map(p => parseInt(p, 10) || 0);
    return { major: parts[0] ?? 0, minor: parts[1] ?? 0, patch: parts[2] ?? 0 };
  };

  const va = parseVersion(a);
  const vb = parseVersion(b);

  if (va.major !== vb.major) return va.major < vb.major;
  if (va.minor !== vb.minor) return va.minor < vb.minor;
  return va.patch < vb.patch;
}
