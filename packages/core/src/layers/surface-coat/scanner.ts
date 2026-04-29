import { readdir, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { RiskLevel } from '@resimantle/types';
import type { SurfaceScanResult } from './types';
import { SecretDetector } from './detectors/secret-detector';
import { DependencyChecker } from './detectors/dependency-checker';
import { ConfigAuditor } from './detectors/config-auditor';
import { logger } from '../../common/logger';

/**
 * Directories to always skip, regardless of config.
 */
const ALWAYS_IGNORE = new Set([
  'node_modules', '.git', '.resimantle', 'dist', 'build', 'out',
  '.next', '.nuxt', '.output', '.cache', '.turbo', '.vercel',
  'coverage', '__pycache__', '.tox', 'venv', '.venv',
]);

/**
 * The Surface Coat Scanner is the primary static analysis engine.
 * It walks the project tree and runs all detectors (secrets, dependencies,
 * config) in a single pass, producing an aggregated result.
 *
 * This layer never modifies files — it only reads and reports.
 */
export interface SurfaceCoatScannerOptions {
  projectRoot: string;
  scanPaths: string[];
  ignorePatterns?: string[];
}

export class SurfaceCoatScanner {
  public scanPaths: string[];
  public ignorePatterns: string[];
  public projectRoot: string;

  private secretDetector = new SecretDetector();
  private dependencyChecker = new DependencyChecker();
  private configAuditor = new ConfigAuditor();

  constructor(
    scanPathsOrOptions: string[] | SurfaceCoatScannerOptions,
    ignorePatterns: string[] = [],
    projectRoot?: string,
  ) {
    if (Array.isArray(scanPathsOrOptions)) {
      this.scanPaths = scanPathsOrOptions;
      this.ignorePatterns = ignorePatterns;
      this.projectRoot = projectRoot ?? scanPathsOrOptions[0] ?? '.';
    } else {
      this.scanPaths = scanPathsOrOptions.scanPaths;
      this.ignorePatterns = scanPathsOrOptions.ignorePatterns ?? [];
      this.projectRoot = scanPathsOrOptions.projectRoot;
    }
  }

  /**
   * Performs a full Surface Coat scan across all configured paths.
   */
  async scan(): Promise<SurfaceScanResult> {
    const startTime = Date.now();
    logger.info(`Surface Coat scan starting across ${this.scanPaths.length} path(s)`);

    let filesScanned = 0;
    const allSecrets = [];
    const allConfigIssues = await this.configAuditor.checkMissingFiles(this.projectRoot);

    // Walk each scan path
    for (const scanPath of this.scanPaths) {
      const files = await this.walkDirectory(scanPath);
      filesScanned += files.length;

      // Secret detection (parallel per batch for performance)
      const batchSize = 50;
      for (let i = 0; i < files.length; i += batchSize) {
        const batch = files.slice(i, i + batchSize);
        const results = await Promise.all(
          batch.map(f => this.secretDetector.detect(f))
        );
        for (const secrets of results) {
          allSecrets.push(...secrets);
        }
      }

      // Config auditing on individual files
      for (const file of files) {
        const issues = await this.configAuditor.audit(file);
        allConfigIssues.push(...issues);
      }
    }

    // Dependency analysis (runs once per project root)
    const depVulns = await this.dependencyChecker.check(this.projectRoot);

    const durationMs = Date.now() - startTime;

    // Calculate aggregate risk level
    const totalRisk = this.calculateTotalRisk(allSecrets.length, depVulns.length, allConfigIssues.length);

    logger.info(`Surface Coat scan completed in ${durationMs}ms — ${filesScanned} files, ${allSecrets.length} secrets, ${depVulns.length} vulnerable deps, ${allConfigIssues.length} config issues`);

    return {
      exposedSecrets: allSecrets,
      vulnerableDependencies: depVulns,
      configIssues: allConfigIssues,
      totalRisk,
      filesScanned,
      durationMs,
    };
  }

  /**
   * Recursively walks a directory and returns all file paths, respecting ignore patterns.
   */
  private async walkDirectory(dir: string): Promise<string[]> {
    const files: string[] = [];

    try {
      const entries = await readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        const relativePath = normalizePath(relative(this.projectRoot, fullPath));

        // Check if this entry should be ignored
        if (ALWAYS_IGNORE.has(entry.name)) continue;
        if (this.isIgnored(entry.name, relativePath)) continue;

        if (entry.isDirectory()) {
          const subFiles = await this.walkDirectory(fullPath);
          files.push(...subFiles);
        } else if (entry.isFile()) {
          // Skip very large files (> 5MB)
          try {
            const fileStat = await stat(fullPath);
            if (fileStat.size > 5_000_000) continue;
          } catch {
            continue;
          }
          files.push(fullPath);
        }
      }
    } catch (error) {
      logger.warn(`Cannot read directory ${dir}: ${(error as Error).message}`);
    }

    return files;
  }

  /**
   * Checks if a file/directory name matches any ignore pattern.
   */
  private isIgnored(name: string, relativePath: string): boolean {
    const normalizedRelativePath = normalizePath(relativePath);
    const pathSegments = normalizedRelativePath.split('/').filter(Boolean);

    for (const pattern of this.ignorePatterns) {
      const normalizedPattern = normalizePath(pattern);

      // Simple glob matching
      if (normalizedPattern.startsWith('*.')) {
        if (name.endsWith(normalizedPattern.slice(1))) return true;
        continue;
      }

      if (normalizedPattern.includes('*')) {
        const regex = globPatternToRegExp(normalizedPattern);
        if (regex.test(normalizedRelativePath) || regex.test(name)) return true;
        continue;
      }

      if (
        name === normalizedPattern ||
        normalizedRelativePath === normalizedPattern ||
        normalizedRelativePath.startsWith(`${normalizedPattern}/`) ||
        pathSegments.includes(normalizedPattern)
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Calculates the overall risk level based on finding counts and severities.
   */
  private calculateTotalRisk(
    secretCount: number,
    vulnCount: number,
    configCount: number,
  ): RiskLevel {
    const totalScore = (secretCount * 8) + (vulnCount * 4) + (configCount * 1);

    if (totalScore === 0) return RiskLevel.NONE;
    if (totalScore <= 3) return RiskLevel.LOW;
    if (totalScore <= 10) return RiskLevel.MEDIUM;
    if (totalScore <= 30) return RiskLevel.HIGH;
    return RiskLevel.CRITICAL;
  }
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.\//, '');
}

function globPatternToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
  return new RegExp(`^${escaped.replace(/\*/g, '.*')}$`);
}
