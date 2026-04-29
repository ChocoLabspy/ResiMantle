import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ResiMantleConfigSchema, type ResiMantleConfig } from './schema';
import { DEFAULT_CONFIG } from './defaults';
import { ConfigError } from '../common/errors';
import { COMMON_CONSTANTS } from '../common/constants';

/**
 * Loads, validates, and merges the ResiMantle configuration from disk.
 * Falls back to sensible defaults if no config file is found.
 */
export class ConfigLoader {
  /**
   * Attempts to locate and load `resimantle.config.json` starting from `cwd`.
   * If not found, returns the default configuration.
   */
  static async load(cwd: string, configPath?: string): Promise<ResiMantleConfig> {
    const resolvedPath = configPath
      ? resolve(cwd, configPath)
      : join(cwd, COMMON_CONSTANTS.DEFAULT_CONFIG_FILE);

    if (!existsSync(resolvedPath)) {
      return DEFAULT_CONFIG;
    }

    try {
      const raw = await readFile(resolvedPath, 'utf-8');
      const parsed = JSON.parse(raw);
      const validated = ResiMantleConfigSchema.parse(parsed);
      return validated;
    } catch (error) {
      if (error instanceof z.ZodError) {
        const issues = error.issues.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
        throw new ConfigError(`Invalid resimantle.config.json:\n${issues}`);
      }
      if (error instanceof SyntaxError) {
        throw new ConfigError(`Malformed JSON in ${resolvedPath}: ${error.message}`);
      }
      throw new ConfigError(`Failed to load config from ${resolvedPath}: ${(error as Error).message}`);
    }
  }

  /**
   * Generates a fresh default config file content.
   */
  static generateDefault(): string {
    return JSON.stringify(DEFAULT_CONFIG, null, 2);
  }
}
