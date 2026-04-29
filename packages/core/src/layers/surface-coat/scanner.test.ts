import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SurfaceCoatScanner } from './scanner';

describe('SurfaceCoatScanner', () => {
  it('uses the project root for dependency and critical file checks', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-scanner-root-'));

    try {
      await mkdir(join(projectRoot, 'src'));
      await writeFile(join(projectRoot, 'package.json'), JSON.stringify({ dependencies: { lodash: '4.17.20' } }, null, 2));
      await writeFile(join(projectRoot, '.gitignore'), 'node_modules\n.env\n', 'utf-8');
      await writeFile(join(projectRoot, 'src', 'index.ts'), 'export const ok = true;\n', 'utf-8');

      const scanner = new SurfaceCoatScanner({
        projectRoot,
        scanPaths: [join(projectRoot, 'src')],
        ignorePatterns: [],
      });

      const result = await scanner.scan();

      expect(result.vulnerableDependencies).toHaveLength(1);
      expect(result.vulnerableDependencies[0]?.name).toBe('lodash');
      expect(result.configIssues.some(issue => issue.issue === 'No .gitignore file found')).toBe(false);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });

  it('does not ignore files that only contain an ignore token as a substring', async () => {
    const projectRoot = await mkdtemp(join(tmpdir(), 'resimantle-scanner-ignore-'));

    try {
      await writeFile(join(projectRoot, 'distribution.ts'), 'export const x = 1;\n', 'utf-8');

      const scanner = new SurfaceCoatScanner({
        projectRoot,
        scanPaths: [projectRoot],
        ignorePatterns: ['dist'],
      });

      const result = await scanner.scan();

      expect(result.filesScanned).toBe(1);
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  });
});