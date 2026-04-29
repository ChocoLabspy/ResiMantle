import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Reporter } from './reporter';

describe('Reporter', () => {
  it('rejects unsupported report formats', async () => {
    const outputDir = await mkdtemp(join(tmpdir(), 'resimantle-reporter-'));

    try {
      const reporter = new Reporter([], outputDir);
      await expect(reporter.writeToDisk('foo' as never)).rejects.toThrow(
        'Unsupported report format: foo. Use one of: md, json, both.',
      );
    } finally {
      await rm(outputDir, { recursive: true, force: true });
    }
  });
});