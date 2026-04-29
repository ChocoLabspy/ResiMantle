import { randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { FalseVictoryActionType, ShadowSinkRecord } from './types';

export interface ShadowSinkWriteInput {
  planId: string;
  actorId: string;
  sessionId: string;
  resource: string;
  actionType: FalseVictoryActionType;
  payload?: Record<string, unknown>;
}

export class ShadowSink {
  private shadowDir: string;

  constructor(resiMantleDir: string) {
    this.shadowDir = join(resiMantleDir, 'shadow');
  }

  async write(input: ShadowSinkWriteInput): Promise<ShadowSinkRecord> {
    await this.ensureDirectory();

    const id = `shadow-${randomUUID().slice(0, 8)}`;
    const filePath = join(this.shadowDir, `${id}.json`);
    const record: ShadowSinkRecord = {
      id,
      planId: input.planId,
      actorId: input.actorId,
      sessionId: input.sessionId,
      resource: input.resource,
      actionType: input.actionType,
      payload: input.payload ?? {},
      writtenAt: new Date().toISOString(),
      filePath,
    };

    await writeFile(filePath, JSON.stringify(record, null, 2), 'utf-8');
    return record;
  }

  async list(): Promise<ShadowSinkRecord[]> {
    if (!existsSync(this.shadowDir)) {
      return [];
    }

    const files = await readdir(this.shadowDir);
    const records = await Promise.all(
      files
        .filter(file => file.endsWith('.json'))
        .map(async file => {
          const raw = await readFile(join(this.shadowDir, file), 'utf-8');
          return JSON.parse(raw) as ShadowSinkRecord;
        }),
    );

    return records.sort((left, right) => left.writtenAt.localeCompare(right.writtenAt));
  }

  private async ensureDirectory(): Promise<void> {
    if (!existsSync(this.shadowDir)) {
      await mkdir(this.shadowDir, { recursive: true });
    }
  }
}