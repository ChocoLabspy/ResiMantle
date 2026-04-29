import { randomBytes } from 'node:crypto';
import type { TrapScope } from './types';

interface PromptCanaryRecord extends TrapScope {
  createdAt: string;
}

/**
 * Generates invisible canary markers that can be injected into AI prompts.
 * These markers use Unicode zero-width characters to create unique,
 * invisible fingerprints. If the AI agent's output contains these markers,
 * it indicates the agent is leaking or repeating system prompt content.
 */
export class PromptCanary {
  private canaryMap: Map<string, PromptCanaryRecord> = new Map();

  /**
   * Injects an invisible canary watermark into a prompt string.
   * The watermark is invisible to humans but detectable by the system.
   */
  inject(prompt: string, scope: TrapScope = {}): string {
    const canaryId = randomBytes(4).toString('hex');
    const watermark = this.encodeToZeroWidth(canaryId);

    // Insert the watermark at a natural boundary (after first sentence)
    const firstPeriod = prompt.indexOf('. ');
    let injectedPrompt: string;

    if (firstPeriod > 0) {
      injectedPrompt = prompt.slice(0, firstPeriod + 1) + watermark + prompt.slice(firstPeriod + 1);
    } else {
      injectedPrompt = watermark + prompt;
    }

    this.canaryMap.set(canaryId, {
      ...scope,
      createdAt: new Date().toISOString(),
    });
    return injectedPrompt;
  }

  /**
   * Checks if a string (e.g., AI output) contains any of our canary watermarks.
   * If it does, the AI is leaking system prompt content.
   */
  detect(output: string): {
    leaked: boolean;
    canaryId?: string;
    actorId?: string;
    sessionId?: string;
    storyId?: string;
  } {
    const decoded = this.decodeFromZeroWidth(output);
    if (decoded) {
      const record = this.canaryMap.get(decoded);
      if (record) {
        return {
          leaked: true,
          canaryId: decoded,
          actorId: record.actorId,
          sessionId: record.sessionId,
          storyId: record.storyId,
        };
      }
    }
    return { leaked: false };
  }

  // ── Zero-width encoding ────────────────────────────────────────────────

  /**
   * Encodes a hex string into zero-width Unicode characters.
   * Uses: Zero-Width Space (U+200B), Zero-Width Non-Joiner (U+200C),
   * Zero-Width Joiner (U+200D), Word Joiner (U+2060).
   */
  private encodeToZeroWidth(hex: string): string {
    const chars = ['\u200B', '\u200C', '\u200D', '\u2060'];
    let result = '\uFEFF'; // Start marker (Zero-Width No-Break Space)

    for (const char of hex) {
      const nibble = parseInt(char, 16);
      result += chars[(nibble >> 2) & 3]!;
      result += chars[nibble & 3]!;
    }

    result += '\uFEFF'; // End marker
    return result;
  }

  /**
   * Decodes zero-width characters back to a hex string.
   */
  private decodeFromZeroWidth(text: string): string | null {
    const chars: Record<string, number> = {
      '\u200B': 0, '\u200C': 1, '\u200D': 2, '\u2060': 3,
    };

    // Find the watermark boundaries
    const startIdx = text.indexOf('\uFEFF');
    if (startIdx === -1) return null;
    const endIdx = text.indexOf('\uFEFF', startIdx + 1);
    if (endIdx === -1) return null;

    const watermark = text.slice(startIdx + 1, endIdx);
    let hex = '';

    for (let i = 0; i < watermark.length; i += 2) {
      const high = chars[watermark[i]!];
      const low = chars[watermark[i + 1]!];
      if (high === undefined || low === undefined) return null;
      hex += ((high << 2) | low).toString(16);
    }

    return hex;
  }
}
