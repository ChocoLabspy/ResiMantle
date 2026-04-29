import { join } from 'node:path';
import { z } from 'zod';

const RegexPatternSchema = z.string().superRefine((value, context) => {
  try {
    new RegExp(value);
  } catch {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Invalid regular expression pattern',
    });
  }
});

const ContainmentAllowlistSchema = z.object({
  readPatterns: z.array(RegexPatternSchema).default([]),
  processPatterns: z.array(RegexPatternSchema).default([]),
  socketHosts: z.array(z.string()).default([]),
  socketHostPatterns: z.array(RegexPatternSchema).default([]),
  socketPathPatterns: z.array(RegexPatternSchema).default([]),
});

export const ResiMantleConfigSchema = z.object({
  version: z.literal('0.1.0'),
  layers: z.object({
    surfaceCoat: z.object({
      enabled: z.boolean().default(true),
      scanPaths: z.array(z.string()).default(['.']),
      ignorePatterns: z.array(z.string()).default(['node_modules', 'dist', '.git']),
    }),
    aiDefense: z.object({
      enabled: z.boolean().default(true),
      proxyMode: z.boolean().default(false),
    }),
    runtimeMonitor: z.object({
      enabled: z.boolean().default(true),
      sampleRate: z.number().min(0).max(1).default(1.0),
      control: z.object({
        autoPosture: z.boolean().default(true),
        sessionTtlMs: z.number().int().min(1_000).default(15 * 60_000),
        heartbeatGraceMs: z.number().int().min(1_000).default(45_000),
        capabilityQuarantine: z.boolean().default(true),
      }).default({
        autoPosture: true,
        sessionTtlMs: 15 * 60_000,
        heartbeatGraceMs: 45_000,
        capabilityQuarantine: true,
      }),
      containment: z.object({
        mode: z.enum(['off', 'adaptive', 'strict']).default('adaptive'),
        allow: ContainmentAllowlistSchema.default({
          readPatterns: [],
          processPatterns: [],
          socketHosts: [],
          socketHostPatterns: [],
          socketPathPatterns: [],
        }),
      }).default({
        mode: 'adaptive',
        allow: {
          readPatterns: [],
          processPatterns: [],
          socketHosts: [],
          socketHostPatterns: [],
          socketPathPatterns: [],
        },
      }),
      baseline: z.object({
        enabled: z.boolean().default(true),
        mode: z.enum(['off', 'observe', 'assist']).default('assist'),
        persistencePath: z.string().default(join('.resimantle', 'runtime-baseline.json')),
        minOccurrences: z.number().int().min(1).default(3),
        autoApplyToContainment: z.boolean().default(true),
        reduceRiskFromKnownActivity: z.boolean().default(true),
      }).default({
        enabled: true,
        mode: 'assist',
        persistencePath: join('.resimantle', 'runtime-baseline.json'),
        minOccurrences: 3,
        autoApplyToContainment: true,
        reduceRiskFromKnownActivity: true,
      }),
    }),
  }),
  policy: z.object({
    path: z.string().default('./.resimantle/policy.json'),
  }),
});

export type ResiMantleConfig = z.infer<typeof ResiMantleConfigSchema>;
