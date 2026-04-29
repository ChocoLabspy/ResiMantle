import { z } from 'zod';
import { AccessDecision } from '@resimantle/types';

export const PolicyRuleSchema = z.object({
  resourcePattern: z.string(),
  actorPattern: z.string(),
  decision: z.nativeEnum(AccessDecision),
  priority: z.number().int().min(0).default(100),
});

export const PolicySchema = z.object({
  version: z.literal('0.1.0'),
  rules: z.array(PolicyRuleSchema),
});
