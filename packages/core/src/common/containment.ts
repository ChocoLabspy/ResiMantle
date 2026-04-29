import type { ProcessContainmentAllowlist } from './types';

export function normalizeContainmentAllowlist(allowlist: ProcessContainmentAllowlist): ProcessContainmentAllowlist {
  return {
    readPatterns: Array.isArray(allowlist.readPatterns) ? allowlist.readPatterns : [],
    processPatterns: Array.isArray(allowlist.processPatterns) ? allowlist.processPatterns : [],
    socketHosts: Array.isArray(allowlist.socketHosts) ? allowlist.socketHosts : [],
    socketHostPatterns: Array.isArray(allowlist.socketHostPatterns) ? allowlist.socketHostPatterns : [],
    socketPathPatterns: Array.isArray(allowlist.socketPathPatterns) ? allowlist.socketPathPatterns : [],
  };
}

export function serializeContainmentAllowlist(allowlist: ProcessContainmentAllowlist): string | undefined {
  const normalized = normalizeContainmentAllowlist(allowlist);
  const hasRules = Object.values(normalized).some(value => Array.isArray(value) && value.length > 0);
  return hasRules ? JSON.stringify(normalized) : undefined;
}

export function mergeContainmentAllowlists(
  primary: ProcessContainmentAllowlist,
  learned: ProcessContainmentAllowlist,
): ProcessContainmentAllowlist {
  const normalizedPrimary = normalizeContainmentAllowlist(primary);
  const normalizedLearned = normalizeContainmentAllowlist(learned);

  return {
    readPatterns: Array.from(new Set([...(normalizedPrimary.readPatterns ?? []), ...(normalizedLearned.readPatterns ?? [])])),
    processPatterns: Array.from(new Set([...(normalizedPrimary.processPatterns ?? []), ...(normalizedLearned.processPatterns ?? [])])),
    socketHosts: Array.from(new Set([...(normalizedPrimary.socketHosts ?? []), ...(normalizedLearned.socketHosts ?? [])])),
    socketHostPatterns: Array.from(new Set([...(normalizedPrimary.socketHostPatterns ?? []), ...(normalizedLearned.socketHostPatterns ?? [])])),
    socketPathPatterns: Array.from(new Set([...(normalizedPrimary.socketPathPatterns ?? []), ...(normalizedLearned.socketPathPatterns ?? [])])),
  };
}