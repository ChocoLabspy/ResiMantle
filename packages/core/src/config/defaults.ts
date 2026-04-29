export const DEFAULT_CONFIG = {
  version: '0.1.0' as const,
  layers: {
    surfaceCoat: {
      enabled: true,
      scanPaths: ['.'],
      ignorePatterns: ['node_modules', 'dist', '.git', '.resimantle'],
    },
    aiDefense: {
      enabled: true,
      proxyMode: false,
    },
    runtimeMonitor: {
      enabled: true,
      sampleRate: 1.0,
      control: {
        autoPosture: true,
        sessionTtlMs: 15 * 60_000,
        heartbeatGraceMs: 45_000,
        capabilityQuarantine: true,
      },
      containment: {
        mode: 'adaptive' as const,
        allow: {
          readPatterns: [],
          processPatterns: [],
          socketHosts: [],
          socketHostPatterns: [],
          socketPathPatterns: [],
        },
      },
      baseline: {
        enabled: true,
        mode: 'assist' as const,
        persistencePath: '.resimantle/runtime-baseline.json',
        minOccurrences: 3,
        autoApplyToContainment: true,
        reduceRiskFromKnownActivity: true,
      },
    },
  },
  policy: {
    path: './.resimantle/policy.json',
  },
};
