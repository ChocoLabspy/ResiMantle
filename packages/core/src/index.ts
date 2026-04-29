// Core infrastructure
export * from './common/logger';
export * from './common/errors';
export * from './common/constants';
export * from './common/containment';
export * from './common/types';

// Configuration
export * from './config/schema';
export * from './config/loader';
export * from './config/defaults';

// Layer 1: Surface Coat
export * from './layers/surface-coat';

// Layer 2: AI Defense
export * from './layers/ai-defense';

// Layer 3: Resin Traps
export * from './layers/resin-traps';

// Experimental vNext: False Victory
export * from './layers/false-victory';

// Layer 4: Runtime Monitor
export * from './layers/runtime-monitor';

// Layer 5: Behavior Model
export * from './layers/behavior-model';

// Layer 6: Deep Seal
export * from './layers/deep-seal';

// Layer 7: Access Gatekeeper
export * from './layers/access-gatekeeper';

// Layer 8: Policy Engine
export * from './layers/policy-engine';

// Layer 9: Audit & Explain
export * from './layers/audit';

// Runtime entrypoints
export * from './runtime';

// Engine
export * from './engine';
