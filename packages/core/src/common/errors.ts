export class ResiMantleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResiMantleError';
  }
}

export class ConfigError extends ResiMantleError {
  constructor(message: string) {
    super(`Config Error: ${message}`);
    this.name = 'ConfigError';
  }
}

export class PolicyError extends ResiMantleError {
  constructor(message: string) {
    super(`Policy Error: ${message}`);
    this.name = 'PolicyError';
  }
}
