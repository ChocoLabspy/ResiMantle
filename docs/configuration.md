# Configuration

The central configuration for ResiMantle lives in `resimantle.config.json` at the root of your project.

## Example Configuration

```json
{
  "version": "0.1.0",
  "layers": {
    "surfaceCoat": {
      "enabled": true,
      "scanPaths": ["."],
      "ignorePatterns": ["node_modules", "dist", ".git", ".resimantle"]
    },
    "aiDefense": {
      "enabled": true,
      "proxyMode": false
    },
    "runtimeMonitor": {
      "enabled": true,
      "sampleRate": 1.0
    }
  },
  "policy": {
    "path": "./.resimantle/policy.json"
  }
}
```

## Configuration Reference

### `layers`
Controls the activation and settings for individual defensive layers.

#### `surfaceCoat`
- `enabled`: (boolean) Run static scans on command.
- `scanPaths`: (array of strings) Directories to scan.
- `ignorePatterns`: (array of strings) Patterns to ignore during scanning.

#### `aiDefense`
- `enabled`: (boolean) Enable prompt injection detection and tool policies.
- `proxyMode`: (boolean) If true, ResiMantle will attempt to intercept outbound HTTP calls to known AI providers.

#### `runtimeMonitor`
- `enabled`: (boolean) Enable real-time observation when using `resimantle run`.
- `sampleRate`: (number 0.0 - 1.0) What percentage of requests to log (useful for high-traffic apps).

### `policy`
- `path`: Location of the declarative policy file (usually generated in the `.resimantle` directory).
