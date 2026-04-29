import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'bin/resimantle.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
});
