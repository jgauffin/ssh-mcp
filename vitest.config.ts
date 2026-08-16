import { defineConfig } from 'vitest/config';

/**
 * The default run needs no network and no server, so it stays usable as the
 * thing you run on every save. The integration suite needs Docker and is a
 * separate command; see `vitest.integration.config.ts`.
 */
export default defineConfig({
  test: {
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.integration.test.ts'],
  },
});
