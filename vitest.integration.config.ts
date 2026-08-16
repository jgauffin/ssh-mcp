import { defineConfig } from 'vitest/config';

/**
 * Against a real SSH host in a container. Builds an image, starts sshd, and
 * edits files on it for real, so the timeouts are generous and the files run
 * one at a time: two suites racing for the same container is a flake, not a
 * finding.
 */
export default defineConfig({
  test: {
    include: ['**/*.integration.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 600_000,
    fileParallelism: false,
  },
});
