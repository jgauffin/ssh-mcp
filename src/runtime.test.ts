import { describe, expect, it } from 'vitest';
import { isLoopback } from './runtime.js';

/** Decides whether an unencrypted key needs a click, so a remote host must never pass. */
describe('isLoopback', () => {
  it.each(['localhost', 'LOCALHOST', '127.0.0.1', '127.1.2.3', '::1', '[::1]'])('treats %s as this machine', (host) => {
    expect(isLoopback(host)).toBe(true);
  });

  it.each(['10.0.0.4', 'localhost.example.com', '127.0.0.1.example.com', '1270.0.0.1', '::2', 'prod-1'])(
    'treats %s as remote',
    (host) => {
      expect(isLoopback(host)).toBe(false);
    },
  );
});
