import { describe, expect, it } from 'vitest';
import { formatPattern, matches, parsePattern, PatternError, proposePatterns } from './matcher.js';

describe('parsePattern', () => {
  it('splits on whitespace', () => {
    expect(parsePattern('  systemctl   restart *  ')).toEqual(['systemctl', 'restart', '*']);
  });

  it('rejects an empty pattern', () => {
    expect(() => parsePattern('   ')).toThrow(PatternError);
  });

  it('allows ** only in tail position', () => {
    expect(parsePattern('systemctl **')).toEqual(['systemctl', '**']);
    expect(() => parsePattern('systemctl ** restart')).toThrow(PatternError);
  });
});

describe('matches', () => {
  const pattern = (text: string) => parsePattern(text);

  it('matches an exact command', () => {
    expect(matches(pattern('systemctl restart nginx'), ['systemctl', 'restart', 'nginx'])).toBe(true);
  });

  it('lets * stand for exactly one argument', () => {
    expect(matches(pattern('systemctl restart *'), ['systemctl', 'restart', 'nginx'])).toBe(true);
    expect(matches(pattern('systemctl restart *'), ['systemctl', 'restart'])).toBe(false);
  });

  it('refuses an extra argument — the case a string glob would let through', () => {
    expect(matches(pattern('systemctl restart *'), ['systemctl', 'restart', 'nginx', '--now'])).toBe(false);
  });

  it('does not let * cross an argument boundary', () => {
    expect(matches(pattern('systemctl *'), ['systemctl', 'restart', 'nginx'])).toBe(false);
  });

  it('lets ** cover the remaining arguments', () => {
    expect(matches(pattern('systemctl **'), ['systemctl', 'restart', 'nginx'])).toBe(true);
    expect(matches(pattern('systemctl **'), ['systemctl'])).toBe(true);
    expect(matches(pattern('systemctl **'), ['journalctl', '-u', 'nginx'])).toBe(false);
  });

  it('does not match a different verb', () => {
    expect(matches(pattern('systemctl restart *'), ['systemctl', 'stop', 'nginx'])).toBe(false);
  });

  it('is not a substring match', () => {
    expect(matches(pattern('systemctl restart ngin'), ['systemctl', 'restart', 'nginx'])).toBe(false);
  });
});

describe('proposePatterns', () => {
  it('offers exact, then one-argument, then tail wildcards', () => {
    expect(proposePatterns(['systemctl', 'restart', 'nginx']).map(formatPattern)).toEqual([
      'systemctl restart nginx',
      'systemctl restart *',
      'systemctl **',
    ]);
  });

  it('offers only the exact command when there is nothing to widen', () => {
    expect(proposePatterns(['reboot']).map(formatPattern)).toEqual(['reboot']);
  });

  it('never proposes a pattern that fails to match the command it came from', () => {
    const argv = ['journalctl', '-u', 'nginx', '--since', 'today'];
    for (const proposal of proposePatterns(argv)) {
      expect(matches(proposal, argv)).toBe(true);
    }
  });
});
