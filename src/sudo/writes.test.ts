import { describe, expect, it } from 'vitest';
import { parseCommandLine } from './parse.js';
import { detectFileWrite, guardedPath } from './writes.js';

const detect = (line: string) => detectFileWrite(parseCommandLine(line));

describe('guardedPath', () => {
  it('guards absolute paths', () => {
    expect(guardedPath('/etc/nginx/nginx.conf')).toBe(true);
    expect(guardedPath('/home/deploy/app.yml')).toBe(true);
    expect(guardedPath('/var/log/app.log')).toBe(true);
  });

  it('leaves the scratch roots alone', () => {
    for (const path of ['/dev/null', '/dev/stderr', '/tmp/out', '/var/tmp/x', '/dev/shm/x', '/run/user/1000/x']) {
      expect(guardedPath(path), path).toBe(false);
    }
  });

  it('does not reason about relative paths at all', () => {
    for (const path of ['out.txt', './out.txt', '$HOME/log', '~/notes', '"$ROOT"/etc/x']) {
      expect(guardedPath(path), path).toBe(false);
    }
  });
});

/**
 * The half that protects users.
 *
 * A guard that refuses ordinary commands gets switched off, and then it guards
 * nothing at all. These are written first and deliberately mundane.
 */
describe('commands that must keep working', () => {
  it.each([
    'uptime',
    'systemctl status nginx',
    'journalctl -u nginx | tail -50',
    'systemctl status nginx > /dev/null 2>&1',
    'ls 2>&1',
    'ls >&2',
    'dmesg > /tmp/dmesg.txt',
    'foo >> /var/tmp/log',
    'make 2>&1 | tee build.log',
    'echo hi > out.txt',
    'ls > $HOME/list',
    'ls > ~/list',
    'cat < /etc/hosts',
    'diff /tmp/a /tmp/b',
    'grep -r shared_buffers /etc',
    'echo "x > /etc/foo"',
    "echo 'x > /etc/foo'",
    'sed s/a/b/ /etc/hosts',
    'sed -n 2p /etc/hosts',
    'sed -i s/a/b/ /tmp/scratch',
    'curl -o /tmp/x https://example.test/x',
    'curl -sSL https://example.test/x',
    'cp /etc/nginx/nginx.conf /tmp/backup',
    'tee /dev/stderr',
    'tar -tzf /tmp/x.tgz',
    'sudo systemctl restart nginx',
    'sudo journalctl -u nginx --since today',
  ])('%s', (line) => {
    expect(detect(line)).toBeUndefined();
  });
});

describe('writes that must be refused', () => {
  it.each([
    ['echo x > /etc/foo', '/etc/foo'],
    ['echo x >> /etc/foo', '/etc/foo'],
    ['echo x >/etc/foo', '/etc/foo'],
    ['cat /tmp/new > /etc/nginx/nginx.conf', '/etc/nginx/nginx.conf'],
    ['uptime && echo x > /etc/foo', '/etc/foo'],
    ['echo x > /home/deploy/app/config.yml', '/home/deploy/app/config.yml'],
    ['sed -i s/a/b/ /etc/hosts', '/etc/hosts'],
    ['sed -i.bak -e s/a/b/ /etc/hosts', '/etc/hosts'],
    ['sed --in-place=.bak -e s/a/b/ /etc/hosts', '/etc/hosts'],
    ['sed -ni p /etc/hosts', '/etc/hosts'],
    ["perl -pi -e 's/a/b/' /etc/hosts", '/etc/hosts'],
    ['tee /etc/hosts', '/etc/hosts'],
    ['tee -a /etc/hosts', '/etc/hosts'],
    ['dd if=/dev/zero of=/etc/x', '/etc/x'],
    ['truncate -s 0 /var/log/syslog', '/var/log/syslog'],
    ['curl -o /etc/yum.repos.d/x.repo https://example.test/x', '/etc/yum.repos.d/x.repo'],
    ['curl --output=/etc/x https://example.test/x', '/etc/x'],
    ['wget -O /etc/x https://example.test/x', '/etc/x'],
    ['patch /etc/hosts /tmp/x.patch', '/etc/hosts'],
    ['vim /etc/hosts', '/etc/hosts'],
    ['ed /etc/hosts', '/etc/hosts'],
    ['cp /tmp/x /etc/nginx/nginx.conf', '/etc/nginx/nginx.conf'],
    ['mv /tmp/x /etc/hosts', '/etc/hosts'],
    ['install -m 0644 /tmp/x /etc/x', '/etc/x'],
  ])('%s', (line, target) => {
    expect(detect(line)).toMatchObject({ target });
  });

  it('sees through sudo', () => {
    expect(detect('sudo sed -i s/a/b/ /etc/hosts')).toMatchObject({ target: '/etc/hosts' });
    expect(detect('echo x | sudo tee -a /etc/hosts')).toMatchObject({ target: '/etc/hosts' });
    expect(detect('sudo -u postgres tee /etc/hosts')).toMatchObject({ target: '/etc/hosts' });
  });

  it('says what the command would do, in words that fit a sentence', () => {
    expect(detect('sed -i s/a/b/ /etc/hosts')!.reason).toBe('edits the file in place');
    expect(detect('echo x > /etc/foo')!.reason).toBe('redirects output onto it');
    expect(detect('echo x >> /etc/foo')!.reason).toBe('appends to it');
    expect(detect('cp /tmp/x /etc/hosts')!.reason).toBe('replaces it');
  });

  it('quotes the segment that would do it, not the whole line', () => {
    expect(detect('uptime && sed -i s/a/b/ /etc/hosts')!.command).toBe('sed -i s/a/b/ /etc/hosts');
  });
});

/**
 * Known and documented rather than half-solved. Chasing a relative target means
 * tracking the working directory across segments, and the next line would just
 * be `cd /etc; cd .; sed -i …`.
 */
describe('what this deliberately does not catch', () => {
  it('lets a relative target through after a cd', () => {
    expect(detect('cd /etc && sed -i s/a/b/ nginx.conf')).toBeUndefined();
  });

  it('lets a command wrapper hide the write', () => {
    expect(detect('env FOO=1 sed -i s/a/b/ /etc/hosts')).toBeUndefined();
    expect(detect('xargs sed -i s/a/b/ /etc/hosts')).toBeUndefined();
  });
});
