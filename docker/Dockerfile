# A throwaway host for the integration tests.
#
# Debian rather than Alpine on purpose: `ssh_edit` reads and writes through
# `sudo base64 -- <path>` and `sudo cp -- <src> <dst>`, and busybox's applets
# differ from GNU coreutils exactly where those invocations are careful (`--`,
# and `cp` truncating rather than unlinking). A test host that behaves unlike
# every real target would prove the wrong thing.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd && ssh-keygen -A

# Keys only, as the server itself insists on.
RUN printf '%s\n' \
      'PermitRootLogin no' \
      'PasswordAuthentication no' \
      'KbdInteractiveAuthentication no' \
      'PubkeyAuthentication yes' \
      > /etc/ssh/sshd_config.d/ssh-mcp-test.conf

ARG PUBKEY
RUN useradd --create-home --shell /bin/bash deploy \
 && mkdir -p /home/deploy/.ssh \
 && printf '%s\n' "$PUBKEY" > /home/deploy/.ssh/authorized_keys \
 && chown -R deploy:deploy /home/deploy/.ssh \
 && chmod 700 /home/deploy/.ssh \
 && chmod 600 /home/deploy/.ssh/authorized_keys

# No password prompt for sudo: the sudo-password page is covered by the unit
# suite, and what these tests are about is what ends up in the files.
RUN printf 'deploy ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/deploy \
 && chmod 440 /etc/sudoers.d/deploy

# Root-owned and not writable by deploy: the ordinary shape of /etc, and the
# path that makes ssh_edit escalate.
RUN mkdir -p /etc/app \
 && printf '%s\n' \
      '# app config' \
      'host = db.internal' \
      'db_password = hunter2-do-not-lose' \
      'pool_size = 10' \
      'api_key = "abc123XYZ"' \
      > /etc/app/app.conf \
 && chown root:root /etc/app/app.conf \
 && chmod 0644 /etc/app/app.conf

# Named in [secrets].paths by the test config: readable, and still never returned.
RUN printf '%s\n' 'SERVICE_TOKEN=tok_live_9f3b21' > /etc/app/prod.env \
 && chmod 0644 /etc/app/prod.env

# Writable by the connecting user, so the unprivileged write path is exercised too.
RUN printf '%s\n' 'name = local' 'password = user-secret-99' > /home/deploy/user.conf \
 && chown deploy:deploy /home/deploy/user.conf

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
