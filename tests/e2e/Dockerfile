# A disposable "production host" for end-to-end tests.
#
# Ubuntu 24.04 with real systemd as PID 1, sshd, sudo, journald and its OWN Docker
# daemon — so `safereach enroll --hardened` runs here exactly as on a server: creates the
# diag account, installs the root-owned shim and policy, starts the socket proxy on this
# host's daemon, writes sudoers and the sshd drop-in, reloads sshd. Nothing is mocked.
#
# Needs --privileged (systemd + a nested dockerd). Run only through tests/e2e/rig.py.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus openssh-server sudo python3 ca-certificates curl \
        iptables iproute2 procps util-linux e2fsprogs kmod docker.io \
    && rm -rf /var/lib/apt/lists/*

# The admin account you already have access to on a real host: key-only login,
# passwordless sudo, the way a cloud image ships.
RUN useradd -m -s /bin/bash ops \
    && echo 'ops ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ops && chmod 0440 /etc/sudoers.d/ops \
    && mkdir -p /home/ops/.ssh && chmod 700 /home/ops/.ssh && chown -R ops:ops /home/ops/.ssh

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && mkdir -p /run/sshd \
    && systemctl enable ssh docker

# A service that carries secrets the way real ones do: an Environment= line in the unit
# and a password on its command line. The probes assert neither ever reaches the agent.
COPY app.py /opt/app/app.py
COPY app.service /etc/systemd/system/app.service
RUN systemctl enable app

# Keep the nested daemon's storage off the overlay so overlay2 works inside.
VOLUME /var/lib/docker

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
