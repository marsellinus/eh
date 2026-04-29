FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog iptables \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd \
    && useradd -m -s /bin/bash researcher \
    && echo 'researcher:research123' | chpasswd \
    && echo 'root:root123' | chpasswd

COPY sshd_config /etc/ssh/sshd_config
COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
