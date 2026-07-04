FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=America/Sao_Paulo

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    findutils \
    passwd \
    sudo \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

RUN if getent passwd ubuntu >/dev/null 2>&1; then userdel -r ubuntu || true; fi && \
    if getent group ubuntu >/dev/null 2>&1; then groupdel ubuntu || true; fi

COPY bootstrap.sh /usr/local/bin/bootstrap-backup-server.sh
COPY entrypoint.sh /usr/local/bin/backup-server-entrypoint.sh

RUN chmod +x /usr/local/bin/bootstrap-backup-server.sh /usr/local/bin/backup-server-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/backup-server-entrypoint.sh"]
CMD ["bash"]
