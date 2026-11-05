FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    IS_SANDBOX=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg python3 python3-pip python3-venv && \
    install -d -m 0755 /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main' > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y --no-install-recommends nodejs && \
    npm install --global @anthropic-ai/claude-code@2.1.307 && \
    python3 -m venv /opt/tracekit && \
    /opt/tracekit/bin/pip install --no-cache-dir tracekit-ai==1.5.3 && \
    groupadd --system agent && useradd --system --create-home --gid agent --shell /bin/bash agent && \
    install -d -o root -g root -m 0755 /etc/claude-code && \
    rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/tracekit/bin:${PATH}"

COPY managed-settings.json /etc/claude-code/managed-settings.json
RUN chown root:root /etc/claude-code/managed-settings.json && chmod 0644 /etc/claude-code/managed-settings.json

USER agent
WORKDIR /workspace
ENTRYPOINT ["claude"]
