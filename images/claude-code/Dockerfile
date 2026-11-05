# lean: the base image, NodeSource's signing key and the nodejs package are pinned by name and major version only, not
# by digest, fingerprint and exact version: their current values come from the registries, which could not be read
# when this was written. Pin them before publishing the image: debian:bookworm-slim@sha256:<index digest>, the key
# checked with `gpg --show-keys --with-colons` against its fingerprint, and nodejs=<22.x.y>-1nodesource1.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    IS_SANDBOX=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# Claude Code from package-lock.json (every package, the platform binaries included, checked by its integrity hash);
# the hook client from requirements.txt (every wheel checked by its sha256)
COPY package.json package-lock.json requirements.txt /tmp/image/

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg python3 python3-pip python3-venv && \
    install -d -m 0755 /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main' > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && apt-get install -y --no-install-recommends nodejs && \
    install -d -m 0755 /opt/claude-code && cp /tmp/image/package.json /tmp/image/package-lock.json /opt/claude-code/ && \
    cd /opt/claude-code && npm ci --no-audit --no-fund && cd / && \
    ln -s /opt/claude-code/node_modules/.bin/claude /usr/local/bin/claude && \
    python3 -m venv /opt/tracekit && \
    /opt/tracekit/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/image/requirements.txt && \
    groupadd --system agent && useradd --system --create-home --gid agent --shell /bin/bash agent && \
    install -d -o root -g root -m 0755 /etc/claude-code && \
    rm -rf /var/lib/apt/lists/* /tmp/image

ENV PATH="/opt/tracekit/bin:${PATH}"

COPY managed-settings.json /etc/claude-code/managed-settings.json
RUN chown root:root /etc/claude-code/managed-settings.json && chmod 0644 /etc/claude-code/managed-settings.json

USER agent
WORKDIR /workspace
ENTRYPOINT ["claude"]
