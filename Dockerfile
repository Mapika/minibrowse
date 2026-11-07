# Sandbox image with mb: Google Chrome stable, a virtual display, fonts, and a non-root user so
# Chrome keeps its own sandbox. Build:  docker build -t mb-sandbox .
# Try:  docker run --rm --shm-size=1g mb-sandbox sh -c 'mb goto example.com && mb snap && mb mem'
FROM node:22-bookworm-slim

# Behind a TLS-intercepting proxy, pass its CA: --build-arg EXTRA_CA_CERT="$(cat proxy-ca.crt)"
ARG EXTRA_CA_CERT=""
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg xvfb xauth procps \
      fonts-liberation fonts-noto-core fonts-noto-color-emoji fonts-noto-cjk \
 && if [ -n "$EXTRA_CA_CERT" ]; then printf '%s\n' "$EXTRA_CA_CERT" > /usr/local/share/ca-certificates/extra.crt && update-ca-certificates; fi \
 && curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google.gpg \
 && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
 && apt-get update && apt-get install -y --no-install-recommends google-chrome-stable \
 && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY mb.mjs guard.mjs SKILL.md SECURITY.md /opt/mb/
RUN chmod +x /opt/mb/mb.mjs && ln -s /opt/mb/mb.mjs /usr/local/bin/mb

# Non-root, so Chrome runs with its sandbox on. The profile lives in /home/agent/.mb: mount a
# per-user volume there to keep logins across sandbox restarts.
RUN useradd -m -s /bin/bash agent
USER agent
WORKDIR /home/agent
ENV MB_CHROME=/usr/bin/google-chrome-stable MB_IDLE=300
