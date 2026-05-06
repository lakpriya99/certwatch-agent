# syntax=docker/dockerfile:1.6
#
# CertWatch agent — multi-stage build.
#   - builder: installs Python deps in a venv, with build tools available
#     for cryptography's native extension. Doesn't ship.
#   - runtime: python:3.11-slim + ca-certificates + the venv. Drops
#     privileges to a non-root user. /data is a volume.
#
# The runtime stage deliberately does NOT contain build tools, headers,
# pytest, responses, or the tests/ directory — anything the agent doesn't
# need at runtime stays out so the attack surface and image size are both
# minimal.

# ---------- builder ----------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build deps for cryptography (needs a C compiler + libffi/openssl headers
# when no manylinux wheel matches the target arch — cheap insurance).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libssl-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Install runtime deps in a separately-cached layer so source changes
# don't invalidate the dep install.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Now install the certwatch package itself. --no-deps because deps were
# already installed above; this layer reinvalidates only on package or
# pyproject.toml changes.
COPY pyproject.toml /tmp/build/pyproject.toml
COPY certwatch /tmp/build/certwatch
RUN pip install --no-cache-dir --no-deps /tmp/build


# ---------- runtime ----------
FROM python:3.11-slim AS runtime

# Build args populated by CI from certwatch/_version.py and the commit SHA.
# Default values work for local builds.
ARG VERSION=0.0.0-local
ARG VCS_REF=local

LABEL org.opencontainers.image.title="certwatch-agent" \
      org.opencontainers.image.description="TLS certificate monitoring agent for Kurmi labs" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}"

# Runtime deps only — ca-certificates for verifying TLS to dashboard +
# checked hosts. NO build tools, NO headers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user with a fixed UID/GID so volume ownership matches across
# host bind-mounts and named volumes consistently.
RUN groupadd --system --gid 10001 certwatch \
    && useradd --system --uid 10001 --gid 10001 \
       --create-home --home-dir /home/certwatch --shell /usr/sbin/nologin \
       certwatch

# /data is the persistence volume (agent.json + pending_reports/).
# 0700 because agent_secret is a long-lived credential.
RUN install -d -m 0700 -o certwatch -g certwatch /data

# Copy the venv (with both deps and the certwatch package installed).
COPY --from=builder /opt/venv /opt/venv

WORKDIR /home/certwatch
USER certwatch

VOLUME ["/data"]

ENTRYPOINT ["python", "-m", "certwatch", "agent"]
