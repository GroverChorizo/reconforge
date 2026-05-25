# ── ReconForge Dockerfile ──────────────────────────────────
# Multi-arch: linux/amd64, linux/arm64, linux/arm/v7
# All 16 recon tools pre-installed.
# ───────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    RECON_DATA_DIR=/data \
    PYTHONUNBUFFERED=1

# ── system packages ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # build + network utils
    curl wget git ca-certificates openssl \
    # Nikto dependencies
    perl libnet-ssleay-perl \
    # Nmap
    nmap \
    # Python tools
    python3-pip \
    # Chromium (for Gowitness screenshots)
    chromium \
    # Misc
    unzip tar gzip \
  && rm -rf /var/lib/apt/lists/*

# ── Python packages ────────────────────────────────────────
# Recon CLI tools
RUN pip install --no-cache-dir sublist3r theHarvester wafw00f
# Runtime deps for ReconForge v2 (Phase 4a pinned in pyproject.toml)
RUN pip install --no-cache-dir psutil "pydantic>=2.6,<3" "claude-agent-sdk>=0.1.0" "textual>=0.60"
# Phase C Batch 1: BBOT (recursive multi-source subdomain enumeration).
# pip install is the official path; CLI lands on PATH as `bbot`.
RUN pip install --no-cache-dir "bbot[all]"

# ── Go tools (single RUN to minimise layers) ───────────────
ARG GOVERSION=1.22.4
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

# Map Docker platform → Go GOARCH/GOARM
RUN set -e; \
    OS=linux; \
    case "${TARGETARCH}" in \
      amd64) GOARCH=amd64;; \
      arm64) GOARCH=arm64;; \
      arm)   GOARCH=arm; GOARM=7;; \
      *)     echo "Unsupported arch: ${TARGETARCH}" && exit 1;; \
    esac; \
    GOFILE="go${GOVERSION}.${OS}-${GOARCH}.tar.gz"; \
    curl -fsSL "https://go.dev/dl/${GOFILE}" -o /tmp/go.tar.gz; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}" GOPATH="/go" GOBIN="/usr/local/bin"

# Install Go-based recon tools
RUN go install -v github.com/owasp-amass/amass/v4/...@latest          2>/dev/null || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/tomnomnom/assetfinder@latest               2>/dev/null || true && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest      2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest    2>/dev/null || true && \
    go install -v github.com/sensepost/gowitness@latest                 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/gwen001/github-subdomains@latest           2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest                        2>/dev/null || true && \
    go install -v github.com/d3mondev/puredns/v2@latest                 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest  2>/dev/null || true && \
    go install -v github.com/assetnote/kiterunner/cmd/kr@latest         2>/dev/null || true

# Phase C Batch 2: Rust-based HTTP exploration tools (feroxbuster, x8).
# Installed via cargo so they pick up musl-friendly builds.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install feroxbuster x8

# ── Findomain ──────────────────────────────────────────────
RUN set -e; \
    ARCH="${TARGETARCH}"; \
    case "${ARCH}" in \
      amd64) FINDOMAIN_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip";; \
      arm64) FINDOMAIN_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip";; \
      arm)   FINDOMAIN_URL="https://github.com/findomain/findomain/releases/latest/download/findomain-armv7.zip";; \
      *)     echo "No findomain for ${ARCH}" && exit 0;; \
    esac; \
    curl -fsSL "${FINDOMAIN_URL}" -o /tmp/findomain.zip 2>/dev/null || true; \
    if [ -f /tmp/findomain.zip ]; then \
      unzip -o /tmp/findomain.zip -d /usr/local/bin/; \
      chmod +x /usr/local/bin/findomain* 2>/dev/null || true; \
      rm /tmp/findomain.zip; \
    fi

# ── Nikto ──────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# ── Nuclei templates ───────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Application ────────────────────────────────────────────
WORKDIR /app
COPY pyproject.toml .
COPY __init__.py .
COPY __main__.py .
COPY main.py .
COPY scope_guard.py .
COPY scopes/ ./scopes/
COPY db/ ./db/
COPY attack/ ./attack/
COPY core/ ./core/
COPY data/ ./data/
COPY agents/ ./agents/
COPY tools/ ./tools/
COPY api/ ./api/
COPY ui/ ./ui/
COPY obsidian/ ./obsidian/
COPY submissions/ ./submissions/
COPY wizard/ ./wizard/

RUN mkdir -p /data

VOLUME ["/data"]
EXPOSE 8342

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8342/api/state || exit 1

ENTRYPOINT ["python3", "main.py"]
CMD ["--host", "0.0.0.0", "--port", "8342", "--skip-setup"]
