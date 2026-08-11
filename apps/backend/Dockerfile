# syntax=docker/dockerfile:1
FROM golang:1.26.1-alpine AS scanner-builder

ARG YARA_VERSION=4.5.4
ARG YARA_SHA256=586c9c21878f8b4d1b9423b89ac937f21f8057b03e3e9706f310549d453966fa
ARG SCAN_KERNEL_VERSION=1.0.0
ARG SCAN_KERNEL_COMMIT=unknown
ARG SCAN_KERNEL_BUILD_TIME=unknown

RUN apk add --no-cache \
    autoconf \
    automake \
    bison \
    build-base \
    curl \
    flex \
    libtool \
    openssl-dev \
    openssl-libs-static

WORKDIR /tmp
RUN curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" -o yara.tar.gz \
    && echo "${YARA_SHA256}  yara.tar.gz" | sha256sum -c - \
    && tar -xzf yara.tar.gz \
    && cd "yara-${YARA_VERSION}" \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local --disable-shared --enable-static --disable-proc-scan \
    && make -j"$(getconf _NPROCESSORS_ONLN)" \
    && make install

WORKDIR /src/packages/scan_kernel
COPY packages/scan_kernel/go.mod packages/scan_kernel/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY packages/scan_kernel/ ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 \
    CGO_LDFLAGS="-lyara -lm -lcrypto -ldl -pthread" \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig \
    go build -trimpath \
      -tags "netgo,osusergo,custom_plugins,plugin_agent_skill,yara_native" \
      -ldflags "-s -w -linkmode external -extldflags=-static \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Version=${SCAN_KERNEL_VERSION} \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.Commit=${SCAN_KERNEL_COMMIT} \
        -X gitlab.com/superalign/labs/asset-scan-demo/packages/scan_kernel/internal/buildinfo.BuildTime=${SCAN_KERNEL_BUILD_TIME}" \
      -o /out/scan-kernel-engine ./cmd/scankernel

FROM python:3.12-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_DEV=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    git \
    pkg-config \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.10.8 /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY apps/backend/pyproject.toml apps/backend/pyproject.toml

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --all-packages --no-install-workspace --no-dev

FROM python:3.12-slim-bookworm AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/apps" \
    SCAN_KERNEL_EXECUTABLE="/usr/local/bin/scan-kernel-engine"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1001 appgroup \
    && useradd -u 1001 -g appgroup -m -s /bin/bash appuser

WORKDIR /app

COPY --from=builder --chown=appuser:appgroup /app/.venv /app/.venv
COPY --chown=appuser:appgroup apps/backend/ /app/apps/backend/
COPY --from=scanner-builder --chmod=755 /out/scan-kernel-engine /usr/local/bin/scan-kernel-engine

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "backend.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
